"""Transactional task checkpoints for the current OWASP Web Auditor CLI.

Graceful Ctrl+C is supported. A task is committed only after all its work
finishes. Retrying an interrupted task consumes the remaining original budget.
"""
import argparse
import asyncio
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import fcntl
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import time
from uuid import uuid4

FORMAT = 1
MAX_RECORDS = 500


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
        separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def fingerprint():
    root = Path(__file__).parent
    files = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(root.rglob('*.py'))}
    return digest({'files': files,
                   'dependencies': {name: version(name) for name in
                                    ('httpx', 'beautifulsoup4')}})


@contextmanager
def lock_run(path):
    with (path / '.resume.lock').open('a') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('This run is already active in another process.')
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def read_checkpoint(path):
    file = path / 'checkpoint.json'
    if not file.is_file():
        raise ValueError('No resume checkpoint. Pre-update runs cannot be resumed.')
    envelope = json.loads(file.read_text(encoding='utf-8'))
    state = envelope['state']
    if envelope.get('sha256') != digest(state):
        raise ValueError('Checkpoint checksum mismatch; refusing to resume.')
    if state.get('format') != FORMAT or state.get('fingerprint') != fingerprint():
        raise ValueError('Checkpoint code/dependency version differs. Restore the original environment.')
    if state['request_count'] != len(state['ledger']):
        raise ValueError('Invalid checkpoint request ledger.')
    if state['run_id'] != path.name:
        raise ValueError('Run directory name differs from checkpoint.')
    return state


def empty_inventory():
    return {'status': 'not_parsed', 'reason': 'no_complete_response',
            'pages_parsed': 0, 'pages_fetched_by_crawler': 0,
            'additional_requests': 0, 'records': [], 'limits_reached': [],
            'crawl_errors': [], 'crawl_stop_reason': None,
            'limitations': ['Only query-free .html/.htm links are followed.',
                'Forms are not submitted. Query/form values are omitted.',
                'Paths and input names are retained.',
                'Results may span multiple sessions; target content may change.']}


def new_state(target, profile, tool_version, reflection, exceptional, run_id, checks=None, crawl=True):
    from auditor.planning.selection import select_checks, skipped_by_selection, PAGE_RULES
    selected = select_checks(checks, reflection, exceptional)
    queue = []
    if 'CHK01' in selected:
        queue.append({'kind': 'https'})
    if PAGE_RULES.intersection(selected):
        queue.append({'kind': 'page', 'url': target, 'depth': 0})
    if 'CHK07' in selected:
        queue.append({'kind': 'reflection'})
    if 'CHK08' in selected:
        queue.append({'kind': 'exceptional'})
    inventory = empty_inventory()
    if not PAGE_RULES.intersection(selected):
        inventory['reason'] = 'page_inspection_not_selected'
    return {'format': FORMAT, 'fingerprint': fingerprint(), 'run_id': run_id,
        'target': target, 'profile': deepcopy(profile), 'tool_version': tool_version,
        'selected_checks': selected, 'crawl_enabled': crawl,
        'reflection_param': reflection, 'exception_param': exceptional,
        'started_at': now(), 'ended_at': None, 'active_seconds': 0.0,
        'request_count': 0, 'ledger': [], 'sessions': [],
        'tests': [skipped_by_selection(r, target) for r in
                  ('CHK01','CHK02','CHK03','CHK04','CHK05','CHK06','CHK07','CHK08') if r not in selected],
        'findings': [], 'evidence': {}, 'errors': [],
        'stop_reasons': [], 'pause_reason': None, 'complete': False,
        'inventory': inventory, 'scheduled': [target], 'processed': [],
        'queue': queue}


def attach(state, test, evidence=None, findings=None):
    state['tests'].append(test)
    if evidence:
        state['evidence'][evidence['id']] = evidence
    state['findings'].extend(findings or [])


def collect(state, response):
    from auditor.checks.headers import review_headers
    from auditor.checks.cookies import review_cookies
    from auditor.checks.error_disclosure import review_error_disclosure
    from auditor.checks.directory_listing import review_directory_listing
    endpoint = response['final_url']
    selected = state['selected_checks']
    if 'CHK02' in selected or 'CHK03' in selected:
        tests, evidence, findings = review_headers(response)
        tests = [t for t in tests if t['rule_id'] in selected]
        findings = [f for f in findings if f['rule_id'] in selected]
        evidence['endpoint'] = endpoint
        evidence['test_ids'] = [t['id'] for t in tests]
        for test in tests:
            test['endpoint'] = endpoint
        for finding in findings:
            finding['affected_endpoints'] = [endpoint]
        state['tests'].extend(tests)
        state['evidence'][evidence['id']] = evidence
        state['findings'].extend(findings)
    for rule, check in (('CHK04', review_cookies), ('CHK05', review_error_disclosure),
                        ('CHK06', review_directory_listing)):
        if rule in selected:
            test, evidence, findings = check(response)
            attach(state, test, evidence, findings)


def add_records(state, inventory, depth):
    from urllib.parse import urlsplit
    dest = state['inventory']
    dest['limits_reached'].extend(inventory.get('limits_reached', []))
    for item in inventory['records']:
        if len(dest['records']) >= MAX_RECORDS:
            dest['limits_reached'].append('total_record_limit')
            return
        record = deepcopy(item)
        record.update(id=f"endpoint-{len(dest['records']) + 1:04d}",
                      source_depth=depth, fetch_status='not_requested', crawl_reason=None)
        dest['records'].append(record)
        url = record.get('url')
        if record.get('kind') != 'link':
            reason = 'form_not_submitted'
        elif record.get('scope_decision') != 'allowed' or not url:
            reason = 'scope_or_url_rejected'
        elif record.get('query_values_omitted'):
            reason = 'query_url_not_supported'
        elif not urlsplit(url).path.lower().endswith(('.html', '.htm')):
            reason = 'outside_static_html_profile'
        elif url in state['scheduled'] or url in state['processed']:
            reason = 'already_seen'
        elif not state['crawl_enabled']:
            reason = 'crawling_disabled'
        elif depth >= state['profile']['max_depth']:
            reason = 'depth_limit'
            dest['limits_reached'].append(reason)
        else:
            reason = None
            state['scheduled'].append(url)
            record['fetch_status'] = 'queued'
            task = {'kind': 'page', 'url': url, 'depth': depth + 1,
                    'record_id': record['id']}
            # Insert before probes, after other pending pages (BFS).
            index = next((i for i, t in enumerate(state['queue'])
                          if t['kind'] in ('reflection', 'exceptional')), len(state['queue']))
            state['queue'].insert(index, task)
        record['crawl_reason'] = reason


async def execute_task(state, client, task):
    from auditor.core.http_client import ScanStopped
    from auditor.checks.https_handling import check_https_handling
    from auditor.checks.reflection import review_reflection, skipped_reflection
    from auditor.checks.exceptional_input import review_exceptional, skipped_exceptional
    from auditor.discovery.parser import extract_inventory
    from auditor.planning.coverage import RULES
    target = state['target']
    kind = task['kind']
    if kind == 'https':
        test, evidence, finding = await check_https_handling(target, state['profile'], client=client)
        test['endpoint'] = target
        if evidence:
            evidence['endpoint'] = target
        if finding:
            finding['affected_endpoints'] = [target]
        attach(state, test, evidence, [finding] if finding else [])
        reason = (test.get('observed') or {}).get('stop_reason')
        if reason:
            state['stop_reasons'].append(reason)
    elif kind in ('reflection', 'exceptional'):
        parameter = state['reflection_param'] if kind == 'reflection' else state['exception_param']
        if not parameter:
            attach(state, (skipped_reflection if kind == 'reflection' else skipped_exceptional)(target))
        else:
            fn = review_reflection if kind == 'reflection' else review_exceptional
            test, evidence, findings = await fn(client, target, parameter)
            attach(state, test, evidence, findings)
            if test['status'] == 'Inconclusive':
                state['stop_reasons'].append(kind + '_inconclusive')
    elif kind == 'page':
        inv = state['inventory']
        record = next((r for r in inv['records'] if r['id'] == task.get('record_id')), None)
        start_count = client.request_count
        try:
            response = await client.fetch(task['url'])
        except ScanStopped as exc:
            reason = str(exc)
            state['stop_reasons'].append(reason)
            if record:
                record.update(fetch_status='stopped', crawl_reason=reason)
                inv['crawl_errors'].append({'endpoint_id': record['id'], 'reason': reason})
            else:
                inv.update(status='not_parsed', reason=reason)
                for rule in ('CHK02', 'CHK03', 'CHK04', 'CHK05', 'CHK06'):
                    if rule not in state['selected_checks']:
                        continue
                    attach(state, {'id': 'test-' + uuid4().hex[:12], 'rule_id': rule,
                        'rule_version': '0.1.0', 'category': RULES[rule]['category'],
                        'title': rule + ' response check', 'endpoint': target,
                        'status': 'Not Tested', 'reason': 'No complete response: ' + reason,
                        'steps': [], 'expected': RULES[rule]['prerequisites'], 'observed': None,
                        'request_count': 0, 'evidence_refs': [], 'limitations': []})
            return
        finally:
            if task['depth'] > 0:
                inv['additional_requests'] += client.request_count - start_count
        final = response['final_url']
        if record:
            record.update(fetch_status='fetched', response_status=response['status_code'])
            inv['pages_fetched_by_crawler'] += 1
        if final in state['processed']:
            if record:
                record['crawl_reason'] = 'redirect_destination_seen'
            return
        state['processed'].append(final)
        collect(state, response)
        if task['depth'] > 0 and not 200 <= response['status_code'] < 300:
            if record:
                record['crawl_reason'] = 'non_success_response'
            return
        child = extract_inventory(response, client.check_scope)
        if task['depth'] == 0:
            inv['source_url'] = final
            inv['status'] = child['status']
            inv['reason'] = child.get('reason')
        inv['pages_parsed'] += child['pages_parsed']
        add_records(state, child, task['depth'])
    else:
        raise ValueError('Unknown checkpoint task.')


def export_run(path, state):
    from auditor.scanner import save_json, save_evidence
    from auditor.planning.coverage import build_plan, reconcile_plan, build_coverage
    from auditor.verification.deduplication import deduplicate_findings
    from auditor.reporting.html_report import render_report, write_report
    from auditor.verification.integrity import audit_run
    tests = state['tests']
    inv = deepcopy(state['inventory'])
    inv['additional_requests'] = sum(
        r.get('task_kind') == 'page' and r.get('crawl_depth', 0) > 0
        for r in state['ledger'])
    inv['limits_reached'] = sorted(set(inv['limits_reached']))
    reasons = list(dict.fromkeys(state['stop_reasons'] +
                    ([state['pause_reason']] if state['pause_reason'] else [])))
    if inv['limits_reached']:
        reasons.append('discovery_partial')
    if not state['complete']:
        inv['status'] = 'partial'
        inv['crawl_stop_reason'] = state['pause_reason']
    elif inv['status'] != 'not_parsed':
        inv['status'] = 'partial' if inv['limits_reached'] or inv['crawl_errors'] else 'completed_within_profile'
    scan = {'id': state['run_id'], 'target': state['target'], 'profile': state['profile'],
        'tool_version': state['tool_version'], 'started_at': state['started_at'],
        'ended_at': state['ended_at'], 'status': 'partial' if reasons else 'finished',
        'request_count': state['request_count'], 'stop_reason': '; '.join(reasons) or None,
        'operational_errors': state['errors'], 'active_seconds': state['active_seconds'],
        'sessions': state['sessions'], 'resumable': not state['complete'],
        'rule_versions': {t['rule_id']: t['rule_version'] for t in tests},
        'supported_checks': [f'CHK{i:02}' for i in range(1, 9)],
        'selected_checks': state['selected_checks'], 'crawl_enabled': state['crawl_enabled'],
        'discovery': {'status': inv['status'], 'records': len(inv['records']),
                      'pages_parsed': inv['pages_parsed'], 'limits_reached': inv['limits_reached']},
        'note': 'Checkpointed assessment; results can span multiple sessions.'}
    save_json(path / 'scan.json', scan)
    save_json(path / 'request_ledger.json', state['ledger'])
    save_json(path / 'discovery/endpoints.json', inv)
    for evidence in state['evidence'].values():
        save_evidence(path, deepcopy(evidence))
    findings = deduplicate_findings(state['findings'])
    save_json(path / 'results/tests.json', tests)
    save_json(path / 'results/findings_raw.json', state['findings'])
    save_json(path / 'results/findings.json', findings)
    save_json(path / 'results/plan.json', reconcile_plan(build_plan(state['target'],
        state['reflection_param'], state['exception_param'], selected_checks=state['selected_checks']), tests))
    save_json(path / 'results/coverage.json', build_coverage(tests))
    report = path / 'reports/report.html'
    write_report(path)
    errors = audit_run(path)
    save_json(path / 'results/integrity.json', {'status': 'FAIL' if errors else 'PASS',
        'checked_at': now(), 'errors': errors,
        'scope': 'Saved references, evidence hashes, ledger and known fixture markers.',
        'limitation': 'Integrity is not completion, authentication or a full secret scan.'})
    write_report(path)
    print('Integrity audit:', 'FAIL' if errors else 'PASS')
    for test in tests:
        print(test['rule_id'] + ': ' + test['status'])
    print('Requests attempted:', state['request_count'])
    print('Test records:', len(tests))
    print('Raw findings:', len(state['findings']))
    print('Grouped findings:', len(findings))
    print('Discovery records:', len(inv['records']))
    print('Report:', report.resolve())
    print('Checkpoint:', (path / 'checkpoint.json').resolve())
    if not state['complete']:
        print('Resume: python -m auditor --resume ' + str(path.resolve()))


async def run_scan(target, profile, output, tool_version, reflection_param=None,
                   exception_param=None, resume_dir=None, checks=None, crawl=None):
    from auditor.scanner import save_json
    from auditor.core.http_client import BoundedHTTPClient
    from auditor.planning.selection import select_checks
    if resume_dir is not None and (checks is not None or crawl is not None):
        raise ValueError('Resume preserves check selection and crawl policy; do not override them.')
    if resume_dir is None:
        select_checks(checks, reflection_param, exception_param)
        if crawl is not None and type(crawl) is not bool:
            raise ValueError('crawl must be a boolean.')
        path = Path(output) / ('scan-' + uuid4().hex[:12])
        path.mkdir(parents=True, exist_ok=False)
        for folder in ('results', 'evidence', 'reports', 'discovery'):
            (path / folder).mkdir()
    else:
        path = Path(resume_dir)
        if not path.is_dir():
            raise ValueError('Resume directory does not exist.')
    with lock_run(path):
        if resume_dir is None:
            state = new_state(target, profile, tool_version, reflection_param, exception_param, path.name,
                              checks=checks, crawl=True if crawl is None else crawl)
        else:
            state = read_checkpoint(path)
            if state['complete']:
                print('Scan task queue is already complete; no target requests sent.')
                return path
            if state['tool_version'] != tool_version:
                raise ValueError('Tool version differs from checkpoint.')
            if state['request_count'] >= state['profile']['max_requests']:
                raise ValueError('Original request budget exhausted; start a separately scoped new scan.')
            if state['active_seconds'] >= state['profile']['scan_deadline_seconds']:
                raise ValueError('Original active-time budget exhausted; start a new scan.')
        base_seconds = state['active_seconds']
        session_start = time.monotonic()
        state['sessions'].append({'started_at': now(), 'ended_at': None})
        state['pause_reason'] = None
        client = None
        active_task = None
        cancelled = False
        unexpected = False

        def checkpoint():
            state['active_seconds'] = base_seconds + time.monotonic() - session_start
            if client is not None:
                for record in client.ledger:
                    if active_task and 'task_kind' not in record:
                        record['task_kind'] = active_task['kind']
                        record['crawl_depth'] = active_task.get('depth', 0)
                state['request_count'] = client.request_count
                state['ledger'] = deepcopy(client.ledger)
            save_json(path / 'checkpoint.json', {'state': state, 'sha256': digest(state)})

        checkpoint()
        print('Run:', path.resolve())
        print('Checkpointing enabled. Press Ctrl+C once to pause.')
        try:
            async with BoundedHTTPClient(state['target'], state['profile']) as client:
                client.request_count = state['request_count']
                client.ledger = deepcopy(state['ledger'])
                for record in client.ledger:
                    if record['outcome'] == 'started':
                        record['outcome'] = 'interrupted'
                remaining = state['profile']['scan_deadline_seconds'] - (
                    base_seconds + time.monotonic() - session_start)
                client.deadline = time.monotonic() + max(0, remaining)
                client.checkpoint_hook = checkpoint
                while state['queue']:
                    if client.request_count >= state['profile']['max_requests']:
                        state['pause_reason'] = 'request_budget_exhausted'
                        break
                    if time.monotonic() >= client.deadline:
                        state['pause_reason'] = 'scan_deadline_reached'
                        break
                    # All modifications belong to a candidate transaction.
                    # Cancellation/error leaves the committed queue intact.
                    candidate = deepcopy(state)
                    task = candidate['queue'].pop(0)
                    active_task = task
                    await execute_task(candidate, client, task)
                    state = candidate
                    checkpoint()
                state['complete'] = not state['queue']
        except asyncio.CancelledError:
            cancelled = True
            state['pause_reason'] = 'user_or_task_cancellation'
        except Exception as exc:
            unexpected = True
            state['pause_reason'] = 'unexpected_error'
            state['errors'].append({'type': type(exc).__name__, 'message_retained': False})
        finally:
            if client is not None:
                for record in client.ledger:
                    if record['outcome'] == 'started':
                        record['outcome'] = 'interrupted' if cancelled else 'incomplete_after_error'
            state['ended_at'] = now()
            state['sessions'][-1]['ended_at'] = state['ended_at']
            checkpoint()
        export_run(path, state)
        if cancelled:
            raise asyncio.CancelledError()
        if unexpected:
            raise RuntimeError('Scan stopped unexpectedly; checkpoint and partial outputs saved.')

        return path


def resume_cli():
    from auditor.__main__ import TOOL_VERSION
    from auditor.reporting.ai import run_scan_with_ai
    parser = argparse.ArgumentParser(description='Resume a checkpointed scan using its original settings.')
    parser.add_argument('--resume', required=True, type=Path)
    from auditor.reporting.ai import add_ai_arguments, apply_ai_arguments
    add_ai_arguments(parser)
    args = parser.parse_args()
    apply_ai_arguments(args)
    try:
        asyncio.run(run_scan_with_ai(None, None, None, TOOL_VERSION, resume_dir=args.resume))
    except KeyboardInterrupt:
        parser.exit(130, 'Interrupted; checkpoint saved when graceful cleanup completed.\n')
    except (ValueError, OSError, RuntimeError, KeyError, TypeError) as exc:
        parser.exit(1, 'Resume failed: ' + str(exc) + '\n')
