"""Durable bounded authenticated assessments; credentials never enter run files."""
import asyncio
import hashlib
import json
from pathlib import Path
from uuid import uuid4
from auditor.scanner import now, save_json, save_evidence
from auditor.core.http_client import ScanStopped
from auditor.reporting.html_report import write_report
from auditor.planning.coverage import build_coverage
from auditor.verification.integrity import audit_run
from auditor.reporting.ai import ensure_all_ai
from auditor.resume_engine import lock_run
from .sessions import AccountSessions, SessionError
from .checks import METADATA, access_check, sql_differential, logout_replay
from .rbac import role_access_check

LIMITATIONS = [
    'AuditShop JSON adapter only; configured identities and ownership policy are trusted inputs.',
    'Only declared resources and bounded probes are tested. No complete OWASP assessment is claimed.',
    'Raw bodies, cookies, credentials, CSRF tokens and private markers are discarded.',
    'CHK13 is opt-in, AuditShop /api/rbac/<slug> adapter-specific and trusts the reviewed operator policy.',
    'This authenticated mode is not resumable; interrupted runs retain completed evidence.',
    'Logout tests may leave an invalidation-defective server session until expiry or lab reset.',
]
FIXES = {'CHK09':'Enforce server-side ownership for every order read.',
         'CHK10':'Require authentication and ownership before returning private order data.',
         'CHK11':'Use parameterized queries and review the search implementation.',
         'CHK12':'Revoke the server-side session on logout and reject the old token.',
         'CHK13':'Enforce server-side role authorization on every read of private resources.'}


async def run_assessment(project, profile, credentials, output, *, transport_factory=None, generate_ai=True, rbac_policy=None):
    # generate_ai is an internal offline-test seam, not an end-user option.
    run = Path(output).resolve() / ('scan-' + uuid4().hex[:12])
    run.mkdir(parents=True, exist_ok=False)
    for folder in ('results','evidence','reports'):
        (run/folder).mkdir()
    scan = {'id':run.name, 'tool_version':'0.2.0rc1', 'target':project['base_url'],
            'started_at':now(), 'ended_at':None, 'status':'partial', 'request_count':0,
            'stop_reason':'assessment_in_progress', 'resumable':False,
            'mode':'auditshop_authenticated', 'note':'Bounded declared-resource assessment.'}
    if rbac_policy is not None:
        scan['rbac_policy_sha256'] = hashlib.sha256(json.dumps(rbac_policy, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        scan['rbac_policy_attested'] = True
    tests, findings, account_results = [], [], []
    sessions = AccountSessions(project, profile, transport_factory)
    if rbac_policy is not None:
        sessions.rbac_resource_ids = frozenset(x['resource_id'] for x in rbac_policy['cases'])
    interrupted = False
    completed = False

    def persist():
        scan['request_count'] = sessions.budget.request_count
        save_json(run/'scan.json',scan)
        save_json(run/'request_ledger.json',sessions.budget.ledger)
        save_json(run/'results/tests.json',tests)
        save_json(run/'results/findings.json',findings)
        save_json(run/'results/coverage.json',build_coverage(tests))
        save_json(run/'results/accounts.json',{'accounts':account_results,'cleanup':sessions.cleanup,
                    'secrets_retained':False})

    async def execute(rule, endpoint, coroutine):
        start = sessions.budget.request_count
        try:
            status, reason, observed, steps = await coroutine
        except (SessionError, ScanStopped) as exc:
            status, reason, observed, steps = 'Inconclusive', 'Check stopped: ' + str(exc), {'stop_reason':str(exc)}, []
        category, title, expected = (('A01:2025','Role-based authorization',
            'The denied role cannot read a policy-protected private resource.')
            if rule == 'CHK13' else METADATA[rule])
        test = {'id':'test-'+uuid4().hex[:12], 'rule_id':rule, 'rule_version':'0.1.0',
                'category':category,'title':title,'endpoint':endpoint,'status':status,'reason':reason,
                'expected':expected,'steps':steps,'limitations':LIMITATIONS,
                'observed':observed,'request_count':sessions.budget.request_count-start,'evidence_refs':[]}
        if status != 'Not Tested':
            eid='ev-'+uuid4().hex[:12]
            test['evidence_refs']=[eid]
            save_evidence(run,{'id':eid,'test_id':test['id'],'kind':'bounded_authenticated_comparison',
                              'captured_at':now(),'endpoint':endpoint,'observation':observed,
                              'raw_body_retained':False,'credentials_retained':False})
        tests.append(test)
        if status in ('Confirmed','Potential'):
            findings.append({'id':'finding-'+uuid4().hex[:12],'rule_id':rule,'category':category,
                'title':title,'status':status,'severity':'High' if status=='Confirmed' else 'Medium',
                'confidence':'Controlled response comparison','impact':reason,'fix':FIXES[rule],
                'retest':'Repeat this configured check against vulnerable and fixed fixtures.',
                'affected_endpoints':[endpoint],'contributing_tests':[test['id']],
                'evidence_refs':test['evidence_refs']})
        persist()
        print(rule+': '+status,flush=True)

    print('Run:',run,flush=True)
    print('Authenticated assessment: no session checkpoint; Ctrl+C saves completed results.',flush=True)
    persist()
    # The hook saves counts BEFORE transport and afterwards, with no request payloads.
    sessions.budget.checkpoint_hook = persist
    try:
        async with sessions:
            for account in project['accounts']:
                result={'alias':account['alias'],'verified':False,'reason':None}
                try:
                    await sessions.login(account, credentials[account['alias']])
                    result['verified']=True
                except (SessionError,ScanStopped) as exc:
                    result['reason']=str(exc)
                account_results.append(result)
                persist()
            for resource in project['assessment']['order_resources']:
                endpoint=project['base_url']+'/api/orders/'+str(resource['order_id'])
                await execute('CHK09',endpoint,access_check(sessions,resource))
                await execute('CHK10',endpoint,access_check(sessions,resource,anonymous=True))
            await execute('CHK11',project['base_url']+'/api/products',sql_differential(sessions))
            if rbac_policy is not None:
                for case in rbac_policy['cases']:
                    await execute('CHK13',project['base_url']+'/api/rbac/'+case['resource_id'],
                                  role_access_check(sessions,case))
            for account in project['accounts']:
                await execute('CHK12',project['base_url']+'/api/me',logout_replay(sessions,account))
        completed = True
    except asyncio.CancelledError:
        interrupted=True
        scan['stop_reason']='interrupted'
    finally:
        if completed:
            incomplete = any(t['status'] in ('Inconclusive','Not Tested') for t in tests)
            scan['status']='partial' if incomplete else 'finished'
            scan['stop_reason']='incomplete_checks' if incomplete else None
        if not completed and not interrupted:
            scan['stop_reason']='unexpected_execution_error'
        scan['ended_at']=now()
        persist()
        write_report(run)
        errors=audit_run(run)
        save_json(run/'results/integrity.json',{'status':'FAIL' if errors else 'PASS','errors':errors,
            'scope':'Evidence hashes, references and request accounting.',
            'limitation':'Integrity is not a vulnerability or full secret audit.'})
        write_report(run)
        print('Integrity audit:', 'FAIL' if errors else 'PASS', flush=True)
    if generate_ai and not interrupted:
        with lock_run(run):
            await ensure_all_ai(run)
    if interrupted:
        print('AI generation deferred after interruption. Use owasp-auditor-report to generate it.',flush=True)
    print('Requests attempted:',scan['request_count'],flush=True)
    print('Findings:',len(findings),flush=True)
    return run
