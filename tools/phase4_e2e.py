"""Run independently specified *local* HTTP CLI smoke/holdout cases.

These are additional first-party controlled cases, not third-party benchmark data.
No scan outside 127.0.0.1; no AI results are used for scoring.
"""
import argparse
import contextlib
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
from urllib.parse import urlsplit, parse_qs

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SCENARIOS = {
    'hardened_html': {
        'headers': {'Content-Type':'text/html', 'X-Content-Type-Options':'nosniff',
                    'Content-Security-Policy':"frame-ancestors 'none'",
                    'Set-Cookie':'session=PLACEHOLDER; Secure; HttpOnly; SameSite=Lax; Path=/'},
        'body':'<html><title>Local lab</title><p>Welcome</p></html>',
        'expected': {'CHK02':'Inconclusive','CHK03':'No Issue Observed', 'CHK04':'No Issue Observed',
                     'CHK05':'No Issue Observed','CHK06':'No Issue Observed'},
    },
    'missing_headers': {
        'headers': {'Content-Type':'text/html', 'Set-Cookie':'session=PLACEHOLDER; Path=/'},
        'body':'<html><title>Local lab</title><p>Welcome</p></html>',
        'expected': {'CHK02':'Potential','CHK03':'Potential','CHK04':'Potential',
                     'CHK05':'No Issue Observed','CHK06':'No Issue Observed'},
    },
    'traceback_disclosure': {
        'headers': {'Content-Type':'text/plain','X-Content-Type-Options':'nosniff'},
        'body':'Traceback (most recent call last):\n  File "/srv/PRIVATE_PATH/app.py", line 3\nRuntimeError: DO_NOT_SAVE_THIS',
        'expected': {'CHK02':'Not Tested','CHK03':'No Issue Observed',
                     'CHK05':'Potential','CHK06':'Not Tested'},
    },
    'directory_index': {
        'headers': {'Content-Type':'text/html','X-Content-Type-Options':'nosniff'},
        'body':'<html><title>Directory listing for /</title><h1>Directory listing for /</h1><ul><li><a href="private.txt">private.txt</a></li></ul></html>',
        'expected': {'CHK02':'Potential','CHK03':'No Issue Observed','CHK05':'No Issue Observed','CHK06':'Potential'},
    },
    'marker_reflection': {
        'headers': {'Content-Type':'text/plain','X-Content-Type-Options':'nosniff'},
        'body':'fixed landing page',
        'reflect_query':True,
        'expected': {'CHK07':'Potential'},
    },
}


def serve_case(case):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return
        def do_GET(self):
            parsed = urlsplit(self.path)
            text=case['body']
            if case.get('reflect_query'):
                text=parse_qs(parsed.query).get('q',['fixed landing page'])[0]
            payload=text.encode('utf-8')
            self.send_response(200)
            for k,v in case['headers'].items(): self.send_header(k,v)
            self.send_header('Content-Length',str(len(payload)))
            self.end_headers()
            try: self.wfile.write(payload)
            except BrokenPipeError: pass
    server=ThreadingHTTPServer(('127.0.0.1',0), Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    return server,thread


def run_case(name,case,output_dir):
    from auditor.reporting.validation import load_report_data
    from auditor.verification.integrity import audit_run
    server,thread=serve_case(case)
    try:
        with tempfile.TemporaryDirectory(prefix='owa-e2e-') as td:
            target=f'http://127.0.0.1:{server.server_port}/'
            cmd=[sys.executable,'-m','auditor','--url',target,'--no-crawl', '--checks',
                 ('CHK07' if case.get('reflect_query') else 'CHK02,CHK03,CHK04,CHK05,CHK06'),
                 '--output',td]
            if case.get('reflect_query'): cmd.extend(['--reflection-param','q'])
            env=os.environ.copy()
            # Deliberately unavailable localhost-only AI provider; output is not evaluated.
            env.update({'OWA_AI_PROVIDER':'ollama','OWA_AI_ENDPOINT':'http://127.0.0.1:1',
                        'OWA_AI_MODEL':'local-only-e2e-disabled'})
            proc=subprocess.run(cmd,cwd=ROOT,env=env,stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,text=True,timeout=60)
            runs=list(Path(td).glob('scan-*'))
            if proc.returncode or len(runs)!=1:
                raise AssertionError(f'{name}: CLI exited {proc.returncode}, runs={len(runs)}; {proc.stderr[-400:]}')
            run=runs[0]
            data=load_report_data(run)
            issues=audit_run(run)
            if issues: raise AssertionError(f'{name}: integrity errors {issues}')
            html=(run/'reports/report.html').read_text(encoding='utf-8')
            if '<html' not in html.lower() or '</html>' not in html.lower():
                raise AssertionError(f'{name}: HTML report invalid/missing')
            statuses={}
            for chk,expected in case['expected'].items():
                found=[t['status'] for t in data['tests'] if t['rule_id']==chk]
                if expected not in found:
                    raise AssertionError(f'{name} {chk}: expected {expected}, observed {found}')
                statuses[chk]=expected
            # Detect evidence tampering against a COPY, never the original.
            ev=next((run/'evidence').glob('*.json'),None)
            if ev is None: raise AssertionError(f'{name}: no evidence')
            with tempfile.TemporaryDirectory(prefix='owa-e2e-tamper-') as changed:
                clone=Path(changed)/run.name
                shutil.copytree(run,clone)
                damaged=clone/'evidence'/ev.name
                value=json.loads(damaged.read_text())
                value['e2e_tamper_marker']='modified'
                damaged.write_text(json.dumps(value))
                if not any('hash mismatch' in i.lower() for i in audit_run(clone)):
                    raise AssertionError(f'{name}: evidence tamper not detected')
            saved=(run/'results/tests.json').read_bytes()
            # Hash evidence of actual saved records but not secrets/HTTP bodies.
            return {'case':name,'ground_truth_type':'first_party_holdout_lab',
                    'expected_and_observed':statuses,'all_assertions_passed':True,
                    'request_count':data['scan']['request_count'],
                    'test_count':len(data['tests']), 'evidence_files':len(data['evidence']),
                    'tests_json_sha256':hashlib.sha256(saved).hexdigest(),
                    'json_schema_valid':True,'evidence_integrity_valid':True,
                    'tampering_detected':True,'html_report_generated':True,
                    'ai_used_for_classification':False}
    finally:
        server.shutdown();server.server_close();thread.join(timeout=2)


def execute(output):
    output.mkdir(parents=True,exist_ok=True)
    cases=[run_case(name,case,output) for name,case in SCENARIOS.items()]
    total=sum(len(c['expected_and_observed']) for c in cases)
    result={'methodology':'Separate first-party local HTTP server via full CLI subprocess; not external dataset.',
            'scope':'127.0.0.1 only; deterministic first-party holdout response configurations',
            'claims':'Verified expected observable status; NOT real-world vulnerability accuracy.',
            'test_cases':len(cases),'assertions':total,'assertions_passed':total,
            'failed_assertions':0,'cases':cases,'third_party_dataset_cases':0}
    (output/'e2e_results.json').write_text(json.dumps(result,indent=2)+'\n')
    lines=['# Phase 4 Extension — Real localhost CLI integration','',
           'This is a controlled, **first-party** holdout evaluation. No published independent benchmark was executed.','',
           f'- Local server scenarios: {len(cases)}',f'- Expected-status assertions: {total} passed',
           '- Full subprocess CLI, HTTP/TCP localhost, JSON schema, HTML output and integrity audit: passed',
           '- Evidence tampering detected on copied run files in each case',
           '- AI connection deliberately unavailable; no AI-generated classifications were used','',
           '| Scenario | Status checks | Requests | Evidence files |','|---|---:|---:|---:|']
    for c in cases: lines.append(f"| {c['case']} | {len(c['expected_and_observed'])} | {c['request_count']} | {c['evidence_files']} |")
    lines+=['','## Limits','- Cases were written for this project, not borrowed from an independently labeled benchmark.',
            '- Exact observed status is tested; **Potential** remains a preliminary indicator, not confirmed exploitation.',
            '- Loopback HTTP does not validate real TLS, browser frame policies or external environment behavior.',
            '- AuditShop authenticated CLI execution and an independent external benchmark remain pending.',
            '- Tests validate known fixture markers; no blanket confidentiality claim for arbitrary data.',
            '- An AI-provider connection was attempted by existing optional reporting, but it was unavailable and no generated advice was used.']
    (output/'e2e_report.md').write_text('\n'.join(lines)+'\n')
    print(f'PASS: {len(cases)} localhost CLI scenarios, {total} assertions, JSON, HTML, integrity & tamper detection')
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'research/phase4_e2e')
    args=parser.parse_args()
    execute(args.output)
