"""Run actual scanner checks against deterministic, isolated mock HTTP fixtures.

Controlled fixture labels describe OBSERVABLE INDICATORS, not proven exploitable bugs.
This runner never requests a real network destination and never uses AI.
"""
import argparse
import asyncio
import contextlib
import hashlib
import importlib.util
import io
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'tests'))
from auditor.checks.https_handling import check_https_handling
from auditor.checks.headers import review_headers
from auditor.checks.cookies import review_cookies
from auditor.checks.error_disclosure import review_error_disclosure
from auditor.checks.directory_listing import review_directory_listing
from auditor.checks.reflection import review_reflection
from auditor.checks.exceptional_input import review_exceptional
from auditor.core.http_client import BoundedHTTPClient
from auditor.auth.assessment import run_assessment
from auditor.reporting.validation import load_report_data
from auditor.verification.integrity import audit_run
from test_transport import PROFILE, Body
from test_authenticated_assessment import Shop, config, CREDENTIALS, REAL_CLIENT

SPEC_PATH=ROOT/'research/fixtures/case_specifications.json'
DEFAULT_OUTPUT=ROOT/'research/phase4'


def fixture_response(*, url='http://lab.example/files/', body='', headers=None, status=200):
    return {'final_url':url,'status_code':status,'headers':httpx.Headers(headers or {'content-type':'text/html'}),'body':body.encode()}

async def evaluate_public(check, vulnerable):
    if check=='CHK01':
        def handler(request):
            if vulnerable:return httpx.Response(200,stream=Body())
            if request.url.scheme=='http':return httpx.Response(301,headers={'location':'https://lab.example/'})
            return httpx.Response(200,stream=Body())
        result,evidence,_=await check_https_handling('http://lab.example/',dict(PROFILE,max_requests=10),transport=httpx.MockTransport(handler))
    elif check in ('CHK02','CHK03'):
        if check=='CHK02':
            headers={'content-type':'text/html','x-content-type-options':'nosniff'}
            if not vulnerable:headers['content-security-policy']="frame-ancestors 'none'"
        else:
            headers={'content-type':'text/html','content-security-policy':"frame-ancestors 'none'"}
            if not vulnerable:headers['x-content-type-options']='nosniff'
        tests,evidence,_=review_headers({'status_code':200,'headers':httpx.Headers(headers)})
        result=next(t for t in tests if t['rule_id']==check)
    elif check=='CHK04':
        cookie='session=TEST_ONLY; Path=/' if vulnerable else 'session=TEST_ONLY; Secure; HttpOnly; SameSite=Lax; Path=/'
        result,evidence,_=review_cookies(fixture_response(url='https://lab.example/',headers=[('set-cookie',cookie)]))
    elif check=='CHK05':
        body=('Traceback (most recent call last):\n  File "/srv/app.py", line 2\nRuntimeError: secret=NEVER_REPORT' if vulnerable else 'Generic page without errors')
        result,evidence,_=review_error_disclosure(fixture_response(url='http://lab.example/error.html',body=body,headers={'content-type':'text/plain'}))
    elif check=='CHK06':
        body=('<html><title>Directory listing for /files/</title><h1>Directory listing for /files/</h1><ul><li><a href="private.txt">private.txt</a></li></ul></html>' if vulnerable else '<html><title>Files</title><h1>Files</h1></html>')
        result,evidence,_=review_directory_listing(fixture_response(body=body))
    elif check in ('CHK07','CHK08'):
        def handler(request):
            value=request.url.params.get('q' if check=='CHK07' else 'id','')
            if check=='CHK07':
                body=value if vulnerable else 'No query marker reflected'
                return httpx.Response(200,headers={'content-type':'text/plain'},stream=httpx.ByteStream(body.encode()))
            status=200 if value=='1' else (500 if vulnerable else 400)
            return httpx.Response(status,headers={'content-type':'text/plain'},stream=Body())
        target='http://lab.example/search' if check=='CHK07' else 'http://lab.example/item'
        async with BoundedHTTPClient(target,dict(PROFILE,max_requests=10),transport=httpx.MockTransport(handler)) as client:
            result,evidence,_=(await review_reflection(client,target,'q')) if check=='CHK07' else (await review_exceptional(client,target,'id'))
    else:raise ValueError(check)
    return result,evidence

async def evaluate_auth(check,vulnerable):
    scenario = {'CHK09':'idor','CHK10':'guest','CHK11':'sql','CHK12':'revocation'}[check] if vulnerable else 'fixed'
    shop=Shop(scenario)
    def factory(**kwargs):
        if kwargs.get('transport') is None: kwargs['transport']=shop.transport('guest')
        return REAL_CLIENT(**kwargs)
    from unittest.mock import patch
    with tempfile.TemporaryDirectory(prefix='owa-phase4-auth-') as tmp:
        with patch('httpx.AsyncClient',side_effect=factory), contextlib.redirect_stdout(io.StringIO()):
            run=await run_assessment(config(),dict(PROFILE,max_requests=65,scan_deadline_seconds=30),CREDENTIALS,Path(tmp),transport_factory=shop.transport,generate_ai=False)
        if audit_run(run):raise RuntimeError('authenticated report integrity check failed')
        report=load_report_data(run)
        tests=[t for t in report['tests'] if t['rule_id']==check]
        if not tests:raise RuntimeError(f'No output for {check}')
        result=tests[0]
        evidence={'kind':'bounded_authenticated_comparison','observation':result.get('observed'), 'request_count':result['request_count'],'report_integrity_verified':True}
        return result,evidence


def classify(status):
    if status in ('Potential','Confirmed'):return 'positive'
    if status=='No Issue Observed':return 'negative'
    return 'abstained'


def sanitize_observation(value):
    """Only record fixed-shape, already minimized observation objects."""
    return value

async def run(output):
    spec=json.loads(SPEC_PATH.read_text())
    cases=[]
    for rule in spec['rules']:
        # Historical Phase 4 report covers CHK01–CHK12 only. CHK13 has a separate Phase 5 evaluation.
        if rule['chk_id'] == 'CHK13':
            continue
        chk=rule['chk_id']
        for c in rule['cases']:
            vulnerable=c['expected_label']=='positive_candidate'
            result,evidence=await (evaluate_public(chk,vulnerable) if int(chk[3:])<=8 else evaluate_auth(chk,vulnerable))
            actual=classify(result['status'])
            expected='positive' if vulnerable else 'negative'
            item={
                'case_id':c['id'],'rule_id':chk,
                'fixture_class':'controlled_mock_http_or_auditshop',
                'expected_indicator_label':expected,
                'observed_check_status':result['status'],
                'observed_indicator_label':actual,
                'correct_on_scored_cases':(actual==expected) if actual!='abstained' else None,
                'request_count':result.get('request_count',0),
                'evidence':{'kind':evidence.get('kind'),'observation':sanitize_observation(evidence.get('observation'))},
            }
            cases.append(item)
    tp=sum(c['expected_indicator_label']=='positive' and c['observed_indicator_label']=='positive' for c in cases)
    fp=sum(c['expected_indicator_label']=='negative' and c['observed_indicator_label']=='positive' for c in cases)
    tn=sum(c['expected_indicator_label']=='negative' and c['observed_indicator_label']=='negative' for c in cases)
    fn=sum(c['expected_indicator_label']=='positive' and c['observed_indicator_label']=='negative' for c in cases)
    abstained=sum(c['observed_indicator_label']=='abstained' for c in cases)
    metrics={'total':len(cases),'tp':tp,'fp':fp,'tn':tn,'fn':fn,'abstained':abstained,
             'precision':tp/(tp+fp) if (tp+fp) else None,
             'recall_on_scored':tp/(tp+fn) if (tp+fn) else None,
             'false_positive_rate_on_scored':fp/(fp+tn) if (fp+tn) else None,
             'scored_fraction':(len(cases)-abstained)/len(cases)}
    payload={'schema_version':1,'generated_at':datetime.now(timezone.utc).isoformat(),
             'methodology':'Controlled deterministic mock-HTTP and existing AuditShop fixture execution; not external benchmarks or real-world vulnerabilities.',
             'claims':'Metrics describe indicator detection in these fixtures only. Potential is not confirmed exploitation. Inconclusive is abstention.',
             'source_fixture_spec_sha256':hashlib.sha256(SPEC_PATH.read_bytes()).hexdigest(),
             'metrics':metrics,'cases':cases}
    encoded=json.dumps(payload,indent=2,sort_keys=True)
    for forbidden in ('NEVER_REPORT','TEST_ONLY','SECRET_PASSWORD','PRIVATE_SECRET','AUTH_a','AUTH_b'):
        if forbidden in encoded:raise RuntimeError('Secret escaped into report: '+forbidden)
    output.mkdir(parents=True,exist_ok=True)
    (output/'benchmark_results.json').write_text(encoded+'\n')
    report=['# Phase 4 — Controlled Fixture Evaluation','', '**Scope:** CHK01–CHK12; two predetermined cases each.','',
            '**Important:** This is controlled fixture evaluation, not real-world scanner accuracy or confirmed exploitation.','',
            f"- TP: {tp}; FP: {fp}; TN: {tn}; FN: {fn}; Abstained: {abstained}",
            f"- Precision (scored only): {metrics['precision']}",f"- Recall (scored only): {metrics['recall_on_scored']}",
            f"- False positive rate (scored only): {metrics['false_positive_rate_on_scored']}",
            f"- Coverage of planned fixture cases: {metrics['scored_fraction']:.1%}",'',
            '| Case | Expected indicator | Observed status | Outcome |','|---|---|---|---|']
    for c in cases:
        report.append(f"| {c['case_id']} | {c['expected_indicator_label']} | {c['observed_check_status']} | {c['observed_indicator_label']} |")
    report+=['','## Limitations','- MockTransport provides real executed Python decision logic but does not demonstrate network, browser or TLS behavior.','- CHK02 secure framing is Inconclusive by design: policy presence does not prove effective restrictions.','- CHK07 reflects a marker only; it does not prove XSS.','- CHK11 differential is Potential, not proof of SQL injection.','- CHK09–CHK12 depend on the AuditShop-specific adapter and supplied local policies.','- New fixtures are authored transparent lab specifications, not an externally published labeled dataset.','- Independent third-party benchmark and physical lab server validation remain pending.']
    (output/'benchmark_report.md').write_text('\n'.join(report)+'\n')
    print(json.dumps(metrics,indent=2))
    print('Evidence:',output/'benchmark_results.json')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=DEFAULT_OUTPUT)
    args=parser.parse_args()
    asyncio.run(run(args.output))
