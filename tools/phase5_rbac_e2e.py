"""Full authenticated CLI subprocess evaluation of three local first-party RBAC modes.

No external hosts, no AI for verdicts, no claims about independent benchmarks.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from lab.rbac_e2e_server import start_lab, RBAC
from auditor.reporting.validation import load_report_data
from auditor.verification.integrity import audit_run

SCENARIOS={'secure':'No Issue Observed','vulnerable':'Confirmed','ambiguous':'Inconclusive'}
CREDENTIALS={'AUDITSHOP_A_EMAIL':'customer_a@example.invalid','AUDITSHOP_A_PASSWORD':'lab-a-password',
             'AUDITSHOP_B_EMAIL':'customer_b@example.invalid','AUDITSHOP_B_PASSWORD':'lab-b-password',
             'AUDITSHOP_ADMIN_EMAIL':'admin@example.invalid','AUDITSHOP_ADMIN_PASSWORD':'lab-admin-password'}

def make_configuration(folder,base_url,approval=True):
    project=json.loads((ROOT/'config/auditshop.rbac.project.example.json').read_text())
    policy=json.loads((ROOT/'config/rbac.policy.example.json').read_text())
    project['base_url']=base_url
    policy['base_url']=base_url
    policy['authorization']={'approved_by':'Local Lab Maintainer','approval_reference':'LOCAL-LAB-ONLY-CHK13',
                             'authorized_for_testing':approval}
    (folder/'project.json').write_text(json.dumps(project))
    (folder/'policy.json').write_text(json.dumps(policy))
    return folder/'project.json',folder/'policy.json',policy

def run_scenario(name):
    server,thread=start_lab(name)
    try:
        with tempfile.TemporaryDirectory(prefix='owa-rbac-e2e-') as tmp:
            tmp=Path(tmp)
            base=f'http://127.0.0.1:{server.server_port}'
            project,policy,policy_obj=make_configuration(tmp,base)
            cmd=[sys.executable,'-m','auditor','--project',str(project),'--assess',
                 '--rbac-policy',str(policy),'--output',str(tmp/'runs'),
                 '--ai-provider','ollama','--ai-endpoint','http://127.0.0.1:1','--ai-model','offline-disabled']
            env=os.environ.copy()
            env.update(CREDENTIALS)
            env['OWA_AI_ENDPOINT']='http://127.0.0.1:1'
            env['OWA_AI_MODEL']='offline-disabled'
            proc=subprocess.run(cmd,cwd=ROOT,env=env,text=True,capture_output=True,timeout=90)
            runs=list((tmp/'runs').glob('scan-*'))
            if proc.returncode or len(runs)!=1:
                raise AssertionError(f'{name}: exit={proc.returncode}, runs={len(runs)}, stderr={proc.stderr[-500:]} stdout={proc.stdout[-500:]}')
            run=runs[0]
            data=load_report_data(run)
            tests=[t for t in data['tests'] if t['rule_id']=='CHK13']
            if len(tests)!=1: raise AssertionError(f'{name}: expected single CHK13, got {len(tests)}')
            status=tests[0]['status']
            if status!=SCENARIOS[name]: raise AssertionError(f'{name}: expected {SCENARIOS[name]}, got {status}; reason={tests[0]["reason"]}')
            if not any(t['rule_id']=='CHK12' for t in data['tests']): raise AssertionError('Missing ordinary authenticated checks')
            for role in ['CHK09','CHK10','CHK11','CHK12']:
                if not any(t['rule_id']==role for t in data['tests']): raise AssertionError('Missing '+role)
            if not all(a['verified'] for a in json.loads((run/'results/accounts.json').read_text())['accounts']):
                raise AssertionError('Account identity verification failed')
            errors=audit_run(run)
            if errors or data['integrity']['status']!='PASS': raise AssertionError(f'{name}: integrity errors {errors}')
            html=(run/'reports/report.html').read_text()
            if '<html' not in html.lower(): raise AssertionError('HTML report not generated')
            evidence=list((run/'evidence').glob('*.json'))
            if not evidence: raise AssertionError('No saved evidence')
            if RBAC['private_marker'] in '\n'.join(p.read_text() for p in run.rglob('*.json')) or RBAC['private_marker'] in html:
                raise AssertionError('RBAC private marker persisted')
            copied=tmp/'tampered'
            shutil.copytree(run,copied)
            item=next((copied/'evidence').glob('*.json'))
            changed=json.loads(item.read_text());changed['tamper_probe']='modified';item.write_text(json.dumps(changed))
            if not audit_run(copied): raise AssertionError('Tampering not detected')
            # Unapproved-policy test: reject offline before any network traffic.
            count_before=server.request_count
            _,badpolicy,_=make_configuration(tmp,base,approval=False)
            denied=subprocess.run(cmd,cwd=ROOT,env=env,text=True,capture_output=True,timeout=30)
            if denied.returncode==0 or server.request_count!=count_before:
                raise AssertionError('Unapproved policy was not rejected offline')
            receipt={'scenario':name,'expected':SCENARIOS[name],'observed':status,
                     'true_network_requests':server.request_count,
                     'request_ledger_count':len(json.loads((run/'request_ledger.json').read_text())),
                     'account_identities_verified':3,'json_schema_valid':True,
                     'html_report_generated':True,'integrity_passed':True,'tamper_detected':True,
                     'unapproved_policy_blocked_pre_network':True,'ai_used_for_verdict':False,
                     'evidence_count':len(evidence),
                     'policy_sha256':hashlib.sha256(json.dumps(policy_obj,sort_keys=True,separators=(',',':')).encode()).hexdigest()}
            return receipt
    finally:
        server.shutdown();server.server_close();thread.join(timeout=5)

def run_all(output=None):
    rows=[run_scenario(name) for name in SCENARIOS]
    report={'schema_version':1,'methodology':'First-party localhost HTTP server; full authenticated CLI subprocess',
            'ground_truth_origin':'Human-authored explicit lab scenario labels',
            'independent_third_party_cases':0,'ai_generated_rules_or_ground_truth':False,
            'results':rows,'passed':len(rows),'total':len(SCENARIOS),
            'limitations':['Fixtures are purpose-built for this adapter, not an independent benchmark',
                           'Authentication/roles provided by lab, not external identity provider',
                           'Exact response matches only; no general real-world accuracy claim']}
    if output:
        output=Path(output);output.mkdir(parents=True,exist_ok=True)
        (output/'rbac_e2e_results.json').write_text(json.dumps(report,indent=2)+'\n')
        lines=['# Phase 5 Extension — Authenticated RBAC CLI E2E','',
               '**Methodology:** First-party loopback HTTP server + complete authenticated CLI. No AI decisions or external targets.','',
               '| Scenario | Expected | Observed | Integrity | Offline rejection |','|---|---|---|---|---|']
        for row in rows:
            lines.append(f"| {row['scenario']} | {row['expected']} | {row['observed']} | PASS | PASS |")
        lines.extend(['','**Limitation:** This is reproducible first-party lab verification, not an independent vulnerability benchmark.'])
        (output/'rbac_e2e_report.md').write_text('\n'.join(lines)+'\n')
    print(f"PASS: {len(rows)}/{len(SCENARIOS)} full localhost authenticated CLI scenarios; JSON/HTML/integrity/tamper/offline-policy validation")
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',default=str(ROOT/'research/phase5_e2e'))
    args=parser.parse_args()
    run_all(args.output)
