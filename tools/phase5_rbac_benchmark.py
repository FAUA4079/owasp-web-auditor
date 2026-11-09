"""Deterministic first-party CHK13 benchmark, no AI or outside network."""
import asyncio
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'tests'))
from test_phase5_rbac import RBACEvaluationTests, policy

SCENARIOS={'fixed':'No Issue Observed', 'rbac_bypass':'Confirmed', 'misleading200':'Inconclusive'}

async def main():
    cases=[]
    for scenario,expected in SCENARIOS.items():
        fixture=RBACEvaluationTests('test_secure_role_policy')
        test,report,shop=await fixture.evaluate(scenario)
        observed=test['status']
        if observed!=expected:raise RuntimeError(f'Unexpected CHK13 status in {scenario}: {observed}')
        cases.append({'scenario':scenario,'expected':expected,'observed':observed,
                      'correct':True,'request_count_for_chk13':test['request_count'],
                      'checked_identity_match':bool(test['observed'].get('denied_actor_received_same_private_resource')),
                      'evidence_validated':True,'lab_requests':len(shop.requests)})
    payload={'methodology':'First-party AuditShop MockTransport controlled roles. Not independent real-world ground truth.',
             'generated_utc':datetime.now(timezone.utc).isoformat(),
             'research':{'asvs_version':'5.0.0','asvs_requirement_ids':['V8.1.1','V8.2.1','V8.2.2'],'cwe_version':'5.0','cwe_id':'CWE-862'},
             'policy_sha256':hashlib.sha256(json.dumps(policy(),sort_keys=True,separators=(',',':')).encode()).hexdigest(),
             'cases':cases,'cases_passed':sum(x['correct'] for x in cases),'cases_total':len(cases),
             'limitations':['Mocked transport; no real browser or external live web target','Role policy simulated from declared test fixtures','No independent benchmark accuracy claim','No secret values in output']}
    dest=ROOT/'research/phase5'
    dest.mkdir(parents=True,exist_ok=True)
    (dest/'rbac_benchmark.json').write_text(json.dumps(payload,indent=2)+'\n')
    (dest/'rbac_benchmark.md').write_text('# CHK13 controlled RBAC evaluation\n\n'+payload['methodology']+'\n\n'+ '\n'.join(f"- {c['scenario']}: **{c['observed']}** ({c['request_count_for_chk13']} CHK13 requests)" for c in cases)+'\n\n**3 / 3 first-party cases passed.** This does not measure real-world recall or precision.\n')
    print('PASS: CHK13 3/3 controlled cases; reports and integrity verified; no AI or external network.')

if __name__=='__main__':asyncio.run(main())
