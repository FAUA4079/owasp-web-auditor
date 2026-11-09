import asyncio
import json
from pathlib import Path
import sys
import tempfile
import threading
import argparse
parser=argparse.ArgumentParser(description='Disposable AuditShop five-profile integration benchmark; no live target or AI calls.')
parser.add_argument('--shop-source',type=Path,required=True)
args=parser.parse_args()
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root))
sys.path.insert(0,str(args.shop_source.resolve()))
try:
    import flask
except ImportError:
    raise SystemExit('Benchmark requires Flask in this Python environment. See docs/authenticated-assessment.md.')
from app import create_app
from app.accounts import initialize_accounts
from werkzeug.serving import make_server,WSGIRequestHandler
from auditor.auth.project import load_project
from auditor.auth.assessment import run_assessment
from auditor.verification.integrity import audit_run
from auditor.reporting.validation import load_report_data
class Quiet(WSGIRequestHandler):
    def log(self,*args,**kwargs): pass
for lab_profile in ['fixed','SHOP-01','SHOP-03','SHOP-04','SHOP-14']:
    with tempfile.TemporaryDirectory() as d:
        app=create_app({'TESTING':True,'DATABASE':str(Path(d)/'test.sqlite3'),'LAB_PROFILE':lab_profile})
        passwords={101:'Ephemeral-SECRET-A',102:'Ephemeral-SECRET-B',900:'Ephemeral-SECRET-Admin'}
        with app.app_context(): initialize_accounts(passwords)
        server=make_server('127.0.0.1',0,app,request_handler=Quiet)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            project=load_project(root/'config/auditshop.assessment.json')
            project['base_url']=f'http://127.0.0.1:{server.server_port}'
            profile=json.loads((root/'auditor/data/public.json').read_text())
            credentials={'customer_a':('alice@example.test',passwords[101]),'customer_b':('bob@example.test',passwords[102])}
            run=asyncio.run(run_assessment(project,profile,credentials,Path(d)/'runs',generate_ai=False))
            data=load_report_data(run)
            assert not audit_run(run),audit_run(run)
            expected={'CHK09':'Confirmed' if lab_profile=='SHOP-01' else 'No Issue Observed',
                      'CHK10':'Confirmed' if lab_profile=='SHOP-03' else 'No Issue Observed',
                      'CHK11':'Potential' if lab_profile=='SHOP-04' else 'No Issue Observed',
                      'CHK12':'Confirmed' if lab_profile=='SHOP-14' else 'No Issue Observed'}
            actual=[(t['rule_id'],t['status']) for t in data['tests']]
            assert len(actual)==7,actual
            assert all(status==expected[rule] for rule,status in actual),(lab_profile,actual)
            assert data['scan']['request_count']==31,data['scan']
            for file in run.rglob('*'):
                if file.is_file():
                    value=file.read_text()
                    for secret in [*passwords.values(),'ORDER-A-1001','ORDER-B-1002','alice@example.test','bob@example.test']:
                        assert secret not in value,(file.name,secret)
            print(lab_profile+': expected checks, report validation, integrity and secret fixture checks PASS')
        finally:
            server.shutdown();thread.join();server.server_close()
