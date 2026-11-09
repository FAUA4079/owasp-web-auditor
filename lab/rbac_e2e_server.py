"""Explicitly first-party localhost AuditShop protocol lab; never bind off-loopback."""
import json
import secrets
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock, Thread
from urllib.parse import parse_qs, urlsplit

USERS = {
    'customer_a@example.invalid': ('lab-a-password', 101, 'customer'),
    'customer_b@example.invalid': ('lab-b-password', 102, 'customer'),
    'admin@example.invalid': ('lab-admin-password', 103, 'admin'),
}
ORDERS = {1001: {'id':1001,'user_id':101,'private_marker':'LAB_ORDER_A_PRIVATE'},
          1002: {'id':1002,'user_id':102,'private_marker':'LAB_ORDER_B_PRIVATE'}}
RBAC = {'id':'staff-report','private_marker':'LAB_ADMIN_PRIVATE_RESOURCE'}

class Lab(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    def __init__(self, scenario):
        self.scenario=scenario
        self.sessions={}
        self.lock=Lock()
        self.request_count=0
        super().__init__(('127.0.0.1',0), Handler)

class Handler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self, *args): pass
    def _reply(self, code, payload=None, *, cookie=None):
        raw=b'' if payload is None else json.dumps(payload,separators=(',',':')).encode()
        self.send_response(code)
        if payload is not None: self.send_header('Content-Type','application/json')
        if cookie is not None: self.send_header('Set-Cookie',cookie)
        self.send_header('Content-Length',str(len(raw)))
        self.end_headers()
        if raw:
            try: self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError): pass
    def _sid(self):
        try:
            cookie=SimpleCookie(); cookie.load(self.headers.get('Cookie',''))
            return cookie['lab_session'].value if 'lab_session' in cookie else None
        except Exception: return None
    def _person(self):
        with self.server.lock: return self.server.sessions.get(self._sid())
    def _count(self):
        with self.server.lock: self.server.request_count+=1
    def do_GET(self):
        self._count()
        path=urlsplit(self.path).path
        person=self._person()
        if path=='/api/csrf': return self._reply(200,{'csrf_token':'lab-csrf-verified'})
        if path=='/api/me':
            return self._reply(200,{'id':person[1],'role':person[2]}) if person else self._reply(401,{'error':'unauthorized'})
        if path.startswith('/api/orders/'):
            try: order=ORDERS[int(path.rsplit('/',1)[1])]
            except (KeyError,ValueError): return self._reply(404,{'error':'missing'})
            if not person: return self._reply(401,{'error':'unauthorized'})
            if person[1]!=order['user_id']: return self._reply(403,{'error':'forbidden'})
            return self._reply(200,{'order':order})
        if path=='/api/products':
            q=parse_qs(urlsplit(self.path).query,keep_blank_values=True).get('search',[''])[0]
            products=[{'id':1},{'id':2}] if not q else []
            return self._reply(200,{'products':products,'count':len(products)})
        if path=='/api/rbac/staff-report':
            if not person: return self._reply(401,{'error':'unauthorized'})
            if person[2]=='admin': return self._reply(200,{'resource':RBAC})
            if self.server.scenario=='vulnerable': return self._reply(200,{'resource':RBAC})
            if self.server.scenario=='ambiguous': return self._reply(200,{'message':'public landing page'})
            return self._reply(403,{'error':'forbidden'})
        return self._reply(404,{'error':'missing'})
    def do_POST(self):
        self._count()
        path=urlsplit(self.path).path
        size=int(self.headers.get('Content-Length','0'))
        if size>4096: return self._reply(413,{'error':'too large'})
        try: body=json.loads(self.rfile.read(size)) if size else {}
        except ValueError: return self._reply(400,{'error':'invalid JSON'})
        if self.headers.get('X-CSRF-Token')!='lab-csrf-verified': return self._reply(403,{'error':'csrf'})
        if path=='/api/login':
            username=body.get('email')
            user=USERS.get(username)
            if not user or body.get('password')!=user[0]: return self._reply(401,{'error':'invalid credentials'})
            sid=secrets.token_hex(20)
            with self.server.lock: self.server.sessions[sid]=(username,user[1],user[2])
            return self._reply(200,{'csrf_token':'lab-csrf-verified'},cookie='lab_session='+sid+'; HttpOnly; SameSite=Strict; Path=/')
        if path=='/api/logout':
            sid=self._sid()
            with self.server.lock: self.server.sessions.pop(sid,None)
            return self._reply(204,cookie='lab_session=; Max-Age=0; Path=/')
        return self._reply(404,{'error':'missing'})

def start_lab(scenario):
    if scenario not in {'secure','vulnerable','ambiguous'}: raise ValueError('Unknown lab scenario')
    server=Lab(scenario)
    thread=Thread(target=server.serve_forever,daemon=True);thread.start()
    return server,thread
