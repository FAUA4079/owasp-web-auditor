"""Slow loopback-only fixture for a manual Ctrl+C/resume demonstration."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import time
from urllib.parse import urlsplit

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlsplit(self.path).path
        if path == '/start.html':
            body = ('<html><body>' + ''.join(
                f'<a href="/page{i}.html">Page {i}</a>' for i in range(1, 6)
            ) + '</body></html>').encode()
        elif path in {f'/page{i}.html' for i in range(1, 6)}:
            time.sleep(2)
            body = b'<html><body>Slow demo page</body></html>'
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

if __name__ == '__main__':
    server = ThreadingHTTPServer(('127.0.0.1', 8004), Handler)
    print('Resume demo: http://127.0.0.1:8004/start.html')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
