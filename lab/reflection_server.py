from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parts = urlsplit(self.path)

        if parts.path != "/search":
            self.send_error(404)
            return

        query = parse_qs(parts.query)
        value = query.get("q", [""])[0]
        body = ("Search query: " + value).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Do not print query values to fixture logs.
        pass


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8002), Handler)
    print("Reflection lab: http://127.0.0.1:8002/search")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
