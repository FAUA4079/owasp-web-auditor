import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixed", action="store_true")
    args = parser.parse_args()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parts = urlsplit(self.path)

            if parts.path != "/item":
                self.send_error(404)
                return

            value = parse_qs(parts.query).get("id", ["1"])[0]

            try:
                number = int(value)
                status = 200
                text = f"Item number: {number}"
            except ValueError:
                status = 400 if args.fixed else 500
                text = (
                    "Invalid numeric input"
                    if args.fixed else "Internal server error"
                )

            body = text.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    server = HTTPServer(("127.0.0.1", 8003), Handler)
    print("Mode:", "fixed" if args.fixed else "server-error fixture")
    print("URL: http://127.0.0.1:8003/item")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
