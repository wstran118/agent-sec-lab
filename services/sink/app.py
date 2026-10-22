"""Attacker sink: records every request it receives. Exfil is proven by what lands here.

GET /_log returns captured requests as JSON; POST /_reset clears them. Everything else is captured.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def make_server(port: int, host: str = "127.0.0.1") -> ThreadingHTTPServer:
    captured: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def _handle(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            if self.path == "/_log" and self.command == "GET":
                return self._reply(200, json.dumps(captured))
            if self.path == "/_reset" and self.command == "POST":
                captured.clear()
                return self._reply(200, "{}")
            captured.append({"method": self.command, "path": self.path, "body": body})
            self._reply(200, "ok")

        def _reply(self, code: int, text: str):
            data = text.encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = do_POST = do_PUT = do_HEAD = _handle

        def log_message(self, *args):
            pass

    srv = ThreadingHTTPServer((host, port), Handler)
    srv.captured = captured
    return srv


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
    make_server(port, "0.0.0.0").serve_forever()  # noqa: S104 - lab container only
