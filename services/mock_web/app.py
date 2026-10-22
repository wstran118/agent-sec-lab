"""Mock web: serves static pages from data/web. Some pages are attacker-controlled in later scenarios."""
import sys
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

WEB_ROOT = Path(__file__).resolve().parent.parent.parent / "data" / "web"


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def make_server(port: int, host: str = "127.0.0.1", root: Path = WEB_ROOT) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), partial(QuietHandler, directory=str(root)))


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    make_server(port, "0.0.0.0").serve_forever()  # noqa: S104 - lab container only
