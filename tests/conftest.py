import threading

import pytest

from agent.config import Config
from services.mock_web.app import make_server as make_web
from services.sink.app import make_server as make_sink


def _serve(srv):
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def web():
    srv = _serve(make_web(0))
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture
def sink():
    srv = _serve(make_sink(0))
    yield srv
    srv.shutdown()


@pytest.fixture
def cfg(tmp_path, sink):
    ws = tmp_path / "workspace"
    ws.mkdir()
    (ws / "notes.txt").write_text("Alice owns the vendor review.")
    return Config(
        workspace=ws,
        outbox=tmp_path / "outbox.jsonl",
        transcript_dir=tmp_path / "transcripts",
        memory_path=tmp_path / "memory.json",
        sink_url=f"http://127.0.0.1:{sink.server_address[1]}",
    )
