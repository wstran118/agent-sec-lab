"""S5: model output reaching a shell, SQL and HTML sink. Exploit-vs-fix per sink, plus argument validation."""
import json

import pytest

from agent.shellsim import simulate
from agent.tools import Tools
from attacks.s5_output_handling.payloads import SHELL, SHELL_OPTION_INJECTION, SQL, XSS, active_content
from fixes.s5_safe_sinks import HARDENING


@pytest.fixture
def ws(cfg):
    (cfg.workspace / "out").mkdir()
    (cfg.workspace / "a.txt").write_text("hello")
    (cfg.workspace.parent / "secret.txt").write_text("x")
    return cfg


def fixed(cfg):
    cfg.hardening = dict(HARDENING)
    return cfg


# --- shell ----------------------------------------------------------------------------------------------------

def test_shell_simulator_basics():
    assert simulate("wc -c a.txt") == [["wc", "-c", "a.txt"]]
    assert simulate("wc -c a; id") == [["wc", "-c", "a"], ["id"]]
    assert simulate("echo '$(id)'") == [["echo", "$(id)"]]  # single quotes: literal


@pytest.mark.parametrize("payload", SHELL)
def test_shell_injection_spawns_extra_commands_on_vulnerable_sink(ws, payload):
    t = Tools(ws)
    t.call("file_stats", {"filename": payload})
    assert len(t.executed) > 1 or any(tok in {">", ">>"} for c in t.executed for tok in c), t.executed


@pytest.mark.parametrize("payload", SHELL + [SHELL_OPTION_INJECTION, "../secret.txt", "/etc/passwd"])
def test_fix_never_spawns_anything_but_wc_on_the_confined_file(ws, payload):
    t = Tools(fixed(ws))
    out = t.call("file_stats", {"filename": payload})
    assert out.startswith("blocked by policy"), out
    assert t.executed == []


def test_fix_runs_exactly_one_argv_command_for_a_legit_file(ws):
    t = Tools(fixed(ws))
    t.call("file_stats", {"filename": "a.txt"})
    assert len(t.executed) == 1
    assert t.executed[0][:2] == ["wc", "-c"] and t.executed[0][2].endswith("a.txt")


# --- SQL ------------------------------------------------------------------------------------------------------

def test_sql_tautology_dumps_every_customer(ws):
    rows = json.loads(Tools(ws).call("lookup_customer", {"name": SQL["tautology"]}))
    assert len(rows) == 3


def test_sql_union_leaks_private_notes(ws):
    out = Tools(ws).call("lookup_customer", {"name": SQL["union"]})
    assert "CANARY-INTERNAL-0001" in out and "CANARY-CARD-0001" in out


@pytest.mark.parametrize("name", list(SQL.values()) + ["x'; DROP TABLE customers; --"])
def test_fix_blocks_sql_injection(ws, name):
    out = Tools(fixed(ws)).call("lookup_customer", {"name": name})
    assert out.startswith("blocked by policy") and "CANARY" not in out


def test_fix_quote_and_comment_chars_that_pass_the_shape_check_are_only_data(ws):
    # passes the regex, so it is the bound parameter (not the regex) that keeps it harmless
    out = Tools(fixed(ws)).call("lookup_customer", {"name": "Alice Example' --"})
    assert out == "[]"


def test_fix_legit_lookup_still_works_and_hides_notes(ws):
    out = json.loads(Tools(fixed(ws)).call("lookup_customer", {"name": "Bob Example"}))
    assert out == [["Bob Example", "bob@acme.example"]]
    assert json.loads(Tools(fixed(ws)).call("lookup_customer", {"name": "O'Brien"})) == []  # quote is data, not syntax


def test_fix_connection_is_query_only_even_if_the_regex_were_bypassed(ws):
    t = Tools(fixed(ws))
    t.call("lookup_customer", {"name": "Alice Example"})  # opens the connection
    with pytest.raises(Exception, match="readonly"):
        t._db().execute("DELETE FROM customers")


# --- HTML -----------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("payload", XSS)
def test_report_xss_on_vulnerable_sink(ws, payload):
    Tools(ws).call("write_report", {"title": "Q3", "body": payload})
    assert active_content((ws.workspace / "out" / "report.html").read_text())


@pytest.mark.parametrize("payload", XSS)
@pytest.mark.parametrize("field", ["title", "body"])
def test_fix_report_has_no_active_content(ws, payload, field):
    args = {"title": "Q3", "body": "text"}
    args[field] = payload
    Tools(fixed(ws)).call("write_report", args)
    doc = (ws.workspace / "out" / "report.html").read_text()
    assert active_content(doc) == []
    assert "Content-Security-Policy" in doc and "default-src 'none'" in doc


def test_fix_report_text_survives_escaped(ws):
    Tools(fixed(ws)).call("write_report", {"title": "Q3 & Q4", "body": "a < b"})
    doc = (ws.workspace / "out" / "report.html").read_text()
    assert "Q3 &amp; Q4" in doc and "a &lt; b" in doc


# --- argument validation --------------------------------------------------------------------------------------

@pytest.mark.parametrize("args", [
    {"path": "a.txt", "extra": "x"},  # unexpected key
    {},  # missing key
    {"path": ["a.txt"]},  # wrong type
    {"path": 7},
    {"path": "a" * 10_001},  # too long
    {"path": "a\x00b"},
])
def test_validate_args_rejects_malformed_calls(ws, args):
    assert Tools(fixed(ws)).call("read_file", args).startswith("blocked by policy")


def test_validate_args_accepts_a_good_call(ws):
    assert Tools(fixed(ws)).call("read_file", {"path": "a.txt"}) == "hello"
