import json
import socket
import sys
from pathlib import Path

import pytest

from traceleakcheck.cli import child_env, count_items, main

APP = str(Path(__file__).parent / "apps" / "otel_app.py")


def run(tmp_path, *args):
    report = tmp_path / "r.json"
    code = main(["run", "--settle", "0.5", "--timeout", "60", "--report", str(report), *args])
    return code, json.loads(report.read_text())["results"][0]


def test_leak_in_another_process_is_found(tmp_path):
    code, r = run(tmp_path, "--", sys.executable, APP, "leak")
    assert code == 1 and r["status"] == "leak"
    assert {f["path"].split(".")[-1] for f in r["findings"]} >= {"message"}  # status.message at least
    assert r["counts"]["traces"] >= 1


def test_clean_app_is_clean_and_says_what_was_checked(tmp_path, capsys):
    code, r = run(tmp_path, "--", sys.executable, APP, "clean")
    assert (code, r["status"]) == (0, "clean")
    assert r["counts"]["traces"] == 1
    assert "weaker" in capsys.readouterr().out


def test_no_telemetry_is_incomplete_never_clean(tmp_path):
    code, r = run(tmp_path, "--", sys.executable, APP, "silent")
    assert (code, r["status"]) == (2, "incomplete")
    assert "no traces arrived" in r["detail"]


def test_server_mode_drives_then_stops_the_app(tmp_path):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    drive = f'"{sys.executable}" -c "import urllib.request as u; u.urlopen(\'{url}/chat?m={{OPENAI_API_KEY}}\')"'
    code, r = run(tmp_path, "--drive", drive, "--ready-url", url + "/up", "--", sys.executable, APP, "server", str(port))
    assert (code, r["status"]) == (1, "leak"), r
    assert r["drive_exit"] == 0
    assert any("prompt" in f["path"] for f in r["findings"])


def test_child_env_drops_redirects_and_plants_secrets():
    base = {"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "https://real-backend", "OTEL_SDK_DISABLED": "true",
            "OTEL_TRACES_EXPORTER": "console", "KEEP": "1"}
    env = child_env("http://127.0.0.1:9", {"OPENAI_API_KEY": "sk-x"}, base)
    assert "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT" not in env and "OTEL_SDK_DISABLED" not in env
    assert env["OTEL_TRACES_EXPORTER"] == "otlp" and env["OTEL_EXPORTER_OTLP_ENDPOINT"] == "http://127.0.0.1:9"
    assert env["OPENAI_API_KEY"] == "sk-x" and env["KEEP"] == "1"


def test_count_items_ignores_empty_exports():
    assert count_items([("traces", {}), ("logs", {"resourceLogs": [{"scopeLogs": [{"logRecords": [{}, {}]}]}]})]) \
        == {"traces": 0, "logs": 2, "metrics": 0}


def test_bad_secret_kind_is_rejected():
    with pytest.raises(SystemExit, match="bad --secret"):
        main(["run", "--secret", "X=nope", "--", sys.executable, APP, "clean"])


NODE_DEMO = Path(__file__).parents[1] / "examples" / "node_agent"


@pytest.mark.skipif(not (NODE_DEMO / "node_modules").is_dir() or not __import__("shutil").which("node"),
                    reason="needs node and `npm ci` in examples/node_agent")
def test_node_demo_leak_is_found(tmp_path):
    code, r = run(tmp_path, "--", "node", str(NODE_DEMO / "app.js"))
    assert (code, r["status"]) == (1, "leak"), r
    assert len(r["findings"]) == 3  # error message, stack trace, status message
