"""CLI smoke tests, wired to the target agent in-process (no live servers)."""
from fastapi.testclient import TestClient

import target_agent.main as target_main
from redteam_engine import cli
from redteam_engine.db import Base as RedteamBase, engine as redteam_engine_sqla
from redteam_engine.target_client import TargetClient


def _fresh_redteam_db():
    RedteamBase.metadata.drop_all(redteam_engine_sqla)
    RedteamBase.metadata.create_all(redteam_engine_sqla)


def _fake_target_client() -> TargetClient:
    target_main.startup()
    return TargetClient(base_url="http://testserver", client=TestClient(target_main.app))


def test_cli_campaign_run_findings_and_regression(monkeypatch, capsys):
    _fresh_redteam_db()
    client = _fake_target_client()
    monkeypatch.setattr(cli, "TargetClient", lambda: client)

    rc = cli.main(["campaign", "run", "--categories", "system_prompt_extraction", "--name", "cli-test"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "AI SECURITY SCORECARD" in out

    rc = cli.main(["findings", "list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "critical" in out

    rc = cli.main(["findings", "show", "1"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "ATTACK" in out and "EVIDENCE" in out and "REMEDIATION" in out

    rc = cli.main(["regression", "run", "1"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "FAIL" in out  # not fixed, should still reproduce


def test_cli_report_export(monkeypatch, capsys, tmp_path):
    _fresh_redteam_db()
    client = _fake_target_client()
    monkeypatch.setattr(cli, "TargetClient", lambda: client)

    cli.main(["campaign", "run", "--categories", "mcp_attacks", "--name", "cli-report-test"])
    capsys.readouterr()

    out_file = tmp_path / "report.md"
    rc = cli.main(["report", "export", "--scope", "open", "--out", str(out_file)])
    assert rc == 0
    content = out_file.read_text(encoding="utf-8")
    assert "# AgentShield Security Report" in content
    assert "Mcp Attacks" in content


def test_cli_unreachable_target_fails_cleanly(monkeypatch, capsys):
    _fresh_redteam_db()
    unreachable = TargetClient(base_url="http://localhost:1")
    monkeypatch.setattr(cli, "TargetClient", lambda: unreachable)

    rc = cli.main(["campaign", "run"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "unreachable" in err
