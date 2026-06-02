from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from vidis_compliance import server
from vidis_compliance.cli import app
from vidis_compliance.sources.agentic import AgenticCrawlResult


class FakeAgentRunner:
    def run(self, *, base_url: str, task_types: list[str], username: str | None, password: str | None, output_dir: Path, persona: str, pages: int) -> AgenticCrawlResult:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "screenshots").mkdir()
        (output_dir / "pdfs").mkdir()
        (output_dir / "screenshots" / "legal-1.png").write_bytes(b"fake png")
        (output_dir / "pdfs" / "legal-1.pdf").write_bytes(b"%PDF fake")
        return AgenticCrawlResult(
            base_url=base_url,
            persona=persona,
            task_types=task_types,
            visited_urls=[base_url, f"{base_url.rstrip('/')}/dashboard"],
            actions=[{"task": "legal", "action": "navigate", "url": base_url}],
            cookies=[{"name": "session", "value": "abc123"}],
            local_storage={"token": "abc123"},
            session_storage={},
            requests=[{"url": f"{base_url.rstrip('/')}/api/me", "method": "GET"}],
            artifacts={
                "screenshots": ["screenshots/legal-1.png"],
                "pdfs": ["pdfs/legal-1.pdf"],
            },
            steps=[
                {
                    "task": "legal",
                    "url": base_url,
                    "action": "login",
                    "input": username,
                    "password": password,
                }
            ],
        )


def test_cli_agentic_scan_writes_redacted_artifacts(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("VIDIS_AGENT_USERNAME", "env-user")
    monkeypatch.setenv("VIDIS_AGENT_PASSWORD", "env-secret")
    monkeypatch.setattr("vidis_compliance.cli.DefaultAgenticRunner", lambda: FakeAgentRunner())

    result = CliRunner().invoke(
        app,
        [
            "check",
            "--url",
            "https://app.example.test",
            "--output",
            "agent-job",
            "--agentic",
            "--agent-task",
            "legal",
            "--agent-task",
            "student",
            "--agent-persona",
            "SuS",
            "--pages",
            "1",
        ],
    )

    assert result.exit_code == 0, result.output
    agent_dir = tmp_path / "results" / "agent-job" / "agent"
    trace_path = agent_dir / "step_result.jsonl"
    summary_path = agent_dir / "agent_capture.json"
    assert trace_path.exists()
    assert summary_path.exists()
    assert (agent_dir / "screenshots" / "legal-1.png").exists()
    assert (agent_dir / "pdfs" / "legal-1.pdf").exists()

    combined = trace_path.read_text(encoding="utf-8") + summary_path.read_text(encoding="utf-8")
    assert "env-secret" not in combined
    assert "***REDACTED***" in combined
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["task_types"] == ["legal", "student"]
    assert summary["visited_urls"][-1].endswith("/dashboard")


def test_api_agentic_job_exposes_safe_agent_artifact(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("VIDIS_RESULTS_DIR", str(tmp_path / "results"))
    monkeypatch.setenv("VIDIS_AGENT_PASSWORD", "api-secret")
    monkeypatch.setattr(server.cli_module, "DefaultAgenticRunner", lambda: FakeAgentRunner())
    client = TestClient(server.app)

    created = client.post(
        "/jobs",
        json={
            "target_url": "https://app.example.test",
            "pages": 1,
            "agentic": True,
            "agent_tasks": ["teacher", "logout"],
            "agent_username": "api-user",
        },
    )

    assert created.status_code == 202, created.text
    job_id = created.json()["id"]
    completed = None
    for _ in range(100):
        payload = client.get(f"/jobs/{job_id}").json()
        if payload["status"] == "completed":
            completed = payload
            break
    assert completed is not None
    assert "agent_capture_json" in completed["artifacts"]
    assert "api-secret" not in json.dumps(completed)

    artifact = client.get(f"/jobs/{job_id}/artifacts/agent_capture.json")
    assert artifact.status_code == 200
    assert artifact.json()["task_types"] == ["teacher", "logout"]
    assert "api-secret" not in artifact.text

    trace = (tmp_path / "results" / job_id / "agent" / "step_result.jsonl").read_text(encoding="utf-8")
    assert "api-secret" not in trace
