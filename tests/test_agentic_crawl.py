from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from vidis_compliance import server
from vidis_compliance.cli import app
from vidis_compliance.sources.agentic import AgenticCrawlResult, redacted_data


class FakeAgentRunner:
    last_call: dict[str, object] = {}

    def run(self, *, base_url: str, task_types: list[str], username: str | None, password: str | None, output_dir: Path, persona: str, pages: int, vidis_portal: str | None = None) -> AgenticCrawlResult:
        FakeAgentRunner.last_call = {"vidis_portal": vidis_portal, "username": username, "password": password}
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
            "--agent-vidis-portal",
            "Test Landesportal",
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
    assert FakeAgentRunner.last_call["vidis_portal"] == "Test Landesportal"
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


class FakeCountLocator:
    def __init__(self, count: int = 0):
        self._count = count

    def count(self) -> int:
        return self._count

    @property
    def first(self):
        return self

    def fill(self, *_args, **_kwargs):
        return None

    def click(self, *_args, **_kwargs):
        return None


class FakeVidisPage:
    def __init__(self):
        self.url = "https://app.example.test/login"
        self.calls: list[tuple[str, str | None]] = []
        self.selected_portal: str | None = None

    def locator(self, selector: str):
        self.calls.append(("locator", selector))
        if "Mit VIDIS einloggen" in selector:
            return FakeCountLocator(1)
        if "Test Landesportal" in selector:
            return FakeCountLocator(1)
        if "Sichere Anmeldung" in selector:
            return FakeCountLocator(1)
        return FakeCountLocator(0)

    def get_by_role(self, role: str, name=None):
        label = getattr(name, "pattern", name)
        self.calls.append(("role", f"{role}:{label}"))
        return FakeCountLocator(1)

    def wait_for_load_state(self, *_args, **_kwargs):
        return None

    def wait_for_url(self, *_args, **_kwargs):
        return None


class FakePlainLoginPage:
    def __init__(self):
        self.url = "https://app.example.test/login"
        self.goto_calls: list[str] = []

    def locator(self, selector: str):
        if selector in {"input[name='username']", "input[type='password']", "button[type='submit']"}:
            return FakeCountLocator(1)
        return FakeCountLocator(0)

    def wait_for_load_state(self, *_args, **_kwargs):
        return None

    def goto(self, url: str, *_args, **_kwargs):
        self.goto_calls.append(url)
        self.url = url


def test_agentic_task_stays_on_authenticated_page_when_keyword_is_absent() -> None:
    from vidis_compliance.sources.agentic import DefaultAgenticRunner

    page = FakePlainLoginPage()
    page.url = "https://app.example.test/"
    result = AgenticCrawlResult(base_url="https://app.example.test/login", persona="Lehrkraft", task_types=[])

    DefaultAgenticRunner()._perform_task(page, "https://app.example.test/login", "teacher", result)

    assert result.visited_urls == ["https://app.example.test/"]
    assert page.goto_calls == []
    assert result.actions[-1] == {"task": "teacher", "action": "visit", "url": "https://app.example.test/"}


def test_agentic_login_selects_configured_vidis_portal_before_credentials() -> None:
    from vidis_compliance.sources.agentic import DefaultAgenticRunner

    page = FakeVidisPage()
    result = AgenticCrawlResult(base_url="https://app.example.test/login", persona="Lehrkraft", task_types=[])

    DefaultAgenticRunner()._try_login(
        page,
        username="teacher",
        password="secret",
        result=result,
        vidis_portal="Test Landesportal",
    )

    step_actions = [step["action"] for step in result.steps]
    assert "select_vidis_portal" in step_actions
    assert "submit_vidis_portal" in step_actions
    assert any("Test Landesportal" in str(call) for call in page.calls)
    assert result.actions[-1]["username"] == "teacher"


def test_agentic_login_without_vidis_portal_uses_existing_generic_form_path() -> None:
    from vidis_compliance.sources.agentic import DefaultAgenticRunner

    page = FakePlainLoginPage()
    result = AgenticCrawlResult(base_url="https://app.example.test/login", persona="Lehrkraft", task_types=[])

    DefaultAgenticRunner()._try_login(page, username="teacher", password="secret", result=result)

    assert not any(step.get("action") == "select_vidis_portal" for step in result.steps)
    assert result.actions[-1]["action"] == "login"


def test_redacted_data_redacts_credential_values_in_nested_agent_capture() -> None:
    payload = {
        "username": "teacher",
        "login": {"password": "secret", "session_storage": {"login_session_id": "abc123"}},
        "steps": [{"value": "secret"}, {"token": "abc123"}],
    }

    redacted = redacted_data(payload, ["secret", "abc123"])
    dumped = json.dumps(redacted)

    assert "secret" not in dumped
    assert "abc123" not in dumped
    assert dumped.count("***REDACTED***") >= 3
