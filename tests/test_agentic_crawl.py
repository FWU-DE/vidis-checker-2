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

    def run(self, *, base_url: str, task_types: list[str], username: str | None, password: str | None, output_dir: Path, persona: str, pages: int, vidis_portal: str | None = None, vidis_login_label: str | None = None, instructions: list[str] | None = None) -> AgenticCrawlResult:
        FakeAgentRunner.last_call = {"vidis_portal": vidis_portal, "vidis_login_label": vidis_login_label, "instructions": instructions or [], "username": username, "password": password}
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
            "--agent-vidis-login-label",
            "Login über Schulportal",
            "--agent-instruction",
            "Gehe auf Assistenten und prüfe die Übersicht.",
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
    assert FakeAgentRunner.last_call["vidis_login_label"] == "Login über Schulportal"
    assert FakeAgentRunner.last_call["instructions"] == ["Gehe auf Assistenten und prüfe die Übersicht."]
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
    def __init__(self, count: int = 0, *, text: str = "", href: str | None = None, page=None):
        self._count = count
        self.text = text
        self.href = href
        self.page = page

    def count(self) -> int:
        return self._count

    @property
    def first(self):
        return self

    def fill(self, *_args, **_kwargs):
        return None

    def click(self, *_args, **_kwargs):
        if self.page and self.href:
            self.page.url = self.href
        return None

    def wait_for(self, *_args, **_kwargs):
        return None

    def all(self):
        return [self]

    def inner_text(self, *_args, **_kwargs):
        return self.text

    def get_attribute(self, name: str, *_args, **_kwargs):
        if name == "href":
            return self.href
        return None


class FakeLocatorList:
    def __init__(self, items):
        self.items = items

    def count(self) -> int:
        return len(self.items)

    @property
    def first(self):
        return self.items[0] if self.items else FakeCountLocator(0)

    def all(self):
        return self.items


class FakeVidisPage:
    def __init__(self, vidis_login_label: str = "Mit VIDIS einloggen"):
        self.url = "https://app.example.test/login"
        self.calls: list[tuple[str, str | None]] = []
        self.selected_portal: str | None = None
        self.vidis_login_label = vidis_login_label

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
        if role in {"button", "link"} and label and any(token in str(label) for token in ["VIDIS", "Schulportal", "SSO"]):
            return FakeCountLocator(1 if self.vidis_login_label in str(label) else 0)
        return FakeCountLocator(1)

    def wait_for_load_state(self, *_args, **_kwargs):
        return None

    def wait_for_url(self, *_args, **_kwargs):
        return None


class FakeInternalLinksPage:
    def __init__(self):
        self.url = "https://app.example.test/"
        self.goto_calls: list[str] = []
        self.clicks: list[str] = []
        self.links = [
            FakeCountLocator(1, text="Neuer Chat", href="https://app.example.test/chat", page=self),
            FakeCountLocator(1, text="Assistenten", href="https://app.example.test/assistants", page=self),
            FakeCountLocator(1, text="Lernszenarien", href="https://app.example.test/", page=self),
            FakeCountLocator(1, text="Dialogpartner", href="https://app.example.test/", page=self),
            FakeCountLocator(1, text="Datenschutz", href="https://app.example.test/privacy", page=self),
            FakeCountLocator(1, text="Extern", href="https://external.example.test/", page=self),
        ]
        self.text_targets = {"Assistenten": "https://app.example.test/assistants"}

    def locator(self, selector: str):
        if selector == "a[href]":
            return FakeLocatorList(self.links)
        for label, href in self.text_targets.items():
            if label in selector:
                return FakeCountLocator(1, text=label, href=href, page=self)
        return FakeCountLocator(0)

    def get_by_role(self, role: str, name=None):
        label = getattr(name, "pattern", name)
        for link in self.links:
            if role in {"link", "button"} and str(label).lower() in link.text.lower():
                self.clicks.append(link.text)
                return link
        return FakeCountLocator(0)

    def wait_for_load_state(self, *_args, **_kwargs):
        return None

    def goto(self, url: str, *_args, **_kwargs):
        self.goto_calls.append(url)
        self.url = url


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


def test_agentic_discovers_internal_click_paths_until_page_limit() -> None:
    from vidis_compliance.sources.agentic import DefaultAgenticRunner

    page = FakeInternalLinksPage()
    result = AgenticCrawlResult(base_url="https://app.example.test/login", persona="Lehrkraft", task_types=[])

    DefaultAgenticRunner()._browse_click_paths(page, "https://app.example.test/login", result, target_pages=3)

    assert result.visited_urls == [
        "https://app.example.test/",
        "https://app.example.test/chat",
        "https://app.example.test/assistants",
    ]
    assert "https://external.example.test/" not in result.visited_urls
    assert [step["action"] for step in result.steps] == ["click_path", "click_path", "click_path"]


def test_agentic_click_paths_keep_distinct_labels_on_same_spa_url() -> None:
    from vidis_compliance.sources.agentic import DefaultAgenticRunner

    page = FakeInternalLinksPage()
    result = AgenticCrawlResult(base_url="https://app.example.test/login", persona="Lehrkraft", task_types=[])

    DefaultAgenticRunner()._browse_click_paths(page, "https://app.example.test/login", result, target_pages=5)

    labels = [step.get("label") for step in result.steps if step.get("action") == "click_path"]
    assert "Lernszenarien" in labels
    assert "Dialogpartner" in labels
    assert len(result.visited_urls) == 5


def test_agentic_click_paths_ignore_pre_login_urls_for_page_limit() -> None:
    from vidis_compliance.sources.agentic import DefaultAgenticRunner

    page = FakeInternalLinksPage()
    result = AgenticCrawlResult(
        base_url="https://app.example.test/login",
        persona="Lehrkraft",
        task_types=[],
        visited_urls=["https://app.example.test/login", "https://broker.example.test/vidis"],
    )

    DefaultAgenticRunner()._browse_click_paths(page, "https://app.example.test/login", result, target_pages=3, reset_visited=True)

    assert result.visited_urls == [
        "https://app.example.test/",
        "https://app.example.test/chat",
        "https://app.example.test/assistants",
    ]


def test_agentic_executes_natural_language_instruction_clicks_before_discovery() -> None:
    from vidis_compliance.sources.agentic import DefaultAgenticRunner

    page = FakeInternalLinksPage()
    result = AgenticCrawlResult(base_url="https://app.example.test/login", persona="Lehrkraft", task_types=[])

    DefaultAgenticRunner()._browse_click_paths(
        page,
        "https://app.example.test/login",
        result,
        target_pages=2,
        instructions=["Gehe auf Assistenten und prüfe die Übersicht."],
    )

    assert result.visited_urls[0] == "https://app.example.test/assistants"
    assert page.clicks[0] == "Assistenten"
    assert result.steps[0]["instruction"] == "Gehe auf Assistenten und prüfe die Übersicht."


def test_agentic_task_stays_on_authenticated_page_when_keyword_is_absent() -> None:
    from vidis_compliance.sources.agentic import DefaultAgenticRunner

    page = FakePlainLoginPage()
    page.url = "https://app.example.test/"
    result = AgenticCrawlResult(base_url="https://app.example.test/login", persona="Lehrkraft", task_types=[])

    DefaultAgenticRunner()._perform_task(page, "https://app.example.test/login", "teacher", result)

    assert result.visited_urls == ["https://app.example.test/"]
    assert page.goto_calls == []
    assert result.actions[-1] == {"task": "teacher", "action": "visit", "url": "https://app.example.test/"}


def test_agentic_login_uses_configured_vidis_login_label_before_auto_detection() -> None:
    from vidis_compliance.sources.agentic import DefaultAgenticRunner

    page = FakeVidisPage(vidis_login_label="Login über Schulportal")
    result = AgenticCrawlResult(base_url="https://app.example.test/login", persona="Lehrkraft", task_types=[])

    DefaultAgenticRunner()._try_login(
        page,
        username="teacher",
        password="secret",
        result=result,
        vidis_portal="Test Landesportal",
        vidis_login_label="Login über Schulportal",
    )

    first_button_call = next(call for call in page.calls if call[0] == "role" and str(call[1]).startswith("button:"))
    assert "Login über Schulportal" in str(first_button_call[1])
    assert result.steps[1]["vidis_login_label"] == "Login über Schulportal"


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
