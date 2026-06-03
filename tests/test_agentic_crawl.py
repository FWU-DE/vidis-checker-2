from __future__ import annotations

import json
import subprocess
from pathlib import Path

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from vidis_compliance import server
from vidis_compliance.cli import app
from vidis_compliance.sources.agentic import AgenticCrawlResult, redacted_data

PNG_1X1 = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
    b"\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00"
    b"\x00\x00\x0cIDAT\x08\xd7c\xf8\xff\xff?\x00\x05\xfe\x02"
    b"\xfeA\xe2!\xbc\x00\x00\x00\x00IEND\xaeB`\x82"
)


class FakeAgentRunner:
    last_call: dict[str, object] = {}

    def run(self, *, base_url: str, task_types: list[str], username: str | None, password: str | None, output_dir: Path, persona: str, pages: int, vidis_portal: str | None = None, vidis_login_label: str | None = None, instructions: list[str] | None = None) -> AgenticCrawlResult:
        FakeAgentRunner.last_call = {"vidis_portal": vidis_portal, "vidis_login_label": vidis_login_label, "instructions": instructions or [], "username": username, "password": password}
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "screenshots").mkdir()
        (output_dir / "pdfs").mkdir()
        (output_dir / "screenshots" / "legal-1.png").write_bytes(PNG_1X1)
        (output_dir / "screenshots" / "impressum-menu.png").write_bytes(PNG_1X1)
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
                "screenshots": ["screenshots/legal-1.png", "screenshots/impressum-menu.png"],
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

    root_capture = json.loads((tmp_path / "results" / "agent-job" / "capture.json").read_text(encoding="utf-8"))
    assert [s["filename"] for s in root_capture["screenshots"]] == ["legal-1.png", "impressum-menu.png"]
    assert all(Path(s["path"]).exists() for s in root_capture["screenshots"])
    assert all(s["local_only"] is False for s in root_capture["screenshots"])
    assert root_capture["agentic"]["visited_urls"][-1].endswith("/dashboard")
    assert root_capture["ipf"]["impressum_candidates"]
    assert any("impressum" in candidate.lower() for candidate in root_capture["ipf"]["impressum_candidates"])
    result_json = json.loads((tmp_path / "results" / "agent-job" / "result.json").read_text(encoding="utf-8"))
    findings = {finding["criterion"]: finding for finding in result_json["findings"]}
    assert findings["RDS-CUC-371"]["status"] in {"PASS", "FAIL", "MANUELL"}
    assert "authentifizierten Agent-Crawl" in findings["RDS-CUC-371"]["note"]
    assert findings["RDS-CUC-374"]["status"] in {"PASS", "MANUELL"}
    assert "authentifiziertem Agent-Crawl" in findings["RDS-CUC-374"]["note"]
    assert findings["RDS-IPF-364"]["status"] == "MANUELL"
    assert "Impressum" in findings["RDS-IPF-364"]["note"]


def test_agentic_markdown_and_pdf_include_agent_screenshot_artifacts(tmp_path: Path, monkeypatch) -> None:
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
            "agent-report-job",
            "--agentic",
            "--pages",
            "1",
            "--md",
            "results/agent-report-job/report.md",
            "--pdf",
            "results/agent-report-job/report.pdf",
        ],
    )

    assert result.exit_code == 0, result.output
    report_md = tmp_path / "results" / "agent-report-job" / "report.md"
    report_pdf = tmp_path / "results" / "agent-report-job" / "report.pdf"
    assert "Screenshot-Nachweise" in report_md.read_text(encoding="utf-8")
    extracted = subprocess.run(["pdftotext", str(report_pdf), "-"], check=True, text=True, capture_output=True).stdout
    images = subprocess.run(["pdfimages", "-list", str(report_pdf)], check=True, text=True, capture_output=True).stdout
    assert "Screenshot-Nachweise" in extracted
    assert "Screenshot-Thumbnail" in extracted
    assert "image" in images


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
        if self.page and self.text:
            self.page.current_view = self.text
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
        if name == "role" and self.href is None:
            return "button"
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
        self.current_view = "Startseite"
        self.goto_calls: list[str] = []
        self.clicks: list[str] = []
        self.links = [
            FakeCountLocator(1, text="Neuer Chat", href="https://app.example.test/chat", page=self),
            FakeCountLocator(1, text="Assistenten", href="https://app.example.test/assistants", page=self),
            FakeCountLocator(1, text="Lernszenarien", href="https://app.example.test/", page=self),
            FakeCountLocator(1, text="Dialogpartner", href="https://app.example.test/", page=self),
            FakeCountLocator(1, text="Profil", href="https://app.example.test/", page=self),
            FakeCountLocator(1, text="Impressum", href="https://app.example.test/impressum", page=self),
            FakeCountLocator(1, text="Datenschutz", href="https://app.example.test/privacy", page=self),
            FakeCountLocator(1, text="Hilfe-Chat", page=self),
            FakeCountLocator(1, text="Dialogpartner", page=self),
            FakeCountLocator(1, text="Lernszenarien", page=self),
            FakeCountLocator(1, text="Extern", href="https://external.example.test/", page=self),
        ]
        self.text_targets = {
            "Assistenten": "https://app.example.test/assistants",
            "Profil": "https://app.example.test/",
            "Impressum": "https://app.example.test/impressum",
            "Datenschutz": "https://app.example.test/privacy",
        }

    def locator(self, selector: str):
        if selector in {"a[href]", "a[href], button, [role='button'], [role='link'], nav a, nav button"}:
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
        self.current_view = "Startseite"


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


def test_agentic_discovers_button_only_navigation_items() -> None:
    from vidis_compliance.sources.agentic import DefaultAgenticRunner

    page = FakeInternalLinksPage()
    result = AgenticCrawlResult(base_url="https://app.example.test/login", persona="Lehrkraft", task_types=[])

    DefaultAgenticRunner()._browse_click_paths(page, "https://app.example.test/login", result, target_pages=10)

    labels = [step.get("label") for step in result.steps if step.get("action") == "click_path"]
    assert "Hilfe-Chat" in labels
    assert len(result.visited_urls) == 10


def test_agentic_legal_task_prioritizes_profile_menu_legal_paths() -> None:
    from vidis_compliance.sources.agentic import DefaultAgenticRunner

    page = FakeInternalLinksPage()
    result = AgenticCrawlResult(base_url="https://app.example.test/login", persona="Lehrkraft", task_types=["legal"])

    DefaultAgenticRunner()._browse_click_paths(page, "https://app.example.test/login", result, target_pages=4, instructions=["Öffne Profil", "Klicke Impressum", "Klicke Datenschutz"])

    labels = [step.get("label") for step in result.steps]
    assert labels[:3] == ["Profil", "Impressum", "Datenschutz"]
    assert "https://app.example.test/impressum" in result.visited_urls
    assert "https://app.example.test/privacy" in result.visited_urls


def test_agentic_captures_artifacts_immediately_for_same_url_spa_states(tmp_path: Path) -> None:
    from vidis_compliance.sources.agentic import DefaultAgenticRunner

    page = FakeInternalLinksPage()
    result = AgenticCrawlResult(base_url="https://app.example.test/login", persona="Lehrkraft", task_types=[])
    runner = DefaultAgenticRunner()

    captured_views: list[str] = []

    runner._browse_click_paths(
        page,
        "https://app.example.test/login",
        result,
        target_pages=5,
        capture_step=lambda _step: captured_views.append(page.current_view),
    )

    assert captured_views == [
        "Startseite",
        "Neuer Chat",
        "Assistenten",
        "Lernszenarien",
        "Dialogpartner",
    ]
    assert page.goto_calls == []


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
