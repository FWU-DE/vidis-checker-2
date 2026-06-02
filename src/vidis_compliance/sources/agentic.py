from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal, Sequence
from urllib.parse import urljoin

AgentTask = Literal["legal", "student", "teacher", "register", "logout"]
DEFAULT_AGENT_TASKS: list[AgentTask] = ["legal", "student", "teacher", "register", "logout"]

_REDACTED = "***REDACTED***"


@dataclass
class AgenticCrawlResult:
    base_url: str
    persona: str
    task_types: list[str]
    visited_urls: list[str] = field(default_factory=list)
    actions: list[dict[str, Any]] = field(default_factory=list)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    local_storage: dict[str, Any] = field(default_factory=dict)
    session_storage: dict[str, Any] = field(default_factory=dict)
    requests: list[dict[str, Any]] = field(default_factory=list)
    artifacts: dict[str, list[str]] = field(default_factory=dict)
    steps: list[dict[str, Any]] = field(default_factory=list)


class DefaultAgenticRunner:
    """Small optional browser adapter for credentialed persona crawls.

    This intentionally avoids importing Playwright/browser tooling until agent mode is
    requested so deterministic scans and unit tests stay lightweight.
    """

    def run(
        self,
        *,
        base_url: str,
        task_types: list[str],
        username: str | None,
        password: str | None,
        output_dir: Path,
        persona: str,
        pages: int,
    ) -> AgenticCrawlResult:
        from playwright.sync_api import Page, TimeoutError as PlaywrightTimeoutError, sync_playwright

        output_dir.mkdir(parents=True, exist_ok=True)
        screenshots_dir = output_dir / "screenshots"
        pdfs_dir = output_dir / "pdfs"
        screenshots_dir.mkdir(exist_ok=True)
        pdfs_dir.mkdir(exist_ok=True)

        result = AgenticCrawlResult(base_url=base_url, persona=persona, task_types=task_types)
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            page.on("request", lambda request: result.requests.append({"method": request.method, "url": request.url}))
            try:
                self._goto(page, base_url, result, "open")
                if username or password:
                    self._try_login(page, username, password, result)
                for index, task_type in enumerate(task_types[: max(pages, 1)], start=1):
                    self._perform_task(page, base_url, task_type, result)
                    screenshot_rel = f"screenshots/{index:02d}-{task_type}.png"
                    pdf_rel = f"pdfs/{index:02d}-{task_type}.pdf"
                    page.screenshot(path=str(output_dir / screenshot_rel), full_page=True)
                    try:
                        page.pdf(path=str(output_dir / pdf_rel), print_background=True)
                    except Exception:
                        pdf_rel = ""
                    result.artifacts.setdefault("screenshots", []).append(screenshot_rel)
                    if pdf_rel:
                        result.artifacts.setdefault("pdfs", []).append(pdf_rel)
                result.cookies = context.cookies()
                result.local_storage = _safe_eval_dict(page, "() => Object.fromEntries(Object.entries(localStorage))")
                result.session_storage = _safe_eval_dict(page, "() => Object.fromEntries(Object.entries(sessionStorage))")
            finally:
                context.close()
                browser.close()
        return result

    def _goto(self, page: Any, url: str, result: AgenticCrawlResult, action: str) -> None:
        try:
            page.goto(url, wait_until="networkidle", timeout=20_000)
        except Exception:
            page.goto(url, wait_until="domcontentloaded", timeout=20_000)
        current_url = str(page.url)
        result.visited_urls.append(current_url)
        result.actions.append({"action": action, "url": current_url})
        result.steps.append({"action": action, "url": current_url})

    def _try_login(self, page: Any, username: str | None, password: str | None, result: AgenticCrawlResult) -> None:
        result.steps.append({"action": "login", "username": username, "password": password})
        filled = False
        for selector in ["input[name='username']", "input[name='email']", "input[type='email']", "input[type='text']"]:
            try:
                if username and page.locator(selector).count():
                    page.locator(selector).first.fill(username, timeout=2_000)
                    filled = True
                    break
            except Exception:
                continue
        for selector in ["input[name='password']", "input[type='password']"]:
            try:
                if password and page.locator(selector).count():
                    page.locator(selector).first.fill(password, timeout=2_000)
                    filled = True
                    break
            except Exception:
                continue
        if filled:
            for selector in ["button[type='submit']", "input[type='submit']", "button:has-text('Login')", "button:has-text('Anmelden')"]:
                try:
                    if page.locator(selector).count():
                        page.locator(selector).first.click(timeout=2_000)
                        page.wait_for_load_state("networkidle", timeout=10_000)
                        break
                except Exception:
                    continue
        result.visited_urls.append(str(page.url))
        result.actions.append({"action": "login", "url": str(page.url), "username": username})

    def _perform_task(self, page: Any, base_url: str, task_type: str, result: AgenticCrawlResult) -> None:
        keywords = {
            "legal": ["datenschutz", "impressum", "agb", "legal", "privacy"],
            "student": ["schueler", "student", "kurs", "dashboard"],
            "teacher": ["lehrer", "teacher", "klasse", "verwaltung"],
            "register": ["registr", "signup", "konto"],
            "logout": ["logout", "abmelden"],
        }.get(task_type, [])
        for keyword in keywords:
            locator = page.locator(f"a[href*='{keyword}' i], button:has-text('{keyword}')")
            try:
                if locator.count():
                    locator.first.click(timeout=3_000)
                    page.wait_for_load_state("networkidle", timeout=10_000)
                    break
            except Exception:
                continue
        else:
            target = urljoin(base_url.rstrip("/") + "/", keywords[0] if keywords else task_type)
            try:
                self._goto(page, target, result, task_type)
                return
            except Exception:
                pass
        current_url = str(page.url)
        result.visited_urls.append(current_url)
        result.actions.append({"task": task_type, "action": "visit", "url": current_url})
        result.steps.append({"task": task_type, "action": "visit", "url": current_url})


def _safe_eval_dict(page: Any, expression: str) -> dict[str, Any]:
    try:
        value = page.evaluate(expression)
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def normalize_agent_tasks(tasks: list[str] | None) -> list[str]:
    if not tasks:
        return list(DEFAULT_AGENT_TASKS)
    allowed = set(DEFAULT_AGENT_TASKS)
    normalized: list[str] = []
    for task in tasks:
        value = task.strip().lower()
        if value not in allowed:
            raise ValueError(f"unknown agent task: {task}")
        if value not in normalized:
            normalized.append(value)
    return normalized


def resolve_secret(value: str | None, env_name: str) -> str | None:
    return value if value is not None else os.environ.get(env_name)


def redacted_data(data: Any, secrets: Sequence[str | None]) -> Any:
    secret_values = [secret for secret in secrets if secret]
    if isinstance(data, dict):
        output: dict[str, Any] = {}
        for key, value in data.items():
            if str(key).lower() in {"password", "passwort", "secret", "token", "access_token", "refresh_token"}:
                output[key] = _REDACTED
            else:
                output[key] = redacted_data(value, secret_values)
        return output
    if isinstance(data, list):
        return [redacted_data(item, secret_values) for item in data]
    if isinstance(data, str):
        redacted = data
        for secret in secret_values:
            redacted = redacted.replace(secret, _REDACTED)
        return redacted
    return data


def write_agentic_artifacts(result: AgenticCrawlResult, output_dir: Path, secrets: list[str | None]) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = redacted_data(asdict(result), secrets)
    (output_dir / "agent_capture.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    with (output_dir / "step_result.jsonl").open("w", encoding="utf-8") as handle:
        for step in result.steps:
            handle.write(json.dumps(redacted_data(step, secrets), ensure_ascii=False, default=str) + "\n")
    return summary
