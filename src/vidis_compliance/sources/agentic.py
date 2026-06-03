from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal, Sequence

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
        vidis_portal: str | None = None,
        vidis_login_label: str | None = None,
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
                    self._try_login(page, username, password, result, vidis_portal=vidis_portal, vidis_login_label=vidis_login_label)
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

    def _try_login(
        self,
        page: Any,
        username: str | None,
        password: str | None,
        result: AgenticCrawlResult,
        *,
        vidis_portal: str | None = None,
        vidis_login_label: str | None = None,
    ) -> None:
        result.steps.append({"action": "login", "username": username, "password": password})
        if vidis_portal:
            self._select_vidis_portal(page, vidis_portal, result, vidis_login_label=vidis_login_label)
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
        result.actions.append({"action": "login", "url": str(page.url), "username": username, "vidis_portal": vidis_portal})

    def _select_vidis_portal(self, page: Any, vidis_portal: str, result: AgenticCrawlResult, *, vidis_login_label: str | None = None) -> None:
        login_labels = self._vidis_login_labels(vidis_login_label)
        clicked_start = self._click_first_label(page, login_labels, timeout=4_000) or self._click_first(page, self._text_selectors(login_labels), timeout=4_000)
        result.steps.append({"action": "open_vidis_login", "vidis_login_label": vidis_login_label, "clicked": clicked_start})
        self._wait_for_network_idle(page)
        self._wait_for_any_selector(page, [
            "input[role='combobox']",
            "input[placeholder*='Bundesland']",
            "input[placeholder*='Schule']",
        ], timeout=10_000)

        filled = self._fill_first_role(page, [("combobox", None), ("textbox", "Bundesland"), ("textbox", "Schule")], vidis_portal, timeout=3_000)
        for selector in [
            "input[role='combobox']",
            "input[aria-autocomplete='list']",
            "input[placeholder*='Bundesland' i]",
            "input[placeholder*='Schule' i]",
            "input[type='search']",
            "input[type='text']",
        ]:
            try:
                locator = page.locator(selector)
                if not filled and locator.count():
                    locator.first.fill(vidis_portal, timeout=3_000)
                    filled = True
                    break
            except Exception:
                continue
        if not filled:
            try:
                locator = page.get_by_role("combobox")
                if locator.count():
                    locator.first.fill(vidis_portal, timeout=3_000)
                    filled = True
            except Exception:
                pass
        result.steps.append({"action": "select_vidis_portal", "portal": vidis_portal, "selected": filled})
        self._wait_for_network_idle(page)
        self._wait_for_any_selector(page, [
            f"[role='option']:has-text('{vidis_portal}')",
            f"button:has-text('{vidis_portal}')",
            f"text={vidis_portal}",
        ], timeout=5_000)

        (self._click_first_role(page, [("option", vidis_portal), ("button", vidis_portal)], timeout=4_000) or self._click_first(page, [
            f"[role='option']:has-text('{vidis_portal}')",
            f"button:has-text('{vidis_portal}')",
            f"li:has-text('{vidis_portal}')",
            f"text={vidis_portal}",
        ], timeout=4_000))
        self._wait_for_network_idle(page)
        result.steps.append({"action": "confirm_vidis_portal", "portal": vidis_portal})
        self._wait_for_any_selector(page, [
            "button:has-text('Sichere Anmeldung über')",
            "button:has-text('Sichere Anmeldung')",
            "button[aria-label*='Sichere Anmeldung']",
        ], timeout=5_000)

        clicked_secure = self._click_first_role(page, [
            ("button", "Sichere Anmeldung"),
            ("button", "Anmelden mit VIDIS"),
            ("link", "Sichere Anmeldung"),
            ("link", "Anmelden mit VIDIS"),
        ], timeout=5_000) or self._click_first(page, [
            "button:has-text('Sichere Anmeldung')",
            "button:has-text('Anmelden mit VIDIS')",
            "a:has-text('Sichere Anmeldung')",
            "a:has-text('Anmelden mit VIDIS')",
        ], timeout=5_000)
        self._wait_for_network_idle(page)
        result.steps.append({"action": "submit_vidis_portal", "portal": vidis_portal, "clicked": clicked_secure})

    def _vidis_login_labels(self, configured_label: str | None) -> list[str]:
        labels = [
            configured_label,
            "Mit VIDIS einloggen",
            "Anmelden mit VIDIS",
            "VIDIS",
            "Login über Schulportal",
            "Anmeldung über Schulportal",
            "Login über Landesportal",
            "Anmeldung über Landesportal",
            "Schulportal",
            "Landesportal",
            "Single Sign-On",
            "SSO",
        ]
        seen: set[str] = set()
        result: list[str] = []
        for label in labels:
            if label and label.casefold() not in seen:
                seen.add(label.casefold())
                result.append(label)
        return result

    def _text_selectors(self, labels: list[str]) -> list[str]:
        selectors: list[str] = []
        for label in labels:
            escaped = label.replace("'", "\\'")
            selectors.extend([
                f"button:has-text('{escaped}')",
                f"a:has-text('{escaped}')",
                f"[role='button']:has-text('{escaped}')",
                f"[role='link']:has-text('{escaped}')",
                f"text={label}",
            ])
        return selectors

    def _click_first_label(self, page: Any, labels: list[str], *, timeout: int) -> bool:
        role_names: list[tuple[str, str | None]] = []
        for label in labels:
            role_names.append(("button", label))
            role_names.append(("link", label))
        return self._click_first_role(page, role_names, timeout=timeout)

    def _click_first_role(self, page: Any, role_names: list[tuple[str, str | None]], *, timeout: int) -> bool:
        for role, name in role_names:
            try:
                kwargs = {"name": re.compile(name, re.IGNORECASE)} if name else {}
                locator = page.get_by_role(role, **kwargs)
                if locator.count():
                    locator.first.click(timeout=timeout)
                    return True
            except Exception:
                continue
        return False

    def _fill_first_role(self, page: Any, role_names: list[tuple[str, str | None]], value: str, *, timeout: int) -> bool:
        for role, name in role_names:
            try:
                kwargs = {"name": re.compile(name, re.IGNORECASE)} if name else {}
                locator = page.get_by_role(role, **kwargs)
                if locator.count():
                    locator.first.fill(value, timeout=timeout)
                    return True
            except Exception:
                continue
        return False

    def _click_first(self, page: Any, selectors: list[str], *, timeout: int) -> bool:
        for selector in selectors:
            try:
                locator = page.locator(selector)
                if locator.count():
                    locator.first.click(timeout=timeout)
                    return True
            except Exception:
                continue
        return False

    def _wait_for_any_selector(self, page: Any, selectors: list[str], *, timeout: int) -> bool:
        for selector in selectors:
            try:
                page.locator(selector).first.wait_for(state="visible", timeout=timeout)
                return True
            except Exception:
                continue
        return False

    def _wait_for_network_idle(self, page: Any) -> None:
        try:
            page.wait_for_load_state("networkidle", timeout=10_000)
        except Exception:
            try:
                page.wait_for_load_state("domcontentloaded", timeout=5_000)
            except Exception:
                pass

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
            current_url = str(page.url)
            result.visited_urls.append(current_url)
            result.actions.append({"task": task_type, "action": "visit", "url": current_url})
            result.steps.append({"task": task_type, "action": "visit", "url": current_url, "note": "no matching in-app navigation found"})
            return
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
