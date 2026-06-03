from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal, Sequence
from urllib.parse import urldefrag, urljoin, urlparse

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
        instructions: list[str] | None = None,
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
                target_pages = max(pages, 1)
                navigation_instructions = self._navigation_instructions(task_types, instructions)
                self._browse_click_paths(
                    page,
                    base_url,
                    result,
                    target_pages=target_pages,
                    instructions=navigation_instructions,
                    reset_visited=True,
                    capture_step=lambda step: self._capture_current_step_artifact(page, output_dir, result, step, target_pages=target_pages),
                )
                if not result.visited_urls:
                    result.visited_urls.append(str(page.url))
                    result.actions.append({"action": "visit", "url": str(page.url)})
                    result.steps.append({"action": "visit", "url": str(page.url), "note": "no click paths found"})
                    self._capture_current_step_artifact(page, output_dir, result, result.steps[-1], target_pages=target_pages)
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

    def _capture_current_step_artifact(self, page: Any, output_dir: Path, result: AgenticCrawlResult, step: dict[str, Any], *, target_pages: int) -> None:
        if len(result.artifacts.get("screenshots", [])) >= target_pages:
            return
        index = len(result.artifacts.get("screenshots", [])) + 1
        label = str(step.get("task") or step.get("instruction") or step.get("label") or step.get("action") or "page")
        slug = self._slug(label)[:40] or "page"
        screenshot_rel = f"screenshots/{index:02d}-{slug}.png"
        pdf_rel = f"pdfs/{index:02d}-{slug}.pdf"
        page.screenshot(path=str(output_dir / screenshot_rel), full_page=True)
        try:
            page.pdf(path=str(output_dir / pdf_rel), print_background=True)
        except Exception:
            pdf_rel = ""
        result.artifacts.setdefault("screenshots", []).append(screenshot_rel)
        if pdf_rel:
            result.artifacts.setdefault("pdfs", []).append(pdf_rel)

    def _navigation_instructions(self, task_types: list[str], instructions: list[str] | None) -> list[str]:
        result: list[str] = []
        if "legal" in task_types:
            result.extend([
                "Öffne Profil",
                "Öffne Benutzerprofil",
                "Öffne Konto",
                "Klicke Impressum",
                "Klicke Datenschutz",
                "Klicke Rechtliches",
            ])
        for instruction in instructions or []:
            if instruction not in result:
                result.append(instruction)
        return result

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

    def _browse_click_paths(
        self,
        page: Any,
        base_url: str,
        result: AgenticCrawlResult,
        *,
        target_pages: int,
        instructions: list[str] | None = None,
        reset_visited: bool = False,
        capture_step: Any | None = None,
    ) -> None:
        if reset_visited:
            result.visited_urls.clear()
        seen = {self._canonical_url(url) for url in result.visited_urls}
        seen_clicks: set[str] = set()
        for instruction in instructions or []:
            if len(result.visited_urls) >= target_pages:
                return
            label = self._label_from_instruction(instruction)
            clicked = (self._click_first_label(page, [label], timeout=4_000) or self._click_first(page, self._text_selectors([label]), timeout=4_000)) if label else False
            self._wait_for_network_idle(page)
            current_url = str(page.url)
            canonical = self._canonical_url(current_url)
            click_key = self._click_key(canonical, label)
            if clicked and click_key not in seen_clicks:
                seen.add(canonical)
                seen_clicks.add(click_key)
                result.visited_urls.append(current_url)
                result.actions.append({"action": "instruction_click", "url": current_url, "label": label, "instruction": instruction})
                step = {"action": "instruction_click", "url": current_url, "label": label, "instruction": instruction}
                result.steps.append(step)
                if capture_step:
                    capture_step(step)
        if str(page.url) and len(result.visited_urls) < target_pages:
            current = self._canonical_url(str(page.url))
            if current not in seen:
                seen.add(current)
                seen_clicks.add(self._click_key(current, "authenticated start"))
                result.visited_urls.append(str(page.url))
                result.actions.append({"action": "click_path", "url": str(page.url), "label": "authenticated start"})
                step = {"action": "click_path", "url": str(page.url), "label": "authenticated start"}
                result.steps.append(step)
                if capture_step:
                    capture_step(step)
        attempts = 0
        while len(result.visited_urls) < target_pages and attempts < target_pages * 4:
            attempts += 1
            candidate = self._next_internal_link(page, base_url, seen_clicks)
            if not candidate:
                break
            clicked = self._click_first_label(page, [candidate["label"]], timeout=3_000)
            if not clicked:
                try:
                    page.goto(candidate["url"], wait_until="networkidle", timeout=10_000)
                    clicked = True
                except Exception:
                    try:
                        page.goto(candidate["url"], wait_until="domcontentloaded", timeout=10_000)
                        clicked = True
                    except Exception:
                        clicked = False
            self._wait_for_network_idle(page)
            current_url = str(page.url) if clicked else candidate["url"]
            canonical = self._canonical_url(current_url)
            click_key = self._click_key(canonical, candidate["label"])
            if click_key in seen_clicks:
                seen.add(self._canonical_url(candidate["url"]))
                continue
            seen.add(canonical)
            seen_clicks.add(click_key)
            result.visited_urls.append(current_url)
            result.actions.append({"action": "click_path", "url": current_url, "label": candidate["label"], "source_url": candidate["url"]})
            step = {"action": "click_path", "url": current_url, "label": candidate["label"], "source_url": candidate["url"]}
            result.steps.append(step)
            if capture_step:
                capture_step(step)

    def _next_internal_link(self, page: Any, base_url: str, seen_clicks: set[str]) -> dict[str, str] | None:
        try:
            elements = page.locator("a[href], button, [role='button'], [role='link'], nav a, nav button").all()
        except Exception:
            try:
                elements = page.locator("a[href]").all()
            except Exception:
                elements = []
        base_host = urlparse(base_url).netloc
        for element in elements:
            try:
                href = element.get_attribute("href")
                label = " ".join(str(element.inner_text(timeout=500) or "").split())
                absolute = urljoin(str(page.url) or base_url, href) if href else str(page.url) or base_url
                parsed = urlparse(absolute)
                if parsed.scheme not in {"http", "https"} or parsed.netloc != base_host:
                    continue
                canonical = self._canonical_url(absolute)
                label = label or parsed.path.rsplit("/", 1)[-1] or "page"
                if self._click_key(canonical, label) in seen_clicks:
                    continue
                if self._is_low_value_link(label, absolute):
                    continue
                return {"url": absolute, "label": label}
            except Exception:
                continue
        return None

    def _label_from_instruction(self, instruction: str) -> str:
        cleaned = instruction.strip().rstrip(".")
        for pattern in [
            r"(?:gehe|geh|klicke|click|öffne|oeffne)\s+(?:auf|zu|in|den|die|das|dort)?\s*['\"]?([^'\".,;]+)",
            r"(?:seite|menüpunkt|menuepunkt|button|link)\s+['\"]?([^'\".,;]+)",
        ]:
            match = re.search(pattern, cleaned, re.IGNORECASE)
            if match:
                label = match.group(1).strip()
                return re.sub(r"\s+(?:und|dann|anschließend|anschliessend)\b.*$", "", label, flags=re.IGNORECASE).strip()
        return cleaned

    def _canonical_url(self, url: str) -> str:
        without_fragment, _fragment = urldefrag(url)
        parsed = urlparse(without_fragment)
        path = parsed.path or "/"
        if path.endswith("/index.html") or path.endswith("/index.htm"):
            path = path.rsplit("/", 1)[0] + "/"
        return parsed._replace(path=path, query="").geturl().rstrip("/") or parsed._replace(path="/").geturl()

    def _click_key(self, canonical_url: str, label: str) -> str:
        return f"{canonical_url}|{self._slug(label)}"

    def _is_low_value_link(self, label: str, url: str) -> bool:
        value = f"{label} {url}".casefold()
        return any(token in value for token in ["mailto:", "tel:", "download", "javascript:", "#", "cookie"])

    def _slug(self, value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")

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
