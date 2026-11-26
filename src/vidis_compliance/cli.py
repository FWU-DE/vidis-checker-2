from __future__ import annotations
import json
from dataclasses import asdict, dataclass
import os
from urllib.parse import urlparse
from pathlib import Path
from typing import Any
import typer
from .models import JobConfig, JobResult, CheckFinding, CriteriaIndex, VidisCriterion
from .checks.site.advertising import (
    classify_advertising,
    classify_outbound_ad_links,
    classify_youth_protection,
)
from .checks.site.cookies import (
    classify_browser_fingerprinting,
    classify_cookie_description_completeness,
    classify_cookies,
    classify_device_storage_access,
    classify_local_storage,
    classify_tracking_mechanisms,
    classify_tracking_pixel,
)
from .checks.site.basic_http import check_site_transport
from .checks.site.ipf import DOCUMENT_KINDS, analyze_ipf_site, discover_document_links, findings_from_ipf_analysis
from .sources.site.crawl import crawl
from .sources.site.vision import gemini_screenshot_provider, review_screenshots
from .sources.site import crawl_cache
from . import fetch_cache

# Site checks whose criteria a screenshot review can give evidence for.
VISION_CHECKS = frozenset({"site.advertising", "site.outbound_ad_links", "site.youth_protection"})
from .sources.agentic import (
    DefaultAgenticRunner,
    normalize_agent_tasks,
    resolve_secret,
    write_agentic_artifacts,
)
from .sources.code.inspect import inspect_code_path
from .sources.documents.analyze import DOCUMENT_CRITERIA, DocumentInput, analyze_documents, build_document_inputs, extract_text, fetch_document
from .evidence import run_lighthouse, write_webinspector_exports
from .coverage_matrix import write_coverage_matrix
from . import finding_details
from .version import API_VERSION
from .catalog import CRAWL_FREE_SITE_CHECKS, SITE_DECIDES_WITH_DOCUMENTS, checks_for_criteria, criteria_for_checks, resolve_check_selection
from .report.markdown import generate_markdown
from .report.pdf import generate_pdf
import yaml

app = typer.Typer(add_completion=False)

HERE = Path(__file__).resolve().parent
CRITERIA_PATH = HERE / "criteria" / "vidis_v0_2.yaml"


def load_criteria() -> CriteriaIndex:
    data = yaml.safe_load(CRITERIA_PATH.read_text(encoding="utf-8"))
    items = {}
    for code, spec in data.items():
        items[code] = VidisCriterion(code=code, **spec)
    return CriteriaIndex(items=items)



def _extract_privacy_text_for_cookie_descriptions(document_inputs) -> str:
    texts: list[str] = []
    for document in document_inputs:
        if getattr(document, "kind", "document") not in {"privacy", "document"}:
            continue
        try:
            content, content_type, location, _kind = fetch_document(document)
            text = extract_text(content, content_type=content_type, location=location)
        except Exception:
            continue
        lowered = text.lower()
        if getattr(document, "kind", "document") == "privacy" or "datenschutzerklärung" in lowered or "datenschutzerklaerung" in lowered or "cookie" in lowered:
            texts.append(text)
    return "\n".join(texts)


def _ai_model_entry(
    value: str | None,
    *,
    task: str = "VIDIS KI-Bewertungen",
    status: str = "vom CLI übergeben",
) -> dict[str, Any] | None:
    if not value:
        return None
    provider = "—"
    model = value.strip()
    if ":" in model:
        provider, model = model.split(":", 1)
    return {
        "task": task,
        "provider": provider.strip() or "—",
        "model": model.strip() or "nicht angegeben",
        "status": status,
    }


def _append_ai_model_metadata(raw_capture: dict[str, Any] | None, ai_model: str | None, **entry_fields: str) -> dict[str, Any] | None:
    entry = _ai_model_entry(ai_model, **entry_fields)
    if entry is None:
        return raw_capture
    if raw_capture is None:
        raw_capture = {}
    raw_capture.setdefault("ai_models", []).append(entry)
    return raw_capture


def _merge_agentic_report_capture(raw_capture: dict[str, Any] | None, agent_capture: dict[str, Any], agent_dir: Path, result_dir: Path) -> dict[str, Any]:
    merged = dict(raw_capture or {})
    screenshots = list(merged.get("screenshots") or [])
    steps = [step for step in agent_capture.get("steps") or [] if isinstance(step, dict)]
    artifact_screenshots = agent_capture.get("artifacts", {}).get("screenshots") if isinstance(agent_capture.get("artifacts"), dict) else []
    for index, rel in enumerate(artifact_screenshots or []):
        rel_path = Path(str(rel))
        full_path = agent_dir / rel_path
        step = _agentic_step_for_artifact(steps, index)
        screenshots.append(
            {
                "label": str(step.get("label") or step.get("instruction") or step.get("task") or rel_path.stem),
                "url": str(step.get("url") or ""),
                "filename": rel_path.name,
                "path": str(full_path),
                "local_only": False,
                "authenticated": True,
            }
        )
    merged.setdefault("url", agent_capture.get("base_url"))
    merged["cookies"] = agent_capture.get("cookies") or merged.get("cookies") or []
    merged["requests"] = list(merged.get("requests") or []) + list(agent_capture.get("requests") or [])
    merged["local_storage"] = {**(merged.get("local_storage") or {}), **(agent_capture.get("local_storage") or {})}
    merged["session_storage"] = {**(merged.get("session_storage") or {}), **(agent_capture.get("session_storage") or {})}
    merged["screenshots"] = screenshots
    merged["agentic"] = agent_capture
    site_ipf = merged.get("ipf") or {}
    agent_ipf = _agentic_ipf_evidence(agent_capture)
    if isinstance(site_ipf, dict):
        merged["ipf"] = {**site_ipf, "agentic": agent_ipf}
        for key, value in agent_ipf.items():
            if key not in merged["ipf"] or not merged["ipf"].get(key):
                merged["ipf"][key] = value
    else:
        merged["ipf"] = dict(agent_ipf)
    return merged


def _agentic_step_for_artifact(steps: list[dict[str, Any]], index: int) -> dict[str, Any]:
    page_steps = [step for step in steps if step.get("url")]
    if index < len(page_steps):
        return page_steps[index]
    return {}


def _agentic_ipf_evidence(agent_capture: dict[str, Any]) -> dict[str, Any]:
    candidates: list[str] = []
    for step in agent_capture.get("steps") or []:
        if not isinstance(step, dict):
            continue
        text = " ".join(str(step.get(key) or "") for key in ("label", "instruction", "task", "url"))
        lowered = text.lower()
        if any(token in lowered for token in ("impressum", "datenschutz", "privacy", "profile", "profil", "konto", "menü", "menu")):
            candidates.append(text.strip())
    for screenshot in (agent_capture.get("artifacts") or {}).get("screenshots", []) if isinstance(agent_capture.get("artifacts"), dict) else []:
        text = str(screenshot)
        lowered = text.lower()
        if any(token in lowered for token in ("impressum", "datenschutz", "privacy", "profile", "profil", "menu", "menue")):
            candidates.append(text)
    deduped = list(dict.fromkeys(candidate for candidate in candidates if candidate))
    return {
        "visited_urls": agent_capture.get("visited_urls") or [],
        "impressum_candidates": deduped,
        "privacy_candidates": [c for c in deduped if any(token in c.lower() for token in ("datenschutz", "privacy"))],
        "legal_note": "Agentischer authentifizierter Crawl: Rechtsinformationen können in Profil-/Benutzermenüs versteckt sein; gefundene Kandidaten manuell prüfen.",
    }


def _agentic_ipf_findings(agent_capture: dict[str, Any]) -> list[CheckFinding]:
    ipf = _agentic_ipf_evidence(agent_capture)
    candidates = ipf.get("impressum_candidates") or []
    visited_count = len(agent_capture.get("visited_urls") or [])
    note = (
        "Authentifizierter Agent-Crawl hat mögliche Impressum-/Datenschutz-/Rechtsinfo- oder Profilmenü-Kandidaten gefunden: "
        + "; ".join(str(c) for c in candidates[:6])
        if candidates
        else f"Authentifizierter Agent-Crawl hat {visited_count} Seite(n)/Clickpfad(e) erfasst; Impressum/Datenschutzerklärung ggf. im Profilmenü manuell prüfen."
    )
    return [
        CheckFinding(criterion="RDS-IPF-364", status="MANUELL", note=note),
        CheckFinding(criterion="RDS-IPF-365", status="MANUELL", note=note),
        CheckFinding(criterion="RDS-IPF-366", status="MANUELL", note=note),
        CheckFinding(criterion="RDS-IPF-367", status="MANUELL", note=note),
        CheckFinding(criterion="RDS-DSO-383", status="MANUELL", note="Datenschutzbeauftragten-Kontakt in Datenschutzerklärung bzw. Profil-/Rechtsinfo-Menü manuell prüfen."),
    ]


def _agentic_signal_findings(agent_capture: dict[str, Any], audience: str) -> list[CheckFinding]:
    page_signals = {
        "cookies": agent_capture.get("cookies") or [],
        "scripts": [],
        "requests": agent_capture.get("requests") or [],
        "resources": [],
        "links": [],
        "visible_text": "",
        "url": agent_capture.get("base_url"),
        "browser_signals": {},
        "local_storage": agent_capture.get("local_storage") or {},
        "session_storage": agent_capture.get("session_storage") or {},
    }
    findings: list[CheckFinding] = []
    cookie_status, cookie_note = classify_cookies(page_signals, audience)
    agent_cookie_note = f"Aus authentifizierten Agent-Crawl-Daten: {cookie_note}"
    findings.append(CheckFinding(criterion="RDS-CUC-371", status=cookie_status, note=agent_cookie_note))
    findings.append(CheckFinding(criterion="RDS-CUC-372", status=cookie_status, note=agent_cookie_note))
    findings.append(CheckFinding(criterion="RDS-CUC-373", status="MANUELL", note=f"Aus authentifiziertem Agent-Crawl: {len(page_signals['requests'])} Netzwerkanfragen erfasst; Tracking-Pixel manuell prüfen."))
    storage_status, storage_note = classify_local_storage(page_signals, audience)
    findings.append(CheckFinding(criterion="RDS-CUC-374", status=storage_status if storage_status == "PASS" else "MANUELL", note=f"Aus authentifiziertem Agent-Crawl: {storage_note}; sessionStorage- und localStorage-Keys ohne Werte dokumentiert."))
    findings.append(CheckFinding(criterion="RDS-CUC-375", status="MANUELL", note="Aus authentifiziertem Agent-Crawl: Device-/Browser-Storage-APIs ohne zusätzliche Browser-Signal-Instrumentierung manuell prüfen."))
    findings.append(CheckFinding(criterion="RDS-CUC-376", status="MANUELL", note="Aus authentifiziertem Agent-Crawl: Fingerprinting-/Entropy-APIs ohne zusätzliche Browser-Signal-Instrumentierung manuell prüfen."))
    tracking_status, tracking_note = classify_tracking_mechanisms(page_signals, audience)
    findings.append(CheckFinding(criterion="RDS-CUC-377", status=tracking_status if tracking_status != "PASS" else "MANUELL", note=f"Aus authentifiziertem Agent-Crawl: {tracking_note}"))
    findings.append(CheckFinding(criterion="RDS-WER-384", status="MANUELL", note="Aus authentifiziertem Agent-Crawl: Werbung/Sponsoring in erfassten Screenshots und Clickpfaden manuell prüfen."))
    findings.append(CheckFinding(criterion="RDS-WER-385", status="MANUELL", note="Aus authentifiziertem Agent-Crawl: externe Werbelinks in Requests/Screenshots manuell prüfen."))
    findings.append(CheckFinding(criterion="RDS-VIN-354", status="MANUELL", note="Aus authentifiziertem Agent-Crawl: Jugendmedienschutz anhand erfasster Rollen-/App-Oberflächen manuell prüfen."))
    _, completeness_note, completeness_evidence = classify_cookie_description_completeness(page_signals, privacy_text=None)
    findings.append(CheckFinding(criterion="RDS-CUC-453", status="MANUELL", note=f"Aus authentifiziertem Agent-Crawl: {completeness_note}"))
    agent_capture["rds_cuc_453"] = completeness_evidence
    return findings


_CAPTURE_KEYS = (
    "url",
    "cookies",
    "local_storage",
    "session_storage",
    "scripts",
    "requests",
    "resources",
    "links",
    "visible_text",
    "browser_signals",
    "visited_urls",
    "screenshots",
    "vision_reviews",
)


def _capture_to_dict(capture: Any) -> dict[str, Any]:
    try:
        return asdict(capture)
    except TypeError:
        return {key: getattr(capture, key) for key in _CAPTURE_KEYS if hasattr(capture, key)}


@dataclass
class CheckRun:
    result: JobResult
    raw_capture: dict[str, Any] | None = None
    code_capture: dict[str, Any] | None = None
    document_capture: dict[str, Any] | None = None
    agent_capture: dict[str, Any] | None = None


def _cache_dir(cache_root: Path | None, outdir: Path) -> Path:
    return Path(cache_root or os.environ.get("VIDIS_CRAWL_CACHE_DIR") or (Path(outdir).parent / ".crawl-cache"))


def run_checks(**kwargs: Any) -> CheckRun:
    """Run the checks (see ``_run_checks``) with HTTP fetches cached.

    Legal pages and documents fetched within ``crawl_max_age`` seconds are
    reused like the browser crawl; how many came from the cache is recorded
    under ``fetch_cache`` in the captures.
    """
    max_age = kwargs.get("crawl_max_age", crawl_cache.DEFAULT_MAX_AGE_SECONDS)
    cache = fetch_cache.FetchCache(_cache_dir(kwargs.get("cache_root"), kwargs["outdir"]) / fetch_cache.SUBDIR, max_age)
    with fetch_cache.active(cache):
        run = _run_checks(**kwargs)
    if cache.hits or cache.misses:
        for capture in (run.raw_capture, run.document_capture):
            if capture is not None:
                capture["fetch_cache"] = cache.stats()
    for capture in (run.raw_capture, run.code_capture, run.document_capture, run.agent_capture):
        if capture is not None:
            capture["api_version"] = API_VERSION
    return run


def _run_checks(
    *,
    job_id: str,
    outdir: Path,
    url: str | None = None,
    code_path: str | None = None,
    pages: int = 8,
    audience: str = "beide",
    documents: list[Path] | list[str] | None = None,
    agb_url: str | None = None,
    privacy_url: str | None = None,
    avv_url: str | None = None,
    agentic: bool = False,
    agent_tasks: list[str] | None = None,
    agent_persona: str | None = None,
    agent_username: str | None = None,
    agent_password: str | None = None,
    agent_vidis_portal: str | None = None,
    agent_vidis_login_label: str | None = None,
    agent_instructions: list[str] | None = None,
    lighthouse: bool = False,
    webinspector_export: bool = False,
    ai_model: str | None = None,
    checks: list[str] | None = None,
    criteria: list[str] | None = None,
    crawl_max_age: int = crawl_cache.DEFAULT_MAX_AGE_SECONDS,
    cache_root: Path | None = None,
    allow_env_credentials: bool = True,
) -> CheckRun:
    """Run every VIDIS check that the supplied inputs allow, or only ``checks``.

    Shared by ``vidis check`` and the API job runner so both produce the same
    findings for the same inputs. With ``checks`` (ids from the catalog) only
    those checks run and the result only holds their criteria. Raises
    ``ValueError`` for invalid input combinations.

    The browser crawl of ``url`` is reused from a crawl younger than
    ``crawl_max_age`` seconds (0 forces a fresh crawl).

    With ``criteria`` (codes like RDS-IPF-365) the result holds exactly these criteria;
    without ``checks`` the run picks the checks they need (``checks_for_criteria``).
    """
    crit = load_criteria()
    if criteria:
        unknown = [code for code in criteria if code not in crit.items]
        if unknown:
            raise ValueError(f"unknown criterion/criteria: {', '.join(unknown)}; valid codes are listed at GET /criteria")
        if not checks:
            checks = checks_for_criteria(
                criteria,
                has_url=bool(url),
                has_code=bool(code_path),
                has_documents=bool(documents or agb_url or privacy_url or avv_url),
            )
    selected = resolve_check_selection(
        checks,
        has_url=bool(url),
        has_code=bool(code_path),
        has_documents=bool(documents or agb_url or privacy_url or avv_url),
        flags={"agentic": agentic, "lighthouse": lighthouse, "webinspector_export": webinspector_export},
    )
    if criteria and selected is None:
        # No check covers the requested criteria with these inputs: run nothing, answer MANUELL.
        selected = frozenset()
    if selected is not None:
        agentic = "agentic.persona_crawl" in selected
        lighthouse = "evidence.lighthouse" in selected
        webinspector_export = "evidence.webinspector" in selected

    def want(check_id: str) -> bool:
        return selected is None or check_id in selected

    needs_crawl = selected is None or any(
        check_id.split(".", 1)[0] in {"site", "agentic", "evidence"} and check_id not in CRAWL_FREE_SITE_CHECKS
        for check_id in selected
    )
    cfg = JobConfig(job_id=job_id, target_url=url, code_path=code_path, pages=pages, target_audience=audience)  # noqa: E501

    findings = []
    raw_capture = None
    code_capture = None
    document_capture = None
    agent_capture = None
    document_inputs = build_document_inputs(documents or [], agb_url=agb_url, privacy_url=privacy_url, avv_url=avv_url)
    document_discovery = None
    if url and (want("documents.analysis") or want("site.cookie_descriptions") or want("site.tracking_mechanisms")):
        # Callers test along the criteria with just the site; find what they did not supply.
        # The cookie-description check only needs the privacy policy; the tracking check
        # looks for a pedagogical purpose in the privacy policy and the AGB.
        supplied = {document.kind for document in document_inputs}
        if want("documents.analysis"):
            kinds = DOCUMENT_KINDS
        elif want("site.tracking_mechanisms"):
            kinds = tuple(kind for kind in DOCUMENT_KINDS if kind in {"agb", "privacy"})
        else:
            kinds = ("privacy",)
        wanted = tuple(kind for kind in kinds if kind not in supplied)
        if wanted:
            document_discovery = discover_document_links(url, wanted=wanted)
            document_inputs += [
                DocumentInput(location=link, kind=kind, discovered=True) for kind, link in document_discovery["found"].items()
            ]
    privacy_text_for_cookies = _extract_privacy_text_for_cookie_descriptions(document_inputs) if document_inputs else ""
    # Browser capture for cookie/storage-related VIDIS criteria.
    if url and needs_crawl:
        cache_dir = _cache_dir(cache_root, outdir)
        cap, crawl_info = crawl_cache.cached_crawl(
            crawl, url=url, pages=pages, outdir=outdir, cache_root=cache_dir, max_age=crawl_max_age
        )
        raw_capture = _capture_to_dict(cap)
        cached_reviews = crawl_info.pop("vision_reviews", None)
        wants_vision = selected is None or bool(selected & VISION_CHECKS)
        provider = gemini_screenshot_provider() if wants_vision else None
        if provider is None:
            raw_capture["vision_reviews"] = review_screenshots(raw_capture.get("screenshots") or [], provider=None)
        elif cached_reviews is not None:
            raw_capture["vision_reviews"] = cached_reviews
        else:
            # A parallel job may be reviewing the same crawl; wait and reuse its result.
            with crawl_cache.key_lock("vision", cache_dir, url, pages):
                reviews = crawl_cache.load_reviews(cache_dir, url, pages, crawl_info.get("created"))
                if reviews is None:
                    reviews = review_screenshots(raw_capture.get("screenshots") or [], provider=provider)
                    crawl_cache.store(cache_dir, url, pages, cap, reviews, created=crawl_info.get("created"))
            raw_capture["vision_reviews"] = reviews
        for model in sorted({str(r.get("model")) for r in raw_capture["vision_reviews"] if r.get("model")}):
            raw_capture = _append_ai_model_metadata(
                raw_capture, f"vertex:{model}", task="Bewertung der Screenshots", status="vom Dienst genutzt"
            )
        crawl_info.pop("created", None)
        raw_capture["crawl"] = crawl_info
        if lighthouse:
            raw_capture["lighthouse"] = run_lighthouse(url, outdir / "lighthouse")
        if webinspector_export:
            raw_capture["webinspector"] = write_webinspector_exports(raw_capture, outdir / "webinspector")
        page_signals = {
            "cookies": cap.cookies,
            "scripts": cap.scripts,
            "requests": cap.requests,
            "resources": cap.resources,
            "links": cap.links,
            "visible_text": cap.visible_text,
            "url": cap.url,
            "browser_signals": cap.browser_signals,
            "local_storage": cap.local_storage,
            "session_storage": cap.session_storage,
        }
        s1, n1 = classify_cookies(page_signals, audience)
        if want("site.cookies"):
            findings.append(CheckFinding(criterion="RDS-CUC-371", status=s1, note=n1))
            findings.append(CheckFinding(criterion="RDS-CUC-372", status=s1, note=n1))
        s2, n2 = classify_tracking_pixel(page_signals, audience)
        if want("site.tracking_pixel"):
            findings.append(CheckFinding(criterion="RDS-CUC-373", status=s2, note=n2))
        s3, n3 = classify_local_storage(page_signals, audience)
        if want("site.browser_storage"):
            findings.append(CheckFinding(criterion="RDS-CUC-374", status=s3, note=n3))
        s375, n375 = classify_device_storage_access(page_signals, audience)
        if want("site.device_storage"):
            findings.append(CheckFinding(criterion="RDS-CUC-375", status=s375, note=n375))
        s376, n376 = classify_browser_fingerprinting(page_signals, audience)
        if want("site.fingerprinting"):
            findings.append(CheckFinding(criterion="RDS-CUC-376", status=s376, note=n376))
        if want("site.tracking_mechanisms") and document_inputs and not want("documents.analysis"):
            # Run alone, the check still needs the documents' purpose statements, like in a full run.
            _document_findings, purpose_capture = analyze_documents(document_inputs)
            page_signals["document_capture"] = purpose_capture
            raw_capture["document_capture"] = purpose_capture
        s377, n377 = classify_tracking_mechanisms(page_signals, audience)
        if want("site.tracking_mechanisms"):
            findings.append(CheckFinding(criterion="RDS-CUC-377", status=s377, note=n377))
        s4, n4 = classify_advertising(page_signals, audience)
        if want("site.advertising"):
            findings.append(CheckFinding(criterion="RDS-WER-384", status=s4, note=n4))
        s5, n5 = classify_outbound_ad_links(page_signals, audience)
        if want("site.outbound_ad_links"):
            findings.append(CheckFinding(criterion="RDS-WER-385", status=s5, note=n5))
        s6, n6 = classify_youth_protection(page_signals, audience)
        if want("site.youth_protection"):
            findings.append(CheckFinding(criterion="RDS-VIN-354", status=s6, note=n6))
        s453, n453, e453 = classify_cookie_description_completeness(
            page_signals,
            privacy_text=privacy_text_for_cookies,
        )
        raw_capture["rds_cuc_453"] = e453
        if want("site.cookie_descriptions"):
            findings.append(CheckFinding(criterion="RDS-CUC-453", status=s453, note=n453))
    if url and want("site.transport"):
        findings.extend(check_site_transport(url))
    if url and want("site.legal_pages"):
        if raw_capture is None:
            raw_capture = {}
        ipf_analysis = analyze_ipf_site(url)
        raw_capture["ipf"] = {
            "visited_urls": ipf_analysis.visited_urls,
            "impressum_url": ipf_analysis.impressum.url,
            "privacy_url": ipf_analysis.privacy.url,
            "impressum_found": ipf_analysis.impressum.found_signals,
            "impressum_missing": ipf_analysis.impressum.missing_signals,
            "impressum_manual": ipf_analysis.impressum.manual_signals,
            "privacy_found": ipf_analysis.privacy.found_signals,
            "privacy_missing": ipf_analysis.privacy.missing_signals,
            "privacy_manual": ipf_analysis.privacy.manual_signals,
            "privacy_dpo_absent_declared": ipf_analysis.privacy.dpo_absent_declared,
        }
        findings.extend(findings_from_ipf_analysis(ipf_analysis))
    finding_details.tag_site(findings)
    if code_path and want("code.inspection"):
        code_findings, code_capture = inspect_code_path(code_path, audience)
        finding_details.tag(code_findings, "code.inspection")
        if raw_capture is None:
            raw_capture = {}
        raw_capture["code_review"] = code_capture
        by_criterion = {finding.criterion: finding for finding in findings}
        for finding in code_findings:
            by_criterion[finding.criterion] = finding
        findings = list(by_criterion.values())
    if want("documents.analysis") and document_discovery is not None and not document_inputs:
        host = urlparse(url).hostname if url else ""
        note = (
            f"Keine AGB, Datenschutzerklärung oder AVV auf {host} gefunden (Startseite und Rechtsseiten durchsucht); "
            "Dokument-URL mitgeben (agb_url, privacy_url, avv_url) oder manuell prüfen."
        )
        by_criterion = {finding.criterion: finding for finding in findings}
        for code in DOCUMENT_CRITERIA:
            by_criterion.setdefault(
                code,
                CheckFinding(
                    criterion=code,
                    status="MANUELL",
                    note=note,
                    reason="missing_input",
                    check="documents.analysis",
                    review_hint="AGB, Datenschutzerklärung oder AVV per URL mitgeben (agb_url, privacy_url, avv_url) oder manuell prüfen.",
                ),
            )
        findings = list(by_criterion.values())
        document_capture = {"discovery": document_discovery, "documents": [], "skipped": []}
    if document_inputs and want("documents.analysis"):
        document_findings, document_capture = analyze_documents(document_inputs)
        finding_details.tag(document_findings, "documents.analysis")
        if selected is not None and url:
            # With a URL the site check decides these; a second answer from the documents would
            # overwrite it for callers that merge single-check results per criterion.
            document_findings = [f for f in document_findings if f.criterion not in SITE_DECIDES_WITH_DOCUMENTS]
        if document_discovery is not None:
            document_capture["discovery"] = document_discovery
        by_criterion = {finding.criterion: finding for finding in findings}
        for finding in document_findings:
            by_criterion[finding.criterion] = finding
        if raw_capture is not None:
            raw_capture["document_capture"] = document_capture
            page_signals = {
                "cookies": raw_capture.get("cookies") or [],
                "scripts": raw_capture.get("scripts") or [],
                "requests": raw_capture.get("requests") or [],
                "resources": raw_capture.get("resources") or [],
                "browser_signals": raw_capture.get("browser_signals") or {},
                "local_storage": raw_capture.get("local_storage") or {},
                "session_storage": raw_capture.get("session_storage") or {},
                "document_capture": document_capture,
            }
            s453, n453, e453 = classify_cookie_description_completeness(
                page_signals,
                privacy_text=privacy_text_for_cookies,
            )
            raw_capture["rds_cuc_453"] = e453
            if want("site.cookie_descriptions"):
                by_criterion["RDS-CUC-453"] = CheckFinding(criterion="RDS-CUC-453", status=s453, note=n453)
            if want("site.tracking_mechanisms"):
                s377, n377 = classify_tracking_mechanisms(page_signals, audience)
                by_criterion["RDS-CUC-377"] = CheckFinding(criterion="RDS-CUC-377", status=s377, note=n377)
        findings = list(by_criterion.values())
    if agentic:
        if not url:
            raise ValueError("--agentic requires --url")
        task_types = normalize_agent_tasks(agent_tasks)
        if allow_env_credentials:
            username = resolve_secret(agent_username, "VIDIS_AGENT_USERNAME")
            password = resolve_secret(agent_password, "VIDIS_AGENT_PASSWORD")
        else:
            # API callers choose the target site, so the operator's stored login must never be typed into it.
            username, password = agent_username, agent_password
        agent_result = DefaultAgenticRunner().run(
            base_url=url,
            task_types=task_types,
            username=username,
            password=password,
            output_dir=outdir / "agent",
            persona=agent_persona or audience,
            pages=pages,
            vidis_portal=agent_vidis_portal,
            vidis_login_label=agent_vidis_login_label,
            instructions=agent_instructions or [],
        )
        agent_capture = write_agentic_artifacts(agent_result, outdir / "agent", [username, password])
        raw_capture = _merge_agentic_report_capture(raw_capture, agent_capture, outdir / "agent", outdir)
        by_criterion = {finding.criterion: finding for finding in findings}
        for finding in finding_details.tag(_agentic_signal_findings(agent_capture, audience), "agentic.persona_crawl"):
            existing = by_criterion.get(finding.criterion)
            if existing is None or existing.status == "MANUELL":
                by_criterion[finding.criterion] = finding
        for finding in finding_details.tag(_agentic_ipf_findings(agent_capture), "agentic.persona_crawl"):
            existing = by_criterion.get(finding.criterion)
            if existing is None or existing.status in {"MANUELL", "FAIL"}:
                by_criterion[finding.criterion] = finding
        findings = list(by_criterion.values())
    in_scope = set(criteria) if criteria else (criteria_for_checks(selected) if selected is not None else None)
    if in_scope is not None:
        findings = [finding for finding in findings if finding.criterion in in_scope]
    wired = {f.criterion for f in findings}
    for k in crit.items.keys():
        if in_scope is not None and k not in in_scope:
            continue
        if k not in wired:
            inputs = {"site": bool(url), "documents": bool(url or document_inputs), "code": bool(code_path)}
            # A criterion asked for by code always gets an answer; one that only came with a check may be left out.
            if not criteria and selected is not None and finding_details.left_to_other_check(k, inputs=inputs, selected=selected):
                continue
            findings.append(finding_details.placeholder(k, inputs=inputs, selected=selected))
    finding_details.tag_site(findings)
    finding_details.annotate(
        findings,
        raw_capture=raw_capture,
        document_capture=document_capture,
        code_capture=code_capture,
        agent_capture=agent_capture,
    )
    result = JobResult(job_id=cfg.job_id, findings=findings, api_version=API_VERSION)
    raw_capture = _append_ai_model_metadata(raw_capture, ai_model)
    return CheckRun(
        result=result,
        raw_capture=raw_capture,
        code_capture=code_capture,
        document_capture=document_capture,
        agent_capture=agent_capture,
    )


@app.command()
def check(
    url: str = typer.Option(None, "--url"),
    code_path: str = typer.Option(None, "--code-path"),
    output: str = typer.Option("job", "--output"),
    pages: int = typer.Option(8, "--pages"),
    audience: str = typer.Option("beide", "--audience"),
    output_pdf: str | None = typer.Option(None, "--pdf", help="Optionaler Pfad für den PDF-Report."),
    output_md: str | None = typer.Option(None, "--md", help="Optionaler Pfad für den Markdown-Report."),
    documents: list[Path] | None = typer.Option(None, "--document", help="Lokale HTML/PDF/Text-Dokumente für AGB/AVV/Datenschutz-Prüfungen."),
    agb_url: str | None = typer.Option(None, "--agb-url", help="URL zu AGB/Nutzungsbedingungen."),
    privacy_url: str | None = typer.Option(None, "--privacy-url", help="URL zur Datenschutzerklärung."),
    avv_url: str | None = typer.Option(None, "--avv-url", help="URL zum AVV/Auftragsverarbeitungsvertrag."),
    agentic: bool = typer.Option(False, "--agentic", help="Optionalen authentifizierten Agent-/Persona-Crawl aktivieren."),
    agent_tasks: list[str] | None = typer.Option(None, "--agent-task", help="Agent-Task: legal, student, teacher, register oder logout. Wiederholbar."),
    agent_persona: str | None = typer.Option(None, "--agent-persona", help="Persona für Agent-Crawl, z. B. SuS oder Lehrkraefte."),
    agent_username: str | None = typer.Option(None, "--agent-username", envvar="VIDIS_AGENT_USERNAME", help="Login-Benutzername; alternativ VIDIS_AGENT_USERNAME."),
    agent_password: str | None = typer.Option(None, "--agent-password", envvar="VIDIS_AGENT_PASSWORD", help="Login-Passwort; alternativ VIDIS_AGENT_PASSWORD."),
    agent_vidis_portal: str | None = typer.Option(None, "--agent-vidis-portal", envvar="VIDIS_AGENT_VIDIS_PORTAL", help="VIDIS-Landesportal/Schulportal vor Benutzername/Passwort auswählen, z. B. 'Test Landesportal'."),
    agent_vidis_login_label: str | None = typer.Option(None, "--agent-vidis-login-label", envvar="VIDIS_AGENT_VIDIS_LOGIN_LABEL", help="Optionaler Text des VIDIS-/SSO-Login-Buttons, falls er im Testobjekt anders heißt."),
    agent_instructions: list[str] | None = typer.Option(None, "--agent-instruction", help="Natürlichsprachlicher Hinweis für den authentifizierten Agent-Crawl, z. B. 'Gehe auf Assistenten und prüfe die Übersicht'. Wiederholbar."),
    lighthouse: bool = typer.Option(False, "--lighthouse", help="Optional Lighthouse JSON/HTML-Audit als Report-Artefakt erzeugen."),
    webinspector_export: bool = typer.Option(False, "--webinspector-export", help="Optionale WebInspector-artige Network/Console/Storage-JSON-Exporte erzeugen."),
    ai_model: str | None = typer.Option(None, "--ai-model", help="Verwendetes KI-Modell für KI-gestützte Bewertungen, z. B. openai:gpt-4.1-mini."),
    checks: list[str] | None = typer.Option(None, "--check", help="Nur diese Prüfung ausführen, z. B. site.cookies oder site.transport. Wiederholbar; IDs listet `vidis checks`."),
    criteria: list[str] | None = typer.Option(None, "--criterion", help="Nur dieses Kriterium ausgeben, z. B. RDS-IPF-365; die nötigen Prüfungen werden selbst gewählt. Wiederholbar."),
    crawl_max_age: int = typer.Option(1800, "--crawl-max-age", help="Browser-Crawl derselben URL wiederverwenden, wenn jünger als so viele Sekunden; 0 = frisch crawlen."),
):
    """Run unified VIDIS checks (site and/or code)."""
    outdir = Path("results") / output
    try:
        run = run_checks(
            job_id=output,
            outdir=outdir,
            url=url,
            code_path=code_path,
            pages=pages,
            audience=audience,
            documents=documents,
            agb_url=agb_url,
            privacy_url=privacy_url,
            avv_url=avv_url,
            agentic=agentic,
            agent_tasks=agent_tasks,
            agent_persona=agent_persona,
            agent_username=agent_username,
            agent_password=agent_password,
            agent_vidis_portal=agent_vidis_portal,
            agent_vidis_login_label=agent_vidis_login_label,
            agent_instructions=agent_instructions,
            lighthouse=lighthouse,
            webinspector_export=webinspector_export,
            ai_model=ai_model,
            checks=checks,
            criteria=criteria,
            crawl_max_age=crawl_max_age,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    res = run.result
    raw_capture = run.raw_capture
    code_capture = run.code_capture
    document_capture = run.document_capture
    agent_capture = run.agent_capture

    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "result.json").write_text(res.model_dump_json(indent=2), encoding="utf-8")
    if raw_capture is not None:
        (outdir / "capture.json").write_text(json.dumps(raw_capture, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    if code_capture is not None:
        (outdir / "code_capture.json").write_text(json.dumps(code_capture, ensure_ascii=False, indent=2), encoding="utf-8")
    if document_capture is not None:
        (outdir / "document_capture.json").write_text(json.dumps(document_capture, ensure_ascii=False, indent=2), encoding="utf-8")
    if agent_capture is not None:
        (outdir / "agent_capture.json").write_text(json.dumps(agent_capture, ensure_ascii=False, indent=2), encoding="utf-8")
    write_coverage_matrix(
        json_path=outdir / "coverage_matrix.json",
        html_path=outdir / "coverage_matrix.html",
    )
    if output_pdf:
        pdf_path = Path(output_pdf)
        pdf_path.parent.mkdir(parents=True, exist_ok=True)
        generate_pdf(res, pdf_path, raw_capture=raw_capture)
    if output_md:
        md_path = Path(output_md)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        generate_markdown(res, md_path, raw_capture=raw_capture)
    typer.echo(str(outdir / "result.json"))


@app.command("checks")
def list_checks():
    """List the check ids that `vidis check --check` and the API accept."""
    from .catalog import CHECKS

    for item in CHECKS:
        criteria = ", ".join(item.criteria) or "-"
        typer.echo(f"{item.id:<26} {item.name}  [{criteria}]")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", envvar="VIDIS_HOST"),
    port: int = typer.Option(8645, "--port", envvar="VIDIS_PORT"),
    reload: bool = typer.Option(False, "--reload", help="Code bei Änderungen neu laden (nur Entwicklung)."),
):
    """Start FastAPI server."""
    import os

    import uvicorn

    has_keys = any(os.environ.get(name, "").strip() for name in ("VIDIS_API_KEYS", "VIDIS_API_KEY", "API_KEY"))
    if not has_keys and not os.environ.get("VIDIS_AUTH_DISABLED"):
        if host in {"127.0.0.1", "localhost", "::1"}:
            os.environ["VIDIS_AUTH_DISABLED"] = "1"
            typer.echo("Kein VIDIS_API_KEYS gesetzt: API lokal ohne Anmeldung offen.", err=True)
        else:
            raise typer.BadParameter("VIDIS_API_KEYS setzen, bevor die API auf einer öffentlichen Adresse läuft.", param_hint="--host")
    uvicorn.run("vidis_compliance.server:app", host=host, port=port, reload=reload, proxy_headers=True, forwarded_allow_ips=os.environ.get("VIDIS_FORWARDED_ALLOW_IPS", "127.0.0.1"))


if __name__ == "__main__":
    app()
