from __future__ import annotations
import json
from dataclasses import asdict
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
from .checks.site.ipf import analyze_ipf_site, findings_from_ipf_analysis
from .sources.site.crawl import crawl
from .sources.site.vision import review_screenshots
from .sources.agentic import (
    DefaultAgenticRunner,
    normalize_agent_tasks,
    resolve_secret,
    write_agentic_artifacts,
)
from .sources.code.inspect import inspect_code_path
from .sources.documents.analyze import analyze_documents, build_document_inputs, extract_text, fetch_document
from .evidence import run_lighthouse, write_webinspector_exports
from .coverage_matrix import write_coverage_matrix
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


def _ai_model_entry(value: str | None) -> dict[str, Any] | None:
    if not value:
        return None
    provider = "—"
    model = value.strip()
    if ":" in model:
        provider, model = model.split(":", 1)
    return {
        "task": "VIDIS KI-Bewertungen",
        "provider": provider.strip() or "—",
        "model": model.strip() or "nicht angegeben",
        "status": "vom CLI übergeben",
    }


def _append_ai_model_metadata(raw_capture: dict[str, Any] | None, ai_model: str | None) -> dict[str, Any] | None:
    entry = _ai_model_entry(ai_model)
    if entry is None:
        return raw_capture
    if raw_capture is None:
        raw_capture = {}
    raw_capture.setdefault("ai_models", []).append(entry)
    return raw_capture


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
    lighthouse: bool = typer.Option(False, "--lighthouse", help="Optional Lighthouse JSON/HTML-Audit als Report-Artefakt erzeugen."),
    webinspector_export: bool = typer.Option(False, "--webinspector-export", help="Optionale WebInspector-artige Network/Console/Storage-JSON-Exporte erzeugen."),
    ai_model: str | None = typer.Option(None, "--ai-model", help="Verwendetes KI-Modell für KI-gestützte Bewertungen, z. B. openai:gpt-4.1-mini."),
):
    """Run unified VIDIS checks (site and/or code)."""
    crit = load_criteria()
    cfg = JobConfig(job_id=output, target_url=url, code_path=code_path, pages=pages, target_audience=audience)  # noqa: E501

    findings = []
    raw_capture = None
    code_capture = None
    document_capture = None
    agent_capture = None
    document_inputs = build_document_inputs(documents or [], agb_url=agb_url, privacy_url=privacy_url, avv_url=avv_url)
    privacy_text_for_cookies = _extract_privacy_text_for_cookie_descriptions(document_inputs) if document_inputs else ""
    # Browser capture for cookie/storage-related VIDIS criteria.
    if url and not agentic:
        outdir = Path("results") / cfg.job_id
        try:
            cap = crawl(url, pages=pages, headless=True, screenshot_dir=outdir / "screenshots")
        except TypeError as exc:
            if "screenshot_dir" not in str(exc):
                raise
            cap = crawl(url, pages=pages, headless=True)
        raw_capture = asdict(cap)
        raw_capture["vision_reviews"] = review_screenshots(raw_capture.get("screenshots") or [])
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
        findings.append(CheckFinding(criterion="RDS-CUC-371", status=s1, note=n1))
        findings.append(CheckFinding(criterion="RDS-CUC-372", status=s1, note=n1))
        s2, n2 = classify_tracking_pixel(page_signals, audience)
        findings.append(CheckFinding(criterion="RDS-CUC-373", status=s2, note=n2))
        s3, n3 = classify_local_storage(page_signals, audience)
        findings.append(CheckFinding(criterion="RDS-CUC-374", status=s3, note=n3))
        s375, n375 = classify_device_storage_access(page_signals, audience)
        findings.append(CheckFinding(criterion="RDS-CUC-375", status=s375, note=n375))
        s376, n376 = classify_browser_fingerprinting(page_signals, audience)
        findings.append(CheckFinding(criterion="RDS-CUC-376", status=s376, note=n376))
        s377, n377 = classify_tracking_mechanisms(page_signals, audience)
        findings.append(CheckFinding(criterion="RDS-CUC-377", status=s377, note=n377))
        s4, n4 = classify_advertising(page_signals, audience)
        findings.append(CheckFinding(criterion="RDS-WER-384", status=s4, note=n4))
        s5, n5 = classify_outbound_ad_links(page_signals, audience)
        findings.append(CheckFinding(criterion="RDS-WER-385", status=s5, note=n5))
        s6, n6 = classify_youth_protection(page_signals, audience)
        findings.append(CheckFinding(criterion="RDS-VIN-354", status=s6, note=n6))
        s453, n453, e453 = classify_cookie_description_completeness(
            page_signals,
            privacy_text=privacy_text_for_cookies,
        )
        raw_capture["rds_cuc_453"] = e453
        findings.append(CheckFinding(criterion="RDS-CUC-453", status=s453, note=n453))
        findings.extend(check_site_transport(url))
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
    if code_path:
        code_findings, code_capture = inspect_code_path(code_path, audience)
        if raw_capture is None:
            raw_capture = {}
        raw_capture["code_review"] = code_capture
        by_criterion = {finding.criterion: finding for finding in findings}
        for finding in code_findings:
            by_criterion[finding.criterion] = finding
        findings = list(by_criterion.values())
    if document_inputs:
        document_findings, document_capture = analyze_documents(document_inputs)
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
            by_criterion["RDS-CUC-453"] = CheckFinding(criterion="RDS-CUC-453", status=s453, note=n453)
            s377, n377 = classify_tracking_mechanisms(page_signals, audience)
            by_criterion["RDS-CUC-377"] = CheckFinding(criterion="RDS-CUC-377", status=s377, note=n377)
        findings = list(by_criterion.values())
    if agentic:
        if not url:
            raise typer.BadParameter("--agentic requires --url")
        try:
            task_types = normalize_agent_tasks(agent_tasks)
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
        outdir = Path("results") / cfg.job_id
        username = resolve_secret(agent_username, "VIDIS_AGENT_USERNAME")
        password = resolve_secret(agent_password, "VIDIS_AGENT_PASSWORD")
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
        )
        agent_capture = write_agentic_artifacts(agent_result, outdir / "agent", [username, password])
    wired = {f.criterion for f in findings}
    for k in crit.items.keys():
        if k not in wired:
            findings.append(CheckFinding(criterion=k, status="MANUELL", note="Not yet implemented"))
    res = JobResult(job_id=cfg.job_id, findings=findings)
    raw_capture = _append_ai_model_metadata(raw_capture, ai_model)

    outdir = Path("results") / cfg.job_id
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


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8645):
    """Start FastAPI server."""
    import uvicorn

    uvicorn.run("vidis_compliance.server:app", host=host, port=port, reload=True)


if __name__ == "__main__":
    app()
