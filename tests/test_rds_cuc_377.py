from __future__ import annotations

from pathlib import Path

from vidis_compliance.checks.site.cookies import classify_tracking_mechanisms
from vidis_compliance.models import CheckFinding, JobResult
from vidis_compliance.report.markdown import generate_markdown
from vidis_compliance.sources.documents.analyze import analyze_documents


def test_classify_tracking_mechanisms_fails_known_tracker_for_sus_context() -> None:
    status, note = classify_tracking_mechanisms(
        {
            "cookies": [{"name": "_ga_ABC123"}],
            "requests": ["https://www.google-analytics.com/analytics.js"],
            "scripts": ["https://www.googletagmanager.com/gtag/js?id=G-123"],
            "local_storage": {"matomo.id": "visitor"},
            "session_storage": {},
            "browser_signals": {"fingerprinting": []},
        },
        "SuS",
    )

    assert status == "FAIL"
    assert "RDS-CUC-377" in note
    assert "nicht pädagogische Trackingmechanismen" in note
    assert "google-analytics.com" in note
    assert "_ga_ABC123" in note
    assert "matomo.id" in note
    assert "visitor" not in note


def test_classify_tracking_mechanisms_allows_explicit_pedagogical_purpose() -> None:
    status, note = classify_tracking_mechanisms(
        {
            "requests": ["https://learning.example.test/adaptive/progress.gif"],
            "scripts": [],
            "cookies": [{"name": "_ga_course_progress"}],
            "local_storage": {"learning_progress": "redacted"},
            "product_context": "Adaptives Lernsystem: Nutzerverhalten wird ausschließlich zur Lernstandsdiagnose und pädagogischen Anpassung getrackt.",
        },
        "SuS",
    )

    assert status == "PASS"
    assert "pädagogischer Zweck" in note
    assert "Lernstandsdiagnose" in note
    assert "redacted" not in note


def test_classify_tracking_mechanisms_accepts_pedagogical_document_evidence(tmp_path: Path) -> None:
    document = tmp_path / "produktkontext.txt"
    document.write_text(
        "Das Produkt ist ein adaptives Lernsystem. Das Nutzerverhalten wird zur Lernstandsdiagnose "
        "analysiert und das Tracking dient ausschließlich der pädagogischen Anpassung.",
        encoding="utf-8",
    )

    document_findings, document_capture = analyze_documents([document])
    by_code = {finding.criterion: finding for finding in document_findings}
    status, note = classify_tracking_mechanisms(
        {
            "cookies": [{"name": "_ga_course_progress"}],
            "requests": ["https://learning.example.test/adaptive/progress.gif"],
            "document_capture": document_capture,
        },
        "SuS",
    )

    assert by_code["RDS-CUC-377"].status == "PASS"
    assert status == "PASS"
    assert "pädagogischer Zweck" in note
    assert "adaptives Lernsystem" in note


def test_classify_tracking_mechanisms_passes_when_no_tracking_evidence_exists() -> None:
    status, note = classify_tracking_mechanisms(
        {
            "requests": ["https://example.test/app.css"],
            "scripts": ["https://example.test/app.js"],
            "cookies": [{"name": "CookieConsent"}],
            "local_storage": {"csrf_token": "redacted"},
            "session_storage": {},
            "browser_signals": {"fingerprinting": []},
        },
        "SuS",
    )

    assert status == "PASS"
    assert "Keine Trackingmechanismen" in note


def test_classify_tracking_mechanisms_keeps_ambiguous_fingerprinting_manual() -> None:
    status, note = classify_tracking_mechanisms(
        {
            "requests": ["https://example.test/app.js"],
            "scripts": [],
            "cookies": [],
            "local_storage": {},
            "session_storage": {},
            "browser_signals": {"fingerprinting": [{"api": "canvas.toDataURL", "count": 2}]},
        },
        "SuS",
    )

    assert status == "MANUELL"
    assert "RDS-CUC-377" in note
    assert "Trackingmechanismen zu nicht pädagogischen Zwecken" in note
    assert "canvas.toDataURL" in note
    assert "Welche pädagogische Notwendigkeit" in note


def test_rds_cuc_377_manual_report_contains_full_criterion_and_questions(tmp_path: Path) -> None:
    result = JobResult(
        job_id="unit",
        findings=[
            CheckFinding(
                criterion="RDS-CUC-377",
                status="MANUELL",
                note=(
                    "RDS-CUC-377 Trackingmechanismen zu nicht pädagogischen Zwecken: "
                    "Fingerprinting-/Entropy-APIs: canvas.toDataURL. "
                    "Welche pädagogische Notwendigkeit rechtfertigt diese Signale?"
                ),
            )
        ],
    )
    output = tmp_path / "report.md"

    generate_markdown(
        result,
        output,
        raw_capture={"browser_signals": {"fingerprinting": [{"api": "canvas.toDataURL", "count": 2}]}},
    )

    text = output.read_text(encoding="utf-8")
    assert "### RDS-CUC-377: Trackingmechanismen zu nicht pädagogischen Zwecken" in text
    assert "Es werden keine Trackingmechanismen eingesetzt" in text
    assert "Richtet sich das Angebot an Lehrkräfte" in text
    assert "Welche pädagogische Notwendigkeit" in text
    assert "| Fingerprinting-/Entropy-APIs | canvas.toDataURL (2×) |" in text


def _rule_377_status(text: str, tmp_path: Path) -> str:
    document = tmp_path / "datenschutz.txt"
    document.write_text(text, encoding="utf-8")
    findings, _capture = analyze_documents([document])
    return next(f for f in findings if f.criterion == "RDS-CUC-377").status


def test_rds_cuc_377_opt_out_wording_is_no_evidence(tmp_path: Path) -> None:
    # fwu.de, social-media section: says nothing about tracking on the site itself.
    opt_out = "Wenn Sie kein Tracking wünschen, dann loggen Sie sich aus, oder folgen der Anleitung der Plattform."
    assert _rule_377_status(opt_out, tmp_path) == "MANUELL"
    assert _rule_377_status("Auf dieser Website findet kein Tracking statt.", tmp_path) == "PASS"


def _single_check_run(tmp_path: Path, monkeypatch, checks: list[str]):
    from vidis_compliance import cli
    from vidis_compliance.sources.documents import analyze
    from vidis_compliance.sources.site.crawl import PageCapture

    monkeypatch.setattr(
        cli,
        "crawl",
        lambda url, pages=5, headless=True, screenshot_dir=None: PageCapture(
            url=url, cookies=[{"name": "_ga", "domain": "app.example.test"}], local_storage={}, session_storage={}, requests=[], scripts=[], visited_urls=[url]
        ),
    )
    monkeypatch.setattr(
        cli, "discover_document_links", lambda url, wanted=(), **k: {"found": {"privacy": url + "datenschutz"}, "missing": [], "searched": [url], "errors": []}
    )
    purpose = "Adaptives Lernsystem: das Nutzerverhalten wird nur zur Lernstandsdiagnose und für den Lernfortschritt analysiert."
    monkeypatch.setattr(analyze, "fetch_document", lambda d: (purpose.encode(), "text/plain", d.location, d.kind))
    run = cli.run_checks(job_id="j", outdir=tmp_path / "out", url="https://app.example.test/", checks=checks)
    return [f for f in run.result.findings if f.criterion == "RDS-CUC-377"]


def test_rds_cuc_377_site_check_alone_reads_the_purpose_from_the_documents(tmp_path: Path, monkeypatch) -> None:
    [finding] = _single_check_run(tmp_path, monkeypatch, ["site.tracking_mechanisms"])
    assert finding.status == "PASS"
    assert "Lernstandsdiagnose" in finding.note


def test_rds_cuc_377_documents_alone_leave_it_to_the_site_check(tmp_path: Path, monkeypatch) -> None:
    # A second answer from documents.analysis would overwrite the site check for callers merging per criterion.
    assert _single_check_run(tmp_path, monkeypatch, ["documents.analysis"]) == []
