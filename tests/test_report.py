from __future__ import annotations

from pathlib import Path

from vidis_compliance.models import CheckFinding, JobResult
from vidis_compliance.report.markdown import generate_markdown
from vidis_compliance.report.pdf import generate_pdf


PNG_1X1 = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
    b"\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00"
    b"\x00\x00\x0cIDAT\x08\xd7c\xf8\xff\xff?\x00\x05\xfe\x02"
    b"\xfeA\xe2!\xbc\x00\x00\x00\x00IEND\xaeB`\x82"
)


def test_generate_markdown_includes_criterion_text_evidence_and_raw_capture(tmp_path: Path) -> None:
    result = JobResult(
        job_id="unit",
        findings=[CheckFinding(criterion="RDS-CUC-371", status="FAIL", note="Tracker-Cookies: _ga")],
    )
    raw_capture = {"url": "https://example.test", "cookies": [{"name": "_ga"}]}
    output = tmp_path / "report.md"

    generate_markdown(result, output, raw_capture=raw_capture)

    text = output.read_text(encoding="utf-8")
    assert "# VIDIS Prüfkriterien V0.2" in text
    assert "### RDS-CUC-371: Nicht essenzielle Cookies" in text
    assert "Das MUSS-Kriterium" in text
    assert "| Anzahl Cookies | 1 |" in text
    assert "## Anhang: Rohdaten der Erfassung" in text
    assert '"cookies"' in text


def test_generate_markdown_includes_ipf_evidence_urls(tmp_path: Path) -> None:
    result = JobResult(
        job_id="unit",
        findings=[
            CheckFinding(
                criterion="RDS-IPF-366",
                status="PASS",
                note="Impressum vollständig wirkend: https://example.test/impressum",
            )
        ],
    )
    raw_capture = {
        "url": "https://example.test/",
        "ipf": {
            "visited_urls": ["https://example.test/", "https://example.test/impressum"],
            "impressum_url": "https://example.test/impressum",
            "privacy_url": "https://example.test/datenschutz",
        },
    }
    output = tmp_path / "report.md"

    generate_markdown(result, output, raw_capture=raw_capture)

    text = output.read_text(encoding="utf-8")
    assert "| Impressum-URL | https://example.test/impressum |" in text
    assert "| Besuchte IPF-URLs | https://example.test/, https://example.test/impressum |" in text


def test_generate_markdown_lists_browser_signal_evidence_without_storage_values(tmp_path: Path) -> None:
    result = JobResult(
        job_id="unit",
        findings=[
            CheckFinding(
                criterion="RDS-CUC-375",
                status="MANUELL",
                note="Device-/Browser-Storage-APIs genutzt: indexedDB.open",
            ),
            CheckFinding(
                criterion="RDS-CUC-376",
                status="MANUELL",
                note="Browserfingerprinting-/Entropy-APIs genutzt: canvas.toDataURL",
            ),
        ],
    )
    raw_capture = {
        "browser_signals": {
            "device_storage": [{"api": "indexedDB.open", "count": 1}],
            "fingerprinting": [{"api": "canvas.toDataURL", "count": 2}],
        },
        "local_storage": {"sensitive": "large-secret-value"},
    }
    output = tmp_path / "report.md"

    generate_markdown(result, output, raw_capture=raw_capture)

    text = output.read_text(encoding="utf-8")
    assert "| Device-/Browser-Storage-APIs | indexedDB.open (1×) |" in text
    assert "| Fingerprinting-/Entropy-APIs | canvas.toDataURL (2×) |" in text
    assert "large-secret-value" not in text


def test_generate_markdown_lists_screenshot_evidence_and_vision_manual_notes(tmp_path: Path) -> None:
    result = JobResult(
        job_id="unit",
        findings=[CheckFinding(criterion="RDS-IPF-364", status="MANUELL", note="Visuelle Link-Prominenz prüfen")],
    )
    screenshot = tmp_path / "page-1.png"
    screenshot.write_bytes(b"fixture")
    raw_capture = {
        "screenshots": [
            {
                "label": "page-1",
                "url": "https://example.test/",
                "filename": "page-1.png",
                "path": str(screenshot),
                "authenticated": False,
                "local_only": False,
            }
        ],
        "vision_reviews": [
            {
                "label": "page-1",
                "status": "MANUELL",
                "note": "Vision-Review nicht konfiguriert; Screenshot manuell prüfen.",
                "criterion_suggestions": ["RDS-IPF-364"],
            }
        ],
    }
    output = tmp_path / "report.md"

    generate_markdown(result, output, raw_capture=raw_capture)

    text = output.read_text(encoding="utf-8")
    assert "| Screenshot-Nachweise | [page-1](page-1.png) — https://example.test/ |" in text
    assert "| Vision-Review | page-1: MANUELL — Vision-Review nicht konfiguriert; Screenshot manuell prüfen. |" in text
    assert '"path"' not in text
    assert b"fixture" not in text.encode("utf-8")


def test_generate_pdf_writes_non_empty_report(tmp_path: Path) -> None:
    result = JobResult(
        job_id="unit",
        findings=[CheckFinding(criterion="ITS-ENC-359", status="PASS", note="HTTPS 200")],
    )
    output = tmp_path / "report.pdf"

    generate_pdf(result, output, raw_capture={"url": "https://example.test"})

    assert output.stat().st_size > 1000


def test_generate_pdf_embeds_public_screenshot_and_shortens_noisy_evidence(tmp_path: Path) -> None:
    screenshot = tmp_path / "page-1.png"
    screenshot.write_bytes(PNG_1X1)
    long_tracker_url = "https://stats.example.test/matomo.php?" + "x=" * 500
    result = JobResult(
        job_id="unit",
        findings=[CheckFinding(criterion="RDS-CUC-373", status="FAIL", note=f"Tracker erkannt: {long_tracker_url}")],
    )
    output = tmp_path / "report.pdf"

    generate_pdf(
        result,
        output,
        raw_capture={
            "url": "https://example.test",
            "requests": [long_tracker_url],
            "scripts": ["https://stats.example.test/matomo.js"],
            "screenshots": [
                {
                    "label": "page-1",
                    "url": "https://example.test/",
                    "filename": "page-1.png",
                    "path": str(screenshot),
                    "local_only": False,
                }
            ],
        },
    )

    data = output.read_bytes()
    assert output.stat().st_size > 1000
    assert b"/Image" in data



def test_generate_markdown_lists_cookie_local_and_session_storage_evidence(tmp_path: Path) -> None:
    result = JobResult(
        job_id="unit",
        findings=[
            CheckFinding(
                criterion="RDS-CUC-371",
                status="FAIL",
                note="Nicht essenzielle Speicher: _ga, matomo.id, IDE",
            )
        ],
    )
    raw_capture = {
        "cookies": [{"name": "_ga"}, {"name": "CookieConsent"}],
        "local_storage": {"matomo.id": "secret", "CookieConsentBulkSetting-abc": "1"},
        "session_storage": {"IDE": "secret", "csrf_token": "secret"},
    }
    output = tmp_path / "report.md"

    generate_markdown(result, output, raw_capture=raw_capture)

    text = output.read_text(encoding="utf-8")
    assert "| Cookie-Namen | CookieConsent, _ga |" in text
    assert "| LocalStorage-Schlüssel | CookieConsentBulkSetting-abc, matomo.id |" in text
    assert "| SessionStorage-Schlüssel | IDE, csrf_token |" in text
    assert "secret" not in text



def test_generate_markdown_lists_lighthouse_and_webinspector_artifacts(tmp_path: Path) -> None:
    result = JobResult(
        job_id="unit",
        findings=[CheckFinding(criterion="RDS-CUC-371", status="MANUELL", note="Storage prüfen")],
    )
    raw_capture = {
        "url": "https://example.test",
        "lighthouse": {
            "available": True,
            "json": "lighthouse/report.json",
            "html": "lighthouse/report.html",
            "scores": {"performance": 0.88, "accessibility": 0.96, "best-practices": 0.91, "seo": 0.87},
        },
        "webinspector": {
            "network": "webinspector/network.json",
            "console": "webinspector/console.json",
        },
    }
    output = tmp_path / "report.md"

    generate_markdown(result, output, raw_capture=raw_capture)

    text = output.read_text(encoding="utf-8")
    assert "| Lighthouse | performance 88%, accessibility 96%, best-practices 91%, seo 87% |" in text
    assert "| Lighthouse-Artefakte | [JSON](lighthouse/report.json), [HTML](lighthouse/report.html) |" in text
    assert "| WebInspector-Exporte | [Network](webinspector/network.json), [Console](webinspector/console.json)" in text
