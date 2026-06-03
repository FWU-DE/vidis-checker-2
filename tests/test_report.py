from __future__ import annotations

from pathlib import Path
import subprocess

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
    assert "# VIDIS Prüfkriterien V0.2 — Automatisierter Vorab-Check" in text
    assert "### RDS-CUC-371: Nicht essenzielle Cookies" in text
    assert "Das MUSS-Kriterium" in text
    assert "| Anzahl Cookies | 1 |" in text
    assert "## Anhang: Rohdaten der Erfassung" in text
    assert '"cookies"' in text


def test_generate_markdown_includes_ipf_evidence_urls_and_semantic_disclaimer(tmp_path: Path) -> None:
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
    assert "## Hinweis zu inhaltlichen Bewertungen" in text
    assert "KI-gestützte erste Einschätzung" in text
    assert "ersetzt keine rechtliche oder datenschutzfachliche Prüfung" in text


def test_generate_pdf_includes_semantic_disclaimer_for_ipf_evaluation(tmp_path: Path) -> None:
    result = JobResult(
        job_id="unit",
        findings=[
            CheckFinding(
                criterion="RDS-IPF-367",
                status="MANUELL",
                note="Datenschutzerklärung enthält unklare Angaben zu Speicherdauer.",
            )
        ],
    )
    output = tmp_path / "report.pdf"

    generate_pdf(result, output, raw_capture={"url": "https://example.test", "ipf": {"privacy_url": "https://example.test/datenschutz"}})

    assert output.stat().st_size > 1000
    extracted = subprocess.run(["pdftotext", str(output), "-"], check=True, text=True, capture_output=True).stdout
    assert "KI-gestuetzte erste Einschaetzung" in extracted
    assert "ersetzt keine rechtliche oder datenschutzfachliche Pruefung" in extracted


def test_generate_markdown_includes_dso_383_ipf_evidence_and_legal_basis(tmp_path: Path) -> None:
    result = JobResult(
        job_id="unit",
        findings=[
            CheckFinding(
                criterion="RDS-DSO-383",
                status="PASS",
                note="Datenschutzbeauftragter-Kontakt gefunden: https://example.test/datenschutz; Herleitung: Art. 13 Abs. 1 lit. b DSGVO",
            )
        ],
    )
    output = tmp_path / "report.md"

    generate_markdown(
        result,
        output,
        raw_capture={
            "url": "https://example.test",
            "ipf": {
                "privacy_url": "https://example.test/datenschutz",
                "privacy_found": ["Datenschutzbeauftragter-Kontakt, falls bestellt (Art. 13 Abs. 1 lit. b DSGVO)"],
                "privacy_missing": [],
            },
        },
    )

    text = output.read_text(encoding="utf-8")
    section = text_section(text, "### RDS-DSO-383:")
    assert "| Datenschutzerklärung-URL | https://example.test/datenschutz |" in section
    assert "| Datenschutzbeauftragter-Signal | Datenschutzbeauftragter-Kontakt, falls bestellt (Art. 13 Abs. 1 lit. b DSGVO) |" in section
    assert "| Gesetzliche Grundlage | Art. 13 Abs. 1 lit. b DSGVO" in section
    assert "https://dejure.org/gesetze/DSGVO/13.html" in section


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


def test_generate_markdown_includes_ai_model_metadata(tmp_path: Path) -> None:
    result = JobResult(
        job_id="unit",
        findings=[CheckFinding(criterion="RDS-IPF-364", status="MANUELL", note="Visuelle Link-Prominenz prüfen")],
    )
    output = tmp_path / "report.md"

    generate_markdown(
        result,
        output,
        raw_capture={
            "ai_models": [
                {"task": "Vision-Review", "provider": "OpenAI", "model": "gpt-4.1-mini", "status": "konfiguriert"},
                {"task": "Semantische Dokumentbewertung", "model": "claude-3-5-sonnet", "status": "optional"},
            ],
            "vision_reviews": [
                {"label": "home", "status": "MANUELL", "note": "Vision prüfen", "criterion_suggestions": ["RDS-IPF-364"]}
            ],
        },
    )

    text = output.read_text(encoding="utf-8")
    assert "## KI-Modell-Transparenz" in text
    assert "| Vision-Review | OpenAI | gpt-4.1-mini | konfiguriert |" in text
    assert "| Semantische Dokumentbewertung | — | claude-3-5-sonnet | optional |" in text


def test_generate_pdf_includes_ai_model_metadata(tmp_path: Path) -> None:
    result = JobResult(
        job_id="unit",
        findings=[CheckFinding(criterion="RDS-IPF-364", status="MANUELL", note="Visuelle Link-Prominenz prüfen")],
    )
    output = tmp_path / "report.pdf"

    generate_pdf(
        result,
        output,
        raw_capture={"ai_models": [{"task": "Vision-Review", "provider": "OpenAI", "model": "gpt-4.1-mini", "status": "konfiguriert"}]},
    )

    text = subprocess.run(["pdftotext", str(output), "-"], check=True, text=True, capture_output=True).stdout
    assert "KI-Modell-Transparenz" in text
    assert "Vision-Review" in text
    assert "OpenAI" in text
    assert "gpt-4.1-mini" in text


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


def test_generate_markdown_groups_https_transport_evidence_once(tmp_path: Path) -> None:
    result = JobResult(
        job_id="transport",
        findings=[
            CheckFinding(criterion="ITS-ENC-359", status="PASS", note="HTTPS 200 at https://example.test/; HTTP 301 Location=https://example.test/"),
            CheckFinding(criterion="ITS-ENC-360", status="PASS", note="HTTP redirects to HTTPS: HTTP 301 Location=https://example.test/"),
            CheckFinding(criterion="ITS-ENC-361", status="PASS", note="Obsolete protocols rejected: SSLv3, TLSv1.0, TLSv1.1"),
        ],
    )
    output = tmp_path / "report.md"

    generate_markdown(result, output, raw_capture={"url": "https://example.test"})

    text = output.read_text(encoding="utf-8")
    assert text.count("## Gemeinsame HTTPS- und TLS-Bewertung") == 1
    shared_section = text.split("## Gemeinsame HTTPS- und TLS-Bewertung", 1)[1].split("## Kriterienbewertung", 1)[0]
    criteria_section = text.split("## Kriterienbewertung", 1)[1]
    assert "| Betroffene Kriterien | ITS-ENC-359, ITS-ENC-360, ITS-ENC-361 |" in shared_section
    assert "| ITS-ENC-359 | PASS — HTTPS 200 at https://example.test/; HTTP 301 Location=https://example.test/ |" in shared_section
    assert "| ITS-ENC-360 | PASS — HTTP redirects to HTTPS: HTTP 301 Location=https://example.test/ |" in shared_section
    assert "| ITS-ENC-361 | PASS — Obsolete protocols rejected: SSLv3, TLSv1.0, TLSv1.1 |" in shared_section
    assert "| HTTPS/TLS-Bewertung | Details siehe gemeinsamen Abschnitt" in text_section(criteria_section, "### ITS-ENC-359:")
    assert "| HTTPS/TLS-Bewertung | Details siehe gemeinsamen Abschnitt" in text_section(criteria_section, "### ITS-ENC-360:")
    assert "| HTTPS/TLS-Bewertung | Details siehe gemeinsamen Abschnitt" in text_section(criteria_section, "### ITS-ENC-361:")
    assert "| ITS-ENC-359 | PASS" not in text_section(criteria_section, "### ITS-ENC-359:")


def test_generate_pdf_groups_https_transport_evidence_once(tmp_path: Path) -> None:
    result = JobResult(
        job_id="transport-pdf",
        findings=[
            CheckFinding(criterion="ITS-ENC-359", status="PASS", note="HTTPS 200 at https://example.test/; HTTP 301 Location=https://example.test/"),
            CheckFinding(criterion="ITS-ENC-360", status="PASS", note="HTTP redirects to HTTPS: HTTP 301 Location=https://example.test/"),
            CheckFinding(criterion="ITS-ENC-361", status="PASS", note="Obsolete protocols rejected: SSLv3, TLSv1.0, TLSv1.1"),
        ],
    )
    output = tmp_path / "report.pdf"

    generate_pdf(result, output, raw_capture={"url": "https://example.test"})

    text = subprocess.run(["pdftotext", str(output), "-"], check=True, text=True, capture_output=True).stdout
    assert text.count("Gemeinsame HTTPS- und TLS-Bewertung") == 1
    assert "Betroffene Kriterien" in text
    assert "ITS-ENC-359, ITS-ENC-360, ITS-ENC-361" in text
    assert "HTTPS 200 at https://example.test/" in text
    assert "Obsolete protocols rejected" in text


def test_generate_pdf_groups_cookie_and_browser_storage_evidence_once(tmp_path: Path) -> None:
    result = JobResult(
        job_id="unit",
        findings=[
            CheckFinding(criterion="RDS-CUC-371", status="MANUELL", note="Speicher prüfen"),
            CheckFinding(criterion="RDS-CUC-374", status="MANUELL", note="Storage prüfen"),
        ],
    )
    output = tmp_path / "report.pdf"

    generate_pdf(
        result,
        output,
        raw_capture={
            "cookies": [{"name": "_ga"}],
            "local_storage": {"matomo.id": "secret"},
            "session_storage": {"csrf_token": "secret"},
        },
    )

    text = subprocess.run(["pdftotext", str(output), "-"], check=True, text=True, capture_output=True).stdout
    assert text.count("Gemeinsame Cookie- und Browser-Storage-Bewertung") == 1
    assert "Betroffene Kriterien" in text
    assert "RDS-CUC-371, RDS-CUC-374" in text
    assert text.count("Cookie: _ga") == 1
    assert text.count("LocalStorage: matomo.id") == 1
    assert text.count("SessionStorage: csrf_token") == 1
    assert "secret" not in text


def test_generate_pdf_uses_thumbnail_grid_for_screenshot_overview(tmp_path: Path) -> None:
    first = tmp_path / "page-1.png"
    second = tmp_path / "page-2.png"
    first.write_bytes(PNG_1X1)
    second.write_bytes(PNG_1X1)
    result = JobResult(
        job_id="screenshot-thumbnails",
        findings=[CheckFinding(criterion="RDS-IPF-364", status="MANUELL", note="Screenshot prüfen")],
    )
    output = tmp_path / "report.pdf"

    generate_pdf(
        result,
        output,
        raw_capture={
            "url": "https://example.test",
            "screenshots": [
                {
                    "label": "Startseite",
                    "url": "https://example.test/",
                    "filename": "page-1.png",
                    "path": str(first),
                    "local_only": False,
                },
                {
                    "label": "Datenschutz",
                    "url": "https://example.test/datenschutz",
                    "filename": "page-2.png",
                    "path": str(second),
                    "local_only": False,
                },
                {
                    "label": "Login intern",
                    "url": "https://example.test/app",
                    "filename": "auth.png",
                    "path": str(second),
                    "local_only": True,
                },
            ],
        },
    )

    text = subprocess.run(["pdftotext", str(output), "-"], check=True, text=True, capture_output=True).stdout
    assert "Screenshot-Thumbnail-Übersicht" in text
    assert "Miniaturansichten der öffentlichen Screenshot-Nachweise" in text
    thumbnail_section = text.split("Screenshot-Thumbnail-Übersicht", 1)[1].split("Kriterienbewertung", 1)[0]
    assert "Startseite" in thumbnail_section
    assert "Datenschutz" in thumbnail_section
    assert "Login intern" not in thumbnail_section
    assert output.read_bytes().count(b"/Image") >= 3


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



def test_generate_markdown_lists_rds_cuc_453_description_matches_and_misses(tmp_path: Path) -> None:
    result = JobResult(
        job_id="unit",
        findings=[
            CheckFinding(
                criterion="RDS-CUC-453",
                status="FAIL",
                note="Fehlende Beschreibung: LocalStorage: matomo.id; Beschrieben: Cookie: CookieConsent",
            )
        ],
    )
    raw_capture = {
        "cookies": [{"name": "CookieConsent"}],
        "local_storage": {"matomo.id": "secret"},
        "rds_cuc_453": {
            "observed": ["Cookie: CookieConsent", "LocalStorage: matomo.id"],
            "present": ["Cookie: CookieConsent"],
            "missing": ["LocalStorage: matomo.id"],
        },
    }
    output = tmp_path / "report.md"

    generate_markdown(result, output, raw_capture=raw_capture)

    text = output.read_text(encoding="utf-8")
    assert "| RDS-CUC-453 Inventar | Cookie: CookieConsent, LocalStorage: matomo.id |" in text
    assert "| Beschriebene Cookies/Speicher | Cookie: CookieConsent |" in text
    assert "| Fehlende Beschreibungen | LocalStorage: matomo.id |" in text
    assert "secret" not in text


def test_generate_markdown_groups_cookie_local_and_session_storage_evidence_once(tmp_path: Path) -> None:
    result = JobResult(
        job_id="unit",
        findings=[
            CheckFinding(
                criterion="RDS-CUC-371",
                status="FAIL",
                note="Nicht essenzielle Speicher: _ga, matomo.id, IDE",
            ),
            CheckFinding(
                criterion="RDS-CUC-372",
                status="FAIL",
                note="Nicht essenzielle Speicher: _ga, matomo.id, IDE",
            ),
            CheckFinding(
                criterion="RDS-CUC-374",
                status="MANUELL",
                note="Unbekannter Browser-Storage: matomo.id",
            ),
        ],
    )
    raw_capture = {
        "cookies": [
            {"name": "_ga", "domain": ".example.test", "path": "/"},
            {"name": "CookieConsent", "domain": "example.test", "path": "/"},
            {"name": "unknown_cookie", "domain": "example.test", "path": "/"},
        ],
        "local_storage": {"matomo.id": "secret", "CookieConsentBulkSetting-abc": "1"},
        "session_storage": {"IDE": "secret", "csrf_token": "secret"},
    }
    output = tmp_path / "report.md"

    generate_markdown(result, output, raw_capture=raw_capture)

    text = output.read_text(encoding="utf-8")
    assert text.count("## Gemeinsame Cookie- und Browser-Storage-Bewertung") == 1
    shared_section = text.split("## Gemeinsame Cookie- und Browser-Storage-Bewertung", 1)[1].split("## Kriterienbewertung", 1)[0]
    criteria_section = text.split("## Kriterienbewertung", 1)[1]
    assert "| Cookie-Datenbank | Open Cookie Database EDPB" in shared_section
    assert "https://github.com/jkwakman/Open-Cookie-Database/blob/master/open-cookie-database-edpb.json" in shared_section
    assert "| Betroffene Kriterien | RDS-CUC-371, RDS-CUC-372, RDS-CUC-374 |" in shared_section
    assert "| Cookie: _ga | nicht essenziell — Google Analytics / Analytics" in shared_section
    assert "| Cookie: CookieConsent | essenziell — Cookiebot / Functional" in shared_section
    assert "| Cookie: unknown_cookie | manuell prüfen — Keine Einstufung in Open Cookie Database EDPB/Heuristik" in shared_section
    assert "| LocalStorage: matomo.id | nicht essenziell — Heuristik: Tracking-/Analyse-Storage" in shared_section
    assert "| LocalStorage: CookieConsentBulkSetting-abc | essenziell — Cookiebot / Functional" in shared_section
    assert "| SessionStorage: IDE | nicht essenziell — DoubleClick/Google Marketing / Marketing" in shared_section
    assert "| SessionStorage: csrf_token | essenziell — Allowlist-Präfix" in shared_section
    assert "secret" not in text
    assert "| Cookie: _ga |" not in text_section(criteria_section, "### RDS-CUC-371:")
    assert "| LocalStorage: matomo.id |" not in text_section(criteria_section, "### RDS-CUC-374:")



def test_generate_markdown_includes_provider_code_review_overview_without_audit_language(tmp_path: Path) -> None:
    result = JobResult(
        job_id="code-review",
        findings=[
            CheckFinding(criterion="RDS-CUC-373", status="FAIL", note="Tracking-/Analytics-SDKs im Quellcode: src/App.tsx:12 Google Analytics"),
            CheckFinding(criterion="RDS-CUC-374", status="MANUELL", note="localStorage/sessionStorage-Nutzung im Quellcode: src/storage.ts:7 localStorage.setItem('token', value)"),
        ],
    )
    raw_capture = {
        "code_review": {
            "root_label": "anbieter-code",
            "files_scanned": 42,
            "signals": {
                "tracking": [{"file": "src/App.tsx", "line": 12, "value": "Google Analytics"}],
                "storage": [{"file": "src/storage.ts", "line": 7, "value": "localStorage.setItem('token', value)"}],
                "cookies": [{"file": "src/cookies.ts", "line": 3, "value": "document.cookie = 'x=y'"}],
                "external_scripts": [{"file": "src/index.html", "line": 9, "value": "https://cdn.example/script.js"}],
                "fingerprinting": [],
                "fingerprinting_libraries": [],
                "device_storage": [],
                "privacy_links": [],
                "impressum_links": [],
            },
        }
    }
    output = tmp_path / "report.md"

    generate_markdown(result, output, raw_capture=raw_capture)

    text = output.read_text(encoding="utf-8")
    assert "## Code-Durchsicht für Anbieter" in text
    section = text.split("## Code-Durchsicht für Anbieter", 1)[1].split("## Kriterienbewertung", 1)[0]
    assert "unterstützt Anbieter bei der Selbstprüfung" in section
    assert "kein Audit" in section
    assert "keine Zertifizierung" in section
    assert "Security Audit" not in section
    assert "| Gescannte Dateien | 42 |" in section
    assert "| Tracking-/Analytics-Signale | 1 |" in section
    assert "| Cookie-Schreibzugriffe | 1 |" in section
    assert "| Browser-Storage-Signale | 1 |" in section
    assert "| Externe Script-Quellen | 1 |" in section
    assert "| Auffällige Beispiele | tracking: src/App.tsx:12 Google Analytics" in section
    assert "| Code-Durchsicht | Quellcode-Signale siehe Abschnitt" in text_section(text, "### RDS-CUC-373:")


def test_generate_pdf_includes_provider_code_review_overview(tmp_path: Path) -> None:
    result = JobResult(
        job_id="code-review-pdf",
        findings=[CheckFinding(criterion="RDS-CUC-376", status="MANUELL", note="Browserfingerprinting-Signale im Quellcode")],
    )
    output = tmp_path / "report.pdf"

    generate_pdf(
        result,
        output,
        raw_capture={
            "code_review": {
                "root_label": "anbieter-code",
                "files_scanned": 3,
                "signals": {
                    "fingerprinting": [{"file": "src/fp.ts", "line": 4, "value": "canvas.toDataURL"}],
                    "tracking": [],
                    "storage": [],
                    "cookies": [],
                    "external_scripts": [],
                    "device_storage": [],
                    "fingerprinting_libraries": [],
                    "privacy_links": [],
                    "impressum_links": [],
                },
            }
        },
    )

    text = subprocess.run(["pdftotext", str(output), "-"], check=True, text=True, capture_output=True).stdout
    assert "Code-Durchsicht fuer Anbieter" in text
    assert "unterstuetzt Anbieter bei der Selbstpruefung" in text
    assert "kein Audit" in text
    assert "keine Zertifizierung" in text
    assert "Gescannte Dateien" in text
    assert "Fingerprinting-Signale" in text


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



def test_generate_markdown_includes_criteria_missing_from_result_as_untested(tmp_path: Path) -> None:
    result = JobResult(
        job_id="partial",
        findings=[CheckFinding(criterion="RDS-CUC-371", status="PASS", note="Only one criterion was executed")],
    )
    output = tmp_path / "report.md"

    generate_markdown(result, output, raw_capture={"url": "https://example.test"})

    text = output.read_text(encoding="utf-8")
    assert "### RDS-CUC-371: Nicht essenzielle Cookies" in text
    assert "### ITS-ENC-359: Website nur über https:// aufrufbar" in text
    assert "### RDS-AGB-368:" in text
    assert "als manuell zu prüfen bewertet" in text
    assert "Dieses Prüfkriterium wurde im Lauf nicht automatisiert getestet." in text
    assert "Seiten des Angebots sind ausschließlich über https abrufbar." in text


def test_generic_not_yet_implemented_finding_is_normalized_and_shows_full_manual_context(tmp_path: Path) -> None:
    result = JobResult(
        job_id="fallback",
        findings=[CheckFinding(criterion="RDS-CUC-375", status="MANUELL", note="Not yet implemented")],
    )
    output = tmp_path / "report.md"

    generate_markdown(result, output)

    text = output.read_text(encoding="utf-8")
    assert "Not yet implemented" not in text
    assert "### RDS-CUC-375: Informationen auf der Endeinrichtung des Endnutzers" in text
    assert "- Bereich: RDS" in text
    assert "- Verbindlichkeit: MUSS" in text
    assert "Es werden keine sonstigen Informationen auf der Endeinrichtung des Endnutzers gespeichert" in text
    assert "Dieses Prüfkriterium wurde im Lauf nicht automatisiert getestet." in text


def test_pass_fail_markdown_does_not_print_full_criterion_text(tmp_path: Path) -> None:
    result = JobResult(
        job_id="concise",
        findings=[CheckFinding(criterion="RDS-CUC-375", status="PASS", note="Keine auffälligen Browser-Storage-APIs")],
    )
    output = tmp_path / "report.md"

    generate_markdown(result, output)

    rds_cuc_375_section = text_section(output.read_text(encoding="utf-8"), "### RDS-CUC-375:")
    assert "Keine auffälligen Browser-Storage-APIs" in rds_cuc_375_section
    assert "Es werden keine sonstigen Informationen auf der Endeinrichtung" not in rds_cuc_375_section


def test_generate_markdown_explains_every_status_for_beginners_with_next_steps(tmp_path: Path) -> None:
    result = JobResult(
        job_id="beginner",
        findings=[
            CheckFinding(criterion="ITS-ENC-359", status="PASS", note="HTTPS erreichbar"),
            CheckFinding(criterion="RDS-IPF-366", status="FAIL", note="Impressum unvollständig: https://example.test/impressum; gefunden: Kontaktangaben inkl. E-Mail (§ 5 Abs. 1 S. 2 DDG); fehlend: Registerangaben (§ 5 Abs. 1 S. 4 DDG), Steuer-ID/Wirtschafts-ID (§ 5 Abs. 1 S. 6 DDG)"),
            CheckFinding(criterion="RDS-CUC-374", status="MANUELL", note="Unbekannter Browser-Storage: app_state"),
        ],
    )
    output = tmp_path / "report.md"

    generate_markdown(result, output, raw_capture={"url": "https://example.test", "ipf": {"impressum_url": "https://example.test/impressum"}})

    text = output.read_text(encoding="utf-8")
    pass_section = text_section(text, "### ITS-ENC-359:")
    fail_section = text_section(text, "### RDS-IPF-366:")
    manual_section = text_section(text, "### RDS-CUC-374:")
    for section in (pass_section, fail_section, manual_section):
        assert "Was bedeutet das?" in section
        assert "Warum ist das relevant?" in section
        assert "Nächste Schritte" in section
    assert "Dieses Kriterium wirkt aktuell erfüllt" in pass_section
    assert "Für Anfänger: Ein Impressum ist die gesetzliche Anbieterkennzeichnung" in fail_section
    assert "Registerangaben" in fail_section
    assert "Steuer-ID/Wirtschafts-ID" in fail_section
    assert "Prüfe die genannten fehlenden Punkte" in fail_section
    assert "Hier ist eine fachliche oder technische Klärung nötig" in manual_section


def test_generate_pdf_contains_beginner_next_steps_for_failed_imprint(tmp_path: Path) -> None:
    result = JobResult(
        job_id="beginner-pdf",
        findings=[
            CheckFinding(
                criterion="RDS-IPF-366",
                status="FAIL",
                note="Impressum unvollständig: https://example.test/impressum; gefunden: Kontaktangaben inkl. E-Mail (§ 5 Abs. 1 S. 2 DDG); fehlend: Registerangaben (§ 5 Abs. 1 S. 4 DDG)",
            )
        ],
    )
    output = tmp_path / "report.pdf"

    generate_pdf(result, output, raw_capture={"url": "https://example.test", "ipf": {"impressum_url": "https://example.test/impressum"}})

    text = subprocess.run(["pdftotext", str(output), "-"], check=True, text=True, capture_output=True).stdout
    assert "Was bedeutet das?" in text
    assert "Warum ist das relevant?" in text
    assert "Naechste Schritte" in text
    assert "Fuer Anfaenger: Ein Impressum ist die gesetzliche Anbieterkennzeichnung" in text
    assert "Registerangaben" in text


def test_active_registry_criteria_have_non_empty_descriptions() -> None:
    from vidis_compliance.report.data import load_criteria

    criteria = load_criteria()

    assert len(criteria.items) == 26
    assert [code for code, criterion in criteria.items.items() if not criterion.description.strip()] == []


def test_generate_pdf_contains_full_manual_criterion_text(tmp_path: Path) -> None:
    import subprocess

    result = JobResult(
        job_id="pdf-manual",
        findings=[CheckFinding(criterion="RDS-CUC-376", status="MANUELL", note="Not yet implemented")],
    )
    output = tmp_path / "report.pdf"

    generate_pdf(result, output)

    text = subprocess.run(
        ["pdftotext", str(output), "-"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "RDS-CUC-376: Browserfingerprints" in text
    assert "Es werden keine Browserfingerprints gebildet" in text
    assert "Dieses Prüfkriterium wurde im Lauf nicht automatisiert getestet." in text



def test_generate_pdf_contains_coverage_matrix_appendix(tmp_path: Path) -> None:
    import subprocess

    result = JobResult(
        job_id="coverage-pdf",
        findings=[CheckFinding(criterion="ITS-ENC-359", status="PASS", note="HTTPS 200")],
    )
    output = tmp_path / "report.pdf"

    generate_pdf(result, output, raw_capture={"url": "https://example.test"})

    text = subprocess.run(
        ["pdftotext", str(output), "-"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "Anhang: Coverage Matrix" in text
    assert "RDS-CUC-371" in text
    assert "PLATFORM-AUTH-PERSONA-CRAWL" in text
    assert "Implementation status" in text


def text_section(text: str, heading_prefix: str) -> str:
    start = text.index(heading_prefix)
    next_heading = text.find("\n### ", start + 1)
    return text[start:] if next_heading == -1 else text[start:next_heading]


def test_pdf_uses_tall_screenshot_page_slot() -> None:
    import vidis_compliance.report.pdf as pdf

    assert pdf.SCREENSHOT_MAX_HEIGHT_CM >= 20.0
