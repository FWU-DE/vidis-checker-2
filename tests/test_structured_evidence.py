"""Findings carry what was found and how it was classified, not only a note."""

from __future__ import annotations

import re
from pathlib import Path

from vidis_compliance import finding_details
from vidis_compliance.catalog import EVIDENCE_KEYS
from vidis_compliance.checks.site.advertising import advertising_hits, outbound_ad_link_hits, youth_protection_hits
from vidis_compliance.checks.site.basic_http import check_site_transport
from vidis_compliance.checks.site.cookies import classify_tracking_pixel, cookie_inventory, tracker_hits
from vidis_compliance.models import CheckFinding
from vidis_compliance.sources.site.crawl import PageCapture, aggregate_captures


def _capture(url: str, cookies: list[dict], consent_click: dict | None = None) -> PageCapture:
    return PageCapture(url=url, cookies=cookies, local_storage={}, session_storage={}, scripts=[], requests=[],
                       consent_click=consent_click)


def _annotated(check: str, criterion: str, raw: dict, **captures) -> CheckFinding:
    finding = CheckFinding(criterion=criterion, status="MANUELL", note="", check=check)
    finding_details.annotate([finding], raw_capture=raw, document_capture=captures.get("documents"),
                             code_capture=captures.get("code"), agent_capture=captures.get("agent"))
    return finding


def test_cookie_inventory_classifies_each_cookie_without_values() -> None:
    raw = {
        "url": "https://www.schule.example/",
        "cookies": [
            {"name": "_ga", "value": "GA1.2.secret", "domain": ".schule.example", "path": "/", "expires": 1893456000,
             "secure": False, "httpOnly": False, "sameSite": "Lax", "first_seen_url": "https://www.schule.example/",
             "before_consent_click": True},
            {"name": "IDE", "value": "secret", "domain": ".doubleclick.net", "path": "/", "expires": -1},
            {"name": "acme_pref", "value": "x", "domain": "app.schule.example", "path": "/"},
        ],
        "local_storage": {"_ga_session": "secret", "acme.widgetState": "1"},
        "session_storage": {"csrf_token": "secret"},
    }

    inventory = cookie_inventory(raw)

    ga = next(c for c in inventory["cookies"] if c["name"] == "_ga")
    assert ga["classification"] == "non_essential" and ga["basis"] == "cookie_database"
    assert ga["category"] == "Analytics" and ga["platform"]
    assert ga["third_party"] is False and ga["session"] is False and ga["expires"].startswith("2030-01-01")
    assert ga["http_only"] is False and ga["same_site"] == "Lax"
    assert ga["first_seen_url"] == "https://www.schule.example/" and ga["before_consent_click"] is True
    ide = next(c for c in inventory["cookies"] if c["name"] == "IDE")
    assert ide["third_party"] is True and ide["session"] is True
    assert next(c for c in inventory["cookies"] if c["name"] == "acme_pref")["classification"] == "unknown"
    assert {i["key"]: i["classification"] for i in inventory["local_storage"]} == {
        "_ga_session": "non_essential", "acme.widgetState": "unknown"}
    assert inventory["session_storage"] == [{"key": "csrf_token", "classification": "essential", "basis": "allowlist"}]
    assert sum(inventory["counts"].values()) == 6
    assert "secret" not in repr(inventory) and "GA1.2" not in repr(inventory)


def test_site_cookies_finding_lists_classified_cookies_storage_and_consent_click() -> None:
    raw = {
        "url": "https://schule.example/",
        "visited_urls": ["https://schule.example/"],
        "cookies": [{"name": "_ga", "value": "v", "domain": ".schule.example", "path": "/"}],
        "local_storage": {"acme.widgetState": "1"},
        "consent_click": {"url": "https://schule.example/", "selector": "button:has-text('Akzeptieren')"},
    }

    evidence = _annotated("site.cookies", "RDS-CUC-371", raw).evidence

    assert evidence["cookies"][0]["name"] == "_ga" and evidence["cookies"][0]["classification"] == "non_essential"
    assert evidence["local_storage"][0]["key"] == "acme.widgetState"
    assert evidence["counts"] == {"essential": 0, "non_essential": 1, "unknown": 1}
    assert evidence["consent_click"]["selector"].startswith("button")
    assert set(evidence) <= set(EVIDENCE_KEYS["site.cookies"])


def test_aggregate_records_first_page_and_whether_a_cookie_came_before_consent() -> None:
    home = "https://schule.example/"
    about = "https://schule.example/about"
    captures = [
        _capture(home, [
            {"name": "sid", "domain": "schule.example", "path": "/", "value": "1", "first_seen_url": home, "before_consent_click": True},
            {"name": "_ga", "domain": ".schule.example", "path": "/", "value": "1", "first_seen_url": home, "before_consent_click": False},
        ], consent_click={"url": home, "selector": "button"}),
        _capture(about, [
            {"name": "sid", "domain": "schule.example", "path": "/", "value": "2", "first_seen_url": about, "before_consent_click": True},
            {"name": "_gid", "domain": ".schule.example", "path": "/", "value": "1", "first_seen_url": about, "before_consent_click": True},
        ]),
    ]

    aggregate = aggregate_captures(captures)

    by_name = {}
    for cookie in aggregate.cookies:
        by_name.setdefault(cookie["name"], cookie)
    assert by_name["sid"]["first_seen_url"] == home and by_name["sid"]["before_consent_click"] is True
    assert by_name["_ga"]["before_consent_click"] is False
    # Set on a later page, after the banner was accepted on the first one.
    assert by_name["_gid"]["first_seen_url"] == about and by_name["_gid"]["before_consent_click"] is False
    assert aggregate.consent_click == {"url": home, "selector": "button"}


def test_tracker_hits_name_the_matched_pattern_case_insensitively() -> None:
    data = {"scripts": ["https://connect.facebook.net/en_US/fbevents.js"],
            "requests": ["https://www.google-analytics.com/analytics.js", "https://schule.example/app.js"]}

    hits = tracker_hits(data)

    assert [(h["kind"], h["pattern"]) for h in hits] == [
        ("script", "connect.facebook.net/en_US/fbevents.js"), ("request", "google-analytics.com/analytics.js")]
    assert classify_tracking_pixel(data, "SuS")[0] == "FAIL"
    evidence = _annotated("site.tracking_pixel", "RDS-CUC-373", {"url": "https://schule.example/", **data}).evidence
    assert [h["host"] for h in evidence["trackers"]] == ["connect.facebook.net", "www.google-analytics.com"]


def test_tracking_mechanisms_evidence_lists_trackers_non_essential_and_fingerprinting() -> None:
    raw = {
        "url": "https://schule.example/",
        "cookies": [{"name": "_ga", "domain": ".schule.example"}],
        "scripts": ["https://static.hotjar.com/c/hotjar.js"],
        "browser_signals": {"fingerprinting": [{"api": "canvas.toDataURL", "count": 3}]},
    }

    evidence = _annotated("site.tracking_mechanisms", "RDS-CUC-377", raw).evidence

    assert evidence["trackers"][0]["pattern"] == "static.hotjar.com"
    assert evidence["non_essential"][0]["type"] == "cookie" and evidence["non_essential"][0]["name"] == "_ga"
    assert evidence["fingerprinting_apis"] == [{"api": "canvas.toDataURL", "count": 3}]


def test_device_storage_evidence_gives_classification_and_purpose() -> None:
    raw = {"url": "https://schule.example/", "browser_signals": {"device_storage": [
        {"api": "indexedDB.open", "count": 2, "context": "matomo-queue"},
        {"api": "caches.open", "count": 1, "context": "app-shell"},
    ]}}

    evidence = _annotated("site.device_storage", "RDS-CUC-375", raw).evidence

    by_api = {item["api"]: item for item in evidence["device_storage"]}
    assert by_api["indexedDB.open"]["classification"] == "tracking" and by_api["indexedDB.open"]["count"] == 2
    assert by_api["caches.open"]["classification"] == "technical" and by_api["caches.open"]["purpose"] == "Offline-App-Shell"


def test_advertising_outbound_links_and_youth_protection_are_structured() -> None:
    data = {
        "url": "https://schule.example/",
        "requests": ["https://securepubads.g.doubleclick.net/gampad/ads"],
        "visible_text": ["Anzeige: Lernspiel"],
        "links": [{"url": "https://shop.example/item?tag=abc", "text": "Jetzt kaufen", "selector": "a.buy"}],
        "resources": [{"type": "iframe", "url": "https://www.youtube.com/embed/x", "selector": "iframe"}],
    }

    assert [h["type"] for h in advertising_hits(data)] == ["ad_network", "sponsored_label"]
    assert outbound_ad_link_hits(data) == [{"url": "https://shop.example/item?tag=abc", "domain": "shop.example",
                                            "text": "Jetzt kaufen", "selector": "a.buy",
                                            "reasons": ["Affiliate/UTM-Parameter tag"]}]
    assert [(h["type"], h["severity"]) for h in youth_protection_hits(data)] == [("embed", "manual")]
    assert _annotated("site.outbound_ad_links", "RDS-WER-385", data).evidence["ad_links"][0]["reasons"]


def test_transport_findings_carry_status_codes_and_tls_results() -> None:
    class Response:
        def __init__(self, status_code, headers=None):
            self.status_code, self.headers = status_code, headers or {}

    responses = {"https": Response(200), "http": Response(301, {"Location": "https://schule.example/?x=1"})}
    findings = check_site_transport(
        "https://schule.example/",
        http_get=lambda url, **_: responses[url.split(":", 1)[0]],
        tls_probe=lambda host, port: {"SSLv3": False, "TLSv1.0": True, "TLSv1.1": False},
    )
    by_code = {f.criterion: f for f in findings}

    assert by_code["ITS-ENC-359"].evidence["https"]["status_code"] == 200
    assert by_code["ITS-ENC-360"].evidence == {
        "http": {"url": "http://schule.example/", "status_code": 301, "location": "https://schule.example/"},
        "redirects_to_https": True,
    }
    assert by_code["ITS-ENC-361"].evidence["obsolete_protocols"]["TLSv1.0"] is True
    # Annotation keeps what the check set and adds the pages.
    finding = by_code["ITS-ENC-360"]
    finding.check = "site.transport"
    finding_details.annotate([finding], raw_capture={"url": "https://schule.example/"}, document_capture=None,
                             code_capture=None, agent_capture=None)
    assert finding.evidence["redirects_to_https"] is True and finding.evidence["pages"] == ["https://schule.example/"]


def test_code_findings_list_the_lines_behind_each_criterion() -> None:
    code = {"files_scanned": 3, "signals": {
        "cookies": [{"file": "src/app.js", "line": 12, "value": "document.cookie = 'x=1'"}],
        "tracking": [{"file": "src/analytics.js", "line": 4, "value": "gtag('config')"}],
    }}

    cookie_finding = _annotated("code.inspection", "RDS-CUC-371", {}, code=code)
    tracking_finding = _annotated("code.inspection", "RDS-CUC-373", {}, code=code)

    assert cookie_finding.evidence["code_hits"] == [{"file": "src/app.js", "line": 12, "value": "document.cookie = 'x=1'"}]
    assert tracking_finding.evidence["code_hits"][0]["file"] == "src/analytics.js"


def test_long_lists_say_how_much_was_cut() -> None:
    raw = {"url": "https://schule.example/", "cookies": [{"name": f"c{i}", "domain": "schule.example"} for i in range(60)]}

    evidence = _annotated("site.cookies", "RDS-CUC-371", raw).evidence

    assert len(evidence["cookies"]) == finding_details.MAX_ITEMS
    assert evidence["truncated"] == {"cookies": 60}


def test_agentic_cookie_findings_carry_the_authenticated_inventory() -> None:
    agent = {"base_url": "https://schule.example/", "visited_urls": ["https://schule.example/app"],
             "cookies": [{"name": "_ga", "domain": ".schule.example", "value_length": 20}]}

    evidence = _annotated("agentic.persona_crawl", "RDS-CUC-371", {}, agent=agent).evidence

    assert evidence["cookies"][0]["classification"] == "non_essential"
    assert "value_length" not in evidence["cookies"][0]


def test_manual_lists_the_evidence_keys_of_every_check() -> None:
    manual = (Path(__file__).resolve().parents[1] / "docs" / "manual.html").read_text(encoding="utf-8")
    for check_id, keys in EVIDENCE_KEYS.items():
        match = re.search(rf'<code>{re.escape(check_id)}</code><br>.*?<td rowspan="\d" class="ev">(.*?)</td>', manual)
        assert match, check_id
        assert re.findall(r"<code>(.*?)</code>", match.group(1)) == list(keys), check_id
