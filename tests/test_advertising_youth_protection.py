from __future__ import annotations

from vidis_compliance.checks.site.advertising import (
    classify_advertising,
    classify_outbound_ad_links,
    classify_youth_protection,
)


def test_classify_advertising_finds_ad_network_scripts_iframes_and_sponsored_labels() -> None:
    status, note = classify_advertising(
        {
            "scripts": ["https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"],
            "requests": ["https://securepubads.g.doubleclick.net/tag/js/gpt.js"],
            "resources": [
                {
                    "type": "iframe",
                    "url": "https://adservice.google.com/adsid/integrator.html",
                    "selector": "iframe#ad-slot",
                }
            ],
            "visible_text": ["Unsere Partner", "Anzeige: Lernspiel gesponsert von ExampleCo"],
        },
        "sus",
    )

    assert status == "FAIL"
    assert "RDS-WER-384" in note
    assert "pagead2.googlesyndication.com" in note
    assert "securepubads.g.doubleclick.net" in note
    assert "iframe#ad-slot" in note
    assert "Anzeige" in note


def test_classify_outbound_ad_links_keeps_affiliate_and_sponsored_evidence_manual() -> None:
    status, note = classify_outbound_ad_links(
        {
            "links": [
                {
                    "url": "https://shop.example.test/book?utm_source=school&utm_medium=banner&aff_id=42",
                    "text": "Zum Sponsor-Angebot",
                    "selector": "a.sponsor-link",
                }
            ]
        },
        "sus",
    )

    assert status == "MANUELL"
    assert "RDS-WER-385" in note
    assert "shop.example.test" in note
    assert "aff_id" in note
    assert "a.sponsor-link" in note
    assert "Sponsor-Angebot" in note


def test_classify_youth_protection_flags_age_gate_and_obvious_unsafe_content() -> None:
    status, note = classify_youth_protection(
        {
            "url": "https://casino.example.test/games",
            "resources": [
                {
                    "type": "iframe",
                    "url": "https://www.youtube.com/embed/trailer",
                    "selector": "iframe.video",
                }
            ],
            "visible_text": [
                "Bitte bestätige, dass du mindestens 18 Jahre alt bist.",
                "Casino Bonus und Wetten ab 18",
            ],
        },
        "sus",
    )

    assert status == "FAIL"
    assert "RDS-VIN-354" in note
    assert "casino.example.test" in note
    assert "mindestens 18" in note
    assert "Casino" in note
    assert "iframe.video" in note


def test_classifiers_pass_or_stay_manual_without_strong_evidence() -> None:
    page_signals = {
        "scripts": ["https://cdn.example.test/app.js"],
        "requests": ["https://cdn.example.test/app.js"],
        "resources": [],
        "visible_text": ["Mathematik-Übungen für Klasse 5"],
        "links": [{"url": "https://publisher.example.test/info", "text": "Verlag", "selector": "a"}],
    }

    assert classify_advertising(page_signals, "sus")[0] == "PASS"
    assert classify_outbound_ad_links(page_signals, "sus")[0] == "PASS"
    assert classify_youth_protection(page_signals, "sus")[0] == "PASS"
