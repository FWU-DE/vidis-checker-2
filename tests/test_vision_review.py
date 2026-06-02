from pathlib import Path

from vidis_compliance.sources.site.vision import review_screenshots


def test_review_screenshots_returns_manual_fallback_when_no_provider(tmp_path: Path) -> None:
    shot = tmp_path / "page-1.png"
    shot.write_bytes(b"png")
    screenshots = [
        {
            "label": "page-1",
            "url": "https://example.test/",
            "filename": "page-1.png",
            "path": str(shot),
            "authenticated": False,
            "local_only": False,
        }
    ]

    reviews = review_screenshots(screenshots, provider=None)

    assert reviews == [
        {
            "label": "page-1",
            "status": "MANUELL",
            "note": "Vision-Review nicht konfiguriert; Screenshot manuell prüfen.",
            "criterion_suggestions": [],
        }
    ]


def test_review_screenshots_uses_provider_without_sending_local_only_images(tmp_path: Path) -> None:
    public = tmp_path / "public.png"
    private = tmp_path / "private.png"
    public.write_bytes(b"public")
    private.write_bytes(b"private")
    screenshots = [
        {
            "label": "public",
            "url": "https://example.test/",
            "filename": "public.png",
            "path": str(public),
            "authenticated": False,
            "local_only": False,
        },
        {
            "label": "private",
            "url": "https://example.test/account",
            "filename": "private.png",
            "path": str(private),
            "authenticated": True,
            "local_only": True,
        },
    ]
    calls: list[dict] = []

    def provider(screenshot: dict) -> dict:
        calls.append(screenshot)
        return {"status": "MANUELL", "note": f"reviewed {screenshot['label']}", "criterion_suggestions": ["RDS-IPF-364"]}

    reviews = review_screenshots(screenshots, provider=provider)

    assert [call["label"] for call in calls] == ["public"]
    assert reviews == [
        {"label": "public", "status": "MANUELL", "note": "reviewed public", "criterion_suggestions": ["RDS-IPF-364"]},
        {
            "label": "private",
            "status": "MANUELL",
            "note": "Lokales/authentifiziertes Screenshot-Artefakt nicht an Vision-Provider gesendet; manuell prüfen.",
            "criterion_suggestions": [],
        },
    ]
