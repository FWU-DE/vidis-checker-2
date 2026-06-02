from __future__ import annotations

from pathlib import Path

from PIL import Image as PILImage

from vidis_compliance.sources.site.crawl import SCREENSHOT_VIEWPORT
from vidis_compliance.report import pdf


def test_site_screenshot_viewport_is_wide_and_keeps_pdf_page_aspect() -> None:
    """Captured screenshots should be wide enough for PDF readability.

    A4's usable screenshot slot is roughly 18.3 x 20.8 cm. Capturing close to
    that aspect avoids wasting horizontal pixels after ReportLab scales the
    image into one page.
    """
    assert SCREENSHOT_VIEWPORT["width"] >= 1800
    assert SCREENSHOT_VIEWPORT["height"] >= 2000

    capture_ratio = SCREENSHOT_VIEWPORT["height"] / SCREENSHOT_VIEWPORT["width"]
    pdf_slot_ratio = pdf.screenshot_slot_height_points() / pdf.screenshot_slot_width_points()
    assert abs(capture_ratio - pdf_slot_ratio) <= 0.03


def test_pdf_screenshot_slot_uses_page_width_and_fits_one_a4_page() -> None:
    assert pdf.SCREENSHOT_HORIZONTAL_MARGIN_CM <= 1.2
    assert pdf.screenshot_slot_width_points() > 18.5 * pdf.cm
    assert 20.5 * pdf.cm <= pdf.screenshot_slot_height_points() <= 21.2 * pdf.cm


def test_pdf_scales_screenshot_to_fill_available_width_without_exceeding_height(tmp_path: Path) -> None:
    image_path = tmp_path / "wide-page.png"
    PILImage.new("RGB", (1900, 2100), "white").save(image_path)

    image = pdf._scaled_screenshot_image(image_path)

    assert abs(image.drawWidth - pdf.screenshot_slot_width_points()) < 0.01
    assert image.drawHeight <= pdf.screenshot_slot_height_points()
