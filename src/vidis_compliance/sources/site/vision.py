from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Iterable, TypedDict


class VisionReview(TypedDict):
    label: str
    status: str
    note: str
    criterion_suggestions: list[str]


VisionProvider = Callable[[dict], dict]

MAX_REVIEWED_SCREENSHOTS = 8


def _manual(label: str, note: str) -> VisionReview:
    return {"label": label, "status": "MANUELL", "note": note, "criterion_suggestions": []}


def review_screenshots(
    screenshots: Iterable[dict],
    *,
    provider: VisionProvider | None = None,
    concurrency: int | None = None,
) -> list[VisionReview]:
    """Return deterministic MANUELL reviews unless an explicit provider is supplied.

    Local-only/authenticated screenshots are never sent to the provider. The
    returned notes are intentionally conservative so normal tests and offline
    runs do not depend on an LLM or external vision service. Provider calls
    run in parallel (``VIDIS_LLM_CONCURRENCY``, default 4); the order of the
    reviews follows the screenshots.
    """
    reviews: list[VisionReview | None] = []
    pending: list[tuple[int, str, dict]] = []
    for screenshot in screenshots:
        label = str(screenshot.get("label") or screenshot.get("filename") or "screenshot")
        if provider is None:
            reviews.append(_manual(label, "Vision-Review nicht konfiguriert; Screenshot manuell prüfen."))
        elif screenshot.get("local_only") or screenshot.get("authenticated"):
            reviews.append(_manual(label, "Lokales/authentifiziertes Screenshot-Artefakt nicht an Vision-Provider gesendet; manuell prüfen."))
        elif len(pending) >= MAX_REVIEWED_SCREENSHOTS:
            reviews.append(_manual(label, f"Nur die ersten {MAX_REVIEWED_SCREENSHOTS} Screenshots werden per KI bewertet; manuell prüfen."))
        else:
            pending.append((len(reviews), label, dict(screenshot)))
            reviews.append(None)
    if pending and provider is not None:
        workers = max(1, min(concurrency or _concurrency(), len(pending)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="vidis-vision") as pool:
            results = list(pool.map(lambda item: provider(item[2]), pending))
        for (index, label, _shot), provider_result in zip(pending, results):
            review: VisionReview = {
                "label": label,
                "status": str(provider_result.get("status") or "MANUELL"),
                "note": str(provider_result.get("note") or "Vision-Provider lieferte keinen Hinweis."),
                "criterion_suggestions": [str(item) for item in provider_result.get("criterion_suggestions") or []],
            }
            if provider_result.get("model"):
                review["model"] = str(provider_result["model"])  # type: ignore[typeddict-unknown-key]
            reviews[index] = review
    return [review for review in reviews if review is not None]


def _concurrency() -> int:
    try:
        return max(1, min(int(os.environ.get("VIDIS_LLM_CONCURRENCY", "4")), 8))
    except ValueError:
        return 4


# Criteria a screenshot can give evidence for; the model may only suggest these.
VISION_CRITERIA = {
    "RDS-WER-384": "Werbefreiheit: keine Werbung, Bannerwerbung, gesponserten Inhalte",
    "RDS-WER-385": "Keine Verweise oder Links auf Werbeinhalte/Shops/Affiliate-Angebote",
    "RDS-VIN-354": "Jugendmedienschutz: keine gewaltverherrlichenden, sexualisierten oder sonst jugendgefährdenden Inhalte",
    "RDS-IPF-364": "Impressum leicht auffindbar (sichtbarer Link)",
    "RDS-IPF-366": "Datenschutzerklärung leicht auffindbar (sichtbarer Link)",
    "RDS-CUC-371": "Cookie-Banner, das nicht-essenzielle Cookies voreinstellt oder zur Einwilligung drängt",
}

_PROMPT = """Du prüfst einen Screenshot eines digitalen Bildungsangebots für Schulen gegen VIDIS-Prüfkriterien.
Seite: {url}
Kriterien:
{criteria}

Bewerte nur, was im Screenshot sichtbar ist. Antworte als JSON-Objekt:
{{"status": "PASS" | "FAIL" | "MANUELL",
  "note": "ein bis zwei Sätze auf Deutsch, was sichtbar ist und warum",
  "criterion_suggestions": ["Kriterien-Codes, auf die sich die Beobachtung bezieht"]}}
FAIL nur bei klar sichtbarem Verstoß, PASS nur wenn die betroffenen Kriterien im Bild eindeutig erfüllt sind, sonst MANUELL."""

MAX_SCREENSHOT_BYTES = 5 * 1024 * 1024


def gemini_screenshot_provider() -> VisionProvider | None:
    """Vision provider backed by Gemini on Vertex AI, or ``None`` when not configured."""
    from ...util import llm

    config = llm.load_config()
    if config is None:
        return None
    criteria_text = "\n".join(f"- {code}: {text}" for code, text in VISION_CRITERIA.items())

    def provider(screenshot: dict) -> dict:
        path = Path(str(screenshot.get("path") or ""))
        if not path.is_file() or path.stat().st_size > MAX_SCREENSHOT_BYTES:
            return {"status": "MANUELL", "note": "Screenshot-Datei fehlt oder ist zu groß; manuell prüfen."}
        try:
            data = llm.generate_json(
                _PROMPT.format(url=str(screenshot.get("url") or "unbekannt")[:500], criteria=criteria_text),
                task="screenshot_review",
                image=path.read_bytes(),
                config=config,
            )
        except llm.LlmError as exc:
            return {"status": "MANUELL", "note": f"Vision-Review nicht möglich ({exc}); manuell prüfen."}
        status = str(data.get("status") or "MANUELL").upper()
        if status not in {"PASS", "FAIL", "MANUELL"}:
            status = "MANUELL"
        suggestions = [str(code) for code in data.get("criterion_suggestions") or [] if str(code) in VISION_CRITERIA]
        note = " ".join(str(data.get("note") or "").split())[:600] or "Kein Hinweis vom Modell."
        return {
            "status": status,
            "note": f"{note} (KI-Einschätzung, {data.get('_model', config.model_for('screenshot_review'))})",
            "criterion_suggestions": suggestions,
            "model": data.get("_model"),
        }

    return provider
