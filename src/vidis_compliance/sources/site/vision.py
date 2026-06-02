from __future__ import annotations

from typing import Callable, Iterable, TypedDict


class VisionReview(TypedDict):
    label: str
    status: str
    note: str
    criterion_suggestions: list[str]


VisionProvider = Callable[[dict], dict]


def review_screenshots(
    screenshots: Iterable[dict],
    *,
    provider: VisionProvider | None = None,
) -> list[VisionReview]:
    """Return deterministic MANUELL reviews unless an explicit provider is supplied.

    Local-only/authenticated screenshots are never sent to the provider. The
    returned notes are intentionally conservative so normal tests and offline
    runs do not depend on an LLM or external vision service.
    """
    reviews: list[VisionReview] = []
    for screenshot in screenshots:
        label = str(screenshot.get("label") or screenshot.get("filename") or "screenshot")
        if provider is None:
            reviews.append(
                {
                    "label": label,
                    "status": "MANUELL",
                    "note": "Vision-Review nicht konfiguriert; Screenshot manuell prüfen.",
                    "criterion_suggestions": [],
                }
            )
            continue
        if screenshot.get("local_only") or screenshot.get("authenticated"):
            reviews.append(
                {
                    "label": label,
                    "status": "MANUELL",
                    "note": "Lokales/authentifiziertes Screenshot-Artefakt nicht an Vision-Provider gesendet; manuell prüfen.",
                    "criterion_suggestions": [],
                }
            )
            continue
        provider_result = provider(dict(screenshot))
        reviews.append(
            {
                "label": label,
                "status": str(provider_result.get("status") or "MANUELL"),
                "note": str(provider_result.get("note") or "Vision-Provider lieferte keinen Hinweis."),
                "criterion_suggestions": [str(item) for item in provider_result.get("criterion_suggestions") or []],
            }
        )
    return reviews
