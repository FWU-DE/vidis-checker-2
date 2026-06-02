from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Literal

from ...models import Status
from .cookies import _is_sus_audience

RDS_CUC_375_NAME = "Informationen auf der Endeinrichtung des Endnutzers"
RDS_CUC_375_TEXT = (
    "Es werden keine sonstigen Informationen auf der Endeinrichtung des Endnutzers gespeichert "
    "und es erfolgt kein Zugriff auf Informationen, die bereits in der Endeinrichtung gespeichert sind, "
    "sofern dafür eine Einwilligung erforderlich ist und sich das Angebot an die Nutzergruppe der "
    "Schülerinnen und Schüler richtet. Richtet sich das Angebot an Lehrkräfte, darf die Einwilligung "
    "eingeholt werden."
)

TRACKING_PURPOSE_TERMS = {
    "analytics": "Analytics/Tracking",
    "matomo": "Analytics/Tracking",
    "piwik": "Analytics/Tracking",
    "google-analytics": "Analytics/Tracking",
    "gtag": "Analytics/Tracking",
    "fingerprint": "Device-Identifier/Fingerprinting",
    "fingerprintjs": "Device-Identifier/Fingerprinting",
    "visitor": "Device-Identifier/Fingerprinting",
    "beacon": "Tracking-Beacon",
    "telemetry": "Telemetry/Tracking",
    "mixpanel": "Analytics/Tracking",
    "segment": "Analytics/Tracking",
    "hotjar": "Analytics/Tracking",
    "clarity": "Analytics/Tracking",
}

TECHNICAL_PURPOSE_TERMS = {
    "app-shell": "Offline-App-Shell",
    "asset-cache": "technischer Asset-Cache",
    "static-cache": "technischer Asset-Cache",
    "offline": "Offline-/PWA-Funktion",
    "csrf": "Sicherheits-/CSRF-Schutz",
    "xsrf": "Sicherheits-/CSRF-Schutz",
    "session": "Sitzungsfunktion",
    "auth": "Authentifizierung/Sitzung",
    "token-store": "Sicherheits-/Token-Store",
    "service-worker": "Service-Worker-App-Shell",
    "serviceworker": "Service-Worker-App-Shell",
}

_ARG_RE = re.compile(r"\((?P<quote>['\"])(?P<name>[^'\"]{1,160})(?P=quote)")

DecisionStatus = Literal["technical", "tracking", "unresolved"]


@dataclass(frozen=True)
class DeviceStorageSignal:
    api: str
    url: str | None = None
    source: str | None = None
    count: int | None = None
    context: str | None = None
    purpose_hint: str | None = None


def classify_device_storage_access(data: dict[str, Any], audience: str) -> tuple[Status, str]:
    """Evaluate RDS-CUC-375 without inventing legal purpose from generic API use."""
    signals = list(device_storage_signals_from_capture(data))
    if not signals:
        return "PASS", "Keine IndexedDB/Cache/Service-Worker-Storage-Zugriffe erkannt"
    return device_storage_decision(signals, audience)


def device_storage_decision(signals: list[DeviceStorageSignal], audience: str) -> tuple[Status, str]:
    tracking = [signal for signal in signals if _classify_signal(signal)[0] == "tracking"]
    unresolved = [signal for signal in signals if _classify_signal(signal)[0] == "unresolved"]
    technical = [signal for signal in signals if _classify_signal(signal)[0] == "technical"]

    if tracking:
        status = "FAIL" if _is_sus_audience(audience) else "MANUELL"
        prefix = "Einwilligungspflichtige Device-/Browser-Storage-Indizien" if status == "FAIL" else "Device-/Browser-Storage-Indizien manuell prüfen"
        return status, _note(prefix, tracking, technical=technical, include_manual_context=status == "MANUELL")

    if unresolved:
        return "MANUELL", _note(
            "Device-/Browser-Storage-APIs ohne sicher automatisierbaren Zweck",
            unresolved,
            technical=technical,
            include_manual_context=True,
        )

    return "PASS", _note("Ausschließlich technisch erforderliche Device-/Browser-Storage-Indizien", technical)


def device_storage_signals_from_capture(data: dict[str, Any]) -> Iterable[DeviceStorageSignal]:
    browser_signals = data.get("browser_signals") or {}
    for item in browser_signals.get("device_storage", []) or []:
        if not isinstance(item, dict):
            continue
        api = str(item.get("api") or "").strip()
        if api:
            yield DeviceStorageSignal(
                api=api,
                url=_optional_str(item.get("url") or data.get("url")),
                count=_optional_int(item.get("count")),
                context=_optional_str(item.get("context") or item.get("name")),
                purpose_hint=_optional_str(item.get("purpose") or item.get("purpose_hint")),
            )


def device_storage_signal_from_code_evidence(api: str, file: str, line: int, value: str) -> DeviceStorageSignal:
    return DeviceStorageSignal(
        api=api,
        source=f"{file}:{line}",
        context=value,
        purpose_hint=_extract_storage_name(value),
    )


def _classify_signal(signal: DeviceStorageSignal) -> tuple[DecisionStatus, str]:
    haystack = " ".join(
        value.lower()
        for value in [signal.api, signal.url, signal.context, signal.purpose_hint]
        if value
    )
    for needle, label in TRACKING_PURPOSE_TERMS.items():
        if needle in haystack:
            return "tracking", label
    for needle, label in TECHNICAL_PURPOSE_TERMS.items():
        if needle in haystack:
            return "technical", label
    return "unresolved", "Zweck nicht automatisiert bestimmbar"


def _note(prefix: str, primary: list[DeviceStorageSignal], *, technical: list[DeviceStorageSignal] | None = None, include_manual_context: bool = False) -> str:
    parts = [f"{prefix}: {_format_signals(primary)}"]
    if technical:
        parts.append("Technisch erforderlich/consent-free eingeordnet: " + _format_signals(technical))
    if include_manual_context:
        parts.append(f"Kriterium RDS-CUC-375 – {RDS_CUC_375_NAME}: {RDS_CUC_375_TEXT}")
        parts.append(
            "Zu klären: Richtet sich der konkrete Nutzungskontext an Schülerinnen und Schüler oder Lehrkräfte? "
            "Welcher fachliche Zweck steht hinter jedem beobachteten API-Zugriff? Wird eine Einwilligung benötigt "
            "und, falls Lehrkräfte Zielgruppe sind, eingeholt?"
        )
    return "; ".join(parts)


def _format_signals(signals: list[DeviceStorageSignal]) -> str:
    values = []
    for signal in signals[:10]:
        status, label = _classify_signal(signal)
        bits = [signal.api]
        if signal.count:
            bits[-1] = f"{bits[-1]} ({signal.count}×)"
        if signal.purpose_hint:
            bits.append(signal.purpose_hint)
        elif signal.context:
            bits.append(signal.context)
        if signal.source:
            bits.append(signal.source)
        if signal.url:
            bits.append(signal.url)
        bits.append(label if status != "unresolved" else "unresolved")
        values.append(" — ".join(bits))
    if len(signals) > 10:
        values.append(f"+{len(signals) - 10} weitere")
    return ", ".join(values) or "—"


def _extract_storage_name(value: str) -> str | None:
    match = _ARG_RE.search(value)
    return match.group("name") if match else None


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _optional_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None
