from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

AD_DOMAIN_SNIPPETS = (
    "doubleclick.net",
    "googlesyndication.com",
    "googletagservices.com",
    "googleadservices.com",
    "adservice.google.",
    "adsystem.com",
    "adnxs.com",
    "criteo.com",
    "taboola.com",
    "outbrain.com",
    "amazon-adsystem.com",
    "facebook.com/tr",
)

AD_PATH_SNIPPETS = (
    "/ads/",
    "/adserver/",
    "/adservice/",
    "/pagead/",
    "/gampad/",
    "adsbygoogle",
)

SPONSORED_LABEL_RE = re.compile(
    r"\b(anzeige|werbung|advertisement|sponsored|gesponsert|affiliate|partnerangebot|sponsor[- ]?angebot)\b",
    re.IGNORECASE,
)

AFFILIATE_QUERY_KEYS = {
    "aff_id",
    "affiliate",
    "affiliate_id",
    "ref",
    "refid",
    "tag",
    "utm_medium",
    "utm_campaign",
}

AGE_GATE_RE = re.compile(
    r"\b(18\+|ab\s*18|mindestens\s*18|volljährig|volljaehrig|alters(?:bestätigung|prüfung)|age\s*gate)\b",
    re.IGNORECASE,
)

YOUTH_RISK_RE = re.compile(
    r"\b(casino|glücksspiel|gluecksspiel|wetten|poker|slots?|adult|porn|sex|gewalt|violence|waffen|drogen)\b",
    re.IGNORECASE,
)

UNSAFE_EMBED_DOMAINS = (
    "youtube.com/embed/",
    "youtu.be/",
    "vimeo.com/",
    "twitch.tv/",
    "tiktok.com/embed",
)


def _strings(data: dict[str, Any], key: str) -> list[str]:
    return [str(value) for value in data.get(key, []) if value]


def _domain(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.netloc or parsed.path.split("/", 1)[0]).lower()


def _url_matches_ad(url: str) -> bool:
    lowered = url.lower()
    return any(snippet in lowered for snippet in AD_DOMAIN_SNIPPETS + AD_PATH_SNIPPETS)


def _resource_label(resource: dict[str, Any]) -> str:
    url = str(resource.get("url") or "")
    selector = str(resource.get("selector") or "").strip()
    kind = str(resource.get("type") or "resource")
    if selector:
        return f"{kind} {selector} -> {url}"
    return f"{kind} -> {url}"


def _text_hits(lines: list[str], pattern: re.Pattern[str], limit: int = 5) -> list[str]:
    hits: list[str] = []
    for line in lines:
        match = pattern.search(line)
        if match:
            snippet = " ".join(line.split())[:180]
            hits.append(snippet)
            if len(hits) >= limit:
                break
    return hits


def classify_advertising(data: dict[str, Any], audience: str) -> tuple[str, str]:
    """RDS-WER-384: detect strong advertising evidence on the site itself."""
    del audience
    hits: list[str] = []
    for url in _strings(data, "scripts") + _strings(data, "requests"):
        if _url_matches_ad(url):
            hits.append(f"Netzwerk/Script {url}")

    for resource in data.get("resources") or []:
        if not isinstance(resource, dict):
            continue
        url = str(resource.get("url") or "")
        if _url_matches_ad(url):
            hits.append(_resource_label(resource))

    label_hits = _text_hits(_strings(data, "visible_text"), SPONSORED_LABEL_RE)
    hits.extend(f"Textlabel '{hit}'" for hit in label_hits)

    if hits:
        evidence = "; ".join(dict.fromkeys(hits))
        return "FAIL", f"RDS-WER-384 Werbesignale erkannt: {evidence}"
    return "PASS", "RDS-WER-384: Keine offensichtlichen Werbenetzwerke, Anzeigen-Widgets oder Sponsoring-Labels erkannt"


def _link_evidence(link: dict[str, Any]) -> tuple[bool, str]:
    url = str(link.get("url") or "")
    text = str(link.get("text") or "")
    selector = str(link.get("selector") or "")
    parsed = urlparse(url)
    query_keys = {key.lower() for key, _value in parse_qsl(parsed.query, keep_blank_values=True)}
    reasons: list[str] = []
    if _url_matches_ad(url):
        reasons.append("Werbe-/Ad-Domain")
    affiliate_keys = sorted(query_keys & AFFILIATE_QUERY_KEYS)
    if affiliate_keys:
        reasons.append("Affiliate/UTM-Parameter " + ",".join(affiliate_keys))
    if SPONSORED_LABEL_RE.search(text):
        reasons.append("Sponsoring-Linktext")
    if not reasons:
        return False, ""
    selector_part = f" {selector}" if selector else ""
    text_part = f" '{' '.join(text.split())[:100]}'" if text else ""
    return True, f"{_domain(url)}{selector_part}{text_part} ({'; '.join(reasons)}; {url})"


def classify_outbound_ad_links(data: dict[str, Any], audience: str) -> tuple[str, str]:
    """RDS-WER-385: outbound ad-like references are conservative MANUELL findings."""
    del audience
    hits: list[str] = []
    for link in data.get("links") or []:
        if not isinstance(link, dict):
            continue
        matched, evidence = _link_evidence(link)
        if matched:
            hits.append(evidence)

    if hits:
        return "MANUELL", "RDS-WER-385 mögliche Verweise auf Werbeinhalte: " + "; ".join(dict.fromkeys(hits))
    return "PASS", "RDS-WER-385: Keine offensichtlichen ausgehenden Werbe-/Affiliate-Links erkannt"


def classify_youth_protection(data: dict[str, Any], audience: str) -> tuple[str, str]:
    """RDS-VIN-354: conservative youth-protection risk signals."""
    del audience
    strong_hits: list[str] = []
    manual_hits: list[str] = []

    url = str(data.get("url") or "")
    if YOUTH_RISK_RE.search(url):
        strong_hits.append(f"URL/Domain {_domain(url)}")

    text_lines = _strings(data, "visible_text")
    strong_hits.extend(f"Alters-/18+-Hinweis '{hit}'" for hit in _text_hits(text_lines, AGE_GATE_RE))
    strong_hits.extend(f"Risikobegriff '{hit}'" for hit in _text_hits(text_lines, YOUTH_RISK_RE))

    for resource in data.get("resources") or []:
        if not isinstance(resource, dict):
            continue
        resource_type = str(resource.get("type") or "").lower()
        resource_url = str(resource.get("url") or "")
        lowered = resource_url.lower()
        if resource_type in {"iframe", "embed", "object"} and any(domain in lowered for domain in UNSAFE_EMBED_DOMAINS):
            manual_hits.append("Eingebetteter Drittinhalt " + _resource_label(resource))
        if YOUTH_RISK_RE.search(resource_url):
            strong_hits.append("Risikodomain/-URL " + _resource_label(resource))

    if strong_hits:
        evidence = "; ".join(dict.fromkeys(strong_hits + manual_hits))
        return "FAIL", f"RDS-VIN-354 Jugendschutz-Risikosignale erkannt: {evidence}"
    if manual_hits:
        return "MANUELL", "RDS-VIN-354 eingebettete Inhalte manuell prüfen: " + "; ".join(dict.fromkeys(manual_hits))
    return "PASS", "RDS-VIN-354: Keine offensichtlichen 18+/Glücksspiel/Gewalt/Adult-Signale oder riskanten Embeds erkannt"
