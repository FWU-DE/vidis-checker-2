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


def advertising_hits(data: dict[str, Any]) -> list[dict[str, str]]:
    """RDS-WER-384 signals: ad network URLs, ad resources on the page, sponsoring labels in the text."""
    hits: list[dict[str, str]] = []
    for kind, values in (("script", _strings(data, "scripts")), ("request", _strings(data, "requests"))):
        hits.extend({"type": "ad_network", "kind": kind, "url": url} for url in values if _url_matches_ad(url))
    for resource in data.get("resources") or []:
        if isinstance(resource, dict) and _url_matches_ad(str(resource.get("url") or "")):
            hits.append({"type": "ad_resource", "kind": str(resource.get("type") or "resource"),
                         "url": str(resource.get("url") or ""), "selector": str(resource.get("selector") or "")})
    hits.extend({"type": "sponsored_label", "text": hit} for hit in _text_hits(_strings(data, "visible_text"), SPONSORED_LABEL_RE))
    return [{k: v for k, v in hit.items() if v} for hit in hits]


def _advertising_label(hit: dict[str, str]) -> str:
    if hit["type"] == "ad_network":
        return f"Netzwerk/Script {hit['url']}"
    if hit["type"] == "ad_resource":
        return _resource_label({"type": hit.get("kind"), "url": hit.get("url"), "selector": hit.get("selector")})
    return f"Textlabel '{hit['text']}'"


def classify_advertising(data: dict[str, Any], audience: str) -> tuple[str, str]:
    """RDS-WER-384: detect strong advertising evidence on the site itself."""
    del audience
    hits = [_advertising_label(hit) for hit in advertising_hits(data)]
    if hits:
        evidence = "; ".join(dict.fromkeys(hits))
        return "FAIL", f"RDS-WER-384 Werbesignale erkannt: {evidence}"
    return "PASS", "RDS-WER-384: Keine offensichtlichen Werbenetzwerke, Anzeigen-Widgets oder Sponsoring-Labels erkannt"


def _link_reasons(link: dict[str, Any]) -> list[str]:
    url = str(link.get("url") or "")
    text = str(link.get("text") or "")
    query_keys = {key.lower() for key, _value in parse_qsl(urlparse(url).query, keep_blank_values=True)}
    reasons: list[str] = []
    if _url_matches_ad(url):
        reasons.append("Werbe-/Ad-Domain")
    affiliate_keys = sorted(query_keys & AFFILIATE_QUERY_KEYS)
    if affiliate_keys:
        reasons.append("Affiliate/UTM-Parameter " + ",".join(affiliate_keys))
    if SPONSORED_LABEL_RE.search(text):
        reasons.append("Sponsoring-Linktext")
    return reasons


def _link_evidence(link: dict[str, Any]) -> tuple[bool, str]:
    reasons = _link_reasons(link)
    if not reasons:
        return False, ""
    url = str(link.get("url") or "")
    text = str(link.get("text") or "")
    selector = str(link.get("selector") or "")
    selector_part = f" {selector}" if selector else ""
    text_part = f" '{' '.join(text.split())[:100]}'" if text else ""
    return True, f"{_domain(url)}{selector_part}{text_part} ({'; '.join(reasons)}; {url})"


def outbound_ad_link_hits(data: dict[str, Any]) -> list[dict[str, Any]]:
    """RDS-WER-385 signals: links that look like ads or affiliate links, with the reasons."""
    hits: dict[str, dict[str, Any]] = {}
    for link in data.get("links") or []:
        if not isinstance(link, dict):
            continue
        reasons = _link_reasons(link)
        url = str(link.get("url") or "")
        if reasons and url not in hits:
            text = " ".join(str(link.get("text") or "").split())[:100]
            hit = {"url": url, "domain": _domain(url), "text": text, "selector": str(link.get("selector") or ""), "reasons": reasons}
            hits[url] = {k: v for k, v in hit.items() if v}
    return list(hits.values())


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


def youth_protection_hits(data: dict[str, Any]) -> list[dict[str, str]]:
    """RDS-VIN-354 signals; ``severity`` strong leads to FAIL, manual to MANUELL."""
    hits: list[dict[str, str]] = []
    url = str(data.get("url") or "")
    if YOUTH_RISK_RE.search(url):
        hits.append({"type": "risk_domain", "severity": "strong", "value": _domain(url)})
    text_lines = _strings(data, "visible_text")
    hits.extend({"type": "age_gate", "severity": "strong", "value": hit} for hit in _text_hits(text_lines, AGE_GATE_RE))
    hits.extend({"type": "risk_term", "severity": "strong", "value": hit} for hit in _text_hits(text_lines, YOUTH_RISK_RE))
    for resource in data.get("resources") or []:
        if not isinstance(resource, dict):
            continue
        resource_type = str(resource.get("type") or "").lower()
        resource_url = str(resource.get("url") or "")
        lowered = resource_url.lower()
        if resource_type in {"iframe", "embed", "object"} and any(domain in lowered for domain in UNSAFE_EMBED_DOMAINS):
            hits.append({"type": "embed", "severity": "manual", "value": _resource_label(resource), "url": resource_url})
        if YOUTH_RISK_RE.search(resource_url):
            hits.append({"type": "risk_url", "severity": "strong", "value": _resource_label(resource), "url": resource_url})
    return hits


_YOUTH_LABELS = {
    "risk_domain": "URL/Domain {}",
    "age_gate": "Alters-/18+-Hinweis '{}'",
    "risk_term": "Risikobegriff '{}'",
    "embed": "Eingebetteter Drittinhalt {}",
    "risk_url": "Risikodomain/-URL {}",
}


def classify_youth_protection(data: dict[str, Any], audience: str) -> tuple[str, str]:
    """RDS-VIN-354: conservative youth-protection risk signals."""
    del audience
    hits = youth_protection_hits(data)
    strong_hits = [_YOUTH_LABELS[h["type"]].format(h["value"]) for h in hits if h["severity"] == "strong"]
    manual_hits = [_YOUTH_LABELS[h["type"]].format(h["value"]) for h in hits if h["severity"] == "manual"]
    if strong_hits:
        evidence = "; ".join(dict.fromkeys(strong_hits + manual_hits))
        return "FAIL", f"RDS-VIN-354 Jugendschutz-Risikosignale erkannt: {evidence}"
    if manual_hits:
        return "MANUELL", "RDS-VIN-354 eingebettete Inhalte manuell prüfen: " + "; ".join(dict.fromkeys(manual_hits))
    return "PASS", "RDS-VIN-354: Keine offensichtlichen 18+/Glücksspiel/Gewalt/Adult-Signale oder riskanten Embeds erkannt"
