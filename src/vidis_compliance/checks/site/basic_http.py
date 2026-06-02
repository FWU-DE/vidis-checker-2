from __future__ import annotations

import re
import socket
import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

import httpx

from vidis_compliance.models import CheckFinding

USER_AGENT = "vidis-compliance/0.1 (+https://fwu.de)"
OBSOLETE_PROTOCOLS: tuple[tuple[str, ssl.TLSVersion], ...] = (
    ("SSLv3", ssl.TLSVersion.SSLv3),
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
)


@dataclass(frozen=True)
class HttpObservation:
    status_code: int | None
    location: str = ""
    error: str = ""


def _normalize(url: str) -> str:
    normalized = url.strip()
    if not re.match(r"^https?://", normalized, flags=re.I):
        normalized = "https://" + normalized
    return normalized


def _parsed_url(url: str):
    parsed = urlparse(_normalize(url))
    if not parsed.hostname:
        raise ValueError("URL must include a host")
    return parsed


def _path_or_root(path: str) -> str:
    return path or "/"


def _safe_url(url: str) -> str:
    parsed = urlparse(url)
    netloc = parsed.netloc
    path = _path_or_root(parsed.path)
    return urlunparse((parsed.scheme, netloc, path, "", "", ""))


def _origin_url(scheme: str, parsed) -> str:
    host = parsed.hostname or ""
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    return urlunparse((scheme, host, "/", "", "", ""))


def _https_target(parsed) -> str:
    host = parsed.hostname or ""
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    return urlunparse(("https", host, _path_or_root(parsed.path), "", parsed.query, ""))


def _observe_http(url: str, http_get: Callable[..., object]) -> HttpObservation:
    try:
        response = http_get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=10,
            follow_redirects=False,
        )
    except Exception as exc:  # pragma: no cover - exact httpx/socket subclasses vary by platform
        return HttpObservation(status_code=None, error=type(exc).__name__)

    headers = getattr(response, "headers", {}) or {}
    location = ""
    if isinstance(headers, Mapping):
        location = str(headers.get("Location") or headers.get("location") or "")
    return HttpObservation(status_code=int(getattr(response, "status_code")), location=location)


def _is_https_redirect(observation: HttpObservation) -> bool:
    return (
        observation.status_code is not None
        and 300 <= observation.status_code < 400
        and observation.location.lower().startswith("https://")
    )


def _http_note(observation: HttpObservation) -> str:
    if observation.status_code is None:
        return f"HTTP unreachable ({observation.error})"
    location = f" Location={_safe_url(observation.location)}" if observation.location else ""
    return f"HTTP {observation.status_code}{location}"


def _https_note(observation: HttpObservation, url: str) -> str:
    if observation.status_code is None:
        return f"HTTPS unreachable ({observation.error}) at {_safe_url(url)}"
    return f"HTTPS {observation.status_code} at {_safe_url(url)}"


def _probe_obsolete_tls(host: str, port: int = 443, timeout: float = 3.0) -> dict[str, bool]:
    results: dict[str, bool] = {}
    for name, version in OBSOLETE_PROTOCOLS:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = version
            context.maximum_version = version
            with socket.create_connection((host, port), timeout=timeout) as raw_sock:
                with context.wrap_socket(raw_sock, server_hostname=host):
                    results[name] = True
        except Exception:
            results[name] = False
    return results


def _tls_finding(tls_results: Mapping[str, bool]) -> CheckFinding:
    accepted = [name for name, is_accepted in tls_results.items() if is_accepted]
    if accepted:
        return CheckFinding(
            criterion="ITS-ENC-361",
            status="FAIL",
            note="Obsolete protocols accepted: " + ", ".join(f"{name} accepted" for name in accepted),
        )
    checked = ", ".join(tls_results.keys()) or "SSLv3, TLSv1.0, TLSv1.1"
    return CheckFinding(
        criterion="ITS-ENC-361",
        status="PASS",
        note=f"Obsolete protocols rejected: {checked}",
    )


def check_site_transport(
    url: str,
    *,
    http_get: Callable[..., object] = httpx.get,
    tls_probe: Callable[[str, int], Mapping[str, bool]] = _probe_obsolete_tls,
) -> list[CheckFinding]:
    parsed = _parsed_url(url)
    https_url = _https_target(parsed)
    http_url = _origin_url("http", parsed)
    port = parsed.port or 443

    https = _observe_http(https_url, http_get)
    http = _observe_http(http_url, http_get)

    https_ok = https.status_code is not None and 200 <= https.status_code < 400
    redirects = _is_https_redirect(http)
    http_closed = http.status_code is None
    http_forbidden = http.status_code in {401, 403}
    http_serves_content = http.status_code is not None and 200 <= http.status_code < 300

    if https_ok and (redirects or http_closed or http_forbidden):
        https_only = CheckFinding(
            criterion="ITS-ENC-359",
            status="PASS",
            note=f"{_https_note(https, https_url)}; {_http_note(http)}",
        )
    elif http_serves_content:
        https_only = CheckFinding(
            criterion="ITS-ENC-359",
            status="FAIL",
            note=f"HTTP serves content without HTTPS-only enforcement: {_http_note(http)}; {_https_note(https, https_url)}",
        )
    else:
        https_only = CheckFinding(
            criterion="ITS-ENC-359",
            status="FAIL",
            note=f"HTTPS-only reachability not confirmed: {_https_note(https, https_url)}; {_http_note(http)}",
        )

    redirect_status = "PASS" if redirects else "FAIL"
    redirect_note = (
        f"HTTP redirects to HTTPS: {_http_note(http)}"
        if redirects
        else f"HTTP-to-HTTPS redirect missing: {_http_note(http)}"
    )
    redirect = CheckFinding(criterion="ITS-ENC-360", status=redirect_status, note=redirect_note)

    try:
        tls_results = tls_probe(parsed.hostname or "", port)
        tls = _tls_finding(tls_results)
    except Exception as exc:  # pragma: no cover - defensive; mocked in tests
        tls = CheckFinding(
            criterion="ITS-ENC-361",
            status="MANUELL",
            note=f"Obsolete TLS probe inconclusive: {type(exc).__name__}",
        )

    return [https_only, redirect, tls]
