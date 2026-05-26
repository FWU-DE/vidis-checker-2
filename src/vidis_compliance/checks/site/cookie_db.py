from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any, Dict, Literal, Tuple

CookieCategory = Literal["Analytics", "Functional", "Marketing", "Security"]

ESSENTIAL_CATEGORIES = {"Functional", "Security"}
NON_ESSENTIAL_CATEGORIES = {"Analytics", "Marketing"}


@dataclass(frozen=True)
class CookieInfo:
    """Cookie metadata loaded from vidis-checker's cookie_db.json."""

    id: str
    category: str
    cookie: str
    domain: str
    description: str
    retention_period: str
    data_controller: str
    privacy_link: str
    wildcard_match: bool
    platform: str


class CookieDatabase:
    """Lookup adapter for vidis-checker cookie_db.json."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path is not None else None
        self.cookie_db = self.load_cookie_database()

    def load_cookie_database(self) -> Dict[str, CookieInfo]:
        data = self._load_raw_database()
        cookie_db: Dict[str, CookieInfo] = {}

        for service, cookies in data.items():
            if not isinstance(cookies, list):
                continue
            for cookie_data in cookies:
                if not isinstance(cookie_data, dict):
                    continue
                cookie_name = str(cookie_data.get("cookie") or "").strip()
                if not cookie_name:
                    continue
                cookie_db[cookie_name.lower()] = CookieInfo(
                    id=str(cookie_data.get("id") or ""),
                    category=str(cookie_data.get("category") or ""),
                    cookie=cookie_name,
                    domain=str(cookie_data.get("domain") or ""),
                    description=str(cookie_data.get("description") or ""),
                    retention_period=str(cookie_data.get("retentionPeriod") or ""),
                    data_controller=str(cookie_data.get("dataController") or ""),
                    privacy_link=str(cookie_data.get("privacyLink") or ""),
                    wildcard_match=str(cookie_data.get("wildcardMatch") or "") == "1",
                    platform=str(service),
                )

        return cookie_db

    def _load_raw_database(self) -> Dict[str, Any]:
        if self.db_path is not None:
            with self.db_path.open("r", encoding="utf-8") as file:
                return json.load(file)

        resource = resources.files("vidis_compliance.checks.site").joinpath("cookie_db.json")
        with resource.open("r", encoding="utf-8") as file:
            return json.load(file)

    def get_cookie_info(self, cookie_name: str) -> CookieInfo | None:
        normalized = cookie_name.lower()
        exact_match = self.cookie_db.get(normalized)
        if exact_match is not None:
            return exact_match

        wildcard_matches = [
            info
            for prefix, info in self.cookie_db.items()
            if info.wildcard_match and normalized.startswith(prefix)
        ]
        if not wildcard_matches:
            return None
        return max(wildcard_matches, key=lambda info: len(info.cookie))

    def is_cookie_essential(self, cookie_name: str) -> Tuple[bool, CookieInfo] | None:
        cookie_info = self.get_cookie_info(cookie_name)
        if cookie_info is None:
            return None

        if cookie_info.category in ESSENTIAL_CATEGORIES:
            return True, cookie_info
        if cookie_info.category in NON_ESSENTIAL_CATEGORIES:
            return False, cookie_info
        return None


@lru_cache(maxsize=1)
def get_default_cookie_database() -> CookieDatabase:
    return CookieDatabase()
