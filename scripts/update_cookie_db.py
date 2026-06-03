#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.request import urlopen

from vidis_compliance.checks.site.cookie_db import (
    COOKIE_DATABASE_RAW_URL,
    COOKIE_DATABASE_SOURCE_NAME,
    COOKIE_DATABASE_SOURCE_URL,
)

REQUIRED_FIELDS = {
    "id",
    "category",
    "cookie",
    "domain",
    "description",
    "retentionPeriod",
    "dataController",
    "privacyLink",
    "wildcardMatch",
}

DEFAULT_TARGET = Path("src/vidis_compliance/checks/site/cookie_db.json")


def _read_source(source: str) -> dict:
    if source.startswith(("http://", "https://")):
        with urlopen(source, timeout=30) as response:  # noqa: S310 - trusted operator-provided source
            payload = response.read().decode("utf-8")
    else:
        payload = Path(source).read_text(encoding="utf-8")
    data = json.loads(payload)
    if not isinstance(data, dict):
        raise SystemExit("Cookie database must be a JSON object keyed by service/platform name")
    return data


def _validate_edpb_schema(data: dict) -> int:
    count = 0
    for service, entries in data.items():
        if not isinstance(service, str) or not service.strip():
            raise SystemExit("Cookie database contains an empty/non-string service name")
        if not isinstance(entries, list):
            raise SystemExit(f"Cookie database service {service!r} must contain a list")
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise SystemExit(f"Cookie database entry {service}[{index}] must be an object")
            missing = REQUIRED_FIELDS - set(entry)
            if missing:
                raise SystemExit(f"Cookie database entry {service}[{index}] misses fields: {', '.join(sorted(missing))}")
            if not str(entry.get("cookie") or "").strip():
                raise SystemExit(f"Cookie database entry {service}[{index}] has empty cookie name")
            count += 1
    if count == 0:
        raise SystemExit("Cookie database does not contain any cookie entries")
    return count


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Update VIDIS' bundled Open Cookie Database EDPB copy.",
    )
    parser.add_argument(
        "--source",
        default=COOKIE_DATABASE_RAW_URL,
        help=f"Source JSON URL or local file. Default: {COOKIE_DATABASE_RAW_URL}",
    )
    parser.add_argument(
        "--target",
        type=Path,
        default=DEFAULT_TARGET,
        help=f"Target JSON file. Default: {DEFAULT_TARGET}",
    )
    args = parser.parse_args()

    data = _read_source(args.source)
    count = _validate_edpb_schema(data)
    args.target.parent.mkdir(parents=True, exist_ok=True)
    args.target.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Updated {args.target} from {COOKIE_DATABASE_SOURCE_NAME}: {count} cookie entries")
    print(f"Source: {COOKIE_DATABASE_SOURCE_URL}")


if __name__ == "__main__":
    main()
