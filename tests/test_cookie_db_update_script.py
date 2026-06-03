from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


EDPB_FIXTURE = {
    "Example": [
        {
            "id": "ga",
            "category": "Analytics",
            "cookie": "_ga",
            "domain": "",
            "description": "Google Analytics cookie",
            "retentionPeriod": "2 years",
            "dataController": "Google",
            "privacyLink": "https://example.test/privacy",
            "wildcardMatch": "1",
        }
    ]
}


def test_update_cookie_db_script_accepts_local_edpb_json_and_preserves_schema(tmp_path: Path) -> None:
    source = tmp_path / "open-cookie-database-edpb.json"
    target = tmp_path / "cookie_db.json"
    source.write_text(json.dumps(EDPB_FIXTURE), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/update_cookie_db.py",
            "--source",
            str(source),
            "--target",
            str(target),
        ],
        check=True,
        text=True,
        capture_output=True,
    )

    updated = json.loads(target.read_text(encoding="utf-8"))
    assert updated["Example"][0]["cookie"] == "_ga"
    assert updated["Example"][0]["category"] == "Analytics"
    assert updated["Example"][0]["wildcardMatch"] == "1"
    assert "Open Cookie Database EDPB" in completed.stdout
    assert "1 cookie entries" in completed.stdout
