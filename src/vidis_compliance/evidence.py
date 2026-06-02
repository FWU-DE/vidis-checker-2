from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


def run_lighthouse(url: str, output_dir: Path) -> dict[str, Any]:
    """Run Lighthouse when the CLI is available and return report artifact metadata.

    Missing Lighthouse is non-fatal: the normal VIDIS crawl should still produce
    a report, with a manual hint that the optional audit was unavailable.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "report.json"
    html_path = output_dir / "report.html"
    executable = shutil.which("lighthouse")
    if not executable:
        return {"available": False, "note": "Lighthouse CLI not installed"}
    command = [
        executable,
        url,
        "--quiet",
        "--chrome-flags=--headless=new --no-sandbox",
        "--output=json",
        "--output=html",
        f"--output-path={html_path}",
    ]
    completed = subprocess.run(command, cwd=output_dir, text=True, capture_output=True, timeout=180, check=False)
    if completed.returncode != 0:
        return {
            "available": False,
            "note": "Lighthouse run failed",
            "stderr": completed.stderr[-1200:],
        }
    candidate_json = html_path.with_suffix(".report.json")
    candidate_html = html_path.with_suffix(".report.html")
    if candidate_json.exists():
        candidate_json.replace(json_path)
    if candidate_html.exists():
        candidate_html.replace(html_path)
    if not json_path.exists() and completed.stdout.strip().startswith("{"):
        json_path.write_text(completed.stdout, encoding="utf-8")
    scores: dict[str, float] = {}
    if json_path.exists():
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
            categories = data.get("categories") or {}
            for key, category in categories.items():
                score = category.get("score") if isinstance(category, dict) else None
                if isinstance(score, int | float):
                    scores[str(key)] = float(score)
        except Exception as exc:  # pragma: no cover - defensive for malformed external output
            scores["parse_error"] = 0.0
    return {
        "available": True,
        "json": "lighthouse/report.json" if json_path.exists() else None,
        "html": "lighthouse/report.html" if html_path.exists() else None,
        "scores": scores,
    }


def write_webinspector_exports(raw_capture: dict[str, Any], output_dir: Path) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    network_path = output_dir / "network.json"
    console_path = output_dir / "console.json"
    storage_path = output_dir / "storage.json"
    network_payload = {
        "requests": raw_capture.get("requests") or [],
        "resources": raw_capture.get("resources") or [],
        "scripts": raw_capture.get("scripts") or [],
    }
    console_payload = {
        "browser_signals": raw_capture.get("browser_signals") or {},
    }
    storage_payload = {
        "cookies": raw_capture.get("cookies") or [],
        "local_storage_keys": sorted((raw_capture.get("local_storage") or {}).keys()),
        "session_storage_keys": sorted((raw_capture.get("session_storage") or {}).keys()),
    }
    network_path.write_text(json.dumps(network_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    console_path.write_text(json.dumps(console_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    storage_path.write_text(json.dumps(storage_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "network": "webinspector/network.json",
        "console": "webinspector/console.json",
        "storage": "webinspector/storage.json",
    }
