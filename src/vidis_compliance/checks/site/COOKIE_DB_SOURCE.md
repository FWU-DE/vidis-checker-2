# Cookie database source

`src/vidis_compliance/checks/site/cookie_db.json` is a bundled copy of the Open Cookie Database EDPB data:

https://github.com/jkwakman/Open-Cookie-Database/blob/master/open-cookie-database-edpb.json

VIDIS uses this data as deterministic orientation for cookie and browser-storage classification. Functional and Security categories are treated as essential, Analytics and Marketing categories as non-essential. Unknown names remain manual unless VIDIS heuristics or allowlists classify them.

Update the bundled copy with:

```bash
uv run python scripts/update_cookie_db.py
```

For offline/local validation with a downloaded file:

```bash
uv run python scripts/update_cookie_db.py \
  --source /path/to/open-cookie-database-edpb.json \
  --target src/vidis_compliance/checks/site/cookie_db.json
```

After updating, run:

```bash
uv run pytest -q tests/test_cookie_db.py tests/test_report.py
```
