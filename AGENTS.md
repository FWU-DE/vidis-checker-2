# VIDIS Compliance Project Rules

## Documentation rule

When changing user-facing behavior, CLI flags, API endpoints, output files, report content, criteria coverage, authentication, or automation workflows, update the user manual in `docs/manual.html` in the same change.

Also update `README.md` when command examples, setup steps, or the primary manual link change.

Keep rollout-facing documentation free of local developer paths, internal migration history, and references to predecessor tools. Describe the current VIDIS Compliance platform from the user's point of view.

## Verification

For documentation-affecting changes, run at least:

```bash
python3 - <<'PY'
from html.parser import HTMLParser
from pathlib import Path
html = Path('docs/manual.html').read_text(encoding='utf-8')
class Parser(HTMLParser):
    pass
Parser().feed(html)
assert 'uv run vidis check' in html
assert 'docs/manual.html' in Path('README.md').read_text(encoding='utf-8')
print('manual html smoke ok')
PY
```

For implementation changes, also run the relevant project tests with `uv run pytest -q`.
