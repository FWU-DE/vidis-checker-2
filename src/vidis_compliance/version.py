"""Version of the external contract (SemVer).

One number covers everything external test suites and agents read: the API
(/discovery, /checks, /criteria, openapi.json), job and result JSON, the
callback payload and the capture/evidence keys. It is the package version in
pyproject.toml. MAJOR: a field, endpoint, check or criterion is removed or
renamed, or a value changes its meaning. MINOR: something is added. PATCH: a
check decides more accurately without changing the format. The VIDIS criteria
catalog (V0.2) is versioned separately by VIDIS.
"""

from importlib.metadata import PackageNotFoundError, version as _package_version

try:
    API_VERSION = _package_version("vidis-compliance")
except PackageNotFoundError:  # pragma: no cover - source tree without install
    API_VERSION = "0.0.0"

HEADER = "X-VIDIS-API-Version"
