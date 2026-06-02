from pathlib import Path

from vidis_compliance.sources.site.crawl import (
    PageCapture,
    _canonical_page_url,
    _capture_page,
    aggregate_captures,
    discover_internal_links,
)


class FakeContext:
    def cookies(self):
        return [
            {"name": "consent", "domain": "example.test", "path": "/", "value": "yes"}
        ]


class FakePage:
    url = "https://example.test/"
    viewport_size = {"width": 1280, "height": 1400}

    def __init__(self):
        self.events = []

    def goto(self, url, wait_until, timeout):
        self.events.append(("goto", url, wait_until, timeout))
        self.url = url

    def wait_for_load_state(self, state, timeout):
        self.events.append(("wait", state, timeout))

    def add_init_script(self, script):
        self.events.append(("init_script", "__vidisSignals" in script))

    def screenshot(self, path, full_page):
        self.events.append(("screenshot", str(path), full_page))
        Path(path).write_bytes(b"fixture-png")

    def evaluate(self, script):
        if "__vidisSignals" in script:
            return {
                "fingerprinting": [
                    {"api": "canvas.toDataURL", "count": 1},
                    {"api": "navigator.hardwareConcurrency", "count": 2},
                ],
                "device_storage": [
                    {"api": "indexedDB.open", "count": 1},
                    {"api": "caches.open", "count": 1},
                ],
            }
        if "localStorage" in script:
            return {"consent_seen": str(("hook",) in self.events)}
        if "sessionStorage" in script:
            return {"session": "value"}
        if "querySelectorAll('a[href]')" in script:
            return [
                {
                    "url": "https://ads.example.test/deal?aff_id=1",
                    "text": "Sponsor Angebot",
                    "selector": "a.sponsor",
                }
            ]
        if "document.body.innerText" in script:
            return ["Anzeige: Lernspiel gesponsert von ExampleCo"]
        return [
            {"type": "script", "url": "https://example.test/app.js", "selector": "script"},
            {"type": "img", "url": "https://example.test/logo.png", "selector": "img"},
        ]


def test_discover_internal_links_keeps_same_origin_absolute_relative_and_sorted_limit():
    html = """
    <a href="/pricing">Pricing</a>
    <a href="https://example.test/about#team">About</a>
    <a href="https://other.test/offsite">Offsite</a>
    <a href="mailto:hello@example.test">Mail</a>
    <a href="javascript:void(0)">JS</a>
    <a href="../docs?b=2&a=1">Docs</a>
    <a href="/pricing">Duplicate</a>
    """

    links = discover_internal_links(
        "https://example.test/app/index.html", html, limit=3
    )

    assert links == [
        "https://example.test/about",
        "https://example.test/docs?b=2&a=1",
        "https://example.test/pricing",
    ]


def test_canonical_page_url_normalizes_homepage_variants_for_crawl_dedupe():
    assert _canonical_page_url("https://www.example.test") == "https://www.example.test/"
    assert _canonical_page_url("https://www.example.test/") == "https://www.example.test/"
    assert _canonical_page_url("https://www.example.test#top") == "https://www.example.test/"
    assert _canonical_page_url("https://www.example.test/index.html") == "https://www.example.test/"
    assert _canonical_page_url("https://www.example.test/index.php?utm_source=foo") == "https://www.example.test/"
    assert _canonical_page_url("https://www.example.test/start?b=2&a=1") == "https://www.example.test/start?a=1&b=2"


def test_aggregate_captures_deduplicates_cookies_storage_scripts_requests_and_screenshots():
    captures = [
        PageCapture(
            url="https://example.test/",
            cookies=[
                {"name": "sid", "domain": "example.test", "path": "/", "value": "1"}
            ],
            local_storage={"analytics": "on"},
            session_storage={"tab": "1"},
            scripts=["https://cdn.test/a.js"],
            requests=["https://example.test/", "https://cdn.test/a.js"],
            browser_signals={
                "fingerprinting": [{"api": "canvas.toDataURL", "count": 1}],
                "device_storage": [{"api": "indexedDB.open", "count": 1}],
            },
            screenshots=[
                {
                    "label": "page-1",
                    "url": "https://example.test/",
                    "filename": "page-1.png",
                    "path": "/tmp/page-1.png",
                    "authenticated": False,
                    "local_only": False,
                }
            ],
        ),
        PageCapture(
            url="https://example.test/about",
            cookies=[
                {"name": "sid", "domain": "example.test", "path": "/", "value": "1"},
                {
                    "name": "pref",
                    "domain": "example.test",
                    "path": "/",
                    "value": "dark",
                },
            ],
            local_storage={"analytics": "on", "theme": "dark"},
            session_storage={"tab": "2"},
            scripts=["https://cdn.test/a.js", "https://cdn.test/b.js"],
            requests=["https://example.test/about", "https://cdn.test/a.js"],
            browser_signals={
                "fingerprinting": [
                    {"api": "canvas.toDataURL", "count": 2},
                    {"api": "WebGLRenderingContext.getParameter", "count": 1},
                ],
                "device_storage": [
                    {"api": "indexedDB.open", "count": 3},
                    {"api": "serviceWorker.register", "count": 1},
                ],
            },
            screenshots=[
                {
                    "label": "page-2",
                    "url": "https://example.test/about",
                    "filename": "page-2.png",
                    "path": "/tmp/page-2.png",
                    "authenticated": True,
                    "local_only": True,
                }
            ],
        ),
        PageCapture(
            url="https://example.test/index.html?utm_source=foo",
            cookies=[],
            local_storage={},
            session_storage={},
            scripts=[],
            requests=["https://example.test/index.html?utm_source=foo"],
            screenshots=[
                {
                    "label": "page-3",
                    "url": "https://example.test/index.html?utm_source=foo",
                    "filename": "page-3.png",
                    "path": "/tmp/page-3.png",
                    "authenticated": False,
                    "local_only": False,
                }
            ],
        ),
    ]

    aggregate = aggregate_captures(captures)

    assert aggregate.url == "https://example.test/"
    assert aggregate.visited_urls == [
        "https://example.test/",
        "https://example.test/about",
    ]
    assert aggregate.cookies == [
        {"name": "pref", "domain": "example.test", "path": "/", "value": "dark"},
        {"name": "sid", "domain": "example.test", "path": "/", "value": "1"},
    ]
    assert aggregate.local_storage == {"analytics": "on", "theme": "dark"}
    assert aggregate.session_storage == {"tab": "2"}
    assert aggregate.scripts == ["https://cdn.test/a.js", "https://cdn.test/b.js"]
    assert aggregate.requests == [
        "https://cdn.test/a.js",
        "https://example.test/",
        "https://example.test/about",
    ]
    assert aggregate.browser_signals == {
        "fingerprinting": [
            {"api": "WebGLRenderingContext.getParameter", "count": 1},
            {"api": "canvas.toDataURL", "count": 3},
        ],
        "device_storage": [
            {"api": "indexedDB.open", "count": 4},
            {"api": "serviceWorker.register", "count": 1},
        ],
    }
    assert aggregate.screenshots == [
        {
            "label": "page-1",
            "url": "https://example.test/",
            "filename": "page-1.png",
            "path": "/tmp/page-1.png",
            "authenticated": False,
            "local_only": False,
        },
        {
            "label": "page-2",
            "url": "https://example.test/about",
            "filename": "page-2.png",
            "path": "/tmp/page-2.png",
            "authenticated": True,
            "local_only": True,
        },
    ]


def test_capture_page_runs_consent_hook_before_collecting_browser_state():
    page = FakePage()

    capture = _capture_page(
        page,
        FakeContext(),
        "https://example.test/",
        requests=["previous", "https://example.test/", "https://example.test/app.js"],
        consent_hook=lambda p: p.events.append(("hook",)),
        request_start=1,
    )

    assert page.events.index(("hook",)) > page.events.index(
        ("goto", "https://example.test/", "load", 30000)
    )
    assert capture.local_storage == {"consent_seen": "True"}
    assert capture.requests == ["https://example.test/", "https://example.test/app.js"]
    assert capture.scripts == ["https://example.test/app.js"]
    assert ("init_script", True) in page.events
    assert capture.browser_signals == {
        "fingerprinting": [
            {"api": "canvas.toDataURL", "count": 1},
            {"api": "navigator.hardwareConcurrency", "count": 2},
        ],
        "device_storage": [
            {"api": "indexedDB.open", "count": 1},
            {"api": "caches.open", "count": 1},
        ],
    }
    assert capture.resources == [
        {"type": "script", "url": "https://example.test/app.js", "selector": "script"},
        {"type": "img", "url": "https://example.test/logo.png", "selector": "img"},
    ]
    assert capture.links == [
        {
            "url": "https://ads.example.test/deal?aff_id=1",
            "text": "Sponsor Angebot",
            "selector": "a.sponsor",
        }
    ]
    assert capture.visible_text == ["Anzeige: Lernspiel gesponsert von ExampleCo"]


def test_capture_page_records_screenshot_metadata_without_embedding_image_bytes(tmp_path: Path):
    page = FakePage()

    capture = _capture_page(
        page,
        FakeContext(),
        "https://example.test/landing?token=secret#frag",
        requests=[],
        screenshot_dir=tmp_path,
        screenshot_index=3,
    )

    assert capture.screenshots == [
        {
            "label": "page-3",
            "url": "https://example.test/landing?token=secret#frag",
            "filename": "page-3.png",
            "path": str(tmp_path / "page-3.png"),
            "authenticated": False,
            "local_only": False,
            "viewport_width": 1280,
            "viewport_height": 1400,
        }
    ]
    assert (tmp_path / "page-3.png").read_bytes() == b"fixture-png"
    assert ("screenshot", str(tmp_path / "page-3.png"), False) in page.events



def test_capture_page_records_tall_viewport_dimensions_for_pdf_screenshots(tmp_path: Path):
    page = FakePage()

    capture = _capture_page(
        page,
        FakeContext(),
        "https://example.test/tall",
        requests=[],
        screenshot_dir=tmp_path,
        screenshot_index=4,
    )

    screenshot = capture.screenshots[0]
    assert screenshot["viewport_width"] == 1280
    assert screenshot["viewport_height"] >= 1200
