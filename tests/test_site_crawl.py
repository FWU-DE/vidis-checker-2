from vidis_compliance.sources.site.crawl import (
    PageCapture,
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

    def __init__(self):
        self.events = []

    def goto(self, url, wait_until, timeout):
        self.events.append(("goto", url, wait_until, timeout))
        self.url = url

    def wait_for_load_state(self, state, timeout):
        self.events.append(("wait", state, timeout))

    def evaluate(self, script):
        if "localStorage" in script:
            return {"consent_seen": str(("hook",) in self.events)}
        if "sessionStorage" in script:
            return {"session": "value"}
        return [
            {"type": "script", "url": "https://example.test/app.js"},
            {"type": "img", "url": "https://example.test/logo.png"},
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


def test_aggregate_captures_deduplicates_cookies_storage_scripts_and_requests():
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

