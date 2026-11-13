import pytest

from mitmproxy import exceptions
from mitmproxy import h2fingerprint
from mitmproxy.addons.h2_fingerprint import H2_FINGERPRINT_TAG_METADATA_KEY
from mitmproxy.addons.h2_fingerprint import H2Fingerprint
from mitmproxy.addons.h2_fingerprint import parse_tag_spec
from mitmproxy.test import taddons
from mitmproxy.test import tflow

CHROME_FINGERPRINT = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
FIREFOX_FINGERPRINT = "1:65536;2:0;4:131072;5:16384|12517377|0|m,a,s,p"


def test_parse_tag_spec():
    assert parse_tag_spec("/1:65536;2:0/chrome-like") == (
        "1:65536;2:0",
        "chrome-like",
    )
    # Any leading character works as the separator.
    assert parse_tag_spec("|1:65536|browser") == ("1:65536", "browser")


@pytest.mark.parametrize(
    "spec",
    [
        "",
        "/",
        "/prefix",
        "//tag",
        "/prefix/",
    ],
)
def test_parse_tag_spec_invalid(spec):
    with pytest.raises(ValueError):
        parse_tag_spec(spec)


def test_configure_rejects_bad_rule():
    addon = H2Fingerprint()
    with taddons.context(addon) as tctx:
        with pytest.raises(exceptions.OptionsError):
            tctx.configure(addon, h2_fingerprint_tags=["/only-prefix"])


def test_request_assigns_matching_tags():
    addon = H2Fingerprint()
    with taddons.context(addon) as tctx:
        tctx.configure(
            addon,
            h2_fingerprint_tags=[
                "/1:65536;2:0;4:6291456/chromium-family",
                "/1:65536;2:0;4:131072/firefox-family",
                "/1:65536/chrome-or-firefox",
            ],
        )
        flow = tflow.tflow()
        flow.metadata[h2fingerprint.H2_FINGERPRINT_METADATA_KEY] = CHROME_FINGERPRINT
        addon.request(flow)

        assert flow.metadata[H2_FINGERPRINT_TAG_METADATA_KEY] == [
            "chromium-family",
            "chrome-or-firefox",
        ]


def test_request_without_match_leaves_metadata_untouched():
    addon = H2Fingerprint()
    with taddons.context(addon) as tctx:
        tctx.configure(addon, h2_fingerprint_tags=["/9:9/never"])
        flow = tflow.tflow()
        flow.metadata[h2fingerprint.H2_FINGERPRINT_METADATA_KEY] = CHROME_FINGERPRINT
        addon.request(flow)

        assert H2_FINGERPRINT_TAG_METADATA_KEY not in flow.metadata


def test_request_without_fingerprint_is_ignored():
    addon = H2Fingerprint()
    with taddons.context(addon) as tctx:
        tctx.configure(addon, h2_fingerprint_tags=["/1:65536/anything"])
        flow = tflow.tflow()
        addon.request(flow)
        assert H2_FINGERPRINT_TAG_METADATA_KEY not in flow.metadata


def test_default_option_is_disabled():
    addon = H2Fingerprint()
    with taddons.context(addon) as tctx:
        assert tctx.options.h2_fingerprint is False
        assert list(tctx.options.h2_fingerprint_tags) == []


def test_firefox_prefix_distinguishes_clients():
    addon = H2Fingerprint()
    with taddons.context(addon) as tctx:
        tctx.configure(addon, h2_fingerprint_tags=["/1:65536;2:0;4:131072/ff"])
        firefox_flow = tflow.tflow()
        firefox_flow.metadata[h2fingerprint.H2_FINGERPRINT_METADATA_KEY] = (
            FIREFOX_FINGERPRINT
        )
        chrome_flow = tflow.tflow()
        chrome_flow.metadata[h2fingerprint.H2_FINGERPRINT_METADATA_KEY] = (
            CHROME_FINGERPRINT
        )

        addon.request(firefox_flow)
        addon.request(chrome_flow)

        assert firefox_flow.metadata[H2_FINGERPRINT_TAG_METADATA_KEY] == ["ff"]
        assert H2_FINGERPRINT_TAG_METADATA_KEY not in chrome_flow.metadata
