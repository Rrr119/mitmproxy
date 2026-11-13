from h2.events import ChangedSetting

from mitmproxy.h2fingerprint import H2Fingerprint
from mitmproxy.h2fingerprint import H2FingerprintCollector
from mitmproxy.h2fingerprint import H2Priority


def changed_settings(mapping: dict[int, int]) -> dict[int, ChangedSetting]:
    return {
        identifier: ChangedSetting(identifier, 0, value)
        for identifier, value in mapping.items()
    }


chrome_headers = [
    (b":method", b"GET"),
    (b":authority", b"example.com"),
    (b":scheme", b"https"),
    (b":path", b"/"),
    (b"user-agent", b"Chrome"),
]


def test_akamai_known_chrome_sample():
    # Widely referenced Akamai HTTP/2 fingerprint of a current Chrome client.
    collector = H2FingerprintCollector()
    collector.record_settings(changed_settings({1: 65536, 2: 0, 4: 6291456, 6: 262144}))
    collector.record_window_update(0, 15663105)
    fingerprint = collector.record_request_headers(chrome_headers)

    assert str(fingerprint) == "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"


def test_settings_order_is_preserved():
    # Same parameters as Chrome, but in a different order and with an extra
    # MAX_CONCURRENT_STREAMS entry. The fingerprint must reflect wire order.
    collector = H2FingerprintCollector()
    collector.record_settings(
        changed_settings({6: 262144, 3: 1000, 1: 65536, 2: 0, 4: 6291456})
    )
    fingerprint = collector.record_request_headers(chrome_headers)

    assert fingerprint.settings_str() == "6:262144;3:1000;1:65536;2:0;4:6291456"
    assert str(fingerprint) == "6:262144;3:1000;1:65536;2:0;4:6291456|0|0|m,a,s,p"


def test_different_settings_produce_different_fingerprints():
    def fingerprint_for(settings: dict[int, int]) -> str:
        collector = H2FingerprintCollector()
        collector.record_settings(changed_settings(settings))
        return str(collector.record_request_headers(chrome_headers))

    assert fingerprint_for({1: 4096, 2: 0}) != fingerprint_for({1: 65536, 2: 0})
    # Order matters even when the parameter/value pairs are identical.
    assert fingerprint_for({1: 1, 2: 2}) != fingerprint_for({2: 2, 1: 1})


def test_fingerprint_is_stable_across_repeated_computation():
    collector = H2FingerprintCollector()
    assert collector.fingerprint is None
    assert collector.complete is False
    collector.record_settings(changed_settings({1: 65536}))
    first = collector.record_request_headers(chrome_headers)
    # A second request on the same connection must not change anything.
    second = collector.record_request_headers(
        [(b":path", b"/other"), (b":method", b"POST")]
    )

    assert first is second
    assert collector.fingerprint is first
    assert collector.complete is True
    assert str(second) == "1:65536|0|0|m,a,s,p"
    assert collector.complete


def test_only_first_settings_frame_counts():
    collector = H2FingerprintCollector()
    collector.record_settings(changed_settings({1: 65536}))
    # A later SETTINGS frame updates connection parameters, but the
    # fingerprint is defined by the client's first frame only.
    collector.record_settings(changed_settings({3: 1000}))
    fingerprint = collector.record_request_headers(chrome_headers)

    assert fingerprint.settings == [(1, 65536)]


def test_only_first_connection_level_window_update_counts():
    collector = H2FingerprintCollector()
    collector.record_window_update(0, 15663105)
    # Stream-level updates and further connection-level updates are ignored.
    collector.record_window_update(3, 12345)
    collector.record_window_update(0, 999)
    fingerprint = collector.record_request_headers(chrome_headers)

    assert fingerprint.window_update == 15663105


def test_missing_window_update_defaults_to_zero():
    collector = H2FingerprintCollector()
    fingerprint = collector.record_request_headers(chrome_headers)
    assert fingerprint.window_update_str() == "0"


def test_priority_frames_are_rendered_in_order():
    collector = H2FingerprintCollector()
    collector.record_priority(stream_id=3, exclusive=False, depends_on=0, weight=200)
    collector.record_priority(stream_id=5, exclusive=True, depends_on=0, weight=100)
    fingerprint = collector.record_request_headers(chrome_headers)

    assert fingerprint.priorities == [
        H2Priority(3, False, 0, 200),
        H2Priority(5, True, 0, 100),
    ]
    assert fingerprint.priorities_str() == "3:0:0:200,5:1:0:100"


def test_events_after_completion_are_ignored():
    collector = H2FingerprintCollector()
    collector.record_priority(3, False, 0, 1)
    fingerprint = collector.record_request_headers(chrome_headers)
    collector.record_priority(5, True, 0, 2)
    collector.record_window_update(0, 42)

    assert fingerprint.priorities == [H2Priority(3, False, 0, 1)]
    assert fingerprint.window_update == 0


def test_empty_connection_fingerprint():
    fingerprint = H2Fingerprint(settings=[])
    assert str(fingerprint) == "|0|0|"


def test_alternate_pseudo_header_order():
    collector = H2FingerprintCollector()
    fingerprint = collector.record_request_headers(
        [
            (b":method", b"GET"),
            (b":path", b"/"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
        ]
    )
    assert fingerprint.pseudo_headers_str() == "m,p,s,a"
