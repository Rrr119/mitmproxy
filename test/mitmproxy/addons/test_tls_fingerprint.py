import asyncio
import os
from pathlib import Path

import pytest

from mitmproxy import connection
from mitmproxy import http
from mitmproxy import tls
from mitmproxy.addons import tls_fingerprint
from mitmproxy.exceptions import OptionsError
from mitmproxy.proxy import context as proxy_context
from mitmproxy.test import taddons
from mitmproxy.test import tflow

CLIENT_HELLO_NO_EXTENSIONS = bytes.fromhex(
    "03015658a756ab2c2bff55f636814deac086b7ca56b65058c7893ffc6074f5245f70205658a75475103a152637"
    "78e1bb6d22e8bbd5b6b0a3a59760ad354e91ba20d353001a0035002f000a000500040009000300060008006000"
    "61006200640100"
)

CLIENT_HELLO_WITH_EXTENSIONS = bytes.fromhex(
    "03033b70638d2523e1cba15f8364868295305e9c52aceabda4b5147210abc783e6e1000022c02bc02fc02cc030"
    "cca9cca8cc14cc13c009c013c00ac014009c009d002f0035000a0100006cff0100010000000010000e00000b65"
    "78616d706c652e636f6d0017000000230000000d00120010060106030501050304010403020102030005000501"
    "00000000001200000010000e000c02683208687474702f312e3175500000000b00020100000a00080006001d00"
    "170018"
)

EXPECTED_JA3 = "20dd18bdd3209ea718989030a6f93364"
EXPECTED_JA4 = "t12d1711h2_67e6df579eba_de5ccbe16bdd"


def _client_hello(
    ciphers: list[int],
    extensions: list[tuple[int, bytes]],
) -> tls.ClientHello:
    body = (
        b"\x03\x03"
        + b"\x00" * 32
        + b"\x00"
        + len(ciphers * 2).to_bytes(2, "big")
        + b"".join(cipher.to_bytes(2, "big") for cipher in ciphers)
        + b"\x01\x00"
    )
    extension_data = b"".join(
        extension_type.to_bytes(2, "big")
        + len(extension_body).to_bytes(2, "big")
        + extension_body
        for extension_type, extension_body in extensions
    )
    body += len(extension_data).to_bytes(2, "big") + extension_data
    return tls.ClientHello(body)


def _write_rules(tmp_path: Path, content: str) -> str:
    path = tmp_path / "rules.yaml"
    path.write_text(content, encoding="utf-8")
    return str(path)


def _client(tctx) -> connection.Client:
    return connection.Client(
        peername=("client", 1234),
        sockname=("127.0.0.1", 8080),
    )


def test_ja3_known_value():
    client_hello = tls.ClientHello(CLIENT_HELLO_WITH_EXTENSIONS)
    assert client_hello.ja3_raw == (
        "771,49195-49199-49196-49200-52393-52392-52244-52243-49161-49171-"
        "49162-49172-156-157-47-53-10,"
        "65281-0-23-35-13-5-18-16-30032-11-10,29-23-24,0"
    )
    assert client_hello.ja3 == EXPECTED_JA3


def test_ja4_known_value():
    client_hello = tls.ClientHello(CLIENT_HELLO_WITH_EXTENSIONS)
    assert client_hello.ja4_raw == (
        "t12d1711h2_"
        "000a,002f,0035,009c,009d,c009,c00a,c013,c014,c02b,c02c,c02f,c030,"
        "cc13,cc14,cca8,cca9_"
        "0005,000a,000b,000d,0012,0017,0023,7550,ff01_"
        "0601,0603,0501,0503,0401,0403,0201,0203"
    )
    assert client_hello.ja4 == EXPECTED_JA4


def test_ja3_and_ja4_without_extensions():
    client_hello = tls.ClientHello(CLIENT_HELLO_NO_EXTENSIONS)
    assert client_hello.ja3 == "f2a705f3aa28839d4469833b5875b1e3"
    assert client_hello.ja4 == "t10i130000_fb97d3037a6a_000000000000"


def test_grease_values_are_ignored():
    client_hello = _client_hello(
        ciphers=[0x0A0A, 0x1301, 0x1302, 0x1A1A],
        extensions=[
            (0x1A1A, b""),
            (0x000A, b"\x00\x04\x0A\x0A\x00\x1D"),
            (0x000B, b"\x01\x00"),
        ],
    )
    assert "2570" not in client_hello.ja3_raw
    assert "6682" not in client_hello.ja3_raw
    assert client_hello.ja4_raw.startswith("t12i020200")
    assert "0a0a" not in client_hello.ja4_raw
    assert "1a1a" not in client_hello.ja4_raw


def test_tls_clienthello_caches_per_connection(monkeypatch):
    addon = tls_fingerprint.TlsFingerprint()
    with taddons.context(addon) as tctx:
        client = _client(tctx)
        data = tls.ClientHelloData(
            proxy_context.Context(client, tctx.options),
            tls.ClientHello(CLIENT_HELLO_WITH_EXTENSIONS),
        )
        addon.tls_clienthello(data)
        assert addon.get_fingerprint(client.id).ja3 == EXPECTED_JA3

        monkeypatch.setattr(
            tls.ClientHello,
            "ja3",
            property(lambda self: pytest.fail("JA3 was recomputed")),
        )
        monkeypatch.setattr(
            tls.ClientHello,
            "ja4",
            property(lambda self: pytest.fail("JA4 was recomputed")),
        )
        addon.tls_clienthello(data)
        assert addon.get_fingerprint(client.id).ja4 == EXPECTED_JA4


def test_parse_rules_and_evaluate():
    config = tls_fingerprint.parse_rules(
        f"""
threshold: 60
weights:
  ja3: 30
  ja4: 40
rules:
  - name: chrome
    user_agent_prefix: "Mozilla/5.0 Chrome/"
    fingerprints:
      ja3: {EXPECTED_JA3}
      ja4:
        - {EXPECTED_JA4}
"""
    )
    rule = tls_fingerprint.find_matching_rule(
        "Mozilla/5.0 Chrome/123.0", config.rules
    )
    assert rule is not None
    assert rule.name == "chrome"
    assert config.threshold == 60
    assert config.weights["ja3"] == 30

    matching = tls_fingerprint.evaluate(
        "Mozilla/5.0 Chrome/123.0",
        {"ja3": EXPECTED_JA3, "ja4": EXPECTED_JA4},
        config,
        60,
    )
    assert matching.score == 100
    assert matching.reasons == ()
    assert not matching.blocked

    mismatching = tls_fingerprint.evaluate(
        "Mozilla/5.0 Chrome/123.0",
        {"ja3": "0" * 32, "ja4": "t00i000000_000000000000_000000000000"},
        config,
        60,
    )
    assert mismatching.score == 30
    assert len(mismatching.reasons) == 2
    assert mismatching.blocked

    missing = tls_fingerprint.evaluate(
        "Mozilla/5.0 Chrome/123.0",
        {"ja3": None, "ja4": None},
        config,
        60,
    )
    assert missing.score == 30
    assert all("missing" in reason for reason in missing.reasons)


def test_evaluate_without_matching_rule():
    config = tls_fingerprint.parse_rules(
        f"""
rules:
  - user_agent_prefix: "curl/"
    ja3: {EXPECTED_JA3}
"""
    )
    result = tls_fingerprint.evaluate(
        "Mozilla/5.0",
        {"ja3": EXPECTED_JA3},
        config,
        60,
    )
    assert result.score == 100
    assert result.rule is None
    assert not result.blocked


def test_empty_expected_fingerprint_is_ignored():
    rule = tls_fingerprint.FingerprintRule(
        name="empty",
        user_agent_prefix="curl/",
        expected={"ja3": frozenset()},
        weights={},
    )
    config = tls_fingerprint.RuleConfig(
        rules=(rule,),
        weights={"ja3": 25},
        threshold=60,
    )
    result = tls_fingerprint.evaluate("curl/8.0", {}, config, 60)
    assert result.score == 100


def test_long_expected_fingerprint_preview():
    rule = tls_fingerprint.FingerprintRule(
        name="many",
        user_agent_prefix="curl/",
        expected={"ja3": frozenset({"a", "b", "c", "d"})},
        weights={},
    )
    config = tls_fingerprint.RuleConfig(
        rules=(rule,),
        weights={"ja3": 25},
        threshold=60,
    )
    result = tls_fingerprint.evaluate(
        "curl/8.0", {"ja3": "mismatch"}, config, 60
    )
    assert "..." in result.reasons[0]


def test_empty_document():
    config = tls_fingerprint.parse_rules("")
    assert config.rules == ()
    assert config.threshold == tls_fingerprint.DEFAULT_THRESHOLD
    assert config.weights == tls_fingerprint.DEFAULT_WEIGHTS


def test_document_without_rules():
    config = tls_fingerprint.parse_rules("weights:\n  ja3: 25\n")
    assert config.rules == ()


def test_single_rule_document():
    config = tls_fingerprint.parse_rules(
        f"""
user_agent_prefix: "Mozilla/"
name: browser
ja3: {EXPECTED_JA3}
"""
    )
    assert config.rules[0].name == "browser"


def test_user_agent_map_document():
    config = tls_fingerprint.parse_rules(
        f"""
"Mozilla/":
  name: browser
  ja3: {EXPECTED_JA3}
"""
    )
    assert config.rules[0].user_agent_prefix == "Mozilla/"


def test_rule_list_document():
    config = tls_fingerprint.parse_rules(
        f"""
- user_agent_prefix: "Mozilla/"
  ja3: {EXPECTED_JA3}
"""
    )
    assert len(config.rules) == 1


@pytest.mark.parametrize(
    "content,error",
    [
        ("threshold: true\nrules: []\n", "must be an integer"),
        ("rules: scalar\n", "rules must be a list"),
        ("scalar\n", "rules document must be a mapping or a list"),
        (
            "rules:\n  - user_agent_prefix: ''\n    ja3: abc\n",
            "needs a non-empty user_agent_prefix",
        ),
        (
            'rules:\n  - user_agent_prefix: "Mozilla/"\n    name: ""\n    ja3: abc\n',
            "name must be a non-empty string",
        ),
        (
            'rules:\n  - user_agent_prefix: "Mozilla/"\n    fingerprints: nope\n',
            "fingerprints must be a mapping",
        ),
        (
            'rules:\n  - user_agent_prefix: "Mozilla/"\n    ja3: 12\n',
            "must be a string or a list of strings",
        ),
        (
            'rules:\n  - user_agent_prefix: "Mozilla/"\n    ja3: [""]\n',
            "must only contain non-empty strings",
        ),
        (
            'rules:\n  - user_agent_prefix: "Mozilla/"\n    ja3: abc\n    weights: nope\n',
            "weights must be a mapping",
        ),
        (
            'rules:\n  - user_agent_prefix: "Mozilla/"\n    ja3: abc\n    weights:\n      ja4: true\n',
            "must be an integer",
        ),
    ],
)
def test_more_invalid_rules(content, error):
    with pytest.raises(tls_fingerprint.RuleConfigError, match=error):
        tls_fingerprint.parse_rules(content)


def test_configure_rejects_invalid_options(tmp_path):
    addon = tls_fingerprint.TlsFingerprint()
    with taddons.context(addon) as tctx:
        with pytest.raises(OptionsError, match="Cannot load tls_fingerprint_rules"):
            tctx.configure(
                addon, tls_fingerprint_rules=str(tmp_path / "missing.yaml")
            )
        with pytest.raises(OptionsError, match="between 0 and 100"):
            tctx.configure(addon, tls_fingerprint_threshold=101)


def test_threshold_option_overrides_file(tmp_path):
    rules_path = _write_rules(
        tmp_path,
        f"""
threshold: 60
rules:
  - user_agent_prefix: "Mozilla/"
    ja3: {EXPECTED_JA3}
""",
    )
    addon = tls_fingerprint.TlsFingerprint()
    with taddons.context(addon) as tctx:
        tctx.configure(
            addon,
            tls_fingerprint_rules=rules_path,
            tls_fingerprint_threshold=75,
        )
        assert addon._threshold() == 75
        tctx.configure(addon, tls_fingerprint_rules=None)
        assert addon._config.rules == ()


def test_option_without_context(monkeypatch):
    addon = tls_fingerprint.TlsFingerprint()
    monkeypatch.delattr(tls_fingerprint.ctx, "options", raising=False)
    assert addon._option("missing", "fallback") == "fallback"


def test_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(tls_fingerprint, "MAX_CACHED_CONNECTIONS", 2)
    addon = tls_fingerprint.TlsFingerprint()
    fingerprint = tls_fingerprint.ClientFingerprint(
        ja3=EXPECTED_JA3,
        ja4=EXPECTED_JA4,
        ja3_raw="",
        ja4_raw="",
    )
    addon._cache_fingerprint("one", fingerprint)
    addon._cache_fingerprint("two", fingerprint)
    addon._cache_fingerprint("three", fingerprint)
    assert addon.get_fingerprint("one") is None
    assert addon.get_fingerprint("three") is fingerprint


def test_longest_user_agent_prefix_wins():
    config = tls_fingerprint.parse_rules(
        f"""
rules:
  - name: generic
    user_agent_prefix: "Mozilla/"
    ja3: {EXPECTED_JA3}
  - name: chrome
    user_agent_prefix: "Mozilla/5.0 Chrome/"
    ja4: {EXPECTED_JA4}
"""
    )
    rule = tls_fingerprint.find_matching_rule(
        "Mozilla/5.0 Chrome/123.0", config.rules
    )
    assert rule.name == "chrome"


@pytest.mark.parametrize(
    "threshold,blocked",
    [(76, True), (75, False), (100, True), (74, False)],
)
def test_threshold_boundary(threshold, blocked):
    config = tls_fingerprint.parse_rules(
        f"""
threshold: {threshold}
weights:
  ja3: 25
rules:
  - user_agent_prefix: "curl/"
    ja3: {EXPECTED_JA3}
"""
    )
    result = tls_fingerprint.evaluate(
        "curl/8.0",
        {"ja3": "0" * 32},
        config,
        threshold,
    )
    assert result.score == 75
    assert result.blocked is blocked


def test_request_blocks_and_records_metadata(tmp_path):
    rules_path = _write_rules(
        tmp_path,
        f"""
threshold: 60
weights:
  ja3: 25
  ja4: 25
rules:
  - name: chrome
    user_agent_prefix: "Mozilla/5.0 Chrome/"
    ja3: {EXPECTED_JA3}
    ja4: {EXPECTED_JA4}
""",
    )
    addon = tls_fingerprint.TlsFingerprint()
    with taddons.context(addon) as tctx:
        tctx.configure(addon, tls_fingerprint_rules=rules_path)
        client = _client(tctx)
        addon.tls_clienthello(
            tls.ClientHelloData(
                proxy_context.Context(client, tctx.options),
                tls.ClientHello(CLIENT_HELLO_NO_EXTENSIONS),
            )
        )
        flow = tflow.tflow(client_conn=client)
        flow.request.headers["user-agent"] = "Mozilla/5.0 Chrome/123.0"
        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        assert flow.metadata["fingerprint_blocked"] is True
        assert flow.metadata["fingerprint_score"] == 50
        assert flow.metadata["fingerprint_rule"] == "chrome"
        assert "ja3 mismatch" in flow.metadata["fingerprint_reason"]
        assert "ja4 mismatch" in flow.metadata["fingerprint_reason"]
        assert flow.metadata["ja3"] == addon.get_fingerprint(client.id).ja3
        assert flow.metadata["ja4"] == addon.get_fingerprint(client.id).ja4


def test_request_allows_matching_fingerprint(tmp_path):
    rules_path = _write_rules(
        tmp_path,
        f"""
threshold: 60
rules:
  - name: browser
    user_agent_prefix: "Mozilla/"
    ja3: {EXPECTED_JA3}
    ja4: {EXPECTED_JA4}
""",
    )
    addon = tls_fingerprint.TlsFingerprint()
    with taddons.context(addon) as tctx:
        tctx.configure(addon, tls_fingerprint_rules=rules_path)
        client = _client(tctx)
        addon.tls_clienthello(
            tls.ClientHelloData(
                proxy_context.Context(client, tctx.options),
                tls.ClientHello(CLIENT_HELLO_WITH_EXTENSIONS),
            )
        )
        flow = tflow.tflow(client_conn=client)
        flow.request.headers["user-agent"] = "Mozilla/5.0 Chrome/123.0"
        addon.request(flow)

        assert flow.response is None
        assert flow.metadata["fingerprint_blocked"] is False
        assert flow.metadata["fingerprint_score"] == 100
        assert flow.metadata["fingerprint_reason"] is None


def test_request_uses_connection_attribute_cache():
    addon = tls_fingerprint.TlsFingerprint()
    with taddons.context(addon):
        client = _client(None)
        fingerprint = tls_fingerprint.ClientFingerprint(
            ja3=EXPECTED_JA3,
            ja4=EXPECTED_JA4,
            ja3_raw="",
            ja4_raw="",
        )
        client._tls_fingerprint = fingerprint
        flow = tflow.tflow(client_conn=client)
        addon.request(flow)
        assert flow.metadata["ja3"] == EXPECTED_JA3


def test_request_skips_without_fingerprint_or_when_handled():
    addon = tls_fingerprint.TlsFingerprint()
    with taddons.context(addon):
        flow = tflow.tflow()
        addon.request(flow)
        assert "tls_fingerprint" not in flow.metadata

        flow.response = http.Response.make(200)
        addon.request(flow)
        assert "tls_fingerprint" not in flow.metadata


def test_disabled_addon_does_nothing(tmp_path):
    rules_path = _write_rules(
        tmp_path,
        f"""
threshold: 60
rules:
  - user_agent_prefix: "Mozilla/"
    ja3: {EXPECTED_JA3}
""",
    )
    addon = tls_fingerprint.TlsFingerprint()
    with taddons.context(addon) as tctx:
        tctx.configure(
            addon,
            tls_fingerprint_rules=rules_path,
            tls_fingerprint_enabled=False,
        )
        client = _client(tctx)
        addon.tls_clienthello(
            tls.ClientHelloData(
                proxy_context.Context(client, tctx.options),
                tls.ClientHello(CLIENT_HELLO_WITH_EXTENSIONS),
            )
        )
        assert addon.get_fingerprint(client.id) is None
        flow = tflow.tflow(client_conn=client)
        flow.request.headers["user-agent"] = "Mozilla/5.0"
        addon.request(flow)
        assert "tls_fingerprint" not in flow.metadata


def test_blocking_can_be_disabled(tmp_path):
    rules_path = _write_rules(
        tmp_path,
        f"""
threshold: 60
rules:
  - name: chrome
    user_agent_prefix: "Mozilla/"
    ja3: {EXPECTED_JA3}
    ja4: {EXPECTED_JA4}
""",
    )
    addon = tls_fingerprint.TlsFingerprint()
    with taddons.context(addon) as tctx:
        tctx.configure(
            addon,
            tls_fingerprint_rules=rules_path,
            tls_fingerprint_block=False,
        )
        client = _client(tctx)
        addon.tls_clienthello(
            tls.ClientHelloData(
                proxy_context.Context(client, tctx.options),
                tls.ClientHello(CLIENT_HELLO_NO_EXTENSIONS),
            )
        )
        flow = tflow.tflow(client_conn=client)
        flow.request.headers["user-agent"] = "Mozilla/5.0 Chrome/123.0"
        addon.request(flow)

        assert flow.response is None
        assert flow.metadata["fingerprint_score"] == 50
        assert flow.metadata["fingerprint_blocked"] is False


async def test_hot_reload_does_not_keep_old_rules(tmp_path):
    addon = tls_fingerprint.TlsFingerprint()
    with taddons.context(addon) as tctx:
        rules_path = _write_rules(
            tmp_path,
            f"""
threshold: 60
rules:
  - name: old
    user_agent_prefix: "Mozilla/"
    ja3: {EXPECTED_JA3}
""",
        )
        tctx.configure(addon, tls_fingerprint_rules=rules_path)
        assert addon._config.rules[0].name == "old"

        Path(rules_path).write_text(
            f"""
threshold: 80
rules:
  - name: new
    user_agent_prefix: "Mozilla/"
    ja4: {EXPECTED_JA4}
""",
            encoding="utf-8",
        )
        os.utime(rules_path, ns=(1, 2))
        assert await addon.reload_rules_if_changed()
        assert addon._config.rules[0].name == "new"
        assert addon._config.threshold == 80


async def test_reload_without_path(monkeypatch):
    addon = tls_fingerprint.TlsFingerprint()
    with taddons.context(addon):
        assert not await addon.reload_rules_if_changed()


async def test_reload_missing_path(tmp_path):
    addon = tls_fingerprint.TlsFingerprint()
    with taddons.context(addon) as tctx:
        rules_path = _write_rules(
            tmp_path,
            f"""
rules:
  - user_agent_prefix: "Mozilla/"
    ja3: {EXPECTED_JA3}
""",
        )
        tctx.configure(addon, tls_fingerprint_rules=rules_path)
        assert not await addon.reload_rules_if_changed()
        os.unlink(rules_path)
        assert not await addon.reload_rules_if_changed()


async def test_watch_rules_loop(monkeypatch):
    addon = tls_fingerprint.TlsFingerprint()
    calls = 0

    async def fake_sleep(delay):
        nonlocal calls
        calls += 1
        if calls > 1:
            raise asyncio.CancelledError

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    with pytest.raises(asyncio.CancelledError):
        await addon._watch_rules()


def test_start_watcher_outside_running_loop(tmp_path):
    addon = tls_fingerprint.TlsFingerprint()
    with taddons.context(addon):
        addon._start_watcher()
        addon._rules_path = _write_rules(tmp_path, "rules: []\n")
        addon._start_watcher()
        assert addon._watch_task is None


async def test_watcher_lifecycle(tmp_path):
    addon = tls_fingerprint.TlsFingerprint()
    with taddons.context(addon) as tctx:
        rules_path = _write_rules(tmp_path, "rules: []\n")
        tctx.configure(addon, tls_fingerprint_rules=rules_path)
        addon.running()
        task = addon._watch_task
        assert task is not None
        addon._start_watcher()
        assert addon._watch_task is task
        addon.configure({"tls_fingerprint_rules"})
        addon.done()
        assert addon._watch_task is None
        with pytest.raises(asyncio.CancelledError):
            await task


async def test_reload_keeps_old_rules_on_invalid_yaml(tmp_path, caplog):
    rules_path = _write_rules(
        tmp_path,
        f"""
rules:
  - name: valid
    user_agent_prefix: "Mozilla/"
    ja3: {EXPECTED_JA3}
""",
    )
    addon = tls_fingerprint.TlsFingerprint()
    with taddons.context(addon) as tctx:
        tctx.configure(addon, tls_fingerprint_rules=rules_path)
        Path(rules_path).write_text("rules: [", encoding="utf-8")
        os.utime(rules_path, ns=(2, 3))
        assert not await addon.reload_rules_if_changed()
        assert addon._config.rules[0].name == "valid"
        assert "Cannot reload tls_fingerprint_rules" in caplog.text


@pytest.mark.parametrize(
    "content,error",
    [
        ("rules: not-a-list", "rules must be a list"),
        (
            "rules:\n  - user_agent_prefix: Mozilla/\n    ja3: []\n",
            "needs at least one",
        ),
        (
            "weights:\n  invalid: 10\nrules: []\n",
            "unsupported fingerprint type",
        ),
        (
            "threshold: 101\nrules: []\n",
            "must be between 0 and 100",
        ),
    ],
)
def test_invalid_rules(content, error):
    with pytest.raises(tls_fingerprint.RuleConfigError, match=error):
        tls_fingerprint.parse_rules(content)
