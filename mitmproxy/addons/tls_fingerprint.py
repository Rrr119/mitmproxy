from __future__ import annotations

import asyncio
import logging
import os
from collections import OrderedDict
from collections.abc import Mapping
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml import YAMLError

from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import http
from mitmproxy import tls
from mitmproxy import version
from mitmproxy.utils import asyncio_utils

logger = logging.getLogger(__name__)

DEFAULT_THRESHOLD = 80
DEFAULT_WEIGHTS = {"ja3": 25, "ja4": 25}
FINGERPRINT_TYPES = frozenset(DEFAULT_WEIGHTS)
MAX_CACHED_CONNECTIONS = 4096


class RuleConfigError(ValueError):
    """Raised when a fingerprint rules YAML file is invalid."""


@dataclass(frozen=True)
class FingerprintRule:
    name: str
    user_agent_prefix: str
    expected: Mapping[str, frozenset[str]]
    weights: Mapping[str, int]


@dataclass(frozen=True)
class RuleConfig:
    rules: tuple[FingerprintRule, ...]
    weights: Mapping[str, int]
    threshold: int


@dataclass(frozen=True)
class Evaluation:
    score: int
    threshold: int
    rule: FingerprintRule | None
    reasons: tuple[str, ...]
    blocked: bool


@dataclass(frozen=True)
class ClientFingerprint:
    ja3: str
    ja4: str
    ja3_raw: str
    ja4_raw: str

    def as_dict(self) -> dict[str, str]:
        return {
            "ja3": self.ja3,
            "ja4": self.ja4,
            "ja3_raw": self.ja3_raw,
            "ja4_raw": self.ja4_raw,
        }


def _empty_config() -> RuleConfig:
    return RuleConfig(rules=(), weights=dict(DEFAULT_WEIGHTS), threshold=DEFAULT_THRESHOLD)


def _as_mapping(value: Any, what: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RuleConfigError(f"{what} must be a mapping")
    return value


def _parse_weight(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuleConfigError(f"{what} must be an integer")
    if value < 0 or value > 100:
        raise RuleConfigError(f"{what} must be between 0 and 100")
    return value


def _parse_fingerprint_values(value: Any, what: str) -> frozenset[str]:
    if isinstance(value, str):
        values: Sequence[Any] = [value]
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        values = value
    else:
        raise RuleConfigError(f"{what} must be a string or a list of strings")

    normalized = set()
    for item in values:
        if not isinstance(item, str) or not item.strip():
            raise RuleConfigError(f"{what} must only contain non-empty strings")
        normalized.add(item.strip().lower())
    return frozenset(normalized)


def _parse_weights(value: Any, what: str) -> dict[str, int]:
    if value is None:
        return {}
    weights = {}
    for key, weight in _as_mapping(value, what).items():
        normalized_key = str(key).lower()
        if normalized_key not in FINGERPRINT_TYPES:
            raise RuleConfigError(
                f"{what} contains an unsupported fingerprint type: {key}"
            )
        weights[normalized_key] = _parse_weight(weight, f"{what}.{key}")
    return weights


def _parse_rule(value: Any, index: int) -> FingerprintRule:
    rule = _as_mapping(value, f"rules[{index}]")

    prefix = None
    for key in ("user_agent_prefix", "user_agent", "ua_prefix"):
        if key in rule:
            prefix = rule[key]
            break
    if not isinstance(prefix, str) or not prefix:
        raise RuleConfigError(
            f"rules[{index}] needs a non-empty user_agent_prefix"
        )

    name = rule.get("name", f"rule-{index}")
    if not isinstance(name, str) or not name:
        raise RuleConfigError(f"rules[{index}].name must be a non-empty string")

    fingerprints = rule.get("fingerprints", rule)
    fingerprints = _as_mapping(fingerprints, f"rules[{index}].fingerprints")
    expected = {}
    for fingerprint_type in FINGERPRINT_TYPES:
        if fingerprint_type in fingerprints:
            parsed = _parse_fingerprint_values(
                fingerprints[fingerprint_type],
                f"rules[{index}].{fingerprint_type}",
            )
            if parsed:
                expected[fingerprint_type] = parsed

    if not expected:
        raise RuleConfigError(
            f"rules[{index}] needs at least one of: "
            + ", ".join(sorted(FINGERPRINT_TYPES))
        )

    weights = _parse_weights(rule.get("weights"), f"rules[{index}].weights")
    return FingerprintRule(
        name=name,
        user_agent_prefix=prefix,
        expected=expected,
        weights=weights,
    )


def parse_rules(text: str) -> RuleConfig:
    """Parse a YAML fingerprint rules document."""
    try:
        data = YAML(typ="safe").load(text)
    except YAMLError as e:
        raise RuleConfigError(str(e)) from e
    if data is None:
        return _empty_config()

    weights = dict(DEFAULT_WEIGHTS)
    threshold = DEFAULT_THRESHOLD
    if isinstance(data, Mapping):
        if "weights" in data:
            weights.update(_parse_weights(data["weights"], "weights"))
        if "threshold" in data:
            threshold = _parse_weight(data["threshold"], "threshold")

        if "rules" in data:
            raw_rules = data["rules"]
        elif any(
            key in data for key in ("user_agent_prefix", "user_agent", "ua_prefix")
        ):
            raw_rules = [data]
        else:
            settings = {"rules", "weights", "threshold"}
            if any(key not in settings for key in data):
                raw_rules = [
                    {"user_agent_prefix": key, **value}
                    for key, value in data.items()
                    if isinstance(value, Mapping)
                ]
            else:
                raw_rules = []
    elif isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray)):
        raw_rules = data
    else:
        raise RuleConfigError("rules document must be a mapping or a list")

    if not isinstance(raw_rules, Sequence) or isinstance(
        raw_rules, (str, bytes, bytearray)
    ):
        raise RuleConfigError("rules must be a list")

    rules = tuple(_parse_rule(rule, index) for index, rule in enumerate(raw_rules))
    return RuleConfig(rules=rules, weights=weights, threshold=threshold)


def load_rules_file(path: str) -> RuleConfig:
    """Load and parse a fingerprint rules YAML file."""
    return parse_rules(Path(path).read_text(encoding="utf-8"))


def find_matching_rule(
    user_agent: str, rules: Sequence[FingerprintRule]
) -> FingerprintRule | None:
    """Return the rule with the longest matching User-Agent prefix."""
    matching = [rule for rule in rules if user_agent.startswith(rule.user_agent_prefix)]
    if not matching:
        return None
    return max(matching, key=lambda rule: len(rule.user_agent_prefix))


def _format_expected(expected: frozenset[str]) -> str:
    values = sorted(expected)
    preview = ", ".join(values[:3])
    if len(values) > 3:
        preview += ", ..."
    return preview


def evaluate(
    user_agent: str,
    actual: Mapping[str, str | None],
    config: RuleConfig,
    threshold: int,
) -> Evaluation:
    """
    Score a client against the first matching User-Agent rule.

    A client starts at 100 points. Matching fingerprints cost no points,
    missing or unexpected fingerprints deduct their configured weight.
    """
    rule = find_matching_rule(user_agent, config.rules)
    if rule is None:
        return Evaluation(
            score=100,
            threshold=threshold,
            rule=None,
            reasons=(),
            blocked=False,
        )

    deductions = 0
    reasons = []
    for fingerprint_type, expected in rule.expected.items():
        if not expected:
            continue
        weight = rule.weights.get(
            fingerprint_type, config.weights.get(fingerprint_type, 0)
        )
        value = actual.get(fingerprint_type)
        if value is None:
            deductions += weight
            reasons.append(
                f"{fingerprint_type} missing "
                f"(expected one of: {_format_expected(expected)})"
            )
        elif value.lower() not in expected:
            deductions += weight
            reasons.append(
                f"{fingerprint_type} mismatch "
                f"(expected one of: {_format_expected(expected)}; got: {value})"
            )

    score = max(0, 100 - deductions)
    return Evaluation(
        score=score,
        threshold=threshold,
        rule=rule,
        reasons=tuple(reasons),
        blocked=score < threshold,
    )


class TlsFingerprint:
    """
    Fingerprint intercepted TLS clients and enforce User-Agent fingerprint rules.
    """

    def __init__(self) -> None:
        self._config = _empty_config()
        self._rules_path: str | None = None
        self._rules_signature: tuple[int, int] | None = None
        self._fingerprints: OrderedDict[str, ClientFingerprint] = OrderedDict()
        self._watch_task: asyncio.Task | None = None
        self._running = False
        self._threshold_override: int | None = None
        self._enabled = True
        self._block_enabled = True

    def load(self, loader) -> None:
        loader.add_option(
            "tls_fingerprint_rules",
            str | None,
            None,
            """
            Path to a YAML rules file mapping User-Agent prefixes to expected
            JA3/JA4 fingerprints. The file is reloaded automatically when it changes.
            """,
        )
        loader.add_option(
            "tls_fingerprint_threshold",
            int | None,
            None,
            """
            Score threshold for TLS fingerprint enforcement. If unset, the
            threshold from the rules file is used (default: 80).
            """,
        )
        loader.add_option(
            "tls_fingerprint_enabled",
            bool,
            True,
            "Enable TLS fingerprint collection and rule evaluation.",
        )
        loader.add_option(
            "tls_fingerprint_block",
            bool,
            True,
            """
            Return HTTP 403 when a client's score is below the configured
            threshold. Fingerprints and scoring are still recorded when disabled.
            """,
        )

    def configure(self, updated: set[str]) -> None:
        if "tls_fingerprint_enabled" in updated:
            self._enabled = bool(ctx.options.tls_fingerprint_enabled)
        if "tls_fingerprint_block" in updated:
            self._block_enabled = bool(ctx.options.tls_fingerprint_block)
        if "tls_fingerprint_threshold" in updated:
            threshold = ctx.options.tls_fingerprint_threshold
            if threshold is not None and not 0 <= threshold <= 100:
                raise exceptions.OptionsError(
                    "tls_fingerprint_threshold must be between 0 and 100"
                )
            self._threshold_override = threshold
        if "tls_fingerprint_rules" in updated:
            path = ctx.options.tls_fingerprint_rules
            self._rules_path = (
                os.path.abspath(os.path.expanduser(path)) if path else None
            )
            self._load_rules()
            if self._running:
                self._start_watcher()

    def running(self) -> None:
        self._running = True
        self._start_watcher()

    def done(self) -> None:
        self._running = False
        if self._watch_task is not None:
            self._watch_task.cancel()
            self._watch_task = None

    def _load_rules(self) -> None:
        if self._rules_path is None:
            self._config = _empty_config()
            self._rules_signature = None
            return

        try:
            self._config = load_rules_file(self._rules_path)
            stat = os.stat(self._rules_path)
        except (OSError, RuleConfigError, ValueError) as e:
            raise exceptions.OptionsError(
                f"Cannot load tls_fingerprint_rules {self._rules_path}: {e}"
            ) from e
        self._rules_signature = (stat.st_mtime_ns, stat.st_size)

    def _start_watcher(self) -> None:
        if self._rules_path is None:
            return
        if self._watch_task is not None and not self._watch_task.done():
            return
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return
        self._watch_task = asyncio_utils.create_task(
            self._watch_rules(),
            name="tls fingerprint rules watcher",
            keep_ref=True,
        )

    async def _watch_rules(self) -> None:
        while True:
            await asyncio.sleep(1.0)
            await self.reload_rules_if_changed()

    async def reload_rules_if_changed(self) -> bool:
        """Reload the rules file if its metadata changed, without blocking the event loop."""
        if self._rules_path is None:
            return False

        try:
            stat = await asyncio.to_thread(os.stat, self._rules_path)
        except OSError as e:
            logger.warning(
                "Cannot stat tls_fingerprint_rules %s: %s", self._rules_path, e
            )
            return False

        signature = (stat.st_mtime_ns, stat.st_size)
        if signature == self._rules_signature:
            return False

        try:
            text = await asyncio.to_thread(
                Path(self._rules_path).read_text, encoding="utf-8"
            )
            config = await asyncio.to_thread(parse_rules, text)
        except (OSError, RuleConfigError, ValueError) as e:
            logger.warning(
                "Cannot reload tls_fingerprint_rules %s: %s", self._rules_path, e
            )
            self._rules_signature = signature
            return False

        self._config = config
        self._rules_signature = signature
        logger.info("Reloaded TLS fingerprint rules from %s.", self._rules_path)
        return True

    def _threshold(self) -> int:
        threshold = self._option(
            "tls_fingerprint_threshold", self._threshold_override
        )
        if threshold is not None:
            return int(threshold)
        return self._config.threshold

    def _option(self, name: str, default: Any) -> Any:
        options = getattr(ctx, "options", None)
        if options is None:
            return default
        return getattr(options, name, default)

    def _cache_fingerprint(
        self, connection_id: str, fingerprint: ClientFingerprint
    ) -> None:
        self._fingerprints[connection_id] = fingerprint
        self._fingerprints.move_to_end(connection_id)
        while len(self._fingerprints) > MAX_CACHED_CONNECTIONS:
            self._fingerprints.popitem(last=False)

    def get_fingerprint(self, connection_id: str) -> ClientFingerprint | None:
        return self._fingerprints.get(connection_id)

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        if not self._option("tls_fingerprint_enabled", self._enabled):
            return
        client = data.context.client
        if client.id in self._fingerprints:
            return

        fingerprint = ClientFingerprint(
            ja3=data.client_hello.ja3,
            ja4=data.client_hello.ja4,
            ja3_raw=data.client_hello.ja3_raw,
            ja4_raw=data.client_hello.ja4_raw,
        )
        self._cache_fingerprint(client.id, fingerprint)
        setattr(client, "_tls_fingerprint", fingerprint)

    def _get_flow_fingerprint(self, flow: http.HTTPFlow) -> ClientFingerprint | None:
        fingerprint = self.get_fingerprint(flow.client_conn.id)
        if fingerprint is not None:
            return fingerprint
        return getattr(flow.client_conn, "_tls_fingerprint", None)

    def request(self, flow: http.HTTPFlow) -> None:
        if not self._option("tls_fingerprint_enabled", self._enabled):
            return
        if flow.response or flow.error or not flow.live:
            return

        fingerprint = self._get_flow_fingerprint(flow)
        if fingerprint is None:
            return

        threshold = self._threshold()
        user_agent = flow.request.headers.get("user-agent", "")
        result = evaluate(
            user_agent,
            actual={"ja3": fingerprint.ja3, "ja4": fingerprint.ja4},
            config=self._config,
            threshold=threshold,
        )
        blocked = result.blocked and bool(
            self._option("tls_fingerprint_block", self._block_enabled)
        )
        reason = "; ".join(result.reasons) if result.reasons else None

        metadata = {
            **fingerprint.as_dict(),
            "score": result.score,
            "threshold": threshold,
            "matched_rule": result.rule.name if result.rule else None,
            "reason": reason,
            "blocked": blocked,
        }
        flow.metadata["tls_fingerprint"] = metadata
        flow.metadata["ja3"] = fingerprint.ja3
        flow.metadata["ja4"] = fingerprint.ja4
        flow.metadata["fingerprint_score"] = result.score
        flow.metadata["fingerprint_rule"] = (
            result.rule.name if result.rule else None
        )
        flow.metadata["fingerprint_reason"] = reason
        flow.metadata["fingerprint_blocked"] = blocked

        if blocked:
            body = (
                "403 Forbidden: TLS fingerprint policy violation"
                + (f" ({reason})" if reason else "")
                + "\n"
            ).encode("utf-8")
            flow.response = http.Response.make(
                403,
                body,
                {
                    "Content-Type": "text/plain; charset=utf-8",
                    "Server": version.MITMPROXY,
                },
            )

