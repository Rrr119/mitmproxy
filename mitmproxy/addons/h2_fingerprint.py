"""
HTTP/2 client fingerprinting addon.

The actual fingerprint computation lives in :mod:`mitmproxy.h2fingerprint`
and the client-facing HTTP/2 layer. This addon owns the user-facing options:

* ``h2_fingerprint`` enables/disables the feature entirely. When it is off,
  the proxy core does not even instantiate a fingerprint collector, so no
  additional parsing work is performed.
* ``h2_fingerprint_tags`` maps fingerprint prefixes to tags that are written
  to ``flow.metadata`` and can be used to filter the flow list.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import NamedTuple

from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import h2fingerprint
from mitmproxy import http

H2_FINGERPRINT_TAG_METADATA_KEY = "h2_fingerprint_tags"
"""``flow.metadata`` key holding the list of tags assigned by matching
rules, in rule order."""


class H2FingerprintTag(NamedTuple):
    prefix: str
    tag: str


def parse_tag_spec(spec: str) -> H2FingerprintTag:
    """
    Parse a ``prefix/tag`` rule. The leading character is the separator,
    mirroring the syntax of options such as ``block_list``.
    """
    if len(spec) < 2:
        raise ValueError("Rule must start with a separator character")
    sep, remainder = spec[0], spec[1:]
    parts = remainder.split(sep, 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError("Expected a non-empty fingerprint prefix and a non-empty tag")
    return H2FingerprintTag(prefix=parts[0], tag=parts[1])


class H2Fingerprint:
    def __init__(self) -> None:
        self.tag_rules: list[H2FingerprintTag] = []

    def load(self, loader):
        loader.add_option(
            "h2_fingerprint",
            bool,
            False,
            """
            Compute an Akamai-style HTTP/2 fingerprint for every client
            connection. The fingerprint is based on the client's first SETTINGS
            frame (parameters and order), the initial connection-level
            WINDOW_UPDATE and the first request's pseudo-header order. It is
            stored as "h2_fingerprint" in flow.metadata and on the client
            connection. Disable this to avoid any extra processing overhead.
            """,
        )
        loader.add_option(
            "h2_fingerprint_tags",
            Sequence[str],
            [],
            """
            Tag flows whose HTTP/2 fingerprint starts with the given prefix.
            Option syntax is "/fingerprint-prefix/tag", the separator ("/" in
            the example) can be any character. Matching tags are stored as the
            "h2_fingerprint_tags" list in flow.metadata, e.g. filter with
            "~m h2_fingerprint_tags".
            """,
        )

    def configure(self, updated):
        if "h2_fingerprint_tags" in updated:
            rules: list[H2FingerprintTag] = []
            for spec in ctx.options.h2_fingerprint_tags:
                try:
                    rules.append(parse_tag_spec(spec))
                except ValueError as e:
                    raise exceptions.OptionsError(
                        f"Cannot parse h2_fingerprint_tags rule {spec!r}: {e}"
                    ) from e
            self.tag_rules = rules

    def request(self, flow: http.HTTPFlow) -> None:
        fingerprint = flow.metadata.get(h2fingerprint.H2_FINGERPRINT_METADATA_KEY)
        if not isinstance(fingerprint, str) or not self.tag_rules:
            return
        tags = [
            rule.tag for rule in self.tag_rules if fingerprint.startswith(rule.prefix)
        ]
        if tags:
            flow.metadata[H2_FINGERPRINT_TAG_METADATA_KEY] = tags


__all__ = [
    "H2Fingerprint",
    "H2FingerprintTag",
    "H2_FINGERPRINT_TAG_METADATA_KEY",
    "parse_tag_spec",
]
