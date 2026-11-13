"""
HTTP/2 client fingerprinting following the algorithm proposed by Akamai.

The fingerprint consists of four connection-level components joined with
``|`` separators:

1. The SETTINGS frame's parameters and parameter values, in transmission
   order, written as ``id:value`` pairs joined with ``;``.
2. The initial connection-level WINDOW_UPDATE increment, or ``0`` if the
   client did not send one.
3. The PRIORITY frames seen before the first request, written as
   ``stream_id:exclusive:depends_on:weight`` tuples joined with ``,``,
   or ``0`` if there were none.
4. The order of the pseudo-headers in the first request's HEADERS frame,
   written as the single-letter names (``m`` for ``:method``, ``a`` for
   ``:authority``, ``s`` for ``:scheme``, ``p`` for ``:path``) joined
   with ``,``.

All components describe the client-to-server direction only. Frames that
mitmproxy itself sends back to the client must never be fed into a
fingerprint collector.

Reference: Shuster, "Passive Fingerprinting of HTTP/2 Clients",
Black Hat Europe 2017.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field

from h2.events import ChangedSetting

PSEUDO_HEADER_LETTERS: dict[bytes, str] = {
    b":method": "m",
    b":authority": "a",
    b":scheme": "s",
    b":path": "p",
    b":status": "s",
}
"""
Mapping of HTTP/2 pseudo-header names to the single letters used in the
fingerprint. ``:status`` shares the ``s`` letter for completeness, the
client-side fingerprint only contains request pseudo-headers.
"""

H2_FINGERPRINT_METADATA_KEY = "h2_fingerprint"
"""``flow.metadata`` key under which the connection-level HTTP/2 fingerprint
is exposed for every flow reused on the fingerprinted connection."""


@dataclass
class H2Priority:
    """The fields of a single HTTP/2 PRIORITY frame (RFC 9113, Section 5.3)."""

    stream_id: int
    exclusive: bool
    depends_on: int
    weight: int

    def __str__(self) -> str:
        return f"{self.stream_id}:{int(self.exclusive)}:{self.depends_on}:{self.weight}"


@dataclass
class H2Fingerprint:
    """
    The connection-level HTTP/2 fingerprint of a client.

    All fields preserve the wire order observed on the client connection.
    """

    settings: list[tuple[int, int]]
    """The SETTINGS parameters of the client's first SETTINGS frame,
    in transmission order, as ``(identifier, value)`` pairs."""

    window_update: int = 0
    """The increment of the initial connection-level WINDOW_UPDATE frame
    (stream id 0). ``0`` if the client did not send one."""

    priorities: list[H2Priority] = field(default_factory=list)
    """PRIORITY frames and HEADERS priority information observed before the
    first request HEADERS frame, in transmission order."""

    pseudo_headers: tuple[bytes, ...] = ()
    """The pseudo-header names (e.g. ``b":method"``) of the first request's
    HEADERS frame, in transmission order."""

    def settings_str(self) -> str:
        return ";".join(f"{identifier}:{value}" for identifier, value in self.settings)

    def window_update_str(self) -> str:
        return str(self.window_update)

    def priorities_str(self) -> str:
        if not self.priorities:
            return "0"
        return ",".join(str(priority) for priority in self.priorities)

    def pseudo_headers_str(self) -> str:
        return ",".join(PSEUDO_HEADER_LETTERS[name] for name in self.pseudo_headers)

    def __str__(self) -> str:
        return "|".join(
            (
                self.settings_str(),
                self.window_update_str(),
                self.priorities_str(),
                self.pseudo_headers_str(),
            )
        )


class H2FingerprintCollector:
    """
    Collects the raw data for a client's :class:`H2Fingerprint`.

    One collector belongs to exactly one client-side HTTP/2 connection.
    Feed it the h2 events emitted while parsing frames received from the
    client until :attr:`complete` is true (that is, until the first request
    HEADERS frame has been seen). Events of later requests are ignored so
    that the fingerprint is computed exactly once per connection.
    """

    def __init__(self) -> None:
        self.settings: list[tuple[int, int]] | None = None
        self.window_update: int = 0
        self.priorities: list[H2Priority] = []
        self.pseudo_headers: tuple[bytes, ...] = ()
        self._fingerprint: H2Fingerprint | None = None

    @property
    def complete(self) -> bool:
        return self._fingerprint is not None

    @property
    def fingerprint(self) -> H2Fingerprint | None:
        return self._fingerprint

    def record_settings(self, settings: Mapping[int, ChangedSetting]) -> None:
        """
        Record the client's first SETTINGS frame.

        The mapping's insertion order must match the frame's wire order.
        Later SETTINGS frames are part of the connection's lifetime and not
        part of the fingerprint, so they are ignored.
        """
        if self.settings is None:
            self.settings = [
                (int(identifier), int(change.new_value))
                for identifier, change in settings.items()
            ]

    def record_window_update(self, stream_id: int, delta: int) -> None:
        """Record the initial connection-level (stream id 0) WINDOW_UPDATE."""
        if stream_id == 0 and not self.window_update:
            self.window_update = delta

    def record_priority(
        self,
        stream_id: int,
        exclusive: bool,
        depends_on: int,
        weight: int,
    ) -> None:
        """Record a PRIORITY frame or HEADERS frame priority information."""
        if not self.complete:
            self.priorities.append(H2Priority(stream_id, exclusive, depends_on, weight))

    def record_request_headers(
        self, headers: list[tuple[bytes, bytes]]
    ) -> H2Fingerprint:
        """
        Record the first request's pseudo-header order and finalize the
        fingerprint.

        Calling this more than once returns the already finalized fingerprint
        without recomputing anything.
        """
        if self._fingerprint is None:
            self.pseudo_headers = tuple(
                name for name, _value in headers if name.startswith(b":")
            )
            self._fingerprint = H2Fingerprint(
                settings=self.settings or [],
                window_update=self.window_update,
                priorities=self.priorities,
                pseudo_headers=self.pseudo_headers,
            )
        return self._fingerprint


__all__ = [
    "H2_FINGERPRINT_METADATA_KEY",
    "H2Fingerprint",
    "H2FingerprintCollector",
    "H2Priority",
    "PSEUDO_HEADER_LETTERS",
]
