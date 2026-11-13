import hashlib
import io
from dataclasses import dataclass

from kaitaistruct import KaitaiStream
from OpenSSL import SSL

from mitmproxy import connection
from mitmproxy.contrib.kaitaistruct import dtls_client_hello
from mitmproxy.contrib.kaitaistruct import tls_client_hello
from mitmproxy.net import check
from mitmproxy.proxy import context

# GREASE values (RFC 8701) are deliberately ignored by TLS fingerprinting.
GREASE_VALUES = frozenset(
    {
        0x0A0A,
        0x1A1A,
        0x2A2A,
        0x3A3A,
        0x4A4A,
        0x5A5A,
        0x6A6A,
        0x7A7A,
        0x8A8A,
        0x9A9A,
        0xAAAA,
        0xBABA,
        0xCACA,
        0xDADA,
        0xEAEA,
        0xFAFA,
    }
)

_JA4_TLS_VERSIONS = {
    0x0002: "s2",
    0x0300: "s3",
    0x0301: "10",
    0x0302: "11",
    0x0303: "12",
    0x0304: "13",
    0xFEFF: "d1",
    0xFEFC: "d3",
    0xFEFD: "d2",
}


def _is_grease(value: int) -> bool:
    return value in GREASE_VALUES


def _extension_body(client_hello: "ClientHello", extension_type: int) -> bytes | None:
    for current_type, body in client_hello.extensions:
        if current_type == extension_type:
            return body
    return None


def _parse_u16_list(body: bytes | None, length_bytes: int) -> list[int]:
    if not body or len(body) < length_bytes:
        return []
    declared_length = int.from_bytes(body[:length_bytes], "big")
    data = body[length_bytes : length_bytes + declared_length]
    if len(data) % 2:
        data = data[:-1]
    return [
        int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2)
    ]


def _parse_u8_list(body: bytes | None) -> list[int]:
    if not body:
        return []
    declared_length = body[0]
    return list(body[1 : 1 + declared_length])


def _parse_signature_algorithms(body: bytes | None) -> list[int]:
    if not body or len(body) < 2:
        return []
    declared_length = int.from_bytes(body[:2], "big")
    data = body[2 : 2 + declared_length]
    if len(data) % 2:
        data = data[:-1]
    return [
        int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2)
    ]


def _ja4_alpn_code(alpn: bytes | None) -> str:
    if not alpn:
        return "00"
    if (
        0x30 <= alpn[0] <= 0x39
        or 0x41 <= alpn[0] <= 0x5A
        or 0x61 <= alpn[0] <= 0x7A
    ) and (
        0x30 <= alpn[-1] <= 0x39
        or 0x41 <= alpn[-1] <= 0x5A
        or 0x61 <= alpn[-1] <= 0x7A
    ):
        return chr(alpn[0]) + chr(alpn[-1])
    encoded = alpn.hex()
    return encoded[0] + encoded[-1]


def _ja4_version(client_hello: "ClientHello") -> str:
    supported_versions = _parse_u16_list(
        _extension_body(client_hello, 0x002B), length_bytes=1
    )
    versions = [version for version in supported_versions if not _is_grease(version)]
    version = max(versions) if versions else client_hello.tls_version
    return _JA4_TLS_VERSIONS.get(version, "00")


class ClientHello:
    """
    A TLS ClientHello is the first message sent by the client when initiating TLS.
    """

    _raw_bytes: bytes

    def __init__(self, raw_client_hello: bytes, dtls: bool = False):
        """Create a TLS ClientHello object from raw bytes."""
        self._raw_bytes = raw_client_hello
        if dtls:
            self._client_hello = dtls_client_hello.DtlsClientHello(
                KaitaiStream(io.BytesIO(raw_client_hello))
            )
        else:
            self._client_hello = tls_client_hello.TlsClientHello(
                KaitaiStream(io.BytesIO(raw_client_hello))
            )

    def raw_bytes(self, wrap_in_record: bool = True) -> bytes:
        """
        The raw ClientHello bytes as seen on the wire.

        If `wrap_in_record` is True, the ClientHello will be wrapped in a synthetic TLS record
        (`0x160303 + len(chm) + 0x01 + len(ch)`), which is the format expected by some tools.
        The synthetic record assumes TLS version (`0x0303`), which may be different from what has been sent over the
        wire. JA3 hashes are unaffected by this as they only use the TLS version from the ClientHello data structure.

        A future implementation may return not just the exact ClientHello, but also the exact record(s) as seen on the
        wire.
        """
        if isinstance(self._client_hello, dtls_client_hello.DtlsClientHello):
            raise NotImplementedError

        if wrap_in_record:
            return (
                # record layer
                b"\x16\x03\x03"
                + (len(self._raw_bytes) + 4).to_bytes(2, byteorder="big")
                +
                # handshake header
                b"\x01"
                + len(self._raw_bytes).to_bytes(3, byteorder="big")
                +
                # ClientHello as defined in https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2.
                self._raw_bytes
            )
        else:
            return self._raw_bytes

    @property
    def cipher_suites(self) -> list[int]:
        """The cipher suites offered by the client (as raw ints)."""
        return self._client_hello.cipher_suites.cipher_suites

    @property
    def sni(self) -> str | None:
        """
        The [Server Name Indication](https://en.wikipedia.org/wiki/Server_Name_Indication),
        which indicates which hostname the client wants to connect to.
        """
        if ext := getattr(self._client_hello, "extensions", None):
            for extension in ext.extensions:
                is_valid_sni_extension = (
                    extension.type == 0x00
                    and len(extension.body.server_names) == 1
                    and extension.body.server_names[0].name_type == 0
                    and check.is_valid_host(extension.body.server_names[0].host_name)
                )
                if is_valid_sni_extension:
                    return extension.body.server_names[0].host_name.decode("ascii")
        return None

    @property
    def alpn_protocols(self) -> list[bytes]:
        """
        The application layer protocols offered by the client as part of the
        [ALPN](https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation) TLS extension.
        """
        if ext := getattr(self._client_hello, "extensions", None):
            for extension in ext.extensions:
                if extension.type == 0x10:
                    return list(x.name for x in extension.body.alpn_protocols)
        return []

    @property
    def extensions(self) -> list[tuple[int, bytes]]:
        """The raw list of extensions in the form of `(extension_type, raw_bytes)` tuples."""
        ret = []
        if ext := getattr(self._client_hello, "extensions", None):
            for extension in ext.extensions:
                body = getattr(extension, "_raw_body", extension.body)
                ret.append((extension.type, body))
        return ret

    @property
    def tls_version(self) -> int:
        """The legacy TLS version from the ClientHello, encoded as an integer."""
        version = self._client_hello.version
        return (int(version.major) << 8) | int(version.minor)

    @property
    def is_dtls(self) -> bool:
        """Whether this ClientHello was sent over DTLS."""
        return isinstance(self._client_hello, dtls_client_hello.DtlsClientHello)

    @property
    def ja3_raw(self) -> str:
        """
        The raw JA3 string before hashing.

        GREASE values are excluded from all lists.
        """
        ciphers = [
            str(cipher)
            for cipher in self.cipher_suites
            if not _is_grease(cipher)
        ]
        extensions = [
            str(extension_type)
            for extension_type, _ in self.extensions
            if not _is_grease(extension_type)
        ]
        groups = [
            str(group)
            for group in _parse_u16_list(
                _extension_body(self, 0x000A), length_bytes=2
            )
            if not _is_grease(group)
        ]
        point_formats = [
            str(point_format)
            for point_format in _parse_u8_list(_extension_body(self, 0x000B))
            if not _is_grease(point_format)
        ]
        return (
            f"{self.tls_version},"
            f"{'-'.join(ciphers)},"
            f"{'-'.join(extensions)},"
            f"{'-'.join(groups)},"
            f"{'-'.join(point_formats)}"
        )

    @property
    def ja3(self) -> str:
        """The JA3 fingerprint (MD5 of `ja3_raw`)."""
        return hashlib.md5(self.ja3_raw.encode("ascii")).hexdigest()

    @property
    def ja4_raw(self) -> str:
        """The raw (unhashed) JA4 fingerprint, including sorted cipher/extension lists."""
        ciphers = [
            f"{cipher:04x}"
            for cipher in self.cipher_suites
            if not _is_grease(cipher)
        ]
        extensions = [
            f"{extension_type:04x}"
            for extension_type, _ in self.extensions
            if not _is_grease(extension_type)
        ]
        signature_algorithms = [
            f"{signature_algorithm:04x}"
            for signature_algorithm in _parse_signature_algorithms(
                _extension_body(self, 0x000D)
            )
            if not _is_grease(signature_algorithm)
        ]

        cipher_count = min(len(ciphers), 99)
        extension_count = min(len(extensions), 99)
        alpn = self.alpn_protocols[0] if self.alpn_protocols else None
        sni = "d" if _extension_body(self, 0x0000) is not None else "i"
        protocol = "d" if self.is_dtls else "t"
        prefix = (
            f"{protocol}{_ja4_version(self)}{sni}"
            f"{cipher_count:02d}{extension_count:02d}{_ja4_alpn_code(alpn)}"
        )

        sorted_ciphers = sorted(ciphers)
        sorted_extensions = sorted(
            extension for extension in extensions if extension not in ("0000", "0010")
        )
        extension_hash_input = ",".join(sorted_extensions)
        if signature_algorithms:
            extension_hash_input += "_" + ",".join(signature_algorithms)

        cipher_raw = ",".join(sorted_ciphers) if sorted_ciphers else ""
        extension_raw = extension_hash_input
        return f"{prefix}_{cipher_raw}_{extension_raw}"

    @property
    def ja4(self) -> str:
        """The JA4 fingerprint."""
        prefix, cipher_raw, extension_raw = self.ja4_raw.split("_", 2)
        cipher_hash = (
            hashlib.sha256(cipher_raw.encode("ascii")).hexdigest()[:12]
            if cipher_raw
            else "000000000000"
        )
        extension_hash = (
            hashlib.sha256(extension_raw.encode("ascii")).hexdigest()[:12]
            if extension_raw
            else "000000000000"
        )
        return f"{prefix}_{cipher_hash}_{extension_hash}"

    def __repr__(self):
        return f"ClientHello(sni: {self.sni}, alpn_protocols: {self.alpn_protocols})"


@dataclass
class ClientHelloData:
    """
    Event data for `tls_clienthello` event hooks.
    """

    context: context.Context
    """The context object for this connection."""
    client_hello: ClientHello
    """The entire parsed TLS ClientHello."""
    ignore_connection: bool = False
    """
    If set to `True`, do not intercept this connection and forward encrypted contents unmodified.
    """
    establish_server_tls_first: bool = False
    """
    If set to `True`, pause this handshake and establish TLS with an upstream server first.
    This makes it possible to process the server certificate when generating an interception certificate.
    """


@dataclass
class TlsData:
    """
    Event data for `tls_start_client`, `tls_start_server`, and `tls_handshake` event hooks.
    """

    conn: connection.Connection
    """The affected connection."""
    context: context.Context
    """The context object for this connection."""
    ssl_conn: SSL.Connection | None = None
    """
    The associated pyOpenSSL `SSL.Connection` object.
    This will be set by an addon in the `tls_start_*` event hooks.
    """
    is_dtls: bool = False
    """
    If set to `True`, indicates that it is a DTLS event.
    """
