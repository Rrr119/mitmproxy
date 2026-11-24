from __future__ import annotations

import asyncio

import pytest

import mitmproxy_rs
from mitmproxy import http
from mitmproxy.addons.clientplayback import ClientPlayback
from mitmproxy.addons.next_layer import NextLayer
from mitmproxy.addons.proxyserver import Proxyserver
from mitmproxy.addons.tlsconfig import TlsConfig
from mitmproxy.test import taddons
from mitmproxy.test import tflow
from test.mitmproxy.addons.test_proxyserver import H3Client
from test.mitmproxy.addons.test_proxyserver import H3EchoServer
from test.mitmproxy.addons.test_proxyserver import quic_connect
from test.mitmproxy.addons.test_proxyserver import quic_server
from test.mitmproxy.addons.test_proxyserver import tlsdata


class H3Modifier:
    def __init__(self) -> None:
        self.flows: list[http.HTTPFlow] = []

    def request(self, flow: http.HTTPFlow) -> None:
        self.flows.append(flow)
        value = flow.request.headers.get("x-request", "")
        flow.request.headers["x-request"] = f"modified:{value}"
        flow.request.headers["x-request-modified"] = "yes"

    def response(self, flow: http.HTTPFlow) -> None:
        value = flow.response.headers.get("x-response", "")
        flow.response.headers["x-response"] = f"modified:{value}"
        flow.response.headers["x-response-modified"] = "yes"
        flow.response.content = b"modified-body:" + (flow.response.content or b"")


@pytest.mark.parametrize(
    "client_name,data,trailers",
    [
        pytest.param("curl", None, None, id="curl"),
        pytest.param("aioquic", b"aioquic-body", None, id="aioquic"),
        pytest.param(
            "nghttp3",
            b"nghttp3-body",
            [(b"x-request", b"nghttp3-trailer")],
            id="nghttp3",
        ),
    ],
)
async def test_http3_addon_modifies_requests_and_responses(
    caplog_async, monkeypatch, client_name: str, data: bytes | None, trailers
) -> None:
    """All three client request styles stay on one QUIC connection."""
    caplog_async.set_level("INFO")
    ps = Proxyserver()
    nl = NextLayer()
    tls = TlsConfig()
    modifier = H3Modifier()

    with taddons.context(ps, nl, tls, modifier) as tctx:
        tls.configure(["confdir"])
        async with quic_server(H3EchoServer, alpn=["h3"]) as server_addr:
            orig_open_connection = mitmproxy_rs.udp.open_udp_connection

            async def open_connection_path(
                host: str, port: int, *args, **kwargs
            ) -> mitmproxy_rs.Stream:
                if host == "example.mitmproxy.org" and port == 443:
                    host = server_addr[0]
                    port = server_addr[1]
                return await orig_open_connection(host, port, *args, **kwargs)

            monkeypatch.setattr(
                mitmproxy_rs.udp, "open_udp_connection", open_connection_path
            )
            tctx.configure(
                tls,
                ssl_verify_upstream_trusted_ca=tlsdata.path(
                    "../net/data/verificationcerts/trusted-root.crt"
                ),
            )
            mode = "http3@127.0.0.1:0"
            tctx.configure(ps, mode=[mode])
            assert await ps.setup_servers()
            ps.running()
            await caplog_async.await_log("HTTP/3 proxy listening")

            addr = ps.servers[mode].listen_addrs[0]
            async with quic_connect(H3Client, alpn=["h3"], address=addr) as client:
                for i in range(3):
                    response = await client.request(
                        headers=[
                            (b":scheme", b"https"),
                            (b":authority", b"example.mitmproxy.org"),
                            (b":method", b"GET"),
                            (b":path", b"/test"),
                            (b"user-agent", client_name.encode()),
                            (b"x-request", f"{client_name}-{i}".encode()),
                        ],
                        data=data,
                        trailers=trailers,
                    ).wait_result()
                    response_headers = dict(response.headers)
                    assert response_headers[b":status"] == b"200"
                    assert response_headers[b"x-response"] == (
                        f"modified:modified:{client_name}-{i}".encode()
                    )
                    assert response_headers[b"x-response-modified"] == b"yes"
                    expected_body = (
                        b"modified-body:" + data if data is not None else b"modified-body:"
                    )
                    assert response.data == expected_body
                    assert response_headers[b"content-length"] == str(
                        len(expected_body)
                    ).encode()

                assert len(ps.connections) == 1
                assert len(modifier.flows) == 3
                assert all(
                    flow.request.headers["x-request-modified"] == "yes"
                    for flow in modifier.flows
                )
                assert len({flow.server_conn.id for flow in modifier.flows}) == 1
                assert all(flow.error is None for flow in modifier.flows)

            tctx.configure(ps, server=False)
            await caplog_async.await_log("stopped")


async def test_client_replay_http3(caplog_async) -> None:
    cp = ClientPlayback()
    ps = Proxyserver()
    tls = TlsConfig()
    modifier = H3Modifier()

    with taddons.context(cp, ps, tls, modifier) as tctx:
        tls.configure(["confdir"])
        tctx.configure(tls, ssl_insecure=True)
        async with quic_server(H3EchoServer, alpn=["h3"]) as server_addr:
            cp.running()
            flow = tflow.tflow(live=False)
            flow.client_conn.transport_protocol = "udp"
            flow.client_conn.tls = True
            flow.client_conn.alpn = b"h3"
            flow.client_conn.tls_version = "QUICv1"
            flow.server_conn.transport_protocol = "udp"
            flow.server_conn.tls = True
            flow.server_conn.alpn = b"h3"
            flow.server_conn.tls_version = "QUICv1"
            flow.request.scheme = "https"
            flow.request.host = server_addr[0]
            flow.request.port = server_addr[1]
            flow.request.authority = "example.mitmproxy.org"
            flow.request.path = "/test"
            flow.request.method = "GET"
            flow.request.content = b"replay-body"
            flow.request.headers["x-request"] = "replay"

            cp.start_replay([flow])
            await asyncio.wait_for(cp.queue.join(), 5)
            while cp.replay_tasks:
                await asyncio.sleep(0.001)

            assert flow.error is None
            assert flow.response
            assert flow.response.status_code == 200
            assert flow.response.headers["x-response"] == (
                "modified:modified:replay"
            )
            assert flow.response.content == b"modified-body:replay-body"
            assert modifier.flows == [flow]

        await cp.done()
