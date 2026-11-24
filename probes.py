import asyncio
import hashlib
import ipaddress
import logging
import re
import secrets
import socket
import ssl
import statistics
from contextlib import suppress
from functools import lru_cache
from struct import error as StructError
from time import perf_counter
from typing import Any

import h11
from aioice import stun, turn

from .config import Settings
from .nodes import TURN_TYPES, Node, canonical_json, clean_host

# These library loggers can include protocol attributes. Use our staged diagnostics instead.
logging.getLogger("aioice.turn").setLevel(logging.WARNING)
logging.getLogger("aioice.ice").setLevel(logging.WARNING)


@lru_cache(maxsize=1)
def default_tls_context() -> ssl.SSLContext:
    return ssl.create_default_context()


def milliseconds(start: float) -> float:
    return round((perf_counter() - start) * 1000, 2)


def scope_for(node: Node, settings: Settings, level: str) -> tuple[str, dict[str, Any]]:
    if node.protocol == "cdn":
        spec = {"domain": settings.cdn_domain, "sni": settings.cdn_sni or settings.cdn_domain,
                "host": settings.cdn_host or settings.cdn_domain, "scheme": settings.cdn_scheme,
                "port": node.port, "path": settings.cdn_path, "download_bytes": settings.download_bytes}
    else:
        spec = {"protocol": node.protocol, "transport": node.transport, "port": node.port, "level": level,
                "echo": [settings.relay_host, settings.relay_port] if level == "full" and settings.relay_host else None}
        if level == "full" and settings.relay_mode == "stun":
            spec["relay_mode"] = "stun"
    return node.protocol + ":" + hashlib.sha256(canonical_json(spec).encode()).hexdigest()[:20], spec


def classify(exc: BaseException) -> str:
    if isinstance(exc, (TimeoutError, stun.TransactionTimeout)):
        return "timeout"
    if isinstance(exc, socket.gaierror):
        return "dns_failed"
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "tls_certificate"
    if isinstance(exc, ssl.SSLError):
        return "tls_failed"
    if isinstance(exc, (h11.ProtocolError, stun.TransactionError)):
        return "protocol_error"
    if isinstance(exc, OSError):
        return "network_error"
    return "invalid_config"


async def cdn_sample(node: Node, settings: Settings, row: dict[str, Any], context: ssl.SSLContext | None) -> bool:
    writer = None
    try:
        row["stage"] = "tcp"
        start = perf_counter()
        async with asyncio.timeout(settings.connect_timeout):
            reader, writer = await asyncio.open_connection(node.host, node.port, happy_eyeballs_delay=0.25)
        row.update(tcp_ms=milliseconds(start), endpoint_reachable=True, resolved_ip=writer.get_extra_info("peername")[0])
        if settings.cdn_scheme == "https":
            row["stage"] = "tls"
            start = perf_counter()
            async with asyncio.timeout(settings.connect_timeout):
                await writer.start_tls(context or default_tls_context(), server_hostname=settings.cdn_sni or settings.cdn_domain,
                                       ssl_handshake_timeout=settings.connect_timeout)
            row["tls_ms"] = milliseconds(start)
        row["stage"] = "http"
        http = h11.Connection(h11.CLIENT, max_incomplete_event_size=32 * 1024)
        host = settings.cdn_host or settings.cdn_domain
        if ":" in host:
            host = f"[{host}]"
        if not settings.cdn_host and node.port != (443 if settings.cdn_scheme == "https" else 80):
            host = f"{host}:{node.port}"
        request = h11.Request(method="GET", target=settings.cdn_path, headers=[
            ("Host", host), ("Connection", "close"), ("Accept-Encoding", "identity"), ("User-Agent", "NodeMaster/1")])
        start = perf_counter()
        writer.write(http.send(request) + http.send(h11.EndOfMessage()))
        count = 0
        download_start = None
        async with asyncio.timeout(settings.request_timeout):
            await writer.drain()
            while True:
                event = http.next_event()
                if event is h11.NEED_DATA:
                    data = await reader.read(16384)
                    if data and "ttfb_ms" not in row:
                        row["ttfb_ms"] = milliseconds(start)
                    http.receive_data(data)
                elif isinstance(event, h11.Response):
                    row["http_status"] = event.status_code
                    if not 200 <= event.status_code < 300:
                        row.update(error="http_status", http_ms=milliseconds(start))
                        return False
                    domain = settings.cdn_sni or settings.cdn_domain
                    if settings.cdn_scheme == "https" and domain.endswith(".cloudflare.com") and host.split(":", 1)[0] == domain:
                        ray = dict(event.headers).get(b"cf-ray", b"")
                        if match := re.fullmatch(rb"[0-9a-fA-F]{16,32}-([A-Z]{3})", ray):
                            row["cdn_colo"] = match[1].decode("ascii")
                    download_start = perf_counter()
                elif isinstance(event, h11.Data):
                    count += min(len(event.data), settings.download_bytes - count)
                    if count >= settings.download_bytes:
                        break
                elif isinstance(event, h11.EndOfMessage):
                    break
                elif event is h11.PAUSED or isinstance(event, h11.ConnectionClosed):
                    raise h11.RemoteProtocolError("HTTP response did not finish")
        row.update(stage="http_complete", http_ms=milliseconds(start), download_bytes=count, latency_ms=row.get("ttfb_ms"))
        # Floor protects short in-memory responses from producing an infinite rate.
        if count and download_start is not None:
            row["speed_mbps"] = round(count * 8 / max(0.001, perf_counter() - download_start) / 1_000_000, 3)
        return True
    finally:
        if writer is not None:
            writer.close()
            with suppress(OSError, TimeoutError):
                async with asyncio.timeout(0.3):
                    await writer.wait_closed()


class ObservedTurn:
    def __init__(self, *args: Any, observed: dict[str, Any], **kwargs: Any):
        self.observed = observed
        super().__init__(*args, **kwargs)

    async def request(self, request: stun.Message) -> tuple[stun.Message, tuple[str, int]]:
        try:
            result = await super().request(request)
        except stun.TransactionFailed as exc:
            if exc.response.message_method != request.message_method:
                raise stun.TransactionError("Unexpected method") from None
            self.observed["protocol_response"] = True
            if request.message_method == stun.Method.ALLOCATE:
                self.observed["turn_response"] = True
                self.observed["turn_error"] = exc.response.error_code
                if exc.response.error_code == 401:
                    self.observed["auth"] = "required" if not self.integrity_key else "rejected"
                elif exc.response.error_code == 441:
                    self.observed["auth"] = "rejected"
            raise
        if result[0].message_method != request.message_method:
            raise stun.TransactionError("Unexpected method")
        self.observed["protocol_response"] = True
        if request.message_method == stun.Method.ALLOCATE:
            self.observed["turn_response"] = True
            self.observed["auth"] = "verified" if self.integrity_key else "not_required"
            self.observed.pop("turn_error", None)
        return result

    async def channel_bind(self, channel_number: int, addr: tuple[str, int]) -> None:
        self.observed["stage"] = "channel_bind"
        await super().channel_bind(channel_number, addr)
        self.observed["channel_ok"] = True


class ObservedUdp(ObservedTurn, turn.TurnClientUdpProtocol):
    pass


class ObservedTcp(ObservedTurn, turn.TurnClientTcpProtocol):
    pass


class RelayReceiver(asyncio.DatagramProtocol):
    def __init__(self, peer: tuple[str, int], mode: str):
        self.peer = peer
        self.binding = stun.Message(stun.Method.BINDING, stun.Class.REQUEST) if mode == "stun" else None
        self.payload = bytes(self.binding) if self.binding else secrets.token_bytes(24)
        self.received = asyncio.get_running_loop().create_future()

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.received.done() or self.peer != addr[:2]:
            return
        if self.binding is None:
            if secrets.compare_digest(self.payload, data):
                self.received.set_result(True)
            return
        if data[4:8] != b"\x21\x12\xa4\x42":
            return
        try:
            reply = stun.parse_message(data)
        except (ValueError, StructError):
            return
        if (reply.message_method == stun.Method.BINDING and reply.message_class == stun.Class.RESPONSE
                and reply.transaction_id == self.binding.transaction_id
                and (mapped := reply.attributes.get("XOR-MAPPED-ADDRESS") or reply.attributes.get("MAPPED-ADDRESS"))):
            self.received.set_result(mapped)

    def connection_lost(self, exc: Exception | None) -> None:
        if not self.received.done():
            self.received.set_result(False)

    def error_received(self, exc: Exception) -> None:
        self.connection_lost(exc)


async def relay_peer(host: str, port: int, timeout: float, family: int = socket.AF_UNSPEC) -> tuple[str, int]:
    async with asyncio.timeout(timeout):
        addresses = await asyncio.get_running_loop().getaddrinfo(host, port, family=family, type=socket.SOCK_DGRAM)
    address = addresses[0][4]
    peer_ip = ipaddress.ip_address(address[0])
    if peer_ip.is_multicast or peer_ip.is_unspecified or peer_ip.is_link_local:
        raise ValueError("Invalid UDP verification peer")
    return peer_ip.compressed, port


async def check_udp_echo(host: str, port: int, timeout: float, mode: str = "echo") -> dict[str, Any]:
    transport = None
    start = perf_counter()
    try:
        peer = await relay_peer(host, port, timeout)
        receiver = RelayReceiver(peer, mode)
        async with asyncio.timeout(timeout):
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(lambda: receiver, remote_addr=peer)
            transport.sendto(receiver.payload)
            if response := await receiver.received:
                result = {"status": "passed", "latency_ms": milliseconds(start), "peer_ip": peer[0]}
                if mode == "stun":
                    result["mapped_address"] = list(response)
                return result
            return {"status": "network_error"}
    except TimeoutError:
        return {"status": "stun_peer_timeout" if mode == "stun" else "echo_timeout"}
    except (OSError, ValueError) as exc:
        return {"status": classify(exc)}
    finally:
        if transport is not None:
            transport.close()


async def turn_sample(node: Node, settings: Settings, level: str, row: dict[str, Any], attempt: int,
                      context: ssl.SSLContext | None) -> bool:
    loop = asyncio.get_running_loop()
    udp = node.transport == "udp"
    ipv = node.config.get("ip_version")
    family = {"4": socket.AF_INET, "6": socket.AF_INET6}.get(str(ipv), socket.AF_UNSPEC)
    row["stage"] = "dns"
    start = perf_counter()
    async with asyncio.timeout(settings.connect_timeout):
        addresses = await loop.getaddrinfo(node.host, node.port, family=family, type=socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
    choices = list(dict.fromkeys((item[0], item[4]) for item in addresses))
    family, address = choices[attempt % len(choices)]
    ip = address[0]
    row.update(dns_ms=milliseconds(start), resolved_ip=ip, address_family=6 if family == socket.AF_INET6 else 4,
               resolved_addresses=list(dict.fromkeys(item[1][0] for item in choices)), transport=node.transport)
    observed = ObservedUdp if udp else ObservedTcp
    protocol = observed((ip, node.port), node.config.get("username"), node.config.get("password"), 60, 30, observed=row)
    transport = None
    sock = None
    try:
        if udp:
            row["stage"] = "udp"
            transport, _ = await loop.create_datagram_endpoint(lambda: protocol, remote_addr=(ip, node.port), family=family)
        else:
            row["stage"] = "tcp"
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.setblocking(False)
            start = perf_counter()
            async with asyncio.timeout(settings.connect_timeout):
                await loop.sock_connect(sock, address)
            row.update(tcp_ms=milliseconds(start), endpoint_reachable=True)
            if node.transport == "tls":
                row["stage"] = "tls"
                sni = clean_host(node.config.get("sni") or node.config.get("servername") or node.host)
                start = perf_counter()
                async with asyncio.timeout(settings.connect_timeout):
                    transport, _ = await loop.create_connection(lambda: protocol, sock=sock,
                        ssl=context or default_tls_context(), server_hostname=sni,
                        ssl_handshake_timeout=settings.connect_timeout)
                row["tls_ms"] = milliseconds(start)
            else:
                transport, _ = await loop.create_connection(lambda: protocol, sock=sock)
            sock = None
        row["stage"] = "binding"
        start = perf_counter()
        binding = stun.Message(stun.Method.BINDING, stun.Class.REQUEST)
        try:
            async with asyncio.timeout(settings.request_timeout if level == "quick" or node.protocol == "stun" else min(1, settings.request_timeout)):
                response, _ = await protocol.request(binding)
            row.update(binding_ok=True, protocol_ms=milliseconds(start), endpoint_reachable=True)
            if address := response.attributes.get("XOR-MAPPED-ADDRESS") or response.attributes.get("MAPPED-ADDRESS"):
                row["mapped_address"] = list(address)
        except (TimeoutError, stun.TransactionError) as exc:
            row["binding_error"] = classify(exc)
            if row.get("protocol_response"):
                row["endpoint_reachable"] = True
        if level == "quick" or node.protocol == "stun":
            row["latency_ms"] = row.get("protocol_ms")
            return bool(row.get("binding_ok"))
        row["stage"] = "allocate"
        start = perf_counter()
        try:
            async with asyncio.timeout(settings.request_timeout):
                relay_address = await protocol.connect()
        finally:
            row["allocate_ms"] = milliseconds(start)
            if row.get("turn_response"):
                row["endpoint_reachable"] = True
        row.update(allocate_ok=True, relay_address=list(relay_address), latency_ms=row["allocate_ms"])
        if level == "standard":
            return True
        row["stage"] = "relay"
        if not settings.relay_host:
            row["error"] = "echo_unconfigured"
            return False
        family = socket.AF_INET6 if ipaddress.ip_address(relay_address[0]).version == 6 else socket.AF_INET
        try:
            peer = await relay_peer(settings.relay_host, settings.relay_port, settings.connect_timeout, family)
        except (socket.gaierror, TimeoutError):
            row["error"] = "relay_peer_unresolved" if settings.relay_mode == "stun" else "echo_family_mismatch"
            return False
        row["relay_peer"] = list(peer)
        receiver = RelayReceiver(peer, settings.relay_mode)
        protocol.receiver = receiver
        start = perf_counter()
        try:
            async with asyncio.timeout(settings.request_timeout):
                await protocol.send_data(receiver.payload, peer)
        except (TimeoutError, stun.TransactionTimeout):
            row["error"] = "channel_timeout" if row["stage"] == "channel_bind" else "timeout"
            return False
        except stun.TransactionFailed as exc:
            row.update(error="channel_rejected", channel_error=exc.response.error_code)
            return False
        row["stage"] = "stun_peer" if settings.relay_mode == "stun" else "echo"
        try:
            async with asyncio.timeout(min(settings.relay_echo_timeout, settings.request_timeout)):
                response = await receiver.received
                if not response:
                    row["error"] = "network_error"
                    return False
        except TimeoutError:
            row["error"] = "stun_peer_timeout" if settings.relay_mode == "stun" else "echo_timeout"
            return False
        if settings.relay_mode == "stun":
            row["relay_mapped_address"] = list(response)
        row.update(relay_ok=True, relay_ms=milliseconds(start))
        return True
    finally:
        if sock is not None:
            sock.close()
        if transport is not None:
            try:
                if protocol.relayed_address and not asyncio.current_task().cancelling():
                    with suppress(TimeoutError, OSError, stun.TransactionError):
                        async with asyncio.timeout(0.35):
                            await protocol.delete()
            finally:
                if protocol.refresh_task:
                    protocol.refresh_task.cancel()
                transport.close()


def score_result(settings: Settings, latency: float | None, speed: float | None, rate: float,
                 jitter: float | None, cdn: bool) -> tuple[float | None, dict[str, float]]:
    parts = {"success": rate}
    if latency is not None:
        parts["latency"] = 100 * settings.latency_target / (settings.latency_target + latency)
    if cdn and speed is not None:
        parts["speed"] = 100 * min(1, speed / settings.speed_target)
    if jitter is not None:
        parts["jitter"] = 100 * settings.jitter_target / (settings.jitter_target + jitter)
    weights = settings.weights.model_dump()
    weight = sum(weights[key] for key in parts)
    score = round(sum(weights[key] * part for key, part in parts.items()) / weight, 2) if weight else None
    return score, {key: round(value, 2) for key, value in parts.items()}


async def detect(node: Node, settings: Settings, level: str = "standard", *, ssl_context: ssl.SSLContext | None = None) -> dict[str, Any]:
    cdn = node.protocol == "cdn"
    level = "http" if cdn else "quick" if node.protocol == "stun" else level
    scope, target = scope_for(node, settings, level)
    if not cdn and node.protocol not in TURN_TYPES:
        return {"scope": scope, "level": level, "status": "unsupported", "data": {"target": target}}
    samples, trials = [], []
    for attempt in range(settings.attempts):
        for retry in range(settings.retries + 1):
            row: dict[str, Any] = {"attempt": attempt + 1, "retry": retry}
            try:
                async with asyncio.timeout(settings.probe_timeout):
                    success = (await cdn_sample(node, settings, row, ssl_context) if cdn else
                               await turn_sample(node, settings, level, row, attempt + retry, ssl_context))
            except (TimeoutError, OSError, ValueError, h11.ProtocolError, stun.TransactionError) as exc:
                success = False
                row["error"] = classify(exc)
                if row["error"] == "timeout":
                    row["error"] = {"allocate": "allocate_timeout", "channel_bind": "channel_timeout",
                                    "echo": "echo_timeout", "stun_peer": "stun_peer_timeout"}.get(row.get("stage"), "timeout")
                if isinstance(exc, stun.TransactionFailed) and row.get("turn_error") in {401, 441}:
                    row["error"] = "authentication"
            row["success"] = success
            trials.append(row)
            if success or row.get("error") in {"authentication", "tls_certificate", "echo_unconfigured",
                                               "echo_family_mismatch", "echo_timeout", "channel_rejected",
                                               "stun_peer_timeout", "relay_peer_unresolved"}:
                break
            if retry < settings.retries:
                await asyncio.sleep(settings.retry_delay)
        samples.append(row)
    passed = [r for r in samples if r["success"]]
    latencies = [r["latency_ms"] for r in passed if r.get("latency_ms") is not None]
    speeds = [r["speed_mbps"] for r in passed if r.get("speed_mbps") is not None]
    rate = round(100 * len(passed) / len(samples), 2)
    latency = round(statistics.median(latencies), 2) if latencies else None
    jitter = round(statistics.pstdev(latencies), 2) if len(latencies) > 1 else None
    speed = round(statistics.median(speeds), 3) if speeds else None
    score, parts = score_result(settings, latency, speed, rate, jitter, cdn) if passed else (None, {})
    status = "passed" if passed else "partial" if any(r.get("endpoint_reachable") for r in trials) else "failed"
    return {"scope": scope, "level": level, "status": status, "latency": latency, "speed": speed,
            "jitter": jitter, "success_rate": rate, "score": score,
            "data": {"target": target, "samples": samples, "trials": trials if len(trials) != len(samples) else [],
                     "average_ms": round(statistics.mean(latencies), 2) if latencies else None,
                     "timeouts": sum(str(r.get("error")).endswith("timeout") or r.get("binding_error") == "timeout" for r in trials),
                     "score_parts": parts}}
