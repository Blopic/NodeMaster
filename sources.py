import asyncio
import hashlib
import ipaddress
import json
import socket
from math import gcd
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from .config import Settings
from .nodes import MAX_INPUT, NodeInputError, parse_one, parse_payload
from .store import Store

CF_LISTS = ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6")


def public_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not (ip.is_multicast or ip.is_reserved)


def public_host(url: str) -> str:
    try:
        part = urlsplit(normalize_url(url, https_only=True))
        host = (part.hostname or "").rstrip(".").lower()
        if part.username is not None or part.password is not None or part.port not in (None, 443):
            raise ValueError
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if "." not in host or host.endswith((".localhost", ".local", ".internal")):
                raise ValueError from None
        else:
            if not public_address(host):
                raise ValueError
        return host
    except (ValueError, TypeError) as exc:
        raise NodeInputError("请使用公网 HTTPS 地址（端口 443，无内嵌用户名或密码）") from exc


async def resolve_public(host: str) -> list[str]:
    rows = await asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(row[4][0] for row in rows))
    if not addresses or not all(map(public_address, addresses)):
        raise NodeInputError("远程地址解析到非公网地址")
    return addresses


def normalize_url(url: str, *, https_only: bool = False) -> str:
    try:
        if not url or any(ord(char) < 33 for char in url) or "\\" in url:
            raise ValueError
        parsed = urlsplit(url)
        if parsed.scheme not in ({"https"} if https_only else {"http", "https"}) or not parsed.hostname or parsed.fragment:
            raise ValueError
        if parsed.port == 0:
            raise ValueError
        if parsed.hostname == "github.com" and parsed.scheme == "https" and not parsed.username and parsed.port is None:
            parts = parsed.path.strip("/").split("/")
            if len(parts) >= 5 and parts[2] in {"blob", "raw"}:
                path = "/" + "/".join(parts[:2] + parts[3:])
                return urlunsplit(("https", "raw.githubusercontent.com", path, parsed.query, ""))
        return url
    except (TypeError, ValueError) as exc:
        raise NodeInputError("请输入有效的 HTTP/HTTPS 直链，地址不能包含片段") from exc


def pasted_source_url(line: str) -> str:
    url = line.strip().removeprefix("\ufeff").strip().removesuffix("\\").rstrip()
    if url[:len(r"https\://")].lower() == r"https\://":
        url = "https://" + url[len(r"https\://"):]
    elif url[:8].lower() == "https://":
        url = "https://" + url[8:]
    return url


def sample_cidrs(text: str, cap: int) -> list[str]:
    collections = {4: [], 6: []}
    try:
        for line in text.splitlines():
            for item in line.partition("#")[0].replace(",", " ").split():
                net = ipaddress.ip_network(item, strict=False)
                if net.is_multicast or net.is_unspecified or net.is_link_local or net.is_loopback and net.num_addresses > 1:
                    raise ValueError
                collections[net.version].append(net)
                if sum(map(len, collections.values())) > 1024:
                    raise ValueError
    except ValueError as exc:
        raise NodeInputError("CIDR 列表无效，最多 1024 个单播网段") from exc
    groups = {version: list(ipaddress.collapse_addresses(nets)) for version, nets in collections.items()}
    networks = [network for row in range(max(map(len, groups.values()))) for version in (4, 6)
                if row < len(groups[version]) for network in [groups[version][row]]]
    if not networks:
        raise NodeInputError("没有可用的 IP 网段")
    candidates = []
    for net in networks:
        exclude_edges = net.version == 4 and net.prefixlen < 31
        width = net.num_addresses - (2 if exclude_edges else 0)
        start = int(net.network_address) + (1 if exclude_edges else 0)
        digest = hashlib.sha256(str(net).encode()).digest()
        offset = int.from_bytes(digest[:16], "big") % width
        step = int.from_bytes(digest[16:], "big") % width or 1
        while gcd(step, width) != 1:
            step += 1
        candidates.append((net, start, width, offset, step))
    result = []
    for row in range(cap):
        for net, start, width, offset, step in candidates:
            if row < width:
                cls = ipaddress.IPv4Address if net.version == 4 else ipaddress.IPv6Address
                result.append(str(cls(start + (offset + row * step) % width)))
                if len(result) == cap:
                    return result
    return result


async def limited_get(client: httpx.AsyncClient, url: str | httpx.URL, timeout: float, limit: int = MAX_INPUT,
                      *, host: str | None = None, accept: str | None = None) -> str:
    route = {} if host is None else {"headers": {"Host": f"[{host}]" if ":" in host else host},
                                    "extensions": {"sni_hostname": host}}
    if accept:
        route.setdefault("headers", {})["Accept"] = accept
    async with asyncio.timeout(timeout):
        async with client.stream("GET", url, follow_redirects=False, timeout=timeout, **route) as response:
            response.raise_for_status()
            chunks = bytearray()
            async for chunk in response.aiter_bytes(chunk_size=16384):
                chunks.extend(chunk)
                if len(chunks) > limit:
                    raise NodeInputError("远程来源超过大小限制")
    try:
        return chunks.decode("utf-8-sig")
    except UnicodeError as exc:
        raise NodeInputError("来源文件需使用 UTF-8 编码") from exc


async def public_get(client: httpx.AsyncClient, url: str, timeout: float, limit: int = MAX_INPUT) -> str:
    original = httpx.URL(normalize_url(url, https_only=True))
    host = public_host(str(original))
    async with asyncio.timeout(timeout):
        try:
            addresses = await resolve_public(host)
        except NodeInputError:
            if host != "raw.githubusercontent.com":
                raise
            # Some local proxies synthesize non-public DNS answers for GitHub.
            # Re-resolve this fixed public file host without connecting to that answer.
            body = await limited_get(client, "https://1.1.1.1/dns-query?name=raw.githubusercontent.com&type=A",
                                     timeout, 16_384, accept="application/dns-json")
            try:
                addresses = [row["data"] for row in json.loads(body).get("Answer", [])
                             if row.get("type") == 1 and row.get("name", "").rstrip(".") == host]
            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                raise NodeInputError("无法获取 GitHub 文件的公网地址") from exc
            if not addresses or not all(map(public_address, addresses)):
                raise NodeInputError("无法获取 GitHub 文件的公网地址")
        for index, address in enumerate(addresses):
            try:
                # Connect to the checked IP while still verifying the original TLS name.
                return await limited_get(client, original.copy_with(host=address), timeout, limit, host=host)
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadError, httpx.RemoteProtocolError):
                if index == len(addresses) - 1:
                    raise
    raise NodeInputError("没有可用的远程地址")


async def refresh_source(store: Store, ident: int, settings: Settings, client: httpx.AsyncClient, *,
                         watch: bool = False) -> dict[str, Any]:
    source = store.get_source(ident)
    if source is None or not source["enabled"]:
        return {"status": "skipped", "reason": "source_disabled"}
    if watch and not source["remote"]:
        return {"status": "skipped", "reason": "not_remote_source"}
    cap = min(source["max_candidates"], settings.max_candidates) if source["kind"] in {"cdn", "official"} else source["max_candidates"]
    try:
        content = source["input"].strip()
        fmt = source["format"]
        digest = None
        previous = source["snapshot"]
        if source["kind"] == "official":
            urls = {"both": CF_LISTS, "ipv4": CF_LISTS[:1], "ipv6": CF_LISTS[1:]}[content]
            bodies = await asyncio.gather(*(public_get(client, url, settings.request_timeout) for url in urls))
            content = "\n".join(bodies)
            fmt = "cidr"
        elif source["remote"]:
            content = await public_get(client, content, settings.request_timeout)
            digest = hashlib.sha256(content.encode()).hexdigest()
            if previous and digest == previous["hash"] and (watch or previous.get("eliminated")):
                report = {"status": "passed", "unchanged": True, "current": len(store.source_candidates(ident, previous["ids"]))}
                store.source_status(ident, "passed", report)
                return report
        kind = "cdn" if source["kind"] in {"cdn", "official"} else "nodes"
        if fmt == "cidr":
            nodes = [parse_one(ip, "cdn", settings.cdn_port) for ip in sample_cidrs(content, cap)]
            errors = []
        else:
            nodes, errors = parse_payload(content, fmt, kind, settings.cdn_port)
        if not nodes:
            raise NodeInputError("来源没有可导入节点，已保留上次结果")
        if watch and errors:
            raise NodeInputError(f"发现 {len(errors)} 条格式错误，保留上一次成功的清单")
        replace = not watch and settings.refresh_mode == "replace" and fmt != "cidr" and not errors
        prior_ids = []
        if watch:
            prior_ids = (store.source_candidates(ident, previous["ids"]) if previous else
                         [row["id"] for row in store.list_nodes({"source": ident}, -1)["items"]])
        result = store.import_nodes(nodes, ident, replace=replace, snapshot=digest if not watch and not previous and not errors else None,
                                    staged=watch)
        report = {"status": "partial" if errors else "passed", **result, "errors": errors[:10], "truncated": 0}
        if watch:
            report.update(snapshot={"hash": digest, "ids": result["ids"]}, previous_ids=prior_ids,
                          previous=len(prior_ids), current=len(result["ids"]))
    except (NodeInputError, KeyError, LookupError) as exc:
        message = str(exc) if isinstance(exc, NodeInputError) else "来源配置已变更或不可用"
        report = {"status": "failed", "reason": "invalid_source", "message": message}
    except httpx.HTTPStatusError as exc:
        report = {"status": "failed", "reason": "http_status", "http_status": exc.response.status_code}
    except (TimeoutError, httpx.TimeoutException):
        report = {"status": "failed", "reason": "timeout"}
    except (OSError, httpx.HTTPError, httpx.InvalidURL):
        report = {"status": "failed", "reason": "network_error"}
    store.source_status(ident, report["status"], {k: v for k, v in report.items() if k not in {"ids", "new_ids", "snapshot", "previous_ids"}})
    return report
