import base64
import binascii
import csv
import io
import ipaddress
import json
import re
from dataclasses import dataclass, field
from string import Template
from typing import Any
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

import yaml

from .network_info import IP_TYPE_LABELS

PROTOCOLS = ("cdn", "turn", "turns", "stun", "ss", "vmess", "vless", "trojan", "socks5", "http", "https")
TURN_TYPES = ("turn", "turns", "stun")
CLASH_TYPES = ("ss", "vmess", "vless", "trojan", "socks5", "http", "https")
MAX_INPUT = 2 * 1024 * 1024
DOMAIN = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
TEXT_ENDPOINT = re.compile(r"(?:[\w.-]+:\d+|\[[\da-fA-F:.]+\]:\d+)")
RELAY_COLUMNS = ("中继", "relay", "relay_url", "turn_url")


class NodeInputError(ValueError):
    """A safe import error whose message contains no input data."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def clean_host(value: str) -> str:
    host = value.strip().removeprefix("[").removesuffix("]").rstrip(".").lower()
    if "%" not in host:
        try:
            return ipaddress.ip_address(host).compressed
        except ValueError:
            pass
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise NodeInputError("域名格式无效") from exc
    if not DOMAIN.fullmatch(host):
        raise NodeInputError("IP 地址或域名无效")
    return host


def defaults(protocol: str) -> tuple[int, str]:
    return {"cdn": (443, "tcp"), "turn": (3478, "udp"), "stun": (3478, "udp"),
            "turns": (5349, "tls"), "http": (80, "tcp"), "https": (443, "tls"),
            "socks5": (1080, "tcp")}.get(protocol, (443, "tcp"))


@dataclass(slots=True)
class Node:
    name: str
    protocol: str
    host: str
    port: int
    transport: str
    config: dict[str, Any] = field(default_factory=dict, repr=False)
    original: str | dict[str, Any] | None = field(default=None, repr=False)
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    id: int | None = None

    def identity(self) -> str:
        return canonical_json([self.protocol, self.host, self.port, self.transport, self.config])

    def public_fields(self) -> dict[str, Any]:
        return dict(name=self.name, protocol=self.protocol, host=self.host, port=self.port,
                    transport=self.transport, notes=self.notes, tags=self.tags)


def decode_b64(data: str) -> str:
    plain = "".join(data.split())
    return base64.b64decode(plain + "=" * (-len(plain) % 4), altchars=b"-_", validate=True).decode("utf-8")


def uri_record(uri: str) -> dict[str, Any]:
    scheme, sep, tail = uri.partition(":")
    protocol = scheme.lower()
    if not sep or protocol not in PROTOCOLS:
        raise NodeInputError("未知协议或缺少协议前缀")
    body = tail.removeprefix("//")
    if protocol == "vmess" and "@" not in body:
        payload = json.loads(decode_b64(body))
        if not isinstance(payload, dict):
            raise NodeInputError("VMess 配置无效")
        return {"protocol": protocol, "name": payload.get("ps"), "host": payload.get("add"),
                "port": payload.get("port"), "transport": payload.get("net") or "tcp",
                "config": {k: v for k, v in payload.items() if k not in {"v", "ps", "add", "port", "net"}}}
    if protocol == "ss":
        location, marker, fragment = body.partition("#")
        if "@" not in location:
            location = decode_b64(location)
        credentials, address = location.rsplit("@", 1)
        credentials = unquote(credentials)
        if ":" not in credentials:
            credentials = decode_b64(credentials)
        cipher, password = credentials.split(":", 1)
        parts = urlsplit("ss://" + address + (marker + fragment if marker else ""))
        options = dict(parse_qsl(parts.query, keep_blank_values=True, max_num_fields=100))
        return dict(protocol=protocol, host=parts.hostname, port=parts.port, name=unquote(parts.fragment),
                    config={"cipher": cipher, "password": password, **options})
    parts = urlsplit(protocol + "://" + body)
    options = dict(parse_qsl(parts.query, keep_blank_values=True, max_num_fields=100))
    transport = options.pop("transport", None) or (options.pop("type", None) if protocol in {"vless", "vmess", "trojan"} else None)
    if protocol == "turns" and transport == "tcp":
        transport = "tls"
    if protocol in TURN_TYPES and parts.path not in {"", "/"}:
        raise NodeInputError("STUN 或 TURN 地址不支持路径")
    if protocol not in TURN_TYPES and parts.path not in {"", "/"}:
        options["path"] = parts.path
    if parts.username is not None:
        key = {"vless": "uuid", "vmess": "uuid", "trojan": "password"}.get(protocol, "username")
        options[key] = unquote(parts.username)
    if parts.password is not None:
        options["password"] = unquote(parts.password)
    return dict(protocol=protocol, host=parts.hostname, port=parts.port, name=unquote(parts.fragment),
                transport=transport, config=options)


def parse_one(value: str | dict[str, Any], kind: str = "nodes", cdn_port: int = 443) -> Node:
    try:
        original = value
        if isinstance(value, str):
            text = value.strip()
            endpoint, _, label = text.partition("#")
            endpoint = endpoint.strip()
            scheme = endpoint.partition(":")[0].lower()
            if text.startswith("{"):
                record = json.loads(text)
            elif "://" not in endpoint and (kind == "cdn" or (scheme not in PROTOCOLS and TEXT_ENDPOINT.fullmatch(endpoint))):
                try:
                    host = ipaddress.ip_address(endpoint).compressed
                    port = None
                except ValueError:
                    address = urlsplit("cdn://" + endpoint)
                    if address.username is not None or address.path or address.query:
                        raise NodeInputError("CDN 候选应为 IP 或域名，可附端口和名称")
                    host, port = address.hostname, address.port
                record = {"protocol": "cdn", "host": host, "port": port, "name": unquote(label).strip()}
            else:
                record = uri_record(text)
        elif isinstance(value, dict):
            record = value
        else:
            raise NodeInputError("节点记录必须是 URI 或对象")
        if not isinstance(record, dict):
            raise NodeInputError("节点记录必须是对象")
        protocol = str(record.get("protocol") or record.get("type") or ("cdn" if kind == "cdn" else "")).lower()
        protocol = {"socks": "socks5", "shadowsocks": "ss"}.get(protocol, protocol)
        if protocol not in PROTOCOLS or (kind == "cdn" and protocol != "cdn"):
            raise NodeInputError("节点类型与导入方式不匹配")
        host = clean_host(str(record.get("host") or record.get("server") or record.get("ip") or ""))
        port_default, transport_default = defaults(protocol)
        raw_port = record.get("port")
        port = int(raw_port) if raw_port not in (None, "") else (cdn_port if protocol == "cdn" else port_default)
        if isinstance(raw_port, (bool, float)) or not 1 <= port <= 65535:
            raise NodeInputError("端口应为 1 至 65535 的整数")
        transport = str(record.get("transport") or record.get("network") or transport_default).lower()
        if protocol == "turns" and transport == "tcp":
            transport = "tls"
        if protocol in TURN_TYPES and transport not in {"udp", "tcp", "tls"}:
            raise NodeInputError("支持的 TURN/STUN 传输为 UDP、TCP、TLS")
        if protocol == "turns" and transport != "tls":
            raise NodeInputError("TURNS 需要 TLS")
        reserved = {"name", "type", "protocol", "host", "ip", "server", "port", "network", "transport", "config", "notes", "tags", "nodemaster"}
        config = record.get("config") or {}
        if isinstance(config, str):
            config = json.loads(config)
        if not isinstance(config, dict):
            raise NodeInputError("节点配置需要是对象")
        config = {**{k: v for k, v in record.items() if k not in reserved}, **config}
        if protocol in TURN_TYPES:
            for key in ("username", "password", "sni", "servername"):
                if key in config and not isinstance(config[key], str):
                    raise NodeInputError("TURN 凭据和 TLS 名称需要是文本")
        canonical_json(config)
        tags = record.get("tags") or []
        if isinstance(tags, str):
            tags = tags.split(",")
        if not isinstance(tags, list):
            raise NodeInputError("标签需要是列表或逗号分隔的文本")
        name = str(record.get("name") or f"{protocol.upper()} {host}:{port}").strip()[:160]
        return Node(name, protocol, host, port, transport, config, original,
                    str(record.get("notes") or "")[:2000], sorted({str(x).strip()[:60] for x in tags if str(x).strip()})[:30])
    except NodeInputError:
        raise
    except (TypeError, ValueError, OverflowError, RecursionError, binascii.Error) as exc:
        raise NodeInputError("节点格式无效，请检查地址、端口或认证配置") from exc


class NodeYamlLoader(yaml.SafeLoader):
    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            raise NodeInputError("导入不支持 YAML 别名，请先展开别名")
        return super().compose_node(parent, index)


def guess_format(text: str) -> str:
    if text.lstrip().startswith("{") or re.match(r'\[\s*(?:["{\[\]]|$)', text):
        return "json"
    if re.search(r"(?m)^\s*(proxies|nodes):|^\s*-\s*(?:\{|name:|type:)", text):
        return "yaml"
    header = text.splitlines()[0].lower()
    if "," in header and any(word in header for word in ("ip", "server", "protocol", "type", "host", "地址", *RELAY_COLUMNS)):
        return "csv"
    return "txt"


def parse_payload(text: str, fmt: str, kind: str, cdn_port: int = 443) -> tuple[list[Node], list[dict[str, Any]]]:
    if len(text.encode("utf-8")) > MAX_INPUT:
        raise NodeInputError("导入文件上限为 2 MiB")
    text = text.strip().removeprefix("\ufeff").strip()
    if not text:
        raise NodeInputError("导入内容为空")
    if fmt == "auto":
        fmt = guess_format(text)
    try:
        if fmt == "csv":
            records = []
            reader = csv.DictReader(io.StringIO(text, newline=""))
            headers = {column.strip().lower() for column in reader.fieldnames or []}
            relay_column = next((column for column in RELAY_COLUMNS if column in headers), None)
            if relay_column:
                kind = "nodes"
            for row in reader:
                row = {k.strip().lower(): v for k, v in row.items() if k is not None and v not in (None, "")}
                if relay_column:
                    uri = row.pop(relay_column, "").strip()
                    scheme = uri.partition(":")[0].lower()
                    if scheme not in TURN_TYPES:
                        records.append(None)
                        continue
                    notes = "\n".join(f"{key}：{value}" for key, value in row.items())
                    records.append((uri, notes))
                    continue
                if kind == "cdn":
                    ip = next((row.get(k) for k in ("ip 地址", "ip地址", "ip address", "ip", "host", "server", "地址") if row.get(k)), "")
                    row = {"host": ip, "port": row.get("port"), "name": row.get("name"), "protocol": "cdn"}
                records.append(row)
        elif fmt in {"json", "yaml"}:
            records = json.loads(text) if fmt == "json" else yaml.load(text, Loader=NodeYamlLoader)
            if isinstance(records, dict):
                records = next((records[k] for k in ("proxies", "nodes") if k in records), [records])
            if not isinstance(records, list):
                raise NodeInputError("JSON 或 YAML 需要包含节点数组")
        else:
            if fmt != "txt":
                raise NodeInputError("不支持此文件格式")
            if kind != "cdn" and ":" not in text and not text.startswith("{"):
                try:
                    decoded = decode_b64(text)
                    if re.search(r"(?im)^\s*(?:turns?|stun|ss|vmess|vless|trojan|https?|socks5):", decoded):
                        text = decoded
                except (ValueError, UnicodeError, binascii.Error):
                    pass
            records = [s.strip() for s in text.splitlines() if s.strip() and not s.lstrip().startswith("#")]
    except NodeInputError:
        raise
    except (ValueError, TypeError, yaml.YAMLError, csv.Error, RecursionError) as exc:
        raise NodeInputError("无法读取文件，请检查声明的格式") from exc
    if not records:
        raise NodeInputError("没有可导入的节点记录")
    nodes, errors = [], []
    for i, record in enumerate(records, 1):
        try:
            if isinstance(record, tuple):
                uri, notes = record
                node = parse_one(uri, kind, cdn_port)
                node.notes = notes[:2000]
                nodes.append(node)
            else:
                nodes.append(parse_one(record, kind, cdn_port))
        except NodeInputError as exc:
            errors.append({"row": i, "message": str(exc)})
    return nodes, errors


def clash_config(node: Node, sensitive: bool) -> dict[str, Any] | None:
    if node.protocol not in CLASH_TYPES:
        return None
    options = node.config.copy() if sensitive else {}
    if isinstance(node.original, str) and sensitive:
        if node.protocol == "vmess" and "id" in options:
            if node.transport not in {"tcp", "ws"} or options.get("type", "none") not in {"", "none"}:
                return None
            vmess = options
            options = {"uuid": vmess["id"], "alterId": int(vmess.get("aid") or 0),
                       "cipher": vmess.get("scy") or "auto", "tls": vmess.get("tls") == "tls",
                       **({"servername": vmess["sni"]} if vmess.get("sni") else {})}
            if node.transport == "ws":
                options["ws-opts"] = {"path": vmess.get("path") or "/", "headers": {"Host": vmess.get("host") or node.host}}
        elif node.protocol in {"vless", "trojan", "vmess"}:
            uri_options = options
            allowed = {"uuid", "password", "security", "sni", "host", "path", "encryption", "flow"}
            if uri_options.keys() - allowed or node.transport not in {"tcp", "ws"} or uri_options.get("security") not in {None, "none", "tls"} or uri_options.get("encryption") not in {None, "none"}:
                return None
            options = {k: v for k, v in uri_options.items() if k in {"uuid", "password", "flow"}}
            if uri_options.get("security") == "tls" and node.protocol != "trojan":
                options["tls"] = True
            if uri_options.get("sni"):
                options["sni" if node.protocol == "trojan" else "servername"] = uri_options["sni"]
            if node.transport == "ws":
                options["ws-opts"] = {"path": uri_options.get("path") or "/", "headers": {"Host": uri_options.get("host") or node.host}}
        elif node.protocol == "ss" and options.keys() - {"password", "cipher"}:
            return None
        elif node.protocol in {"http", "https", "socks5"} and options.keys() - {"username", "password"}:
            return None
    if node.protocol in {"vmess", "vless", "trojan"} and node.transport != "tcp":
        options["network"] = node.transport
    if node.protocol == "https":
        options["tls"] = True
    return {**options, "name": node.name, "type": "http" if node.protocol == "https" else node.protocol,
            "server": node.host, "port": node.port}


def endpoint(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def node_address(node: Node, sensitive: bool = False) -> str:
    address = endpoint(node.host, node.port)
    if node.protocol not in TURN_TYPES:
        return address
    options = dict(node.config) if sensitive else {}
    username = options.pop("username", None)
    password = options.pop("password", None)
    credentials = ""
    if username is not None or password is not None:
        credentials = quote(username or "", safe="")
        if password is not None:
            credentials += ":" + quote(password, safe="")
        credentials += "@"
    if node.transport != defaults(node.protocol)[1]:
        options["transport"] = node.transport
    query = "?" + urlencode(options) if options else ""
    return f"{node.protocol}://{credentials}{address}{query}"


def annotation_values(node: Node, row: dict[str, Any], index: int) -> dict[str, Any]:
    location = row.get("location") or {}
    ip_type = row.get("ip_type") or "unknown"
    return {**node.public_fields(), "ip": node.host, "address": node_address(node), "index": index,
            "country": location.get("country"), "region": location.get("region"), "city": location.get("city"),
            "location": " ".join(dict.fromkeys(location[key] for key in ("country", "region", "city") if location.get(key))),
            "ip_type": ip_type, "ip_type_label": IP_TYPE_LABELS.get(ip_type, ip_type),
            "latency_ms": row.get("latency"), "speed_mbps": row.get("speed"), "success_rate": row.get("success_rate"),
            "score": row.get("score"), "quality_score": row.get("quality_score"),
            "combined_score": row.get("combined_score"), "status": row.get("status"),
            "tags": ",".join(node.tags)}


def template_value(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def render_export(nodes: list[Node], fmt: str, sensitive: bool = False, template: str = "",
                  metadata: dict[int, dict[str, Any]] | None = None, *, suffix: str = "",
                  preferred_endpoint: str = "", addresses_only: bool = False) -> str:
    if fmt == "clash":
        proxies = [proxy for n in nodes if (proxy := clash_config(n, sensitive)) is not None]
        used: set[str] = set()
        for proxy in proxies:
            name = proxy["name"]
            suffix = 2
            while proxy["name"] in used:
                proxy["name"] = f"{name} ({suffix})"
                suffix += 1
            used.add(proxy["name"])
        return yaml.safe_dump({"proxies": proxies}, allow_unicode=True, sort_keys=False)
    records = [n.public_fields() | ({"config": n.config} if sensitive else {}) for n in nodes]
    if metadata and fmt in {"json", "yaml", "csv"}:
        for node, record in zip(nodes, records):
            if node.id in metadata:
                record["nodemaster"] = metadata[node.id]
    if fmt == "json":
        return json.dumps(records, ensure_ascii=False, indent=2)
    if fmt == "yaml":
        return yaml.safe_dump(records, allow_unicode=True, sort_keys=False)
    if fmt == "csv":
        csv_buffer = io.StringIO(newline="")
        columns = ["name", "protocol", "host", "port", "transport", "notes", "tags"]
        columns += ["nodemaster"] if metadata else []
        columns += ["config"] if sensitive else []
        writer = csv.DictWriter(csv_buffer, columns)
        writer.writeheader()
        for record in records:
            safe: dict[str, Any] = {**record, "tags": ",".join(record["tags"])}
            if "nodemaster" in safe:
                safe["nodemaster"] = canonical_json(safe["nodemaster"])
            if sensitive:
                safe["config"] = canonical_json(record["config"])
            for key, value in safe.items():
                if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
                    safe[key] = "'" + value
            writer.writerow(safe)
        return csv_buffer.getvalue()
    pattern = Template(template if fmt == "template" else suffix)
    if not pattern.is_valid():
        raise NodeInputError("模板包含无效的占位符，使用 $$ 输出美元符号")
    lines = []
    for index, (node, record) in enumerate(zip(nodes, records), 1):
        label = ""
        if fmt == "template" or suffix:
            values = annotation_values(node, (metadata or {}).get(node.id, {}), index)
            if fmt == "template":
                values.update(config=canonical_json(node.config) if sensitive else "",
                              uri=node.original if sensitive and isinstance(node.original, str) else "")
            try:
                label = pattern.substitute({key: template_value(value) for key, value in values.items()})
            except KeyError as exc:
                raise NodeInputError(f"模板包含未知占位符：${exc.args[0]}") from exc
            if fmt == "template":
                lines.append(label)
                continue
            label = " ".join(label.splitlines()).strip()
        address = node_address(node, sensitive)
        if preferred_endpoint:
            label = label.replace("$", "＄")
            lines.append(f"{preferred_endpoint}#{label}${address}")
        elif node.protocol in ("cdn", *TURN_TYPES) or addresses_only:
            lines.append(f"{address}#{label}" if label else address)
        elif sensitive and not suffix and isinstance(node.original, str) and "\n" not in node.original:
            lines.append(node.original)
        else:
            lines.append(canonical_json(record | ({"name": label} if label else {})))
    return "\n".join(lines) + ("\n" if lines and fmt != "template" else "")
