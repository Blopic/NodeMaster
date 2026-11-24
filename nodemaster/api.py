import asyncio
import ipaddress
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta, timezone
from math import isfinite
from pathlib import Path
from tempfile import NamedTemporaryFile
from time import monotonic
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, Field, ValidationError
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import FileResponse, Response

from . import __version__
from .config import Settings
from .jobs import TaskManager
from .network_info import IP_TYPES
from .nodes import MAX_INPUT, PROTOCOLS, TURN_TYPES, NodeInputError, TEXT_ENDPOINT, endpoint, parse_one, parse_payload, render_export
from .probes import check_udp_echo, detect
from .quality import KEY_PROVIDERS, QualityService, quality_profile
from .sources import limited_get, normalize_url, pasted_source_url, public_address, public_get, public_host, refresh_source, resolve_public
from .store import Store

LOG = logging.getLogger("nodemaster")
WEB_ROOT = Path(__file__).parent / "static"
PLAN_ZONE = timezone(timedelta(hours=8))
FILTER_NUMBERS = {"min_score", "min_quality_score", "max_latency", "min_speed", "min_success", "max_jitter"}
FILTER_CHOICES = {"protocol": PROTOCOLS, "status": {"untested", "unsupported", "passed", "partial", "failed"},
                  "country": None, "ip_type": IP_TYPES}
PRESET_FILTERS = FILTER_NUMBERS | {"q", "protocol", "status", "country", "ip_type", "enabled", "source", "tag", "family", "port", "scope", "sort", "ascending", "recommended"}
Workspace = Literal["cdn", "turn", "other", "all"]
SuggestionGroup = Literal["cdn", "turn", "turn_server", "all"]
SuggestionMode = Literal["combined", "overall", "latency", "stability", "quality"]


def error(status: int, message: str) -> HTTPException:
    return HTTPException(status, message)


def safe_host(url: str) -> str:
    try:
        return public_host(url)
    except NodeInputError as exc:
        raise error(422, str(exc)) from exc


def validate_https_target(url: str, proxy_url: str = "") -> str:
    host = safe_host(url)
    if proxy_url:
        proxy_host = urlsplit(proxy_url).hostname
        if proxy_host and proxy_host.casefold() == host:
            raise error(422, "查询地址不能与本地代理地址相同")
    return url


class Body(BaseModel):
    model_config = {"extra": "forbid"}


class ImportBody(Body):
    content: str = Field(max_length=MAX_INPUT)
    format: Literal["auto", "txt", "csv", "json", "yaml", "cidr"] = "auto"
    kind: Literal["nodes", "cdn"] = "nodes"
    name: str | None = Field(default=None, max_length=100)
    tags: list[str] = Field(default_factory=list, max_length=30)
    max_candidates: int = Field(default=32, ge=1, le=256)


class NodeBody(Body):
    name: str = Field(default="", max_length=160)
    protocol: str
    host: str
    port: int = Field(ge=1, le=65535)
    transport: str | None = None
    config: dict[str, Any] = Field(default_factory=dict, max_length=50)
    notes: str = Field(default="", max_length=2000)
    tags: list[str] = Field(default_factory=list, max_length=30)


class SourceBody(Body):
    name: str = Field(min_length=1, max_length=100)
    kind: Literal["nodes", "cdn", "official"]
    format: Literal["auto", "txt", "csv", "json", "yaml", "cidr"]
    content: str = Field(max_length=2048)
    max_candidates: int = Field(default=32, ge=1, le=256)
    enabled: bool = True


class SourceUpdate(Body):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    max_candidates: int | None = Field(default=None, ge=1, le=256)
    enabled: bool | None = None


class SourceBatch(Body):
    urls: str = Field(min_length=1, max_length=2_097_152)
    name: str = Field(default="", max_length=80)
    kind: Literal["nodes", "cdn"] = "cdn"
    format: Literal["auto", "txt", "csv", "json", "yaml", "cidr"] = "auto"


class NodeActions(Body):
    ids: list[int] = Field(min_length=1, max_length=1000)
    action: Literal["enable", "disable", "metadata", "delete"]
    tags: list[str] = Field(default_factory=list, max_length=30)
    notes: str | None = Field(default=None, max_length=2000)
    confirm: bool = False


class NodeSelection(Body):
    filters: dict[str, Any] = Field(default_factory=dict, max_length=24)


class RetainBody(NodeSelection):
    token: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class RecommendationSelection(NodeSelection):
    group: SuggestionGroup = "cdn"
    mode: SuggestionMode = "overall"
    all_matches: bool = False


class ExportBody(NodeSelection):
    format: Literal["txt", "csv", "json", "yaml", "clash", "template"]
    sensitive: bool = False
    confirm: bool = False
    template: str = Field(default="$address", max_length=1000)


    suffix: str = Field(default="", max_length=500)
    preferred_endpoint: str = Field(default="", max_length=300)
    recommendation: RecommendationSelection | None = None
    task_id: int | None = Field(default=None, ge=1)
    addresses_only: bool = False


class TaskBody(Body):
    model_config = {"extra": "forbid", "populate_by_name": True}
    kind: Literal["detect", "refresh", "quality", "workflow", "watch"] = "detect"
    group: Literal["all", "cdn", "turn", "turn_server", "turn_relay"] = "all"
    ids: list[int] = Field(default_factory=list)
    source_ids: list[int] = Field(default_factory=list, max_length=100, alias="sources")
    level: Literal["quick", "standard", "full"] = "standard"
    fast: bool = False
    only_expired: bool = True
    filters: dict[str, Any] = Field(default_factory=dict, max_length=24)
    subtasks: list[Literal["refresh", "detect", "quality"]] = Field(default_factory=list, max_length=3)
    eliminate: int = Field(default=0, ge=0)


class ScheduleBody(Body):
    name: str = Field(min_length=1, max_length=100)
    kind: Literal["detect", "refresh", "quality", "workflow", "watch"]
    minutes: int = Field(default=60, ge=1, le=525600)
    cron: str | None = Field(default=None, max_length=120)
    enabled: bool = True
    options: dict[str, Any] = Field(default_factory=dict, max_length=20)


async def get_model(request: Request, model):
    length = request.headers.get("content-length")
    if length and (not length.isdigit() or int(length) > 3 * 1024 * 1024):
        raise error(413, "请求体过大")
    body = await request.body()
    if len(body) > 3 * 1024 * 1024:
        raise error(413, "请求体过大")
    try:
        return model.model_validate_json(body)
    except ValidationError as exc:
        raise error(422, "请求参数无效") from exc


def check_filters(query: dict[str, Any]) -> dict[str, Any]:
    values = dict(query)
    try:
        for key in FILTER_NUMBERS | {"port", "source", "family"}:
            if values.get(key) is not None:
                values[key] = float(values[key]) if key in FILTER_NUMBERS else int(values[key])
                if not isfinite(values[key]) or values[key] < 0:
                    raise ValueError
        for key in ("q", "transport", "tag", "scope", "sort", "group", "workspace"):
            if values.get(key) is not None and not isinstance(values[key], str):
                raise ValueError
        for key, choices in FILTER_CHOICES.items():
            value = values.get(key)
            if value is None:
                continue
            options = value if isinstance(value, list) else [value]
            if len(options) > 250 or any(not isinstance(item, str) or not item.strip() or len(item) > 100 for item in options):
                raise ValueError
            options = list(dict.fromkeys(item.strip() for item in options))
            if choices is not None and any(item not in choices for item in options):
                raise ValueError
            values[key] = options if isinstance(value, list) else options[0]
        for key in ("enabled", "recommended", "ascending"):
            if values.get(key) is not None and not isinstance(values[key], bool):
                if type(values[key]) is int and values[key] in (0, 1):
                    values[key] = bool(values[key])
                else:
                    raise ValueError
        if values.get("ids") is not None and isinstance(values["ids"], str):
            values["ids"] = json.loads(values["ids"])
    except (TypeError, ValueError, OverflowError) as exc:
        raise error(422, "筛选参数格式无效") from exc
    if values.get("ids") is not None and (not isinstance(values["ids"], list) or len(values["ids"]) > 5000):
        raise error(422, "节点筛选上限为 5000 条")
    if values.get("sort") not in {None, "name", "latency", "speed", "score", "success", "jitter", "quality", "recent", "region"}:
        raise error(422, "排序字段无效")
    if values.get("family") not in {None, 4, 6} or values.get("group") not in {None, "turn"}:
        raise error(422, "地址版本或协议组无效")
    if values.get("workspace") not in {None, "cdn", "turn", "other", "all"}:
        raise error(422, "节点分类无效")
    return values


def create_app(data_dir: str | os.PathLike | None = None, *, allowed_hosts: list[str] | None = None, probe=None) -> FastAPI:
    directory = Path(data_dir or os.environ.get("NODEMASTER_DATA_DIR", Path(__file__).parent.parent / "runtime")).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    store = Store(directory)
    store.initialize()
    port = int(os.environ.get("NODEMASTER_PORT", "8765"))
    hostnames = sorted(set(allowed_hosts or ["127.0.0.1", "localhost", "[::1]", f"127.0.0.1:{port}", "testserver"]))
    # The source downloader pins URLs to checked IPs while retaining each original TLS name.
    http = httpx.AsyncClient(timeout=httpx.Timeout(8), follow_redirects=False, trust_env=False,
                             headers={"User-Agent": "NodeMaster/1"}, limits=httpx.Limits(max_connections=16, max_keepalive_connections=0))
    scheduler = AsyncIOScheduler(timezone=PLAN_ZONE)

    async def quality(ip: str, **kwargs):
        service = app.state.quality_service
        service.settings = settings()
        service.keys = {key: store.get_setting(key + "_key", "", secret=True) for key in KEY_PROVIDERS}
        return await service.check(ip, **kwargs)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.http = http
        app.state.quality_service = QualityService(store, settings(), http)
        async def refresh(source_id: int, **kwargs):
            return await refresh_source(store, source_id, settings(), http, **kwargs)
        app.state.manager = TaskManager(store, probe=detect if probe is None else probe,
                                        quality=quality, source_refresh=refresh, resolve_quality=resolve_quality)
        await app.state.manager.start()
        async def clean_quality():
            try:
                store.clean_quality(settings().quality_retention_days)
            except Exception:
                LOG.exception("Local cache cleanup failed")
        scheduler.add_job(clean_quality, "interval", hours=12, id="clean-quality", replace_existing=True)
        scheduler.start(paused=True)
        try:
            for row in store.schedules():
                attach_schedule(row)
            scheduler.resume()
            yield
        finally:
            scheduler.shutdown(wait=False)
            await app.state.manager.close()
            await http.aclose()

    app = FastAPI(title="NodeMaster", version=__version__, lifespan=lifespan)
    app.state.store, app.state.directory, app.state.scheduler = store, directory, scheduler
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=hostnames)

    @app.middleware("http")
    async def local_guard(request: Request, call_next):
        if request.client is None or request.client.host not in {"127.0.0.1", "::1", "testclient"}:
            return Response("只允许本机使用", status_code=403)
        origin = request.headers.get("origin")
        if request.method not in {"GET", "HEAD", "OPTIONS"} and request.headers.get("sec-fetch-site") == "cross-site":
            return Response("拒绝跨来源请求", status_code=403)
        if origin:
            try:
                part = urlsplit(origin)
                origin_port = part.port or (443 if part.scheme == "https" else 80)
            except ValueError:
                return Response("拒绝跨来源请求", status_code=403)
            expected_ports = {port, int(os.environ.get("NODEMASTER_DEV_PORT", port))}
            if part.scheme not in {"http", "https"} or part.hostname not in {"localhost", "127.0.0.1", "::1"} or origin_port not in expected_ports:
                return Response("拒绝跨来源请求", status_code=403)
        response = await call_next(request)
        response.headers.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'self'; frame-ancestors 'none'"})
        return response

    def settings() -> Settings:
        return Settings.model_validate(store.get_setting("app", {}))

    def filter_presets() -> dict[str, Any]:
        try:
            data = json.loads((directory / "node-filters.json").read_text(encoding="utf-8"))
            if not isinstance(data, dict) or any(not isinstance(value, dict) for value in data.values()):
                raise ValueError
            return data
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            raise error(500, "无法读取 node-filters.json，请检查文件格式") from exc

    async def resolve_quality(host: str) -> str:
        async with asyncio.timeout(min(2, settings().connect_timeout)):
            return (await resolve_public(host))[0]

    def attach_schedule(row: dict[str, Any]) -> None:
        async def submit():
            app.state.manager.enqueue(row["kind"], row["options"])

        trigger = CronTrigger.from_crontab(row["cron"], timezone=PLAN_ZONE) if row.get("cron") else "interval"
        interval = {"minutes": row["minutes"]} if trigger == "interval" else {}
        scheduler.add_job(submit, trigger, **interval,
            id=f"schedule-{row['id']}", replace_existing=True, coalesce=True, max_instances=1, misfire_grace_time=90)
        if not row["enabled"]:
            scheduler.pause_job(f"schedule-{row['id']}")

    def make_schedule(body: ScheduleBody, ident: int | None) -> int:
        if body.cron:
            try:
                CronTrigger.from_crontab(body.cron, timezone=PLAN_ZONE)
            except ValueError as exc:
                raise error(422, "Cron 需要 5 个有效时间字段") from exc
        if "kind" in body.options:
            raise error(422, "计划类型应单独设置")
        try:
            task = TaskBody.model_validate({**body.options, "kind": body.kind})
        except ValidationError as exc:
            raise error(422, "计划参数无效") from exc
        saved = store.save_schedule({**body.model_dump(exclude={"options"}), "options": task_options(task)}, ident)
        if saved is None:
            raise error(404, "计划不存在")
        attach_schedule(next(r for r in store.schedules() if r["id"] == saved))
        return saved

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "version": app.version, "local_only": True}

    @app.get("/api/summary")
    async def summary():
        return store.summary()

    @app.get("/api/nodes")
    async def list_nodes(q: str | None = None, protocol: list[str] | None = Query(default=None), transport: str | None = None,
        group: Literal["turn"] | None = None,
        status: list[str] | None = Query(default=None), family: int | None = Query(default=None, ge=4, le=6),
        port: int | None = Query(default=None, ge=1, le=65535), source: int | None = Query(default=None, ge=1),
        tag: str | None = None, country: list[str] | None = Query(default=None), ip_type: list[str] | None = Query(default=None),
        workspace: Workspace | None = None,
        enabled: bool | None = None, recommended: bool = False,
        min_score: float | None = Query(default=None, ge=0, le=100), max_latency: float | None = Query(default=None, ge=0),
        min_quality_score: float | None = Query(default=None, ge=0, le=100),
        min_speed: float | None = Query(default=None, ge=0), min_success: float | None = Query(default=None, ge=0, le=100),
        max_jitter: float | None = Query(default=None, ge=0), scope: str | None = None,
        sort: str = "recent", ascending: bool = False,
        limit: int = Query(default=50, ge=1, le=250), offset: int = Query(default=0, ge=0, le=1_000_000)):
        filters = check_filters(locals())
        filters.pop("limit", None); filters.pop("offset", None)
        return store.list_nodes(filters, limit, offset)

    @app.get("/api/nodes/regions")
    async def node_regions(workspace: Workspace | None = None):
        return store.node_regions(workspace)

    @app.post("/api/nodes/addresses")
    async def node_addresses(request: Request):
        body = await get_model(request, NodeSelection)
        return store.node_addresses(check_filters(body.filters))

    @app.get("/api/nodes/filter-preset")
    async def read_filter_preset(workspace: Workspace = "all"):
        presets = filter_presets()
        fallback = store.get_setting("node_filter_preset", {}) if workspace in {"all", "cdn"} else {}
        return {"filters": presets.get(workspace, fallback)}

    @app.put("/api/nodes/filter-preset")
    async def save_filter_preset(request: Request, workspace: Workspace = "all"):
        body = await get_model(request, NodeSelection)
        if body.filters.keys() - PRESET_FILTERS:
            raise error(422, "包含不支持的筛选参数")
        filters = check_filters(body.filters)
        presets = filter_presets()
        presets[workspace] = filters
        temporary = None
        try:
            with NamedTemporaryFile(mode="w", encoding="utf-8", dir=directory, delete=False) as stream:
                temporary = Path(stream.name)
                json.dump(presets, stream, ensure_ascii=False, indent=2, allow_nan=False)
                stream.write("\n")
            temporary.replace(directory / "node-filters.json")
        except OSError as exc:
            raise error(500, "无法写入 node-filters.json") from exc
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return {"filters": filters}

    @app.post("/api/nodes/retain")
    async def retain_nodes(request: Request):
        body = await get_model(request, RetainBody)
        filters = check_filters(body.filters)
        try:
            return store.retain_nodes(filters, body.token)
        except LookupError as exc:
            raise error(409, str(exc)) from exc
        except ValueError as exc:
            raise error(422, str(exc)) from exc

    @app.post("/api/import")
    async def import_nodes(request: Request):
        body = await get_model(request, ImportBody)
        try:
            if body.format == "cidr":
                from .sources import sample_cidrs
                nodes = [parse_one(ip, "cdn", settings().cdn_port) for ip in sample_cidrs(body.content, settings().max_candidates)]
                rows = []
            else:
                nodes, rows = parse_payload(body.content, body.format, body.kind, settings().cdn_port)
            for item in nodes:
                item.tags = sorted(set(item.tags) | set(body.tags))
            ident = None
            if body.name and nodes:
                # A pasted list is never a subscription, even when it contains a single HTTPS proxy URI.
                content = json.dumps([node.original for node in nodes], ensure_ascii=False)
                ident = store.add_source(body.name, "cdn" if body.format == "cidr" else body.kind, "json", content, body.max_candidates)
            result = store.import_nodes(nodes, ident, restore_deleted=True)
            if ident is not None:
                result["source_id"] = ident
            return {**result, "errors": rows[:30], "truncated": 0}
        except NodeInputError as exc:
            raise error(422, str(exc)) from exc

    @app.post("/api/nodes")
    async def add_node(request: Request):
        body = await get_model(request, NodeBody)
        try:
            parsed = parse_one(body.model_dump())
        except NodeInputError as exc:
            raise error(422, str(exc)) from exc
        report = store.import_nodes([parsed])
        return {"node": store.list_nodes({"ids": report["ids"]}, 1)["items"][0], **report}

    @app.get("/api/nodes/{ident}")
    async def node_detail(ident: int, start: str | None = None, end: str | None = None,
                          history_limit: int = Query(default=100, ge=1, le=500)):
        rows = store.list_nodes({"ids": [ident]}, 1)["items"]
        if not rows:
            raise error(404, "节点不存在")
        item = rows[0]
        item["history"] = store.history(ident, start, end, history_limit)
        item["quality_ip"] = store.node_address(ident, item["host"])
        item["quality_history"] = store.quality(item["quality_ip"]) if item["quality_ip"] else []
        item["quality"] = quality_profile(store.quality_profile_rows(item["quality_ip"])) if item["quality_history"] else None
        return item

    @app.post("/api/nodes/{ident}/configuration")
    async def node_configuration(ident: int):
        node = store.get_node(ident)
        if not node:
            raise error(404, "节点不存在")
        return {"config": node.config, "original": node.original}

    @app.post("/api/nodes/actions")
    async def node_actions(request: Request):
        body = await get_model(request, NodeActions)
        if len(set(body.ids)) != len(body.ids):
            raise error(422, "所选节点中存在重复项")
        if body.action == "delete" and not body.confirm:
            raise error(400, "删除节点需要明确确认")
        return {"changed": store.node_action(body.ids, body.action, body.tags, body.notes)}

    @app.get("/api/schedules")
    async def list_schedules():
        return store.schedules()

    @app.post("/api/schedules")
    async def create_schedule(request: Request):
        return {"id": make_schedule(await get_model(request, ScheduleBody), None)}

    @app.put("/api/schedules/{ident}")
    async def update_schedule(ident: int, request: Request):
        body = await get_model(request, ScheduleBody)
        return {"id": make_schedule(body, ident), "enabled": body.enabled}

    @app.delete("/api/schedules/{ident}")
    async def delete_schedule(ident: int):
        job = f"schedule-{ident}"
        if scheduler.get_job(job):
            scheduler.remove_job(job)
        if not store.delete_schedule(ident):
            raise error(404, "计划不存在")
        return {"deleted": True}

    @app.post("/api/schedules/{ident}/run")
    async def run_schedule(ident: int):
        row = next((item for item in store.schedules() if item["id"] == ident), None)
        if not row:
            raise error(404, "计划不存在")
        return {"task_id": app.state.manager.enqueue(row["kind"], row["options"])}

    @app.post("/api/ip-quality/{address}")
    async def check_ip_quality(address: str, force: bool = False):
        return await lookup_quality(address, force=force)

    async def lookup_quality(address: str, *, force: bool, turn_type: bool = False):
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            raise error(422, "IP 地址无效") from exc
        if not parsed.is_global:
            return {"status": "non_public_ip", "calls": 0, "history": []}
        result = await quality(parsed.compressed, force=force, turn_type=turn_type)
        return {**result, "history": store.quality(parsed.compressed)}

    @app.post("/api/nodes/{ident}/ip-quality")
    async def check_node_quality(ident: int, force: bool = False):
        node = store.get_node(ident)
        if not node:
            raise error(404, "节点不存在")
        address = store.node_address(ident, node.host)
        if not address or (address != node.host and not public_address(address)):
            try:
                address = await resolve_quality(node.host)
                store.save_quality_address(ident, address)
            except (OSError, TimeoutError, NodeInputError) as exc:
                raise error(422, "节点域名未解析到可查询的公网 IP") from exc
        result = await lookup_quality(address, force=force, turn_type=node.protocol in TURN_TYPES)
        rows = store.list_nodes({"ids": [ident]}, 1)["items"]
        return {"address": address, **result, **({"ip_type": rows[0]["ip_type"]} if rows else {})}

    @app.get("/api/ip-quality/usage")
    async def ip_quality_usage():
        month = datetime.now(UTC).strftime("%Y-%m-01T00:00:00")
        with store.connect() as db:
            rows = db.execute("SELECT provider,status,count(*) AS count FROM quality_checks WHERE checked>=? GROUP BY provider,status", (month,)).fetchall()
        return {"records": [dict(row) for row in rows],
                "configured": {key: bool(store.get_setting(key + "_key", "", secret=True)) for key in KEY_PROVIDERS}}

    @app.get("/api/suggestions")
    def suggestions(group: SuggestionGroup = "cdn", mode: SuggestionMode = "overall",
                    country: list[str] | None = Query(default=None), ip_type: list[str] | None = Query(default=None),
                    min_success: float | None = Query(default=None, ge=0, le=100),
                    min_quality_score: float | None = Query(default=None, ge=0, le=100),
                    max_latency: float | None = Query(default=None, ge=0),
                    min_speed: float | None = Query(default=None, ge=0),
                    limit: int | None = Query(default=None, ge=1, le=500)):
        filters = {"country": country, "ip_type": ip_type, "min_success": min_success,
                   "min_quality_score": min_quality_score, "max_latency": max_latency, "min_speed": min_speed}
        return ranked_nodes(group, mode, filters, limit)

    def ranked_nodes(group: SuggestionGroup, mode: SuggestionMode, filters: dict[str, Any], limit: int | None):
        protocols, levels = {
            "cdn": (["cdn"], ("http",)), "turn": (["turn", "turns"], ("full",)),
            "turn_server": (sorted(TURN_TYPES), ("standard", "quick")),
            "all": (["cdn", "turn", "turns"], ("http", "full")),
        }[group]
        if mode == "combined" and group == "all":
            raise error(422, "综合推荐请分别选择 CDN、TURN 中继或 TURN 服务")
        config = settings()
        filters = check_filters({key: filters.get(key) for key in ("country", "ip_type", "min_success",
                                 "min_quality_score", "max_latency", "min_speed")})
        filters.update(protocols=protocols, enabled=True, status="passed")
        if mode == "quality" and filters.get("min_quality_score") is None:
            filters["min_quality_score"] = 0
        if mode in {"overall", "latency", "quality"}:
            filters.update(sort={"overall": "score", "latency": "latency", "quality": "quality"}[mode], ascending=mode == "latency")
            return store.list_nodes(filters, limit or config.top_n, result_levels=levels)

        weights = config.recommendation_weights.model_dump()
        rows = store.list_nodes(filters, -1, result_levels=levels)["items"]
        scored = []
        for row in rows:
            parts = {}
            if (success := row["success_rate"]) is not None:
                jitter = row["jitter"]
                parts["stability"] = success if jitter is None else success * config.jitter_target / (config.jitter_target + jitter)
            if (latency := row["latency"]) is not None:
                parts["latency"] = 100 * config.latency_target / (config.latency_target + latency)
            if (speed := row["speed"]) is not None and row["protocol"] == "cdn":
                parts["speed"] = 100 * min(1, speed / config.speed_target)
            if row["quality_score"] is not None:
                parts["quality"] = row["quality_score"]
            selected = {"stability": 100} if mode == "stability" else weights
            weight = sum(selected.get(key, 0) for key in parts)
            if weight:
                score = sum(selected.get(key, 0) * value for key, value in parts.items()) / weight
                scored.append((score, weight, row | {"combined_score": round(score, 2),
                    "recommendation_parts": {key: round(value, 2) for key, value in parts.items()}}))
        scored.sort(key=lambda entry: (-entry[0], -entry[1], entry[2]["id"]))
        return {"total": len(scored), "items": [row for _, _, row in scored[:limit or config.top_n]], "weights": weights}

    @app.post("/api/turn/echo-check")
    async def turn_echo_check():
        config = settings()
        if not config.relay_host:
            return {"status": "echo_unconfigured"}
        return await check_udp_echo(config.relay_host, config.relay_port, config.relay_echo_timeout, config.relay_mode)

    @app.post("/api/exit-ip")
    async def exit_ip(request: Request):
        length = request.headers.get("content-length", "0")
        if not length.isdigit() or int(length) > 3072:
            raise error(413, "请求过大")
        try:
            payload = await request.json()
        except ValueError as exc:
            raise error(422, "请求体格式无效") from exc
        if not isinstance(payload, dict) or payload.keys() - {"kind", "proxy_url", "test_url"}:
            raise error(422, "出口查询参数无效")
        kind, proxy = payload.get("kind", "direct"), payload.get("proxy_url", "")
        if kind not in {"direct", "proxy"} or kind == "proxy" and not isinstance(proxy, str):
            raise error(422, "出口查询模式无效")
        if kind == "proxy":
            if not 1 <= len(proxy) <= 1024:
                raise error(422, "代理地址长度无效")
            try:
                part = urlsplit(proxy)
                if part.scheme not in {"http", "https", "socks5", "socks5h"} or not part.hostname or part.port not in range(1, 65536):
                    raise ValueError
            except ValueError as exc:
                raise error(422, "代理格式需为 HTTP、HTTPS 或 SOCKS5") from exc
        target = payload.get("test_url", settings().exit_url)
        if not isinstance(target, str) or len(target) > 1500:
            raise error(422, "IP 查询地址长度无效")
        validate_https_target(target, proxy if kind == "proxy" else "")
        start = monotonic()
        try:
            async with httpx.AsyncClient(timeout=settings().request_timeout, follow_redirects=False,
                 trust_env=False, proxy=proxy if kind == "proxy" else None) as session:
                getter = limited_get if kind == "proxy" else public_get
                text = await getter(session, target, settings().request_timeout, 65536)
            try:
                content = json.loads(text)
                value = content.get("ip") if isinstance(content, dict) else text.strip()
            except json.JSONDecodeError:
                value = text.strip()
            ip = ipaddress.ip_address(value)
            return {"kind": kind, "ip": ip.compressed, "family": ip.version, "latency_ms": round((monotonic() - start) * 1000, 2)}
        except (ValueError, NodeInputError, httpx.HTTPError, TimeoutError, OSError) as exc:
            raise error(502, "出口查询失败，请检查网络或代理设置") from exc

    @app.get("/api/tasks/{ident}/events")
    async def task_events(ident: int, after: int = Query(default=0, ge=0), limit: int = Query(default=100, ge=1, le=500)):
        if not store.task(ident):
            raise error(404, "任务不存在")
        with store.connect() as db:
            rows = db.execute("SELECT * FROM task_events WHERE task_id=? AND id>? ORDER BY id LIMIT ?", (ident, after, limit))
            return {"events": [dict(row) | {"data": json.loads(row["data"])} for row in rows]}



    @app.post("/api/export")
    async def export_nodes(request: Request):
        body = await get_model(request, ExportBody)
        if body.sensitive and not body.confirm:
            raise error(400, "导出认证信息需要明确确认")
        if body.task_id and body.recommendation:
            raise error(422, "请选择一个导出来源")
        preferred = body.preferred_endpoint.strip()
        if preferred and (body.format != "txt" or not TEXT_ENDPOINT.fullmatch(preferred)):
            raise error(422, "配对导出需要填写优选地址和端口，并选择 TXT 格式")
        limit = 200 if body.sensitive else 5000
        try:
            if preferred:
                candidate = parse_one(preferred, "cdn")
                preferred = endpoint(candidate.host, candidate.port)
            if body.task_id:
                task = store.task(body.task_id)
                if task is None:
                    raise error(404, "检测任务不存在")
                selection = store.list_nodes({"protocols": ["turn", "turns"], "status": "passed", "sort": "score"},
                                             limit, result_levels=("full",), result_task=body.task_id)
                rows, count = selection["items"], selection["total"]
            elif query := body.recommendation:
                selection = ranked_nodes(query.group, query.mode, query.filters, limit if query.all_matches else None)
                rows = selection["items"]
                count = selection["total"] if query.all_matches else len(rows)
            else:
                selection = store.list_nodes(check_filters(body.filters), limit)
                rows = selection["items"]
                count = selection["total"]
            if count > limit:
                qualifier = "含认证信息的" if body.sensitive else ""
                raise error(413, f"{qualifier}导出每次最多 {limit} 个节点，请缩小范围")
            if preferred:
                rows = [row for row in rows if row["level"] == "full" and row["status"] == "passed"
                        and row["protocol"] in {"turn", "turns"}]
            if not rows:
                raise error(422, "没有通过完整中继验证的节点" if preferred or body.task_id else "没有可导出的节点")
            metadata_keys = ["status", "location", "ip_type"]
            if body.format in {"txt", "csv", "template"} or body.recommendation or body.task_id:
                metadata_keys += ["score", "quality_score", "combined_score", "latency", "speed", "success_rate", "level"]
            metadata = {row["id"]: {key: row[key] for key in metadata_keys if key in row} for row in rows}
            complete = store.export_nodes(rows, body.sensitive)
            text = render_export(complete, body.format, body.sensitive, body.template, metadata,
                                 suffix=body.suffix, preferred_endpoint=preferred, addresses_only=body.addresses_only)
        except NodeInputError as exc:
            raise error(422, str(exc)) from exc
        media = {"json": "application/json", "yaml": "application/yaml", "csv": "text/csv", "txt": "text/plain", "clash": "application/yaml", "template": "text/plain"}[body.format]
        suffix = {"clash": "yaml", "template": "txt"}.get(body.format, body.format)
        name = f'nodemaster-{datetime.now(UTC):%Y%m%dT%H%M%SZ}.{suffix}'
        return Response(text, media_type=f"{media}; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @app.get("/api/sources")
    async def list_sources():
        return store.list_sources()

    @app.post("/api/sources")
    async def create_source(request: Request):
        body = await get_model(request, SourceBody)
        if body.kind == "official":
            if body.format != "cidr" or body.content not in {"both", "ipv4", "ipv6"}:
                raise error(422, "官方来源格式设为 CIDR，内容选择 both、ipv4 或 ipv6")
        elif body.content.startswith(("https://", "http://")) and "\n" not in body.content:
            try:
                body.content = normalize_url(body.content)
                safe_host(body.content)
            except NodeInputError as exc:
                raise error(422, str(exc)) from exc
            if body.format == "cidr" and body.kind != "cdn":
                raise error(422, "远程 CIDR 请配置为优选 IP 来源")
        ident = store.add_source(body.name, body.kind, body.format, body.content, body.max_candidates, enabled=body.enabled)
        return {"id": ident, "name": body.name, "kind": body.kind, "format": body.format,
                "enabled": body.enabled, "max_candidates": body.max_candidates}

    @app.post("/api/sources/batch")
    async def create_sources(request: Request):
        body = await get_model(request, SourceBatch)
        if body.format == "cidr" and body.kind != "cdn":
            raise error(422, "远程 CIDR 请配置为优选 IP 来源")
        existing = {item["input"]: item for source in store.list_sources() if source["remote"]
                    if (item := store.get_source(source["id"])) and item["kind"] == body.kind and item["format"] == body.format}
        entries, errors = [], []
        seen, retry = set(), []
        duplicates = 0
        for row, line in enumerate(body.urls.splitlines(), 1):
            if not (line := pasted_source_url(line)) or line.startswith("#"):
                continue
            try:
                if len(line) > 2048:
                    raise NodeInputError("链接长度超过 2048 字符")
                url = normalize_url(line, https_only=True)
                host = public_host(url)
            except NodeInputError as exc:
                errors.append({"row": row, "message": str(exc)})
                continue
            if url in seen:
                duplicates += 1
                continue
            seen.add(url)
            if url in existing:
                duplicates += 1
                if existing[url]["enabled"]:
                    retry.append(existing[url]["id"])
                continue
            stem = body.name.strip()
            name = f"{stem} {row}" if stem else f"{host}{urlsplit(url).path}"
            entries.append((name[:100], body.kind, body.format, url, settings().max_candidates, True))
        ids = store.add_sources(entries)
        task = app.state.manager.enqueue("refresh", {"source_ids": ids + retry}) if ids or retry else None
        return {"added": len(ids), "duplicates": duplicates, "errors": errors, "task_id": task}

    @app.patch("/api/sources/{ident}")
    async def update_source(ident: int, request: Request):
        body = await get_model(request, SourceUpdate)
        if not store.source_update(ident, body.model_dump(exclude_none=True)):
            raise error(404, "来源不存在")
        return next(row for row in store.list_sources() if row["id"] == ident)

    @app.delete("/api/sources/{ident}")
    async def delete_source(ident: int):
        if not store.source_action(ident):
            raise error(404, "来源不存在")
        return {"deleted": True}

    @app.post("/api/sources/{ident}/refresh")
    async def source_refresh(ident: int):
        item = store.get_source(ident)
        if not item:
            raise error(404, "来源不存在")
        if not item["enabled"]:
            raise error(409, "请先启用此来源")
        return {"task_id": app.state.manager.enqueue("refresh", {"source_ids": [ident]})}

    @app.get("/api/tasks")
    async def list_tasks(summary: bool = False):
        return store.tasks(summary=summary)

    @app.get("/api/tasks/{ident}")
    async def get_task(ident: int):
        item = store.task(ident)
        if not item:
            raise error(404, "任务不存在")
        return item

    def task_options(body: TaskBody) -> dict[str, Any]:
        if len(set(body.ids)) != len(body.ids) or len(set(body.source_ids)) != len(body.source_ids):
            raise error(422, "节点或来源列表中存在重复 ID")
        allowed = PRESET_FILTERS | {"transport", "group", "workspace"}
        if body.filters.keys() - allowed:
            raise error(422, "不支持的任务筛选条件")
        sources = {source["id"]: source for source in store.list_sources()} if body.source_ids or body.kind == "watch" else {}
        if any(value not in sources or (body.kind != "watch" and not sources[value]["enabled"]) for value in body.source_ids):
            raise error(422, "任务引用了不存在或已暂停的来源")
        if body.kind == "watch" and body.source_ids and any(not sources[value]["remote"] for value in body.source_ids):
            raise error(422, "直链更新计划只能选择 HTTPS 文件来源")
        if body.kind == "workflow" and not body.subtasks:
            body.subtasks = ["refresh", "detect", "quality"]
        return body.model_dump(exclude={"kind"}) | {"filters": check_filters(body.filters)}

    @app.post("/api/tasks")
    async def start_task(request: Request):
        body = await get_model(request, TaskBody)
        return {"task_id": app.state.manager.enqueue(body.kind, task_options(body))}

    @app.post("/api/tasks/{ident}/cancel")
    async def cancel_task(ident: int):
        if not app.state.manager.cancel(ident):
            raise error(409, "任务不存在或已结束")
        return {"cancelled": True}

    @app.get("/api/history/changes")
    async def history_changes(days: int = Query(default=7, ge=1, le=365)):
        return store.changes(days)

    @app.get("/api/settings")
    async def read_settings():
        values = settings().model_dump()
        values["provider_keys"] = {key: bool(store.get_setting(key + "_key", "", secret=True)) for key in KEY_PROVIDERS}
        return values

    @app.put("/api/settings")
    async def update_settings(request: Request):
        try:
            values = json.loads(await request.body())
        except (ValueError, TypeError) as exc:
            raise error(422, "检测设置需要使用 JSON 对象") from exc
        if not isinstance(values, dict):
            raise error(422, "检测设置需要使用对象")
        secrets = {}
        for key in KEY_PROVIDERS:
            if key + "_key" in values:
                token = values.pop(key + "_key")
                if not isinstance(token, str) or len(token) > 512:
                    raise error(422, "服务密钥长度无效")
                secrets[key + "_key"] = token
        try:
            value = Settings.model_validate(values)
        except ValidationError as exc:
            raise error(422, "检测设置超出有效范围") from exc
        store.set_settings({"app": value.model_dump()}, secrets)
        return await read_settings()



    @app.get("/", include_in_schema=False)
    async def index():
        path = WEB_ROOT / "index.html"
        if not path.is_file():
            return Response("正在准备界面文件。请先运行 npm install 和 npm run build。", media_type="text/plain", status_code=503)
        return FileResponse(path)

    @app.get("/{path:path}", include_in_schema=False)
    async def frontend_file(path: str):
        if path.startswith("api/") or path in {"", "index.html"} or "/" in path and not path.startswith("assets/"):
            raise error(404, "页面不存在")
        target = (WEB_ROOT / path).resolve()
        allowed = (WEB_ROOT / "assets").resolve() if path.startswith("assets/") else WEB_ROOT.resolve()
        if not target.is_relative_to(allowed) or not target.is_file():
            raise error(404, "资源不存在")
        return FileResponse(target)

    return app
