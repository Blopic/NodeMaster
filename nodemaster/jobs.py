import asyncio
from collections.abc import Iterable
from ipaddress import IPv6Address, ip_address
from typing import Any, Awaitable, Callable

from .config import Settings
from .nodes import TURN_TYPES, Node, NodeInputError
from .probes import detect
from .store import Store, now

Probe = Callable[[Node, Settings, str], Awaitable[dict[str, Any]]]
GROUP_PROTOCOLS = {
    "cdn": ["cdn"], "turn": sorted(TURN_TYPES), "turn_server": sorted(TURN_TYPES), "turn_relay": ["turn", "turns"],
}


def fast_settings(settings: Settings) -> Settings:
    return settings.model_copy(update={"attempts": 1, "retries": 0,
        "connect_timeout": min(settings.connect_timeout, 1.5), "request_timeout": min(settings.request_timeout, 2.5),
        "probe_timeout": min(settings.probe_timeout, 6), "download_bytes": min(settings.download_bytes, 65_536)})


def compare_results(current: dict[str, Any], previous: dict[str, Any], settings: Settings) -> dict[str, Any]:
    old_ms, new_ms = previous.get("latency"), current.get("latency")
    old_score, new_score = previous.get("score"), current.get("score")
    delta = new_score - old_score if new_score is not None and old_score is not None else None
    return {"previous": {key: previous.get(key) for key in ("status", "latency", "speed", "score", "success_rate", "jitter")},
            "current": {key: current.get(key) for key in ("status", "latency", "speed", "score", "success_rate", "jitter")},
            "latency_delta_ms": round(new_ms - old_ms, 2) if new_ms is not None and old_ms is not None else None,
            "score_delta": round(delta, 2) if delta is not None else None, "new": False,
            "still_available": current["status"] == previous["status"] == "passed",
            "lost": previous["status"] == "passed" and current["status"] != "passed",
            "improved": (new_ms is not None and old_ms is not None and old_ms - new_ms >= settings.change_ms) or
                        (delta is not None and delta >= settings.change_score),
            "worse": current["status"] == previous["status"] == "passed" and
                     ((new_ms is not None and old_ms is not None and new_ms - old_ms >= settings.change_ms) or
                      (delta is not None and delta <= -settings.change_score))}


class TaskManager:
    """Persistent, single-worker task queue. Cancellation signals are local to one process."""
    def __init__(self, store: Store, probe: Probe = detect, quality=None, source_refresh=None, resolve_quality=None):
        self.store, self.probe = store, probe
        self.quality, self.source_refresh = quality, source_refresh
        self.resolve_quality = resolve_quality
        self.queue: asyncio.Queue[int | None] = asyncio.Queue()
        self.tasks: dict[int, asyncio.Task[None]] = {}
        self.current = 0
        self.cancel_events: dict[int, asyncio.Event] = {}
        self.in_flight: set[str] = set()
        self.worker: asyncio.Task[None] | None = None
        self.closed = False

    async def start(self):
        self.store.recover_tasks()
        self.closed = False
        self.worker = asyncio.create_task(self.run())
        return self

    async def close(self):
        self.closed = True
        for ident, event in list(self.cancel_events.items()):
            event.set()
            task = self.tasks.get(ident)
            if task:
                task.cancel()
            else:
                self.store.task_update(ident, state="interrupted", finished=now())
        if self.worker:
            self.queue.put_nowait(None)
            try:
                await asyncio.wait_for(self.worker, timeout=5)
            except TimeoutError:
                self.worker.cancel()
                try:
                    await self.worker
                except asyncio.CancelledError:
                    pass
            self.worker = None

    def enqueue(self, kind: str, options: dict[str, Any]) -> int:
        if self.closed:
            raise RuntimeError("任务队列已关闭")
        identity = kind + ":" + str(sorted(options.items()))
        if identity in self.in_flight:
            return next(ident for ident in self.in_flight_by_id if self.in_flight_by_id[ident] == identity)
        ident = self.store.create_task(kind, options)
        self.in_flight.add(identity)
        self.in_flight_by_id[ident] = identity
        self.cancel_events[ident] = asyncio.Event()
        self.queue.put_nowait(ident)
        self.store.task_event(ident, "queued", {"kind": kind})
        return ident

    @property
    def in_flight_by_id(self):
        if not hasattr(self, "_in_flight_by_id"):
            self._in_flight_by_id = {}
        return self._in_flight_by_id

    async def run(self):
        while True:
            ident = await self.queue.get()
            try:
                if ident is None:
                    return
                if not self.cancel_events[ident].is_set():
                    self.current = ident
                    task = asyncio.create_task(self.execute(ident))
                    self.tasks[ident] = task
                    try:
                        await task
                    except asyncio.CancelledError:
                        self.store.finish_task(ident, "cancelled", {"reason": "cancelled"})
            finally:
                if ident is not None:
                    self.finish_tracking(ident)
                self.current = 0
                self.queue.task_done()

    def finish_tracking(self, ident: int) -> None:
        identity = self.in_flight_by_id.pop(ident, None)
        if identity:
            self.in_flight.discard(identity)
        self.cancel_events.pop(ident, None)
        self.tasks.pop(ident, None)

    def cancel(self, ident: int) -> bool:
        task = self.store.task(ident)
        event = self.cancel_events.get(ident)
        if not task or not event or task["state"] not in {"queued", "running"}:
            return False
        event.set()
        if ident == self.current:
            running = self.tasks.get(ident)
            if running:
                running.cancel()
        else:
            self.store.task_update(ident, state="cancelled", finished=now())
            self.store.task_event(ident, "cancelled", {})
        return True

    async def execute(self, ident: int):
        task = self.store.task(ident)
        options = task["options"]
        settings = Settings.model_validate(self.store.get_setting("app", {}))
        cancel = self.cancel_events[ident]
        self.store.task_update(ident, state="running", started=now())
        self.store.task_event(ident, "started", {"kind": task["kind"]})
        try:
            results, details, updates = [], [], []
            progress = {"total": 0, "done": 0, "succeeded": 0, "failed": 0}
            filters = dict(options.get("filters", {}))
            source_ids = options.get("source_ids", options.get("sources"))
            if source_ids:
                filters["source_ids"] = source_ids
            group, level, ids = options.get("group", "all"), options.get("level", "standard"), options.get("ids", [])
            kind = task["kind"]
            steps = [kind]
            if kind == "workflow":
                steps = options.get("subtasks") or ["refresh", "detect", "quality"]
            if kind == "watch":
                results, details, updates = await self.watch_sources(ident, source_ids, options.get("eliminate", 0), settings, cancel, progress)
            if "refresh" in steps:
                sources = [s for s in self.store.list_sources() if s["enabled"]
                           and (not source_ids or s["id"] in source_ids)]
                self.plan_step(ident, progress, "refresh", len(sources))
                for source in sources:
                    if cancel.is_set():
                        raise asyncio.CancelledError
                    report = await self.source_refresh(source["id"])
                    details.append({"source": source["id"], "source_name": source["name"],
                                    **{k: v for k, v in report.items() if k not in {"ids", "new_ids"}}})
                    self.advance(ident, progress, report["status"] in {"passed", "partial"},
                                 "source_refresh", {"source": source["id"], "source_name": source["name"], "status": report["status"]})
            if "detect" in steps:
                probe_settings = fast_settings(settings) if options.get("fast") else settings
                results = await self.detect(ident, filters, group, level, probe_settings, cancel, ids, progress,
                                            fast=bool(options.get("fast")))
            if "quality" in steps:
                if "detect" in steps:
                    hosts = public_ips(sample.get("resolved_ip") for result in results
                                       for key in ("samples", "trials") for sample in result["data"].get(key, []))
                    turn_hosts = set(public_ips(sample.get("resolved_ip") for result in results if result["protocol"] in TURN_TYPES
                                                for key in ("samples", "trials") for sample in result["data"].get(key, [])))
                else:
                    selection = filters | {"enabled": 1}
                    if ids:
                        selection["ids"] = ids
                    if group != "all":
                        selection["protocols"] = GROUP_PROTOCOLS[group]
                    nodes = [] if filters.get("enabled") is False else self.store.list_nodes(selection, -1)["items"]
                    hosts, turn_hosts = await self.quality_addresses(nodes)
                self.plan_step(ident, progress, "quality", len(hosts))
                remaining = iter(hosts)

                async def query_worker():
                    for host in remaining:
                        if cancel.is_set():
                            raise asyncio.CancelledError
                        report = await self.quality(host, force=not options.get("only_expired", True), turn_type=host in turn_hosts)
                        profile = report.get("profile", {})
                        details.append({"ip": host, **{k: v for k, v in report.items() if k != "profile"},
                                        "location": profile.get("location"), "asn": profile.get("asn")})
                        self.advance(ident, progress, report["status"] in {"passed", "partial"},
                                     "quality", {"ip": host, "status": report["status"]})

                async with asyncio.TaskGroup() as workers:
                    for _ in range(min(8, len(hosts))):
                        workers.create_task(query_worker())
            if cancel.is_set():
                raise asyncio.CancelledError
            if results:
                self.store.task_event(ident, "stage", {"step": "ranking", "count": len(results)})
            comparison, rankings, updated, auto_disabled = self.compare(results, settings)
            report = {"results": sorted(({k: v for k, v in r.items() if k != "data"} for r in results),
                                        key=lambda r: (r["status"] == "passed", r["node_id"])),
                      "comparison": comparison, "recommendations": rankings,
                      "recommendation_scopes": updated, "details": details, "auto_disabled": auto_disabled}
            if not progress["total"]:
                report["reason"] = {"detect": "no_eligible_nodes", "quality": "no_public_addresses",
                                    "watch": "no_remote_sources", "refresh": "no_sources"}.get(kind, "no_eligible_nodes")
            self.store.finish_task(ident, "completed", report, updates)
            self.store.task_event(ident, "finished", {"state": "completed", "count": progress["done"]})
        except asyncio.CancelledError:
            self.store.finish_task(ident, "cancelled", {"reason": "cancelled"})
            self.store.task_event(ident, "cancelled", {})
        except Exception as exc:
            self.store.finish_task(ident, "failed", {"reason": type(exc).__name__, "message": safe_error(exc)})
            self.store.task_event(ident, "failed", {"error": type(exc).__name__})

    def plan_step(self, ident: int, progress: dict[str, int], step: str, count: int) -> None:
        progress["total"] += count
        self.store.task_update(ident, total=progress["total"])
        self.store.task_event(ident, "stage", {"step": step, "count": count})

    def advance(self, ident: int, progress: dict[str, int], passed: bool, event: str, data: dict[str, Any]) -> None:
        progress["done"] += 1
        progress["succeeded" if passed else "failed"] += 1
        self.store.task_update(ident, **progress)
        self.store.task_event(ident, event, {**data, "done": progress["done"], "total": progress["total"]})

    async def quality_addresses(self, nodes):
        addresses = []
        turn_addresses = []
        unknown = {}
        for node in nodes:
            address = node["quality_ip"]
            if public_ips([address]):
                addresses.append(address)
                if node["protocol"] in TURN_TYPES:
                    turn_addresses.append(address)
            elif self.resolve_quality and address != node["host"]:
                unknown.setdefault(node["host"], []).append(node)
        pending = iter(unknown.items())

        async def resolve():
            for host, entries in pending:
                try:
                    address = await self.resolve_quality(host)
                except (OSError, TimeoutError, NodeInputError):
                    continue
                for node in entries:
                    self.store.save_quality_address(node["id"], address)
                if any(node["protocol"] in TURN_TYPES for node in entries):
                    turn_addresses.append(address)
                addresses.append(address)

        async with asyncio.TaskGroup() as workers:
            for _ in range(min(12, len(unknown))):
                workers.create_task(resolve())
        return public_ips(addresses), set(public_ips(turn_addresses))

    async def watch_sources(self, ident, source_ids, eliminate, settings, cancel, progress):
        sources = [source for source in self.store.list_sources() if source["enabled"] and source["remote"]
                   and (not source_ids or source["id"] in source_ids)]
        self.plan_step(ident, progress, "refresh", len(sources))
        details, candidates = [], set()
        changed = []
        for source in sources:
            if cancel.is_set():
                raise asyncio.CancelledError
            report = await self.source_refresh(source["id"], watch=True)
            snapshot = report.pop("snapshot", None)
            previous = report.pop("previous_ids", [])
            current = report.pop("ids", [])
            report.pop("new_ids", None)
            detail = {"source": source["id"], "source_name": source["name"], **report}
            details.append(detail)
            if snapshot:
                union = set(current).union(previous)
                candidates.update(union)
                detail["candidates"] = len(union)
                changed.append((snapshot, union, detail))
            self.advance(ident, progress, report["status"] == "passed", "source_refresh", detail)
        results = await self.detect(ident, {}, "all", "standard", fast_settings(settings), cancel,
                                    sorted(candidates), progress, fast=True) if candidates else []
        scores = {result["node_id"]: result for result in results}

        def worst(node_id):
            result = scores[node_id]
            status = {"failed": 0, "partial": 1, "passed": 2}.get(result["status"], 3)
            score, latency = result.get("score"), result.get("latency")
            return status, score if score is not None else -1, -(latency if latency is not None else float("inf")), node_id

        updates = []
        for snapshot, union, detail in changed:
            measured = sorted((i for i in union if i in scores), key=worst)
            dropped = set(measured[:eliminate])
            detail.update(eliminated=len(dropped), retained=len(union - dropped))
            snapshot["eliminated"] = len(dropped)
            updates.append({"source": detail["source"], "snapshot": snapshot, "retained": sorted(union - dropped),
                            "dropped": sorted(dropped)})
        return results, details, updates

    async def detect(self, ident: int, filters: dict[str, Any], group: str, level: str,
                     settings: Settings, cancel: asyncio.Event, ids: list[int], progress: dict[str, int], *, fast: bool = False):
        clean = dict(filters)
        clean.update({"enabled": 1})
        if ids:
            clean["ids"] = ids
        groups = {}
        for category, protocols in (("cdn", ["cdn"]), ("turn", sorted(TURN_TYPES))):
            if group not in {"all", category} and not (category == "turn" and group in {"turn_server", "turn_relay"}):
                continue
            groups[category] = [] if filters.get("enabled") is False else self.store.list_nodes(
                clean | {"protocols": GROUP_PROTOCOLS.get(group, protocols)}, -1)["items"]
        total = sum(map(len, groups.values()))
        level = {"turn_server": "standard", "turn_relay": "full"}.get(group, level)
        self.plan_step(ident, progress, "turn_relay" if level == "full" and group != "cdn" else "detect", total)
        async def inspect(entry: dict[str, Any]) -> dict[str, Any] | None:
            node = self.store.get_node(entry["id"])
            if not node:
                self.advance(ident, progress, False, "progress", {"node_id": entry["id"], "status": "skipped"})
                return None
            try:
                if cancel.is_set():
                    raise asyncio.CancelledError
                result = await self.probe(node, settings, level)
                if fast:
                    result["scope"] += ":fast"
                result.update(node_id=node.id, node_name=node.name, host=node.host, port=node.port, protocol=node.protocol)
                samples = result["data"].get("samples", [])
                if node.protocol == "cdn":
                    response = next((sample for sample in samples if sample.get("success")), samples[0] if samples else {})
                    result["http_status"] = response.get("http_status")
                if entry.get("source_names"):
                    result["source"] = entry["source_names"]
                if result["status"] in {"failed", "partial"}:
                    failures = [sample.get("error") or sample.get("binding_error")
                                for sample in samples if not sample.get("success")]
                    result["failure"] = next((reason for reason in failures if reason), None)
                    self.store.task_event(ident, "diagnostic", {"node_id": node.id, "status": result["status"],
                        "failures": failures})
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.store.task_event(ident, "node_error", {"node_id": node.id, "error": type(exc).__name__})
                result = {"scope": node.protocol + ":task-error", "status": "failed", "level": level,
                          "latency": None, "speed": None, "success_rate": 0, "jitter": None, "score": None,
                          "data": {"error": type(exc).__name__}, "node_id": node.id, "node_name": node.name,
                          "host": node.host, "port": node.port, "protocol": node.protocol}
            result["result_id"] = self.store.save_result(node.id, ident, result)
            self.advance(ident, progress, result["status"] == "passed", "progress", {
                "node_id": node.id, "node": node.name, "status": result["status"],
                "latency": result.get("latency"), "score": result.get("score"), "level": result.get("level")})
            return result

        collected = []

        async def worker(entries):
            for entry in entries:
                if cancel.is_set():
                    raise asyncio.CancelledError
                if (result := await inspect(entry)) is not None:
                    collected.append(result)

        concurrency = {"cdn": settings.cdn_concurrency, "turn": settings.turn_concurrency}
        async with asyncio.TaskGroup() as workers:
            for category, entries in groups.items():
                remaining = iter(entries)
                for _ in range(min(len(entries), concurrency[category])):
                    workers.create_task(worker(remaining))
        return collected

    def compare(self, results: list[dict[str, Any]], settings: Settings):
        groups: dict[str, list[dict[str, Any]]] = {}
        rankings, updated, auto_disabled = [], [], []
        for result in results:
            if not result.get("node_id"):
                continue
            groups.setdefault(result["scope"], []).append(result)
        comparisons = []
        for scope, values in groups.items():
            baseline = self.store.comparison_snapshot(scope)
            previous_ranks = self.store.recommendation_ranks(scope)
            examined = {r["node_id"] for r in values}
            new = improved = worse = lost = stable = 0
            available = []
            for result in values:
                old = baseline.get(result["node_id"])
                comparison = compare_results(result, old, settings) if old else {"new": True, "still_available": False, "lost": False, "improved": False, "worse": False}
                result["comparison"] = comparison
                new += int(old is None)
                improved += int(comparison["improved"])
                worse += int(comparison["worse"])
                lost += int(comparison["lost"])
                stable += int(comparison["still_available"])
                if result["status"] == "passed":
                    available.append(result)
            changed = []
            if available:
                updated.append(scope)
                policy = settings.update_policy if scope.startswith("cdn:") else "top"
                if policy == "archive_stale":
                    failures = [r["node_id"] for r in values if r["status"] == "failed"]
                    auto_disabled.extend(self.store.stale_candidates(scope, failures, settings.stale_days))
                if policy != "latest":
                    available.extend({**row, "result_id": row["id"]} for row in baseline.values()
                                     if row["node_id"] not in examined and row["eligible"] and row["status"] == "passed")
                if policy == "threshold":
                    available = [r for r in available if r.get("score") is not None and r["score"] >= settings.min_recommend_score]

                def order(result: dict[str, Any]) -> tuple[float, float, int]:
                    latency = result.get("latency")
                    return -(result.get("score") or 0), latency if latency is not None else float("inf"), result["node_id"]

                available.sort(key=order)
                if policy == "keep":
                    available.sort(key=lambda r: r["node_id"] in examined or r["node_id"] not in previous_ranks)
                selected = available if policy == "successful" else available[:settings.top_n]
                known = {}
                for rank, result in enumerate(sorted(selected, key=order), 1):
                    known[result["node_id"]] = rank
                    rankings.append({"scope": scope, "node_id": result["node_id"], "result_id": result["result_id"], "rank": rank})
                names = {**{i: r["node_name"] for i, r in baseline.items()}, **{r["node_id"]: r["node_name"] for r in values}}
                changed = [{"node_id": node_id, "name": names.get(node_id),
                            "previous_rank": previous_ranks.get(node_id), "rank": known.get(node_id)}
                           for node_id in sorted(previous_ranks.keys() | known.keys()) if previous_ranks.get(node_id) != known.get(node_id)]
            comparisons.append({"scope": scope, "new": new, "stable": stable, "improved": improved,
                                "worse": worse, "lost": lost, "disappeared": sum(r["node_id"] not in examined for r in baseline.values()),
                                "rank_changes": changed, "recommendations_kept": bool(previous_ranks) and scope not in updated})
        return comparisons, rankings, updated, auto_disabled


def public_ips(values: Iterable[str | None]) -> list[str]:
    addresses: dict[str, None] = {}
    for value in values:
        if value is None:
            continue
        try:
            ip = ip_address(value)
        except ValueError:
            continue
        if isinstance(ip, IPv6Address):
            if ip.scope_id:
                continue
            ip = ip.ipv4_mapped or ip
        if ip.is_global and not (ip.is_multicast or ip.is_reserved):
            addresses[ip.compressed] = None
    return list(addresses)


def safe_error(exc):
    text = (str(exc).splitlines() or [type(exc).__name__])[0][:200]
    for token in text.split():
        if "@" in token or "://" in token or len(token) >= 32 and all(c.isalnum() or c in "-_=" for c in token):
            return type(exc).__name__
    return text
