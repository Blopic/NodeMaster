import base64
import hashlib
import hmac
import json
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet

from .db import SCHEMA
from .network_info import EDGE_CITIES, classify_ip
from .nodes import Node, canonical_json

QUALITY_IP = "COALESCE(n.quality_address,r.endpoint_ip,n.host)"
NODE_JOINS = ("FROM nodes n LEFT JOIN results r ON r.id=n.latest_id "
              f"LEFT JOIN ip_quality_scores q ON q.ip={QUALITY_IP} "
              f"LEFT JOIN ip_network_types nt ON nt.ip={QUALITY_IP}")
VALID_COUNTRY = "json_type(data,'$.country')='text' AND trim(json_extract(data,'$.country'))<>''"
DATABASE_LOCATION = f"""(SELECT json_object('provider',g.provider,
    'country',upper(trim(json_extract(g.data,'$.country'))), 'region',json_extract(g.data,'$.region'),
    'city',json_extract(g.data,'$.city')) FROM quality_checks g
    WHERE g.ip={QUALITY_IP} AND g.status='passed' AND {VALID_COUNTRY}
      AND g.id=(SELECT MAX(v.id) FROM quality_checks v
                WHERE v.ip=g.ip AND v.provider=g.provider AND v.status='passed' AND {VALID_COUNTRY})
    ORDER BY (json_extract(g.data,'$.region') IS NOT NULL)+(json_extract(g.data,'$.city') IS NOT NULL) DESC,
      CASE g.provider WHEN 'dbip' THEN 0 WHEN 'ipinfo' THEN 1 WHEN 'ipapi' THEN 2 WHEN 'ipwhois' THEN 3 ELSE 4 END,
      g.id DESC LIMIT 1)"""
NODE_LOCATION = f"COALESCE(r.edge_location,{DATABASE_LOCATION})"
NODE_COUNTRY = f"json_extract({NODE_LOCATION},'$.country')"
NODE_IP_TYPE = "COALESCE(nt.type, CASE WHEN r.edge_location IS NOT NULL THEN 'hosting' END, 'unknown')"
NODE_STATUS = "COALESCE(r.status,CASE WHEN n.protocol IN ('cdn','turn','turns','stun') THEN 'untested' ELSE 'unsupported' END)"


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def unpack(row: sqlite3.Row | None, *fields: str) -> dict[str, Any] | None:
    if row is None:
        return None
    value = dict(row)
    for field in fields:
        if value.get(field) is not None:
            value[field] = json.loads(value[field])
    return value


class Store:
    def __init__(self, directory: Path):
        self.directory = directory
        self.path = directory / "nodemaster.sqlite3"

    def initialize(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / "local.key"
        if not path.exists():
            if self.path.exists():
                raise RuntimeError("找不到 local.key，请从同一份备份恢复数据库和密钥")
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as key_file:
                    key_file.write(Fernet.generate_key())
            except FileExistsError:
                pass
        key = path.read_bytes().strip()
        self.cipher = Fernet(key)
        self.mac = hmac.digest(base64.urlsafe_b64decode(key), b"nodemaster/node-fingerprint/v1", "sha256")
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
        with self.connect(write=True) as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version > len(SCHEMA):
                raise RuntimeError("数据库来自更新版本的 NodeMaster")
            for number, sql in enumerate(SCHEMA[version:], version + 1):
                for statement in sql.split(";"):
                    if statement.strip():
                        db.execute(statement)
                if number == 2:
                    for (ip,) in db.execute("SELECT DISTINCT ip FROM quality_checks"):
                        self.update_quality_score(db, ip)
                if number == 3:
                    for row in db.execute("SELECT id,input FROM sources WHERE kind!='official'").fetchall():
                        value = self.decrypt(row["input"]).strip()
                        if value.startswith(("https://", "http://")) and "\n" not in value:
                            db.execute("UPDATE sources SET remote=1 WHERE id=?", (row["id"],))
                if number == 5:
                    for (ip,) in db.execute("SELECT DISTINCT ip FROM quality_checks").fetchall():
                        self.update_network_type(db, ip)
                db.execute(f"PRAGMA user_version={number}")

    @contextmanager
    def connect(self, write: bool = False) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            if write:
                db.execute("BEGIN IMMEDIATE")
            yield db
            if write:
                db.commit()
        except BaseException:
            if write:
                db.rollback()
            raise
        finally:
            db.close()

    def encrypt(self, value: Any) -> bytes:
        return self.cipher.encrypt(canonical_json(value).encode())

    def decrypt(self, value: bytes) -> Any:
        return json.loads(self.cipher.decrypt(value))

    @staticmethod
    def audit(db: sqlite3.Connection, operation: str, info: dict[str, Any]) -> None:
        db.execute("INSERT INTO audit(time,operation,detail) VALUES(?,?,?)", (now(), operation, canonical_json(info)))

    def backup(self) -> Path:
        dest = self.directory / "backups"
        dest.mkdir(exist_ok=True)
        path = dest / (datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f") + ".sqlite3")
        with self.connect() as db:
            backup = sqlite3.connect(path)
            try:
                db.backup(backup)
            finally:
                backup.close()
        return path

    def import_nodes(self, nodes: list[Node], source: int | None = None, replace: bool = False,
                     *, restore_deleted: bool = False, snapshot: str | None = None, staged: bool = False) -> dict[str, Any]:
        report: dict[str, Any] = {"added": 0, "duplicates": 0, "restored": 0, "excluded": 0, "ids": [], "new_ids": []}
        checked = now()
        with self.connect(write=True) as db:
            if source is not None and not db.execute("SELECT 1 FROM sources WHERE id=? AND enabled=1", (source,)).fetchone():
                raise LookupError("来源不存在或已暂停")
            prior = {row[0] for row in db.execute("SELECT node_id FROM node_sources WHERE source_id=? AND present=1", (source,))} if replace else set()
            excluded = {row[0] for row in db.execute(
                "SELECT node_id FROM node_sources WHERE source_id=? AND eliminated=1", (source,)
            )} if source is not None else set()
            seen = set()
            for item in nodes:
                finger = hmac.new(self.mac, item.identity().encode(), hashlib.sha256).hexdigest()
                found = db.execute("SELECT id,deleted FROM nodes WHERE fingerprint=?", (finger,)).fetchone()
                if found:
                    node_id = found["id"]
                    if source is not None and not restore_deleted and (found["deleted"] or node_id in excluded):
                        report["excluded"] += 1
                        continue
                    report["duplicates"] += 1
                    if found["deleted"] and (source is None or restore_deleted):
                        db.execute("UPDATE nodes SET deleted=NULL,enabled=1 WHERE id=?", (node_id,))
                        report["restored"] += 1
                        report["new_ids"].append(node_id)
                else:
                    insert = db.execute(
                        "INSERT INTO nodes(fingerprint,name,protocol,host,port,transport,secret,notes,tags,created) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (finger, item.name, item.protocol, item.host, item.port, item.transport,
                         self.encrypt([item.config, item.original]), item.notes, canonical_json(item.tags), checked),
                    )
                    node_id = insert.lastrowid
                    report["added"] += 1
                    report["new_ids"].append(node_id)
                if source is not None:
                    if staged:
                        db.execute("INSERT OR IGNORE INTO node_sources(node_id,source_id,seen,present) VALUES(?,?,?,0)",
                                   (node_id, source, checked))
                    else:
                        db.execute("""INSERT INTO node_sources(node_id,source_id,seen,present) VALUES(?,?,?,1)
                                      ON CONFLICT(node_id,source_id) DO UPDATE SET seen=excluded.seen,present=1""",
                                   (node_id, source, checked))
                seen.add(node_id)
            absent = sorted(prior - seen)
            if absent:
                db.executemany("UPDATE node_sources SET present=0 WHERE node_id=? AND source_id=?", [(i, source) for i in absent])
            report["ids"] = sorted(seen)
            report["missing"] = len(absent)
            if snapshot is not None:
                db.execute("UPDATE sources SET snapshot=? WHERE id=?", (canonical_json({"hash": snapshot, "ids": report["ids"]}), source))
            self.audit(db, "import", {"source": source, **{k: v for k, v in report.items() if not isinstance(v, list)}})
        return report

    @staticmethod
    def filters(filters: dict[str, Any]) -> tuple[str, list[Any]]:
        where, params = ["n.deleted IS NULL"], []
        if search := filters.get("q"):
            escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            where.append("(n.name LIKE ? ESCAPE '\\' OR n.host LIKE ? ESCAPE '\\' OR n.notes LIKE ? ESCAPE '\\')")
            params.extend([f"%{escaped}%"] * 3)
        for key, column in (("transport", "n.transport"), ("port", "n.port"), ("enabled", "n.enabled")):
            if filters.get(key) is not None:
                where.append(f"{column}=?")
                params.append(filters[key])
        for key, column in (("protocol", "n.protocol"), ("status", NODE_STATUS),
                            ("country", f"COALESCE({NODE_COUNTRY},'unknown') COLLATE NOCASE"), ("ip_type", NODE_IP_TYPE)):
            if values := filters.get(key):
                where.append(f"{column} IN (SELECT value FROM json_each(?))")
                params.append(canonical_json(values if isinstance(values, list) else [values]))
        workspace = filters.get("workspace")
        if workspace == "cdn":
            where.append("n.protocol='cdn'")
        if workspace == "turn" or filters.get("group") == "turn":
            where.append("n.protocol IN ('turn','turns','stun')")
        if workspace == "other":
            where.append("n.protocol NOT IN ('cdn','turn','turns','stun')")
        if family := filters.get("family"):
            where.append("n.protocol='cdn'")
            address = "COALESCE(r.endpoint_ip,n.host)"
            where.append(f"instr({address},':')>0" if family == 6 else
                         f"instr({address},'.')>0 AND {address} NOT GLOB '*[^0-9.]*'")
        if tag := filters.get("tag"):
            where.append("EXISTS(SELECT 1 FROM json_each(n.tags) j WHERE j.value=?)")
            params.append(tag)
        if source := filters.get("source"):
            where.append("EXISTS(SELECT 1 FROM node_sources ns WHERE ns.node_id=n.id AND ns.source_id=? AND ns.present=1)")
            params.append(source)
        if sources := filters.get("source_ids"):
            where.append("EXISTS(SELECT 1 FROM node_sources ns WHERE ns.node_id=n.id AND ns.present=1 AND ns.source_id IN (SELECT value FROM json_each(?)))")
            params.append(canonical_json(sources))
        if filters.get("protocols") is not None:
            where.append("n.protocol IN (SELECT value FROM json_each(?))")
            params.append(canonical_json(filters["protocols"]))
        if filters.get("recommended"):
            where.append("n.enabled=1 AND EXISTS(SELECT 1 FROM recommendations p WHERE p.node_id=n.id AND p.result_id=r.id)")
        if filters.get("ids") is not None:
            where.append("n.id IN (SELECT value FROM json_each(?))")
            params.append(canonical_json(filters["ids"]))
        for key, column, operator in (
            ("min_score", "r.score", ">="), ("min_speed", "r.speed", ">="), ("max_latency", "r.latency", "<="),
            ("min_success", "r.success_rate", ">="), ("max_jitter", "r.jitter", "<="), ("scope", "r.scope", "="),
            ("min_quality_score", "q.score", ">="),
        ):
            if filters.get(key) is not None:
                where.append(f"{column}{operator}?")
                params.append(filters[key])
        return " AND ".join(where), params

    def list_nodes(self, filters: dict[str, Any], limit: int = 50, offset: int = 0, *,
                   result_levels: tuple[str, ...] = (), result_task: int | None = None) -> dict[str, Any]:
        where, params = self.filters(filters)
        sort = {"name": "n.name COLLATE NOCASE", "latency": "r.latency", "speed": "r.speed", "score": "r.score",
                "success": "r.success_rate", "jitter": "r.jitter", "quality": "q.score", "recent": "n.id"}.get(filters.get("sort"), "n.id")
        direction = "ASC" if filters.get("ascending") else "DESC"
        order = ("json_extract(location,'$.country') IS NULL, json_extract(location,'$.country') COLLATE NOCASE ASC, n.id DESC"
                 if filters.get("sort") == "region" else f"({sort}) IS NULL, {sort} {direction}, n.id")
        joins = NODE_JOINS
        if result_levels:
            joins = joins.replace("r.id=n.latest_id", """r.id=(SELECT sample.id FROM results sample
                JOIN tasks task ON task.id=sample.task_id
                WHERE sample.node_id=n.id AND sample.level IN (SELECT value FROM json_each(?)) AND task.state='completed'
                AND (sample.level<>'quick' OR n.protocol='stun') AND (? IS NULL OR sample.task_id=?)
                ORDER BY sample.id DESC LIMIT 1)""")
            params[:0] = [canonical_json(result_levels), result_task, result_task]
        base = f"{joins} WHERE {where}"
        with self.connect() as db:
            count = db.execute("SELECT count(*) " + base, params).fetchone()[0]
            rows = db.execute(f"""SELECT n.id,n.name,n.protocol,n.host,n.port,n.transport,n.notes,n.tags,n.created,n.enabled,
                      {NODE_STATUS} AS status,
                      r.level,r.scope,r.score,r.latency,r.speed,r.success_rate,r.jitter,r.tested,q.score AS quality_score,
                      COALESCE(r.endpoint_ip,n.host) AS test_address,
                      COALESCE(n.quality_address,r.endpoint_ip,CASE WHEN instr(n.host, ':')>0 OR
                        (instr(n.host,'.')>0 AND n.host NOT GLOB '*[^0-9.]*') THEN n.host END) AS quality_ip,
                      {NODE_LOCATION} AS location, {NODE_IP_TYPE} AS ip_type,
                      CASE WHEN r.edge_location IS NOT NULL THEN {DATABASE_LOCATION} END AS database_location,
                      COALESCE((SELECT json_group_array(name) FROM (SELECT s.name FROM node_sources ns
                      JOIN sources s ON s.id=ns.source_id WHERE ns.node_id=n.id AND ns.present=1 ORDER BY s.id)),'[]') AS source_names,
                      (SELECT MAX(a.tested) FROM results a JOIN tasks t ON t.id=a.task_id
                       WHERE a.node_id=n.id AND a.status='passed' AND t.state='completed') AS last_available,
                      (SELECT p.ranking FROM recommendations p WHERE p.node_id=n.id AND p.result_id=r.id) AS rank
                    {base} ORDER BY {order} LIMIT ? OFFSET ?""", (*params, limit, offset))
            return {"total": count, "items": [unpack(row, "tags", "source_names", "location", "database_location") for row in rows]}

    def node_regions(self, workspace: str | None = None) -> list[dict[str, Any]]:
        where, params = self.filters({"workspace": workspace})
        with self.connect() as db:
            rows = db.execute(f"""SELECT {NODE_COUNTRY} AS country, count(*) AS count
                               {NODE_JOINS} WHERE {where} GROUP BY country COLLATE NOCASE
                               ORDER BY country IS NULL, country COLLATE NOCASE""", params)
            return [dict(row) for row in rows]

    def node_addresses(self, filters: dict[str, Any]) -> list[dict[str, Any]]:
        where, params = self.filters(filters)
        with self.connect() as db:
            rows = db.execute(f"SELECT n.host,n.port,n.protocol,n.transport {NODE_JOINS} WHERE {where} ORDER BY n.id DESC", params)
            return [dict(row) for row in rows]

    def retain_nodes(self, filters: dict[str, Any], token: str | None) -> dict[str, Any]:
        where, params = self.filters(filters)
        scope, scope_params = self.filters({"workspace": filters.get("workspace")})
        with self.connect(write=token is not None) as db:
            if token is None:
                # Read both sets from the same snapshot.
                db.execute("BEGIN")
            kept = [row[0] for row in db.execute(f"SELECT n.id {NODE_JOINS} WHERE {where} ORDER BY n.id", params)]
            active = [row[0] for row in db.execute(f"SELECT n.id FROM nodes n WHERE {scope} ORDER BY n.id", scope_params)]
            keep_set = set(kept)
            removed = [node_id for node_id in active if node_id not in keep_set]
            current = hmac.digest(self.mac, canonical_json([kept, removed]).encode(), "sha256").hex()
            report = {"kept": len(kept), "removed": len(removed), "token": current}
            if token is None:
                return report
            if not hmac.compare_digest(current, token):
                raise LookupError("节点或筛选结果已变化，请重新预览")
            if not kept:
                raise ValueError("筛选结果为空，无法覆盖节点列表")
            if removed:
                self.backup()
                ids = canonical_json(removed)
                selector = "IN (SELECT value FROM json_each(?))"
                db.execute(f"UPDATE nodes SET deleted=?,enabled=0 WHERE id {selector}", (now(), ids))
                db.execute(f"UPDATE node_sources SET present=0 WHERE node_id {selector}", (ids,))
                self.audit(db, "retain_nodes", {"kept": len(kept), "removed": len(removed)})
            return report

    def get_node(self, node_id: int, include_deleted: bool = False) -> Node | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM nodes WHERE id=? AND (deleted IS NULL OR ?)", (node_id, include_deleted)).fetchone()
        if row is None:
            return None
        options, original = self.decrypt(row["secret"])
        return Node(row["name"], row["protocol"], row["host"], row["port"], row["transport"],
                    options, original, row["notes"], json.loads(row["tags"]), row["id"])

    def export_nodes(self, rows: list[dict[str, Any]], sensitive: bool) -> list[Node]:
        secrets = {}
        if sensitive:
            with self.connect() as db:
                secrets = {row["id"]: self.decrypt(row["secret"]) for row in db.execute(
                    "SELECT id,secret FROM nodes WHERE id IN (SELECT value FROM json_each(?)) AND deleted IS NULL",
                    (canonical_json([row["id"] for row in rows]),))}
        return [Node(row["name"], row["protocol"], row["host"], row["port"], row["transport"],
                     *secrets.get(row["id"], ({}, None)), row["notes"], row["tags"], row["id"])
                for row in rows if not sensitive or row["id"] in secrets]

    def node_action(self, ids: list[int], action: str, tags: list[str], notes: str | None = None) -> int:
        selector = "id IN (SELECT value FROM json_each(?)) AND deleted IS NULL"
        selected = canonical_json(ids)
        if action == "delete":
            self.backup()
        with self.connect(write=True) as db:
            if action == "delete":
                count = db.execute(f"UPDATE nodes SET deleted=?,enabled=0 WHERE {selector}", (now(), selected)).rowcount
            elif action in {"enable", "disable"}:
                count = db.execute(f"UPDATE nodes SET enabled=? WHERE {selector}", (action == "enable", selected)).rowcount
            elif action == "metadata":
                count = db.execute(f"UPDATE nodes SET tags=?,notes=COALESCE(?,notes) WHERE {selector}", (canonical_json(tags), notes, selected)).rowcount
            else:
                raise ValueError("不支持此节点操作")
            self.audit(db, action, {"changed": count, "ids": ids})
        return count

    def history(self, node_id: int, since: str | None = None, until: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("""SELECT r.*,t.state AS task_state FROM results r JOIN tasks t ON t.id=r.task_id
                                 WHERE r.node_id=? AND (? IS NULL OR r.tested>=?) AND (? IS NULL OR r.tested<?)
                                 ORDER BY r.id DESC LIMIT ?""", (node_id, since, since, until, until, limit))
            return [unpack(row, "data") for row in rows]

    def node_address(self, node_id: int, host: str) -> str | None:
        import ipaddress

        try:
            return ipaddress.ip_address(host).compressed
        except ValueError:
            pass
        with self.connect() as db:
            row = db.execute("SELECT COALESCE(n.quality_address,r.endpoint_ip) FROM nodes n LEFT JOIN results r ON r.id=n.latest_id WHERE n.id=?", (node_id,)).fetchone()
            return row[0] if row else None

    def save_quality_address(self, node_id: int, address: str) -> None:
        with self.connect(write=True) as db:
            db.execute("UPDATE nodes SET quality_address=? WHERE id=? AND quality_address IS NOT ?", (address, node_id, address))

    def add_source(self, name: str, kind: str, fmt: str, content: str, cap: int, *, enabled: bool = True) -> int:
        return self.add_sources([(name, kind, fmt, content, cap, enabled)])[0]

    def add_sources(self, sources: list[tuple[str, str, str, str, int, bool]]) -> list[int]:
        with self.connect(write=True) as db:
            return [db.execute("INSERT INTO sources(name,kind,format,input,max_candidates,enabled,remote) VALUES(?,?,?,?,?,?,?)",
                               (name, kind, fmt, self.encrypt(content), cap, enabled,
                                kind != "official" and content.startswith(("https://", "http://")) and "\n" not in content)).lastrowid
                    for name, kind, fmt, content, cap, enabled in sources]

    def list_sources(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            return [unpack(row, "report") for row in db.execute("""SELECT id,name,kind,format,max_candidates,enabled,
                       refreshed,status,report,remote,(SELECT count(*) FROM node_sources ns JOIN nodes n ON n.id=ns.node_id
                         WHERE ns.source_id=s.id AND ns.present=1 AND n.deleted IS NULL) AS node_count
                       FROM sources s ORDER BY id""")]

    def get_source(self, ident: int) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM sources WHERE id=?", (ident,)).fetchone()
        data = unpack(row, "report", "snapshot")
        if data:
            data["input"] = self.decrypt(data["input"])
        return data

    def source_status(self, ident: int, status: str, report: dict[str, Any]) -> None:
        with self.connect(write=True) as db:
            db.execute("UPDATE sources SET refreshed=?,status=?,report=? WHERE id=?", (now(), status, canonical_json(report), ident))

    def source_candidates(self, ident: int, ids: list[int]) -> list[int]:
        with self.connect() as db:
            return [row[0] for row in db.execute("""SELECT n.id FROM nodes n
                LEFT JOIN node_sources ns ON ns.node_id=n.id AND ns.source_id=?
                WHERE n.deleted IS NULL AND COALESCE(ns.eliminated,0)=0
                  AND n.id IN (SELECT value FROM json_each(?)) ORDER BY n.id""", (ident, canonical_json(ids)))]

    def source_action(self, ident: int, enabled: bool | None = None) -> bool:
        with self.connect(write=True) as db:
            if enabled is None:
                changed = db.execute("DELETE FROM sources WHERE id=?", (ident,)).rowcount
            else:
                changed = db.execute("UPDATE sources SET enabled=? WHERE id=?", (enabled, ident)).rowcount
            if changed:
                self.audit(db, "source_change", {"id": ident, "enabled": enabled})
        return bool(changed)

    def source_update(self, ident: int, values: dict[str, Any]) -> bool:
        columns = {"name", "kind", "format", "max_candidates", "enabled"}
        if not values or not values.keys() <= columns:
            raise ValueError("不支持的来源设置")
        assignments = ",".join(f"{key}=?" for key in values)
        with self.connect(write=True) as db:
            count = db.execute(f"UPDATE sources SET {assignments} WHERE id=?", (*values.values(), ident)).rowcount
            if count:
                self.audit(db, "source_update", {"id": ident, "fields": list(values)})
            return bool(count)

    def get_setting(self, key: str, default: Any = None, secret: bool = False) -> Any:
        with self.connect() as db:
            row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        if not row:
            return default
        return self.decrypt(row[0]) if secret else json.loads(row[0])

    def set_settings(self, values: dict[str, Any], secrets: dict[str, str] | None = None) -> None:
        rows = [(key, canonical_json(value)) for key, value in values.items()]
        rows.extend((key, self.encrypt(value)) for key, value in (secrets or {}).items())
        with self.connect(write=True) as db:
            db.executemany("INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", rows)

    def tasks(self, limit: int = 50, *, summary: bool = False) -> list[dict[str, Any]]:
        report = "NULL AS report" if summary else "report"
        with self.connect() as db:
            return [unpack(row, "report", "options") for row in db.execute(f"""SELECT id,kind,state,options,created,started,finished,
                total,done,succeeded,failed,{report} FROM tasks ORDER BY id DESC LIMIT ?""", (limit,))]

    def task(self, ident: int) -> dict[str, Any] | None:
        with self.connect() as db:
            task = unpack(db.execute("SELECT * FROM tasks WHERE id=?", (ident,)).fetchone(), "report", "options")
            if task:
                events = db.execute("SELECT * FROM task_events WHERE task_id=? ORDER BY id DESC LIMIT 50", (ident,))
                task["events"] = [unpack(row, "data") for row in events]
            return task

    def create_task(self, kind: str, options: dict[str, Any]) -> int:
        with self.connect(write=True) as db:
            return db.execute("INSERT INTO tasks(kind,state,options,created) VALUES(?,'queued',?,?)", (kind, canonical_json(options), now())).lastrowid

    def task_update(self, ident: int, **values: Any) -> None:
        if not values.keys() <= {"state", "total", "done", "succeeded", "failed", "started", "finished", "report"}:
            raise ValueError("Unknown task field")
        if "report" in values:
            values["report"] = canonical_json(values["report"])
        assignments = ",".join(f"{key}=?" for key in values)
        with self.connect(write=True) as db:
            db.execute(f"UPDATE tasks SET {assignments} WHERE id=?", (*values.values(), ident))

    def task_event(self, ident: int, event: str, data: dict[str, Any]) -> None:
        with self.connect(write=True) as db:
            db.execute("INSERT INTO task_events(task_id,time,event,data) VALUES(?,?,?,?)", (ident, now(), event, canonical_json(data)))

    def recover_tasks(self) -> None:
        with self.connect(write=True) as db:
            db.execute("UPDATE tasks SET state='interrupted',finished=? WHERE state IN ('queued','running')", (now(),))

    def save_result(self, node_id: int, task_id: int, result: dict[str, Any]) -> int:
        fields = ("scope", "level", "status", "latency", "speed", "success_rate", "jitter", "score")
        samples = result["data"].get("samples", [])
        observed = next((sample for sample in samples if sample.get("resolved_ip") and sample.get("success") and sample.get("cdn_colo")), None)
        attempts = result["data"].get("trials") or samples
        best = observed or next((sample for sample in samples if sample.get("resolved_ip") and sample.get("success")), None)
        endpoint_ip = best["resolved_ip"] if best else next((sample["resolved_ip"] for sample in attempts if sample.get("resolved_ip")), None)
        edge_location = None
        if observed and result.get("status") == "passed" and result.get("level") == "http":
            colo = observed["cdn_colo"]
            country, city = EDGE_CITIES.get(colo, (None, None))
            edge_location = canonical_json({"country": country, "region": None, "city": city, "provider": "cloudflare", "colo": colo})
        with self.connect(write=True) as db:
            row = db.execute("""INSERT INTO results(node_id,task_id,scope,level,status,latency,speed,success_rate,jitter,score,data,tested,endpoint_ip,edge_location)
                              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                             (node_id, task_id, *(result.get(f) for f in fields), canonical_json(result["data"]), now(), endpoint_ip, edge_location))
            return row.lastrowid

    def comparison_snapshot(self, scope: str) -> dict[int, dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("""SELECT r.id,r.node_id,r.status,r.latency,r.speed,r.success_rate,r.jitter,r.score,
                                        n.name AS node_name,
                                        n.deleted IS NULL AND n.enabled=1 AND n.latest_id=r.id AS eligible
                                  FROM results r JOIN nodes n ON n.id=r.node_id
                                  WHERE r.scope=? AND r.id IN (
                                    SELECT MAX(prior.id) FROM results prior JOIN tasks task ON task.id=prior.task_id
                                    WHERE prior.scope=? AND task.state='completed' GROUP BY prior.node_id)
                                  ORDER BY r.node_id""", (scope, scope))
            return {row["node_id"]: dict(row) for row in rows}

    def recommendation_ranks(self, scope: str) -> dict[int, int]:
        with self.connect() as db:
            return dict(db.execute("SELECT node_id,ranking FROM recommendations WHERE scope=?", (scope,)))

    def stale_candidates(self, scope: str, failures: list[int], days: int) -> list[int]:
        if not failures:
            return []
        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat(timespec="milliseconds")
        with self.connect() as db:
            return [row[0] for row in db.execute("""SELECT DISTINCT r.node_id
                FROM results r JOIN tasks t ON t.id=r.task_id
                WHERE r.node_id IN (SELECT value FROM json_each(?)) AND r.scope=?
                    AND r.status='failed' AND t.state='completed' AND r.tested<=?
                    AND NOT EXISTS (SELECT 1 FROM results newer JOIN tasks tn ON tn.id=newer.task_id
                        WHERE newer.node_id=r.node_id AND newer.scope=r.scope AND newer.id>r.id
                              AND newer.status!='failed' AND tn.state='completed')
                ORDER BY r.node_id""", (canonical_json(failures), scope, cutoff))]

    def finish_task(self, ident: int, state: str, report: dict[str, Any], updates: list[dict[str, Any]] | None = None) -> None:
        with self.connect(write=True) as db:
            db.execute("UPDATE tasks SET state=?,finished=?,report=? WHERE id=?", (state, now(), canonical_json(report), ident))
            scopes = report.get("recommendation_scopes", [])
            self.audit(db, "task_finish", {"id": ident, "state": state, "comparison_groups": len(report.get("comparison", [])),
                                          "updated_recommendation_scopes": scopes})
            if state != "completed":
                return
            db.execute("""UPDATE nodes SET latest_id=(SELECT r.id FROM results r WHERE r.task_id=? AND r.node_id=nodes.id),
                          quality_address=COALESCE((SELECT r.endpoint_ip FROM results r WHERE r.task_id=? AND r.node_id=nodes.id),quality_address)
                          WHERE id IN (SELECT node_id FROM results WHERE task_id=?)""", (ident, ident, ident))
            for update in updates or ():
                source = update["source"]
                db.execute("""UPDATE node_sources SET eliminated=1
                               WHERE source_id=? AND node_id IN (SELECT value FROM json_each(?))
                               AND EXISTS(SELECT 1 FROM sources WHERE id=? AND enabled=1)""",
                           (source, canonical_json(update["dropped"]), source))
                db.execute("""UPDATE node_sources SET present=(eliminated=0 AND node_id IN (SELECT value FROM json_each(?))
                               AND EXISTS(SELECT 1 FROM nodes n WHERE n.id=node_sources.node_id AND n.deleted IS NULL))
                               WHERE source_id=? AND EXISTS(SELECT 1 FROM sources WHERE id=? AND enabled=1)""",
                           (canonical_json(update["retained"]), source, source))
                db.execute("UPDATE sources SET snapshot=? WHERE id=? AND enabled=1",
                           (canonical_json(update["snapshot"]), source))
            if auto_disabled := report.get("auto_disabled"):
                db.execute("UPDATE nodes SET enabled=0 WHERE deleted IS NULL AND id IN (SELECT value FROM json_each(?))",
                           (canonical_json(auto_disabled),))
                self.audit(db, "auto_disable", {"task": ident, "ids": auto_disabled})
            recommendation = report.get("recommendations", [])
            for scope in scopes:
                db.execute("DELETE FROM recommendations WHERE scope=?", (scope,))
            if recommendation:
                for item in recommendation:
                    db.execute("""INSERT INTO recommendations(scope,node_id,result_id,ranking) VALUES(?,?,?,?)
                                  ON CONFLICT(scope,node_id) DO UPDATE SET result_id=excluded.result_id,ranking=excluded.ranking""",
                               (item["scope"], item["node_id"], item["result_id"], item["rank"]))

    def summary(self) -> dict[str, Any]:
        with self.connect() as db:
            rows = db.execute("""SELECT n.protocol,r.status,count(*) count,avg(r.latency) latency,
                          sum(CASE WHEN r.score>=80 AND r.status='passed' THEN 1 ELSE 0 END) high_quality,
                          max(r.tested) tested FROM nodes n LEFT JOIN results r ON r.id=n.latest_id
                          WHERE n.deleted IS NULL GROUP BY n.protocol,r.status""").fetchall()
            tasks = [dict(row) for row in db.execute("SELECT state,count(*) count FROM tasks GROUP BY state")]
            high_ip_quality = db.execute("""SELECT count(*) FROM nodes n LEFT JOIN results r ON r.id=n.latest_id
                JOIN ip_quality_scores q ON q.ip=COALESCE(r.endpoint_ip,n.host)
                WHERE n.deleted IS NULL AND n.enabled=1 AND q.score>=80""").fetchone()[0]
        return {"groups": [dict(row) for row in rows], "tasks": tasks, "high_ip_quality": high_ip_quality}

    def quality(self, ip: str, limit: int = 30) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM quality_checks WHERE ip=? ORDER BY id DESC LIMIT ?", (ip, limit))
            return [unpack(row, "data", "raw") for row in rows]

    def quality_profile_rows(self, ip: str) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(f"""SELECT id,ip,provider,checked,status,data FROM quality_checks WHERE id IN (
                SELECT MAX(id) FROM quality_checks WHERE ip=? GROUP BY provider
                UNION SELECT MAX(id) FROM quality_checks WHERE ip=? AND status='passed' GROUP BY provider
                UNION SELECT MAX(id) FROM quality_checks WHERE ip=? AND status='passed' AND {VALID_COUNTRY} GROUP BY provider
                ) ORDER BY id DESC""", (ip, ip, ip))
            return [unpack(row, "data") for row in rows]

    def save_quality(self, ip: str, provider: str, status: str, data: dict[str, Any], raw: dict[str, Any]) -> None:
        with self.connect(write=True) as db:
            db.execute("INSERT INTO quality_checks(ip,provider,checked,status,data,raw) VALUES(?,?,?,?,?,?)",
                       (ip, provider, now(), status, canonical_json(data), canonical_json(raw)))
            self.update_quality_score(db, ip)
            self.update_network_type(db, ip)

    @staticmethod
    def update_network_type(db: sqlite3.Connection, ip: str) -> None:
        rows = db.execute("""SELECT data,status FROM quality_checks WHERE id IN (
            SELECT MAX(id) FROM quality_checks WHERE ip=? AND status='passed' GROUP BY provider)""", (ip,))
        kind = classify_ip([unpack(row, "data") for row in rows])
        if kind:
            db.execute("INSERT INTO ip_network_types VALUES(?,?) ON CONFLICT(ip) DO UPDATE SET type=excluded.type", (ip, kind))
        else:
            db.execute("DELETE FROM ip_network_types WHERE ip=?", (ip,))

    @staticmethod
    def update_quality_score(db: sqlite3.Connection, ip: str) -> None:
        from .quality import quality_profile

        rows = db.execute("""SELECT * FROM quality_checks WHERE ip=? AND id IN (
                            SELECT MAX(id) FROM quality_checks WHERE ip=? AND status='passed' GROUP BY provider)""", (ip, ip))
        score = quality_profile([unpack(row, "data") for row in rows])["score"]
        if score is None:
            db.execute("DELETE FROM ip_quality_scores WHERE ip=?", (ip,))
        else:
            db.execute("INSERT INTO ip_quality_scores VALUES(?,?) ON CONFLICT(ip) DO UPDATE SET score=excluded.score", (ip, score))

    def clean_quality(self, max_days: int) -> int:
        cutoff = (datetime.now(UTC) - timedelta(days=max_days)).isoformat()
        with self.connect(write=True) as db:
            affected = [row[0] for row in db.execute("SELECT DISTINCT ip FROM quality_checks WHERE checked < ?", (cutoff,))]
            count = db.execute("DELETE FROM quality_checks WHERE checked < ?", (cutoff,)).rowcount
            for ip in affected:
                self.update_quality_score(db, ip)
                self.update_network_type(db, ip)
            self.audit(db, "clean_quality", {"deleted": count})
            return count

    def schedules(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            return [unpack(row, "options") for row in db.execute("SELECT * FROM schedules ORDER BY id")]

    def changes(self, days: int = 7) -> dict[str, Any]:
        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        with self.connect() as db:
            rows = db.execute("""SELECT r.*,n.name,n.host FROM results r JOIN tasks t ON t.id=r.task_id
                                  JOIN nodes n ON n.id=r.node_id WHERE r.tested>=? AND t.state='completed'
                                  ORDER BY r.task_id,r.scope,r.node_id""", (cutoff,)).fetchall()
        grouped: dict[tuple[int, str], list[sqlite3.Row]] = {}
        for row in rows:
            grouped.setdefault((row["task_id"], row["scope"]), []).append(row)
        return {"groups": [{"task": key[0], "scope": key[1], "results": [unpack(row, "data") for row in values]}
                           for key, values in grouped.items()]}

    def save_schedule(self, data: dict[str, Any], ident: int | None = None) -> int | None:
        values = (data["name"], data["kind"], data["minutes"], data.get("cron"), data["enabled"], canonical_json(data["options"]))
        with self.connect(write=True) as db:
            if ident is None:
                return db.execute("INSERT INTO schedules(name,kind,minutes,cron,enabled,options) VALUES(?,?,?,?,?,?)", values).lastrowid
            count = db.execute("UPDATE schedules SET name=?,kind=?,minutes=?,cron=?,enabled=?,options=? WHERE id=?", (*values, ident)).rowcount
            return ident if count else None

    def delete_schedule(self, ident: int) -> bool:
        with self.connect(write=True) as db:
            return bool(db.execute("DELETE FROM schedules WHERE id=?", (ident,)).rowcount)
