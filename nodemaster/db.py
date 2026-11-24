SCHEMA = (
    """
    CREATE TABLE nodes (
        id INTEGER PRIMARY KEY, fingerprint TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL, protocol TEXT NOT NULL, host TEXT NOT NULL,
        port INTEGER NOT NULL, transport TEXT NOT NULL, secret BLOB NOT NULL,
        notes TEXT NOT NULL, tags TEXT NOT NULL, created TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1, deleted TEXT, latest_id INTEGER
    );
    CREATE TABLE sources (
        id INTEGER PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, format TEXT NOT NULL,
        input BLOB NOT NULL, max_candidates INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
        refreshed TEXT, status TEXT, report TEXT
    );
    CREATE TABLE node_sources (
        node_id INTEGER NOT NULL REFERENCES nodes(id),
        source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
        seen TEXT NOT NULL, present INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (node_id, source_id)
    );
    CREATE TABLE tasks (
        id INTEGER PRIMARY KEY, kind TEXT NOT NULL, state TEXT NOT NULL, options TEXT NOT NULL,
        created TEXT NOT NULL, started TEXT, finished TEXT, total INTEGER NOT NULL DEFAULT 0,
        done INTEGER NOT NULL DEFAULT 0, succeeded INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0,
        report TEXT
    );
    CREATE TABLE task_events (
        id INTEGER PRIMARY KEY, task_id INTEGER NOT NULL REFERENCES tasks(id),
        time TEXT NOT NULL, event TEXT NOT NULL, data TEXT NOT NULL
    );
    CREATE TABLE results (
        id INTEGER PRIMARY KEY, node_id INTEGER NOT NULL REFERENCES nodes(id),
        task_id INTEGER NOT NULL REFERENCES tasks(id), scope TEXT NOT NULL, level TEXT NOT NULL,
        status TEXT NOT NULL, latency REAL, speed REAL, success_rate REAL, jitter REAL, score REAL,
        data TEXT NOT NULL, tested TEXT NOT NULL, UNIQUE (task_id, node_id)
    );
    CREATE INDEX results_node ON results (node_id, id DESC);
    CREATE INDEX results_scope ON results (scope, node_id, id DESC);
    CREATE INDEX events_task ON task_events (task_id, id DESC);
    CREATE TABLE quality_checks (
        id INTEGER PRIMARY KEY, ip TEXT NOT NULL, provider TEXT NOT NULL, checked TEXT NOT NULL,
        status TEXT NOT NULL, data TEXT NOT NULL, raw TEXT NOT NULL
    );
    CREATE INDEX quality_ip ON quality_checks (ip, provider, id DESC);
    CREATE TABLE settings (key TEXT PRIMARY KEY, value BLOB NOT NULL);
    CREATE TABLE schedules (
        id INTEGER PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, minutes INTEGER NOT NULL,
        cron TEXT, enabled INTEGER NOT NULL DEFAULT 1, options TEXT NOT NULL
    );
    CREATE TABLE recommendations (
        scope TEXT NOT NULL, node_id INTEGER NOT NULL REFERENCES nodes(id),
        result_id INTEGER NOT NULL REFERENCES results(id), ranking INTEGER NOT NULL,
        PRIMARY KEY (scope, node_id)
    );
    CREATE TABLE audit (
        id INTEGER PRIMARY KEY, time TEXT NOT NULL, operation TEXT NOT NULL, detail TEXT NOT NULL
    );
    """,
    """
    ALTER TABLE results ADD COLUMN endpoint_ip TEXT;
    UPDATE results SET endpoint_ip=(SELECT json_extract(s.value,'$.resolved_ip')
        FROM json_each(results.data,'$.samples') s WHERE json_extract(s.value,'$.resolved_ip') IS NOT NULL LIMIT 1);
    UPDATE nodes SET latest_id=(SELECT MAX(r.id) FROM results r JOIN tasks t ON t.id=r.task_id
        WHERE r.node_id=nodes.id AND t.state='completed');
    CREATE TABLE ip_quality_scores (ip TEXT PRIMARY KEY, score REAL NOT NULL);
    CREATE INDEX quality_checks_date ON quality_checks(checked);
    """,
    """
    ALTER TABLE sources ADD COLUMN remote INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE sources ADD COLUMN snapshot TEXT;
    ALTER TABLE nodes ADD COLUMN quality_address TEXT;
    CREATE INDEX node_sources_by_source ON node_sources(source_id,present);
    CREATE INDEX quality_latest_passed ON quality_checks(ip,id DESC) WHERE status='passed';
    """,
    """
    ALTER TABLE node_sources ADD COLUMN eliminated INTEGER NOT NULL DEFAULT 0;
    """,
    """
    ALTER TABLE results ADD COLUMN edge_location TEXT;
    CREATE TABLE ip_network_types (ip TEXT PRIMARY KEY, type TEXT NOT NULL);
    """,
)
