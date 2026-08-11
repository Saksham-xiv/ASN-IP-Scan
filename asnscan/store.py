"""
SQLite checkpoint store.

Every lookup lands here before anything else happens, so a scan can be
interrupted (Ctrl+C, crash, reboot) and resumed exactly where it stopped.
The spreadsheet is a *view* over this file and can be rebuilt at any time
without re-querying anything.

One database holds exactly one ASN: results, progress and the IPv6 walk
frontier have no ASN column, so mixing two would silently blend two
networks into one report. `bind_db_to_asn` enforces that.
"""

import json
import sqlite3
import time

from .console import bad
from .util import fmt, int_to_key


SCHEMA = """
CREATE TABLE IF NOT EXISTS results (
    ip_key   BLOB    PRIMARY KEY,
    version  INTEGER NOT NULL,
    ip       TEXT    NOT NULL,
    prefix   TEXT    NOT NULL,
    hostname TEXT    NOT NULL,
    label    TEXT    NOT NULL,
    matched  INTEGER NOT NULL DEFAULT 0,
    status   TEXT    NOT NULL,
    verified INTEGER NOT NULL DEFAULT -1,
    ts       INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_results_label  ON results(label);
CREATE INDEX IF NOT EXISTS idx_results_status ON results(status);
CREATE INDEX IF NOT EXISTS idx_results_prefix ON results(prefix);

-- state: live      still announced at the end of the lookback window
--        recent    announced during it, gone before it closed
--        withdrawn was here on an earlier run, absent from this one
CREATE TABLE IF NOT EXISTS prefixes (
    prefix     TEXT    PRIMARY KEY,
    version    INTEGER NOT NULL,
    first_ip   TEXT    NOT NULL,
    last_ip    TEXT    NOT NULL,
    addresses  TEXT    NOT NULL,
    first_seen TEXT    NOT NULL DEFAULT '',
    last_seen  TEXT    NOT NULL DEFAULT '',
    state      TEXT    NOT NULL DEFAULT 'live',
    checked    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS progress (
    prefix  TEXT    PRIMARY KEY,
    version INTEGER NOT NULL,
    cursor  BLOB,
    done    INTEGER NOT NULL DEFAULT 0,
    updated INTEGER NOT NULL
);

-- Frontier of the ip6.arpa tree walk. Persisting it is what makes an
-- IPv6 scan resumable: the queue *is* the scan position.
CREATE TABLE IF NOT EXISTS v6_queue (
    node     TEXT    PRIMARY KEY,
    prefix   TEXT    NOT NULL,
    depth    INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_v6_queue_prefix ON v6_queue(prefix);

CREATE TABLE IF NOT EXISTS v6_dead (
    node   TEXT    PRIMARY KEY,
    prefix TEXT    NOT NULL,
    depth  INTEGER NOT NULL,
    reason TEXT    NOT NULL
);

-- Networks the walk proved are in use but did not descend into, because
-- --v6-max-depth stopped it there. "There are hosts under this /64."
CREATE TABLE IF NOT EXISTS v6_subnets (
    network TEXT PRIMARY KEY,
    prefix  TEXT    NOT NULL,
    depth   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS v6_wildcards (
    node     TEXT PRIMARY KEY,
    prefix   TEXT NOT NULL,
    covers   TEXT NOT NULL,
    depth    INTEGER NOT NULL,
    hostname TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS counters (k TEXT PRIMARY KEY, n INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS state (k TEXT PRIMARY KEY, v TEXT);
"""


# Columns added after the first release. CREATE TABLE IF NOT EXISTS does
# nothing to a table that already exists, so a database written by an
# earlier version needs them added explicitly.
MIGRATIONS = {
    "prefixes": (
        ("first_seen", "TEXT NOT NULL DEFAULT ''"),
        ("last_seen", "TEXT NOT NULL DEFAULT ''"),
        ("state", "TEXT NOT NULL DEFAULT 'live'"),
        ("checked", "INTEGER NOT NULL DEFAULT 0"),
    ),
}


def migrate(conn):

    for table, columns in MIGRATIONS.items():

        have = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}

        for name, decl in columns:

            if name not in have:
                conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN {name} {decl}")

    conn.commit()


def open_db(path):

    conn = sqlite3.connect(path, timeout=60, isolation_level="DEFERRED")

    # WAL + NORMAL keeps commits cheap without risking corruption
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=-65536")        # 64 MB page cache

    conn.executescript(SCHEMA)
    conn.commit()

    migrate(conn)

    return conn


# --- ASN binding --------------------------------------------------------

def bind_db_to_asn(conn, asn):
    """Tie a database to one ASN, permanently. False means refuse to run."""

    row = conn.execute("SELECT v FROM state WHERE k='asn'").fetchone()

    if row is None:

        n = conn.execute("SELECT COUNT(*) FROM results").fetchone()[0]

        if n:
            bad(f"{fmt(n)} addresses were scanned into this database before "
                f"it recorded which ASN they came from.")
            bad(f"Those rows would be reported as AS{asn}. "
                f"Start a clean file:  --db AS{asn}_scan.sqlite3")
            return False

        set_state(conn, "asn", str(asn))
        conn.commit()

        return True

    stored = int(row[0])

    if stored == asn:
        return True

    n = conn.execute("SELECT COUNT(*) FROM results").fetchone()[0]

    bad(f"This database already holds AS{stored} ({fmt(n)} scanned "
        f"addresses), but --asn is {asn}.")
    bad(f"Mixing ASNs in one database blends both networks into one "
        f"report. Use a separate file:  --db AS{asn}_scan.sqlite3")

    return False


# --- key/value state ----------------------------------------------------

def set_state(conn, key, value):
    conn.execute("INSERT OR REPLACE INTO state (k, v) VALUES (?, ?)",
                 (key, value))


def get_state(conn, key, default=None):

    row = conn.execute("SELECT v FROM state WHERE k=?", (key,)).fetchone()

    return row[0] if row else default


def set_json(conn, key, value):
    set_state(conn, key, json.dumps(value))


def get_json(conn, key, default=None):

    raw = get_state(conn, key)

    return json.loads(raw) if raw else default


def bump(conn, key, n=1):
    conn.execute(
        "INSERT INTO counters (k, n) VALUES (?, ?) "
        "ON CONFLICT(k) DO UPDATE SET n = n + excluded.n",
        (key, n),
    )


def counter(conn, key):

    row = conn.execute("SELECT n FROM counters WHERE k=?", (key,)).fetchone()

    return row[0] if row else 0


# --- prefixes -----------------------------------------------------------

def save_prefixes(conn, entries):
    """
    Record the announced blocks, and mark whatever has since vanished.

    Rows are never deleted: a block the ASN has stopped announcing still
    has scan results behind it, and quietly dropping it would make those
    addresses look like they were never found. It is marked withdrawn
    instead, and the report says so.
    """

    now = int(time.time())

    rows = [
        (str(e["net"]), e["net"].version, str(e["net"].network_address),
         str(e["net"].broadcast_address), str(e["net"].num_addresses),
         e.get("first_seen", ""), e.get("last_seen", ""),
         e.get("state", "live"), now)
        for e in entries
    ]

    with conn:
        conn.executemany(
            "INSERT INTO prefixes "
            "(prefix, version, first_ip, last_ip, addresses, first_seen, "
            " last_seen, state, checked) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(prefix) DO UPDATE SET "
            "first_seen=excluded.first_seen, last_seen=excluded.last_seen, "
            "state=excluded.state, checked=excluded.checked",
            rows,
        )

        # a temp table rather than a NOT IN (...) list: an ASN can
        # announce more prefixes than SQLite will take as parameters
        conn.execute("CREATE TEMP TABLE IF NOT EXISTS announced_now "
                     "(prefix TEXT PRIMARY KEY)")
        conn.execute("DELETE FROM announced_now")

        conn.executemany("INSERT OR IGNORE INTO announced_now VALUES (?)",
                         [(r[0],) for r in rows])

        conn.execute(
            "UPDATE prefixes SET state = 'withdrawn' "
            "WHERE prefix NOT IN (SELECT prefix FROM announced_now)")


# --- results / checkpoints ----------------------------------------------

INSERT_RESULT = (
    "INSERT OR REPLACE INTO results "
    "(ip_key, version, ip, prefix, hostname, label, matched, status, "
    " verified, ts) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


def write_rows(conn, prefix, rows, now=None):
    """rows: (ip_key, version, ip, hostname, label, matched, status, ver)."""

    now = now or int(time.time())

    conn.executemany(
        INSERT_RESULT,
        [
            (r[0], r[1], r[2], prefix, r[3], r[4], r[5], r[6], r[7], now)
            for r in rows
        ],
    )


def checkpoint(conn, prefix, version, cursor, done=0, now=None):

    conn.execute(
        "INSERT INTO progress (prefix, version, cursor, done, updated) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(prefix) DO UPDATE SET "
        "cursor=excluded.cursor, done=excluded.done, updated=excluded.updated",
        (prefix, version, cursor, done, now or int(time.time())),
    )


def save_chunk(conn, prefix, version, rows, cursor_int, done=0):
    """Results + checkpoint in one transaction, so they cannot disagree."""

    now = int(time.time())

    cursor = (int_to_key(cursor_int, version)
              if cursor_int is not None else None)

    with conn:
        write_rows(conn, prefix, rows, now)
        checkpoint(conn, prefix, version, cursor, done, now)


def load_progress(conn):

    return {
        row[0]: (row[1], row[2])
        for row in conn.execute("SELECT prefix, cursor, done FROM progress")
    }


# --- IPv6 walk frontier -------------------------------------------------

def queue_size(conn, prefix=None):

    if prefix:
        row = conn.execute(
            "SELECT COUNT(*) FROM v6_queue WHERE prefix=?", (prefix,)
        ).fetchone()
    else:
        row = conn.execute("SELECT COUNT(*) FROM v6_queue").fetchone()

    return row[0]


def enqueue(conn, nodes):
    """nodes: (node, prefix, depth)."""

    conn.executemany(
        "INSERT OR IGNORE INTO v6_queue (node, prefix, depth) VALUES (?,?,?)",
        nodes,
    )


def take_batch(conn, prefix, limit):
    """
    Next nodes to expand: deepest first.

    Depth-first is not a preference here, it is the difference between a
    walk that works and one that does not. Breadth-first would expand
    every node at level n before touching level n+1, so the frontier
    grows 16x per level (a /32 has 16^24 nodes at full depth) and not one
    real address is found until the very end. Diving instead keeps the
    frontier at roughly 16 nodes per level and starts producing addresses
    within seconds.
    """

    return conn.execute(
        "SELECT node, prefix, depth, attempts FROM v6_queue "
        "WHERE prefix=? ORDER BY depth DESC, node LIMIT ?",
        (prefix, limit),
    ).fetchall()
