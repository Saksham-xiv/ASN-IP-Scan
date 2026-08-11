"""The per-address unit of work, shared by the IPv4 and IPv6 scanners."""

from .classify import Classifier
from .resolve import CFG, forward_confirm, reverse_dns
from .util import addr_from_int, to_key


CLASSIFIER = Classifier()


def set_classifier(classifier):

    global CLASSIFIER

    CLASSIFIER = classifier


def make_row(addr, hostname, status, verified=-1):
    """(ip_key, version, ip, hostname, label, matched, status, verified)."""

    label, matched = CLASSIFIER(hostname)

    return (to_key(addr), addr.version, str(addr), hostname, label,
            int(matched), status, verified)


def probe(job):
    """Worker: resolve one address. job = (version, ip_int)."""

    version, ip_int = job

    addr = addr_from_int(ip_int, version)
    ip = str(addr)

    hostname, status = reverse_dns(ip)

    verified = -1

    if CFG["verify"] and hostname:
        verified = forward_confirm(hostname, ip, version)

    return make_row(addr, hostname, status, verified)


def confirm_row(row):
    """Forward-confirm an address the IPv6 walk already found a name for."""

    if not CFG["verify"] or not row[3]:
        return row

    verified = forward_confirm(row[3], row[2], row[1])

    return row[:7] + (verified,)


def relabel(conn, batch=20_000):
    """
    Recompute every stored label from the hostname already on record.

    Labels are decided during the scan, so editing a rules file changes
    nothing about results already in the database. Rescanning hundreds of
    thousands of addresses to pick up a one-line JSON edit would be
    absurd; this re-runs only the labelling half of the work, and touches
    no nameserver at all.

    Paged by primary key rather than held open on one cursor, so the
    updates cannot disturb the read it is walking.
    """

    last = b""

    total = 0
    changed = 0

    while True:

        rows = conn.execute(
            "SELECT ip_key, hostname, label, matched FROM results "
            "WHERE ip_key > ? AND hostname <> '' ORDER BY ip_key LIMIT ?",
            (last, batch),
        ).fetchall()

        if not rows:
            break

        last = rows[-1][0]

        updates = []

        for ip_key, hostname, label, matched in rows:

            new_label, new_matched = CLASSIFIER(hostname)

            if new_label != label or int(new_matched) != matched:
                updates.append((new_label, int(new_matched), ip_key))

        if updates:
            with conn:
                conn.executemany(
                    "UPDATE results SET label = ?, matched = ? "
                    "WHERE ip_key = ?", updates)

        total += len(rows)
        changed += len(updates)

    return total, changed


def skipped_row(version, ip_int, status="no_zone"):
    """An address inside a block that was skipped without being queried."""

    addr = addr_from_int(ip_int, version)

    return (to_key(addr), version, str(addr), "", "", 0, status, -1)
