"""
IPv6: an ip6.arpa reverse-tree walk.

A single IPv6 /32 holds 79 octillion addresses, so the IPv4 approach -
try them all - is not slow, it is impossible. What *is* finite is the
reverse-DNS tree: PTR records live at 32 nibble-deep nodes under
ip6.arpa, and a compliant nameserver answers three different ways:

    NOERROR + PTR   this node is a name (at depth 32, a live address)
    NOERROR, no PTR "empty non-terminal" - nothing here, but there are
                    children below. Descend.
    NXDOMAIN        nothing exists at or under this node. Prune - one
                    answer can eliminate 16^n addresses at a stroke.

So the walk starts at the prefix's node, asks 16 questions per level,
and follows only the branches that exist. On a normal ISP or hosting
network that turns an impossible enumeration into a few thousand
queries, and it finds real, complete addresses rather than guesses.

Two caveats, both handled here:

  * a zone with a PTR wildcard answers "yes" for everything, which would
    make the walk descend forever. Every prefix is wildcard-probed with
    a random deep name first, and any node that answers above depth 32
    is recorded and pruned.
  * some nameservers wrongly return NXDOMAIN for empty non-terminals.
    Nothing can be walked there; the prefix simply comes back empty.

The frontier lives in the database, so this is as resumable as the IPv4
sweep: the queue *is* the scan position.
"""

import ipaddress
import random

from concurrent.futures import ThreadPoolExecutor

from .console import info, progress_bar, warn
from .probe import confirm_row, make_row
from .resolve import STOP, query_node
from .store import (bump, checkpoint, enqueue, load_progress, queue_size,
                    take_batch, write_rows)
from .util import fmt


FULL_DEPTH = 32                                     # 32 nibbles = 128 bits


# --- node <-> network ---------------------------------------------------

def network_to_node(net):
    """
    Node name for a network, as reversed nibbles (no ".ip6.arpa").

    A prefix that is not on a nibble boundary (/33, /35) is rounded down
    to the enclosing nibble-aligned network; the extra addresses that
    pulls in are filtered out when a hit is recorded.
    """

    depth = net.prefixlen // 4

    nibbles = format(int(net.network_address), "032x")[:depth]

    return ".".join(reversed(nibbles))


def node_to_network(node):

    nibbles = "".join(reversed(node.split("."))) if node else ""

    depth = len(nibbles)

    value = int(nibbles.ljust(FULL_DEPTH, "0"), 16) if depth else 0

    return ipaddress.IPv6Network((value, depth * 4))


def node_to_address(node):

    nibbles = "".join(reversed(node.split(".")))

    return ipaddress.IPv6Address(int(nibbles, 16))


def children(node):

    return [f"{n:x}.{node}" if node else f"{n:x}" for n in range(16)]


def random_deep_node(root, depth):
    """A node nobody could plausibly have named, for the wildcard probe."""

    extra = "".join(random.choice("0123456789abcdef")
                    for _ in range(FULL_DEPTH - depth))

    return ".".join(reversed(extra)) + ("." + root if root else "")


# --- the walk -----------------------------------------------------------

def _query(job):
    """Worker. job = (node, prefix, depth, attempts)."""

    node, prefix, depth, attempts = job

    if STOP.is_set():
        return node, prefix, depth, attempts, "error", ""

    status, hostname = query_node(node)

    return node, prefix, depth, attempts, status, hostname


def prepare_prefix(conn, net, args):
    """
    Seed a prefix's frontier, unless it is finished or wildcarded.

    Returns True when there is work queued for it.
    """

    prefix = str(net)

    progress = load_progress(conn)

    started = prefix in progress

    if started and progress[prefix][1]:
        return False                                # already finished

    if queue_size(conn, prefix):
        return True                                 # resuming mid-walk

    if started:
        # the frontier emptied on a previous run that was killed before
        # it could say so
        with conn:
            checkpoint(conn, prefix, 6, None, done=1)

        return False

    depth = net.prefixlen // 4

    root = network_to_node(net)

    # Does this zone answer for names that cannot exist? If so, walking
    # it would descend all 16 branches at every level to no purpose.
    status, hostname = query_node(random_deep_node(root, depth))

    if status == "ok":
        warn(f"{prefix}: reverse zone answers with a wildcard "
             f"({hostname}) - recorded, not walked")

        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO v6_wildcards "
                "(node, prefix, covers, depth, hostname) VALUES (?,?,?,?,?)",
                (root, prefix, prefix, depth, hostname),
            )
            checkpoint(conn, prefix, 6, None, done=1)

        return False

    with conn:
        enqueue(conn, [(root, prefix, depth)])
        checkpoint(conn, prefix, 6, None, done=0)

    return True


def walk_prefix(conn, net, args, bar, task, budget):
    """Walk one prefix until its frontier empties or the budget runs out."""

    prefix = str(net)

    queried = 0
    hits = 0

    with ThreadPoolExecutor(max_workers=args.threads) as pool:

        while not STOP.is_set() and queried < budget:

            batch = take_batch(conn, prefix, min(args.v6_batch,
                                                 budget - queried))

            if not batch:
                break

            results = list(pool.map(_query, batch))

            rows = []
            new_nodes = []
            retry = []
            dead = []
            wildcards = []
            subnets = []

            for node, _p, depth, attempts, status, hostname in results:

                if status == "ok":

                    if depth >= FULL_DEPTH:
                        addr = node_to_address(node)

                        # a rounded-down root can reach outside the real
                        # announcement; drop those
                        if addr in net:
                            rows.append(make_row(addr, hostname, "ok"))
                            hits += 1

                    else:
                        # a name above full depth covers everything under
                        # it; descending would enumerate a wildcard
                        wildcards.append((node, prefix,
                                          str(node_to_network(node)), depth,
                                          hostname))

                elif status == "empty":

                    # exists but holds no PTR: it is a branch, so there
                    # are names underneath it
                    if depth < args.v6_max_depth:
                        new_nodes.extend(
                            (child, prefix, depth + 1)
                            for child in children(node)
                        )
                    else:
                        subnets.append((str(node_to_network(node)), prefix,
                                        depth))

                elif status == "error":

                    if attempts + 1 < args.attempts:
                        retry.append((node,))
                    else:
                        dead.append((node, prefix, depth, "no answer"))

                # nxdomain: prune, which is simply not enqueueing anything

            done_nodes = [
                (r[0],) for r in results
                if not (r[4] == "error" and r[3] + 1 < args.attempts)
            ]

            if args.verify and rows:
                rows = list(pool.map(confirm_row, rows))

            with conn:

                if rows:
                    write_rows(conn, prefix, rows)

                if new_nodes:
                    enqueue(conn, new_nodes)

                if wildcards:
                    conn.executemany(
                        "INSERT OR REPLACE INTO v6_wildcards "
                        "(node, prefix, covers, depth, hostname) "
                        "VALUES (?,?,?,?,?)", wildcards)

                if subnets:
                    conn.executemany(
                        "INSERT OR REPLACE INTO v6_subnets "
                        "(network, prefix, depth) VALUES (?,?,?)", subnets)

                if dead:
                    conn.executemany(
                        "INSERT OR REPLACE INTO v6_dead "
                        "(node, prefix, depth, reason) VALUES (?,?,?,?)", dead)

                if retry:
                    conn.executemany(
                        "UPDATE v6_queue SET attempts = attempts + 1 "
                        "WHERE node = ?", retry)

                if done_nodes:
                    conn.executemany("DELETE FROM v6_queue WHERE node = ?",
                                     done_nodes)

                bump(conn, "v6_nodes", len(results))

            queried += len(results)

            bar.update(task, advance=len(results),
                       extra=f"[good]{fmt(hits)} addresses[/good] "
                             f"[muted]frontier {fmt(queue_size(conn, prefix))}"
                             f"[/muted]")

    remaining = queue_size(conn, prefix)

    if not remaining and not STOP.is_set():
        with conn:
            checkpoint(conn, prefix, 6, None, done=1)

    return queried, hits, remaining


def scan_v6(conn, nets, args):
    """Walk every IPv6 prefix. Returns (nodes queried, addresses found)."""

    if not nets:
        return 0, 0

    if not args.v6_walk:
        info("IPv6 walk disabled (--no-v6-walk); prefixes are still "
             "listed in the report")
        return 0, 0

    from .resolve import HAVE_DNSPYTHON

    if not HAVE_DNSPYTHON:
        warn("IPv6 discovery needs dnspython (it must tell NXDOMAIN from a "
             "timeout). Skipping.  pip install dnspython")
        return 0, 0

    total_queried = 0
    total_hits = 0

    budget = args.v6_max_nodes

    bar = progress_bar(known_total=False)

    with bar:

        task = bar.add_task("IPv6 tree walk", total=None, extra="")

        for net in nets:

            if STOP.is_set() or total_queried >= budget:
                break

            prefix = str(net)

            bar.update(task, description=f"IPv6 {prefix}")

            if not prepare_prefix(conn, net, args):
                continue

            queried, hits, remaining = walk_prefix(
                conn, net, args, bar, task, budget - total_queried)

            total_queried += queried
            total_hits += hits

            if remaining and not STOP.is_set():
                warn(f"{prefix}: node budget reached, {fmt(remaining)} nodes "
                     f"still queued - rerun to continue "
                     f"(--v6-max-nodes {budget * 2})")

    info(f"IPv6 pass: {fmt(total_queried)} tree nodes queried, "
         f"{fmt(total_hits)} addresses found")

    return total_queried, total_hits


def requeue_dead(conn):
    """
    Put the ip6.arpa nodes that never answered back on the frontier.

    A node that timed out was never pruned *or* descended, so whatever
    lives under it is missing from the report. This is the IPv6 half of
    --retry-errors.
    """

    dead = conn.execute(
        "SELECT node, prefix, depth FROM v6_dead").fetchall()

    if not dead:
        return 0

    info(f"Requeueing {fmt(len(dead))} ip6.arpa nodes that never answered")

    with conn:
        enqueue(conn, dead)
        conn.execute("DELETE FROM v6_dead")

        conn.executemany(
            "UPDATE progress SET done = 0 WHERE prefix = ?",
            [(prefix,) for prefix in {d[1] for d in dead}])

    return len(dead)
