"""
IPv4: a straight sweep of every address in every announced prefix.

4.3 billion addresses is small enough to walk one by one, so this is the
exhaustive half of the tool - if an address in the ASN has a PTR record,
this finds it. Work is committed to SQLite every CHUNK addresses, so
Ctrl+C costs at most one chunk.
"""

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from .console import info, progress_bar
from .probe import probe, skipped_row
from .resolve import STOP
from .store import checkpoint, load_progress, save_chunk, write_rows
from .util import fmt, int_to_key, key_to_int


# Addresses handed to the pool per checkpoint. Bigger = fewer commits
# (faster); smaller = less work lost on a hard kill.
CHUNK = 4096


def probe_chunk(pool, jobs, args):
    """
    Probe a chunk, skipping /24s whose reverse zone answers nothing.

    Plenty of announced space has in-addr.arpa delegation that SERVFAILs
    or black-holes every query. Those cost the *full* timeout each, so a
    single dead /22 can dominate an entire run. Sample the head of each
    /24 first; if not one sample answers, record the rest as no_zone
    without querying them.

    --no-breaker turns this off: marginally more thorough, much slower.
    """

    if not args.breaker:
        return list(pool.map(probe, jobs))

    segments = defaultdict(list)

    for job in jobs:
        segments[job[1] >> 8].append(job)

    # phase 1: sample every /24 in the chunk, in parallel
    heads = []

    for seg in segments.values():
        heads.extend(seg[:args.probe_n])

    rows = {key_to_int(r[0]): r for r in pool.map(probe, heads)}

    # phase 2: finish the live /24s, synthesise the dead ones
    tail = []
    dead = []

    for seg in segments.values():

        sampled = seg[:args.probe_n]

        if sampled and all(rows[j[1]][6] == "error" for j in sampled):
            dead.extend(seg[args.probe_n:])
        else:
            tail.extend(seg[args.probe_n:])

    for r in pool.map(probe, tail):
        rows[key_to_int(r[0])] = r

    for version, ip_int in dead:
        rows[ip_int] = skipped_row(version, ip_int)

    return [rows[ip_int] for _, ip_int in jobs]


def scan_v4(conn, nets, args):
    """Sweep every IPv4 prefix. Returns how many addresses were probed."""

    if not nets:
        return 0

    progress = load_progress(conn)

    total = sum(n.num_addresses for n in nets)

    already = 0

    for net in nets:
        cursor, done = progress.get(str(net), (None, 0))

        if done:
            already += net.num_addresses

        elif cursor is not None:
            already += max(0, key_to_int(cursor) - int(net.network_address) + 1)

    if already:
        info(f"Resuming IPv4: {fmt(already)} of {fmt(total)} addresses "
             f"already done")

    processed = 0
    found = 0

    bar = progress_bar(known_total=True)

    with bar, ThreadPoolExecutor(max_workers=args.threads) as pool:

        task = bar.add_task("IPv4", total=total,
                            completed=min(already, total), extra="")

        for net in nets:

            if STOP.is_set():
                break

            prefix = str(net)

            cursor, done = progress.get(prefix, (None, 0))

            if done:
                continue

            first = int(net.network_address)
            last = int(net.broadcast_address)

            # every address is probed, including network and broadcast: a
            # PTR either exists or it does not, and .hosts() would drop
            # exactly the addresses routers most often name
            pos = first if cursor is None else key_to_int(cursor) + 1

            if pos > last:
                with conn:
                    checkpoint(conn, prefix, 4, int_to_key(last, 4), done=1)
                continue

            bar.update(task, description=f"IPv4 {prefix}")

            while pos <= last:

                if STOP.is_set():
                    break

                end = min(pos + CHUNK - 1, last)

                jobs = [(4, i) for i in range(pos, end + 1)]

                rows = probe_chunk(pool, jobs, args)

                save_chunk(conn, prefix, 4, rows, end, done=int(end == last))

                found += sum(1 for r in rows if r[6] == "ok")
                processed += len(rows)

                bar.update(task, advance=len(rows),
                           extra=f"[good]{fmt(found)} PTRs[/good]")

                pos = end + 1

                if args.limit and processed >= args.limit:
                    info(f"--limit reached after {fmt(processed)} lookups")
                    STOP.set()
                    break

    info(f"IPv4 pass: {fmt(processed)} addresses probed, {fmt(found)} with "
         f"a PTR")

    return processed


def retry_errors(conn, args):
    """
    Re-query the addresses that never gave a definitive answer.

    An "error" row is not "no PTR" - it is "we do not know", and a busy
    resolver can leave millions of them. --include-dead also revisits the
    /24s the circuit breaker skipped without asking.
    """

    wanted = ("error", "no_zone") if args.include_dead else ("error",)

    rows = conn.execute(
        "SELECT ip_key, version, prefix FROM results WHERE status IN (%s)"
        % ",".join("?" * len(wanted)), wanted).fetchall()

    if not rows:
        info("No unresolved lookups to retry.")
        return 0

    info(f"Retrying {fmt(len(rows))} unresolved lookups ...")

    by_prefix = defaultdict(list)

    for ip_key, version, prefix in rows:
        by_prefix[prefix].append((version, key_to_int(ip_key)))

    fixed = 0

    bar = progress_bar(known_total=True)

    with bar, ThreadPoolExecutor(max_workers=args.threads) as pool:

        task = bar.add_task("Retry", total=len(rows), extra="")

        for prefix, jobs in by_prefix.items():

            if STOP.is_set():
                break

            bar.update(task, description=f"Retry {prefix}")

            for i in range(0, len(jobs), CHUNK):

                if STOP.is_set():
                    break

                batch = jobs[i:i + CHUNK]

                # queried directly: the breaker's whole job is to avoid
                # these addresses, so applying it again would skip them
                results = list(pool.map(probe, batch))

                # only the rows change here, so the cursor is left alone
                cur = conn.execute(
                    "SELECT cursor, done FROM progress WHERE prefix=?",
                    (prefix,)).fetchone()

                with conn:
                    write_rows(conn, prefix, results)

                    if cur:
                        checkpoint(conn, prefix, 4, cur[0], cur[1])

                fixed += sum(1 for r in results if r[6] != "error")

                bar.update(task, advance=len(results),
                           extra=f"[good]{fmt(fixed)} resolved[/good]")

    info(f"{fmt(fixed)} previously unresolved addresses now have a "
         f"definitive answer")

    return fixed
