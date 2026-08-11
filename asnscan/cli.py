"""Command line: argument parsing, the run order, and the safety rails."""

import argparse
import os
import signal
import sys
import time

from . import __version__
from .classify import Classifier
from .console import bad, console, good, info, rule, warn
from .prefixes import asn_info, get_prefixes
from .probe import relabel, set_classifier
from .report import print_summary, save_report
from .resolve import HAVE_DNSPYTHON, STOP, configure
from .scan4 import retry_errors, scan_v4
from .scan6 import requeue_dead, scan_v6
from .store import bind_db_to_asn, get_json, open_db, set_json
from .util import fmt, fmt_duration, parse_asn, parse_duration


EPILOG = """
examples:
  asn_scan.py --asn 32934                    scan Meta's ASN, v4 + v6
  asn_scan.py --asn AS13335 --family 6       IPv6 tree walk only
  asn_scan.py --asn 15169 --prefixes-only    just the announced space
  asn_scan.py --asn 32934 --rules rules/meta.json --only-matching
  asn_scan.py --asn 32934 --retry-errors     re-query what never answered
  asn_scan.py --asn 32934 --report-only      rebuild the report, no DNS
  asn_scan.py --asn 7018 --format csv --yes  92M addresses, skip Excel

Ctrl+C is safe: the current chunk is committed and the next run resumes
from the same address.
"""


def parse_args(argv=None):

    p = argparse.ArgumentParser(
        prog="asn_scan",
        description="Find every reachable IPv4 and IPv6 address an ASN "
                    "announces, by reverse DNS.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument("--version", action="version",
                   version=f"asn-ip-scan {__version__}")

    target = p.add_argument_group("target")

    target.add_argument("--asn", required=True,
                        help="AS number to scan, e.g. 32934 or AS32934")
    target.add_argument("--family", choices=["4", "6", "both"], default="both",
                        help="address families to scan (default: both)")
    target.add_argument("--prefix-source", choices=["auto", "ripe", "bgpview"],
                        default="auto",
                        help="where the announced prefixes come from")
    target.add_argument("--expect-holder", default="",
                        help="refuse to scan unless the registered holder "
                             "contains this text (case-insensitive)")
    target.add_argument("--announced-within", default="all", metavar="WHEN",
                        help="which blocks to scan: 'all' (default - "
                             "everything announced during the source's "
                             "lookback window, two weeks for RIPEstat), "
                             "'live' (still announced at the end of it), or "
                             "an age such as 3d / 36h / 2w. Blocks left out "
                             "are still listed in the report.")
    target.add_argument("--live-only", action="store_true",
                        help="shorthand for --announced-within live")

    out = p.add_argument_group("output")

    out.add_argument("--out-dir", default="output",
                     help="directory for the database and report "
                          "(default: output)")
    out.add_argument("--db", default="",
                     help="default: <out-dir>/AS<asn>_scan.sqlite3 "
                          "(one ASN per file)")
    out.add_argument("--output", default="",
                     help="default: <out-dir>/AS<asn>_report.xlsx")
    out.add_argument("--format", choices=["xlsx", "csv", "json", "all"],
                     default="xlsx",
                     help="csv and json have no row ceiling; use them past "
                          "~1M results")
    out.add_argument("--max-rows", type=int, default=1_048_575,
                     help="rows per sheet before spilling to a new one")

    lab = p.add_argument_group("labelling")

    lab.add_argument("--rules", default="",
                     help="JSON rules file mapping DNS zones and hostname "
                          "tokens to labels (see rules/meta.json). Without "
                          "one, results are grouped by registrable domain.")
    lab.add_argument("--only-matching", action="store_true",
                     help="report only the addresses the rules matched")

    dns_ = p.add_argument_group("resolution")

    dns_.add_argument("--threads", type=int, default=0,
                      help="0 = auto (256 with dnspython, 64 without)")
    dns_.add_argument("--timeout", type=float, default=1.5,
                      help="per-query DNS timeout in seconds")
    dns_.add_argument("--attempts", type=int, default=2,
                      help="tries before a lookup is recorded as unresolved")
    dns_.add_argument("--resolvers", default="",
                      help="comma-separated nameservers, e.g. 1.1.1.1,8.8.8.8 "
                           "(one fast resolver beats three slow ones)")
    dns_.add_argument("--rate", type=float, default=0,
                      help="cap queries per second across all threads "
                           "(0 = unlimited)")
    dns_.add_argument("--verify", action="store_true",
                      help="forward-confirm every hostname found (FCrDNS, "
                           "roughly doubles the queries)")

    v4 = p.add_argument_group("IPv4 sweep")

    v4.add_argument("--no-breaker", dest="breaker", action="store_false",
                    help="probe every address even in /24s whose reverse "
                         "zone answers nothing (much slower)")
    v4.add_argument("--probe-n", type=int, default=4,
                    help="addresses sampled per /24 before it is written off")
    v4.add_argument("--max-addresses", type=int, default=5_000_000,
                    help="confirm before sweeping more IPv4 addresses than "
                         "this (0 = never ask)")

    v6 = p.add_argument_group("IPv6 tree walk")

    v6.add_argument("--no-v6-walk", dest="v6_walk", action="store_false",
                    help="list IPv6 prefixes but do not walk ip6.arpa")
    v6.add_argument("--v6-max-nodes", type=int, default=200_000,
                    help="ip6.arpa nodes to query per run (default 200000)")
    v6.add_argument("--v6-max-depth", type=int, default=32,
                    help="nibbles to descend; 32 = full addresses, 16 = stop "
                         "at /64 and just record which networks are in use")
    v6.add_argument("--v6-batch", type=int, default=64,
                    help="frontier nodes expanded per commit. Keep it small: "
                         "a wide batch spends the budget going sideways at "
                         "one level instead of diving to real addresses")
    v6.add_argument("--v6-threads", type=int, default=32,
                    help="concurrency for the walk. Lower than --threads on "
                         "purpose: a whole zone is usually served by one set "
                         "of nameservers, and hammering it just turns "
                         "answers into timeouts. 0 = use --threads")

    mode = p.add_argument_group("modes")

    mode.add_argument("--prefixes-only", action="store_true",
                      help="fetch the announced space and report it, no DNS")
    mode.add_argument("--report-only", action="store_true",
                      help="rebuild the report from the database")
    mode.add_argument("--relabel", action="store_true",
                      help="re-apply --rules to the hostnames already "
                           "scanned, then rebuild the report. No DNS - use "
                           "this after editing a rules file instead of "
                           "rescanning.")
    mode.add_argument("--retry-errors", action="store_true",
                      help="re-query only what never gave an answer")
    mode.add_argument("--include-dead", action="store_true",
                      help="with --retry-errors, also revisit skipped /24s")
    mode.add_argument("--refresh-prefixes", action="store_true",
                      help="re-fetch the announced prefixes")
    mode.add_argument("--limit", type=int, default=0,
                      help="stop after N IPv4 lookups (for testing)")
    mode.add_argument("-y", "--yes", action="store_true",
                      help="answer yes to the scope confirmation")

    args = p.parse_args(argv)

    args.asn = parse_asn(args.asn)

    args.families = ((4, 6) if args.family == "both"
                     else (int(args.family),))

    if args.threads <= 0:
        args.threads = 256 if HAVE_DNSPYTHON else 64

    if args.v6_threads <= 0:
        args.v6_threads = args.threads

    args.probe_n = max(1, args.probe_n)
    args.attempts = max(1, args.attempts)
    args.v6_max_depth = max(1, min(32, args.v6_max_depth))

    if args.live_only:
        args.announced_within = "live"

    if args.announced_within not in ("all", "live"):
        try:
            parse_duration(args.announced_within)
        except ValueError as e:
            p.error(f"--announced-within: {e}. Use 'all', 'live', or an age "
                    f"like 3d / 36h / 2w.")

    os.makedirs(args.out_dir, exist_ok=True)

    if not args.db:
        args.db = os.path.join(args.out_dir, f"AS{args.asn}_scan.sqlite3")

    if not args.output:
        args.output = os.path.join(args.out_dir, f"AS{args.asn}_report.xlsx")

    args.resolvers = [s.strip() for s in args.resolvers.split(",") if s.strip()]

    return args


# --- safety rails -------------------------------------------------------

def confirm_scope(nets4, args):
    """A 92-million-address ASN should never start by accident."""

    total = sum(n.num_addresses for n in nets4)

    if not total or not args.max_addresses or total <= args.max_addresses:
        return True

    # measured rate is roughly threads * 3 lookups/sec against a healthy
    # resolver; deliberately pessimistic so the estimate is not a lie
    estimate = total / max(1, args.threads * 3)

    warn(f"AS{args.asn} announces {fmt(total)} IPv4 addresses. At "
         f"{args.threads} threads that is roughly "
         f"{fmt_duration(estimate)} of DNS queries.")
    warn("The scan is resumable, so it can be stopped and continued later.")

    if args.yes:
        return True

    if not sys.stdin.isatty():
        bad("Refusing to start unattended. Re-run with --yes, or narrow the "
            "scan with --limit / --family 6.")
        return False

    console.print("[warn]Continue?[/warn] [muted](y/N)[/muted] ", end="")

    return input().strip().lower() in ("y", "yes")


def check_holder(asn, args, conn):
    """Look up who the ASN belongs to, print it, and cache it."""

    meta = asn_info(asn)

    if meta.get("holder"):
        info(f"AS{asn} holder: [bold]{meta['holder']}[/bold]"
             + (f"  ({meta['country']})" if meta.get("country") else ""))
    else:
        warn(f"Could not determine who AS{asn} belongs to.")

    with conn:
        set_json(conn, "asn_info", meta)

    if not args.expect_holder:
        return True

    if args.expect_holder.lower() in (meta.get("holder") or "").lower():
        return True

    bad(f"AS{asn} is registered to '{meta.get('holder') or 'unknown'}', which "
        f"does not contain '{args.expect_holder}'.")
    bad("Scanning the wrong ASN produces a clean, plausible, entirely wrong "
        "report. Drop --expect-holder to scan it anyway.")

    return False


# --- run ----------------------------------------------------------------

SYNC_FOLDERS = ("onedrive", "dropbox", "google drive", "googledrive",
                "icloud", "nextcloud", "sync")


def check_db_location(path):
    """
    Refuse to be quietly corrupted by a file-sync client.

    SQLite in WAL mode keeps committed data in a separate -wal file until
    it is checkpointed. A sync client that copies, locks or rolls back the
    two files independently can leave the database intact but missing
    everything written since the last checkpoint - a scan that "worked"
    and then has no results in it.
    """

    parts = [p.lower() for p in os.path.abspath(path).split(os.sep)]

    hit = next((p for p in parts if any(s in p for s in SYNC_FOLDERS)), None)

    if not hit:
        return

    warn(f"The database is inside a synced folder ('{hit}'). A sync client "
         f"can roll back SQLite's write-ahead log mid-scan and silently "
         f"discard results.")
    warn("Keep the database on a local disk and only the report in the "
         "synced folder:")
    warn(f"    --db %LOCALAPPDATA%\\asn-ip-scan\\{os.path.basename(path)}")


def install_sigint():

    def handler(signum, frame):

        if STOP.is_set():
            bad("Forced quit.")
            sys.exit(130)

        STOP.set()

        warn("Stopping after this chunk - progress is checkpointed. "
             "Ctrl+C again to force quit.")

    signal.signal(signal.SIGINT, handler)


def main(argv=None):

    args = parse_args(argv)

    rule(f"asn-ip-scan {__version__}  ·  AS{args.asn}")

    configure(timeout=args.timeout, attempts=args.attempts,
              resolvers=args.resolvers, verify=args.verify, rate=args.rate)

    set_classifier(Classifier.from_file(args.rules))

    if args.rules:
        info(f"Labelling with rules from {args.rules}")

    if not HAVE_DNSPYTHON:
        warn("dnspython is not installed - falling back to "
             "socket.gethostbyaddr, which is slower, cannot tell 'no PTR' "
             "from 'timeout', and cannot walk IPv6 at all.")
        warn("pip install dnspython")

    install_sigint()

    conn = open_db(args.db)

    try:
        if not bind_db_to_asn(conn, args.asn):
            return 2

        info(f"Database: {args.db}")

        check_db_location(args.db)

        if args.relabel:
            rule("Relabel")

            total, changed = relabel(conn)

            info(f"{fmt(total)} hostnames re-examined, "
                 f"[good]{fmt(changed)} labels changed[/good]")

            rule("Report")
            save_report(conn, args)
            print_summary(conn, args)
            return 0

        if args.report_only:
            rule("Report")
            save_report(conn, args)
            print_summary(conn, args)
            return 0

        if not check_holder(args.asn, args, conn):
            return 2

        nets = get_prefixes(conn, args.asn, args.families,
                            args.refresh_prefixes, args.prefix_source,
                            args.announced_within)

        # remember which source answered, for the report header
        cached = get_json(conn, f"prefixes:{args.asn}", {}) or {}
        meta = get_json(conn, "asn_info", {}) or {}
        meta["prefix_source"] = cached.get("source", "")

        with conn:
            set_json(conn, "asn_info", meta)

        if args.prefixes_only:
            rule("Report")
            save_report(conn, args)
            return 0

        if args.retry_errors:
            rule("Retry")
            retry_errors(conn, args)
            requeue_dead(conn)

            if 6 in args.families:
                scan_v6(conn, nets.get(6, []), args)

            rule("Report")
            save_report(conn, args)
            print_summary(conn, args)
            return 0

        if 4 in args.families and not confirm_scope(nets.get(4, []), args):
            return 2

        started = time.time()

        engine = "dnspython" if HAVE_DNSPYTHON else "socket"

        info(f"Scanning with {args.threads} threads ({engine})"
             + (f", capped at {args.rate:g} q/s" if args.rate else ""))

        if 4 in args.families and nets.get(4):
            rule("IPv4")
            scan_v4(conn, nets[4], args)

        if 6 in args.families and nets.get(6):
            rule("IPv6")
            scan_v6(conn, nets[6], args)

        good(f"Scan pass finished in {fmt_duration(time.time() - started)}")

        rule("Report")
        save_report(conn, args)
        print_summary(conn, args)

        if STOP.is_set():
            warn("Stopped early at --limit - rerun to continue."
                 if args.limit else
                 "Interrupted - rerun the same command to resume.")

    finally:
        conn.close()

    return 0
