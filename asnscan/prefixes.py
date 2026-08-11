"""
Which address space does an ASN actually announce, and how recently?

RIPEstat is the primary source (it sees the global BGP table and returns
IPv4 and IPv6 in one call); BGPView is the fallback for when RIPEstat is
rate-limiting or down.

Two things matter about the answer:

  * **It is a window, not a snapshot.** RIPEstat reports what was
    announced over a lookback period - two weeks by default - and tags
    each prefix with the timelines it was actually visible for. A prefix
    withdrawn ten days ago is still in that list. Those timelines are
    kept here, collapsed onto each block, and turned into a state:

        live       still announced at the end of the window
        recent     announced during it, but gone before it closed
        withdrawn  known from an earlier run, absent from this one

    `--announced-within` decides which of those get scanned; the report
    shows all three, so nothing disappears silently.

  * **Announcements overlap.** Operators announce a /24 inside a /17;
    without collapsing them, the same address is scanned and counted
    twice. Collapsing happens first and the timelines are attached
    afterwards, so one canonical block list drives the scan, the
    checkpoints and the report alike.

What this is *not*: address space merely allocated to the organisation.
That is an RDAP/whois question. This is what is routed.
"""

import bisect
import datetime
import ipaddress
import time

from collections import defaultdict

import requests

from .console import info, warn
from .store import get_json, save_prefixes, set_json
from .util import fmt, parse_duration


SOURCEAPP = "asn-ip-scan"

RIPE_PREFIXES = "https://stat.ripe.net/data/announced-prefixes/data.json"
RIPE_OVERVIEW = "https://stat.ripe.net/data/as-overview/data.json"

BGPVIEW_ASN = "https://api.bgpview.io/asn/{asn}"
BGPVIEW_PREFIXES = "https://api.bgpview.io/asn/{asn}/prefixes"

HEADERS = {"User-Agent": "asn-ip-scan/1.0 (+reverse-DNS inventory tool)"}

TIMEOUT = 45

LIVE = "live"
RECENT = "recent"
WITHDRAWN = "withdrawn"


# --- who owns the ASN ---------------------------------------------------

def _bgpview_asn(asn, timeout=15):

    r = requests.get(BGPVIEW_ASN.format(asn=asn), headers=HEADERS,
                     timeout=timeout)
    r.raise_for_status()

    return r.json()["data"]


def asn_info(asn):
    """
    Who does this ASN belong to?

    RIPEstat has the authoritative holder string but no country, so the
    country comes from BGPView as a best-effort extra. Neither is fatal:
    every field is allowed to come back empty.
    """

    out = {"holder": "", "country": "", "registry": "", "source": ""}

    try:
        r = requests.get(RIPE_OVERVIEW, headers=HEADERS, timeout=TIMEOUT,
                         params={"resource": f"AS{asn}",
                                 "sourceapp": SOURCEAPP})
        r.raise_for_status()

        data = r.json()["data"]

        out["holder"] = data.get("holder") or ""
        out["registry"] = (data.get("block") or {}).get("desc") or ""
        out["source"] = "RIPEstat"

    except (requests.RequestException, ValueError, KeyError):
        pass

    try:
        data = _bgpview_asn(asn)

        out["country"] = data.get("country_code") or ""

        if not out["holder"]:
            out["holder"] = (data.get("description_short")
                             or data.get("name") or "")
            out["source"] = "BGPView"

    except (requests.RequestException, ValueError, KeyError):
        pass

    return out


# --- announced prefixes -------------------------------------------------

def _from_ripe(asn):
    """Records with their visibility timelines, plus the lookback window."""

    r = requests.get(RIPE_PREFIXES, headers=HEADERS, timeout=TIMEOUT,
                     params={"resource": f"AS{asn}", "sourceapp": SOURCEAPP})
    r.raise_for_status()

    data = r.json()["data"]

    window = {
        "start": data.get("query_starttime") or "",
        "end": data.get("query_endtime") or "",
    }

    records = []

    for x in data["prefixes"]:

        timelines = x.get("timelines") or []

        records.append({
            "prefix": x["prefix"],
            # ISO-8601 of identical shape, so plain string comparison is
            # already chronological - no parsing needed on the hot path
            "first_seen": min((t["starttime"] for t in timelines), default=""),
            "last_seen": max((t["endtime"] for t in timelines), default=""),
        })

    return records, window


def _from_bgpview(asn):
    """BGPView reports the current table, with no history to go with it."""

    r = requests.get(BGPVIEW_PREFIXES.format(asn=asn), headers=HEADERS,
                     timeout=TIMEOUT)
    r.raise_for_status()

    data = r.json()["data"]

    now = time.strftime("%Y-%m-%dT%H:%M:%S")

    prefixes = [
        p["prefix"]
        for p in (data.get("ipv4_prefixes") or [])
        + (data.get("ipv6_prefixes") or [])
    ]

    records = [{"prefix": p, "first_seen": "", "last_seen": now}
               for p in prefixes]

    return records, {"start": "", "end": now}


SOURCES = {"ripe": _from_ripe, "bgpview": _from_bgpview}


def fetch_prefixes(asn, source="auto"):

    order = ["ripe", "bgpview"] if source == "auto" else [source]

    errors = []

    for name in order:

        try:
            records, window = SOURCES[name](asn)

            if records:
                return records, window, name

            errors.append(f"{name}: announced nothing")

        except (requests.RequestException, ValueError, KeyError) as e:
            errors.append(f"{name}: {e.__class__.__name__}")

            if len(order) > 1:
                warn(f"{name} failed ({e.__class__.__name__}), trying the "
                     f"next source")

    raise RuntimeError("could not fetch prefixes - " + "; ".join(errors))


# --- collapse, then attach the routing evidence -------------------------

def build(records, window):
    """
    Collapse overlapping announcements, then give each surviving block
    the most recent evidence from the announcements inside it.

    Collapsing first is what keeps everything consistent: one block list
    is used for scanning, checkpointing and reporting, so a prefix string
    always means the same thing. It also gives the right answer - a /24
    withdrawn from inside a /17 that is still announced is still routed
    space, and the collapsed /17 stays live.
    """

    parsed = []

    by_family = defaultdict(list)

    for rec in records:

        try:
            # strict=False: announced prefixes sometimes carry host bits
            net = ipaddress.ip_network(rec["prefix"], strict=False)
        except ValueError:
            continue

        parsed.append((net, rec))
        by_family[net.version].append(net)

    entries = {}
    index = {}

    for version, nets in by_family.items():

        collapsed = sorted(ipaddress.collapse_addresses(nets))

        index[version] = ([int(n.network_address) for n in collapsed],
                          collapsed)

        for net in collapsed:
            entries[net] = {"net": net, "first_seen": "", "last_seen": ""}

    for net, rec in parsed:

        starts, collapsed = index[net.version]

        # collapsed blocks are sorted and disjoint, so the one that can
        # contain this announcement is the last one starting at or below it
        i = bisect.bisect_right(starts, int(net.network_address)) - 1

        if i < 0:
            continue

        entry = entries[collapsed[i]]

        if rec["last_seen"] > entry["last_seen"]:
            entry["last_seen"] = rec["last_seen"]

        if rec["first_seen"] and (not entry["first_seen"]
                                  or rec["first_seen"] < entry["first_seen"]):
            entry["first_seen"] = rec["first_seen"]

    end = window.get("end") or ""

    out = []

    for entry in entries.values():
        entry["state"] = (LIVE if not end or entry["last_seen"] >= end
                          else RECENT)
        out.append(entry)

    return sorted(out, key=lambda e: (e["net"].version,
                                      e["net"].network_address,
                                      e["net"].prefixlen))


def select(entries, window, within):
    """Which blocks to actually scan. Returns (kept, dropped)."""

    if not within or within == "all":
        return entries, []

    if within == "live":
        def keep(entry):
            return entry["state"] == LIVE

    else:
        end = window.get("end") or ""

        if not end:
            warn("The prefix source gave no time window, so "
                 "--announced-within cannot be applied.")
            return entries, []

        cutoff = (datetime.datetime.fromisoformat(end)
                  - parse_duration(within)).isoformat()

        def keep(entry):
            return entry["last_seen"] >= cutoff

    kept = []
    dropped = []

    for entry in entries:
        (kept if keep(entry) else dropped).append(entry)

    return kept, dropped


# --- the public call ----------------------------------------------------

def get_prefixes(conn, asn, families=(4, 6), refresh=False, source="auto",
                 within="all"):
    """Blocks to scan, per family. Cached in the database, states and all."""

    key = f"prefixes:{asn}"

    cached = None if refresh else get_json(conn, key)

    # older databases cached a bare prefix list with no timelines; there
    # is nothing to upgrade in place, so re-fetch instead
    if cached and "entries" in cached:

        window = cached.get("window") or {}
        used = cached.get("source", "")

        entries = [
            {"net": ipaddress.ip_network(e["prefix"]),
             "first_seen": e["first_seen"],
             "last_seen": e["last_seen"],
             "state": e["state"]}
            for e in cached["entries"]
        ]

        info(f"Using cached AS{asn} prefix list from {used} "
             f"({len(entries)} blocks)")

    else:
        info(f"Fetching announced prefixes for AS{asn} ...")

        records, window, used = fetch_prefixes(asn, source)

        entries = build(records, window)

        info(f"{used} returned {len(records)} announcements -> "
             f"{len(entries)} blocks after collapsing overlaps")

        with conn:
            set_json(conn, key, {
                "source": used,
                "window": window,
                "entries": [
                    {"prefix": str(e["net"]), "first_seen": e["first_seen"],
                     "last_seen": e["last_seen"], "state": e["state"]}
                    for e in entries
                ],
            })

    if window.get("start") and window.get("end"):
        info(f"Announcement window: {window['start'][:10]} to "
             f"{window['end'][:10]}")

    stale = [e for e in entries if e["state"] != LIVE]

    if stale:
        warn(f"{len(stale)} of {len(entries)} blocks were announced during "
             f"the window but not at the end of it")

    # the table records everything the ASN announced, scanned or not, and
    # marks anything that has since vanished as withdrawn
    save_prefixes(conn, entries)

    with conn:
        set_json(conn, "prefix_window", window)

    kept, dropped = select(entries, window, within)

    if dropped:
        info(f"--announced-within {within}: skipping {len(dropped)} block"
             f"{'s' if len(dropped) != 1 else ''} no longer announced "
             f"(still listed in the report)")

    wanted = {v: [e["net"] for e in kept if e["net"].version == v]
              for v in families}

    for version in sorted(wanted):

        nets = wanted[version]
        total = sum(n.num_addresses for n in nets)

        if version == 4:
            info(f"IPv4: {len(nets)} blocks, {fmt(total)} addresses")
        else:
            info(f"IPv6: {len(nets)} blocks, {total:.3e} addresses "
                 f"(enumerated by reverse-DNS tree walk, not one by one)")

    return wanted
