"""
Which address space does an ASN actually announce?

RIPEstat is the primary source (it sees the global BGP table and returns
IPv4 and IPv6 in one call); BGPView is the fallback for when RIPEstat is
rate-limiting or down. Whatever comes back is collapsed per family:
operators announce overlapping prefixes - a /24 inside a /17 - and
without collapsing, the same address gets scanned and counted twice.

The result is cached in the database, keyed by ASN, so a resumed scan
always works from the same prefix list it started with.
"""

import ipaddress

import requests

from .console import info, warn
from .store import get_json, save_prefixes, set_json
from .util import fmt


SOURCEAPP = "asn-ip-scan"

RIPE_PREFIXES = "https://stat.ripe.net/data/announced-prefixes/data.json"
RIPE_OVERVIEW = "https://stat.ripe.net/data/as-overview/data.json"

BGPVIEW_ASN = "https://api.bgpview.io/asn/{asn}"
BGPVIEW_PREFIXES = "https://api.bgpview.io/asn/{asn}/prefixes"

HEADERS = {"User-Agent": "asn-ip-scan/1.0 (+reverse-DNS inventory tool)"}

TIMEOUT = 45


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

    r = requests.get(RIPE_PREFIXES, headers=HEADERS, timeout=TIMEOUT,
                     params={"resource": f"AS{asn}", "sourceapp": SOURCEAPP})
    r.raise_for_status()

    return [x["prefix"] for x in r.json()["data"]["prefixes"]]


def _from_bgpview(asn):

    r = requests.get(BGPVIEW_PREFIXES.format(asn=asn), headers=HEADERS,
                     timeout=TIMEOUT)
    r.raise_for_status()

    data = r.json()["data"]

    return [
        p["prefix"]
        for p in (data.get("ipv4_prefixes") or []) + (data.get("ipv6_prefixes") or [])
    ]


SOURCES = {"ripe": _from_ripe, "bgpview": _from_bgpview}


def fetch_prefixes(asn, source="auto"):
    """Raw prefix strings for an ASN, plus the source that answered."""

    order = ["ripe", "bgpview"] if source == "auto" else [source]

    errors = []

    for name in order:

        try:
            raw = SOURCES[name](asn)

            if raw:
                return raw, name

            errors.append(f"{name}: announced nothing")

        except (requests.RequestException, ValueError, KeyError) as e:
            errors.append(f"{name}: {e.__class__.__name__}")

            if len(order) > 1:
                warn(f"{name} failed ({e.__class__.__name__}), trying the "
                     f"next source")

    raise RuntimeError("could not fetch prefixes - " + "; ".join(errors))


def collapse(raw):
    """Parse, split by family and collapse overlaps within each family."""

    by_family = {4: [], 6: []}

    for text in raw:
        try:
            # strict=False: announced prefixes sometimes carry host bits
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            continue

        by_family[net.version].append(net)

    return {
        version: sorted(ipaddress.collapse_addresses(nets))
        for version, nets in by_family.items()
    }


def get_prefixes(conn, asn, families=(4, 6), refresh=False, source="auto"):
    """Collapsed prefixes per family, cached in the database."""

    key = f"prefixes:{asn}"

    cached = None if refresh else get_json(conn, key)

    if cached:
        nets = {
            int(v): [ipaddress.ip_network(p) for p in plist]
            for v, plist in cached["families"].items()
        }

        info(f"Using cached AS{asn} prefix list from {cached.get('source')} "
             f"({len(nets.get(4, []))} IPv4, {len(nets.get(6, []))} IPv6)")

    else:
        info(f"Fetching announced prefixes for AS{asn} ...")

        raw, used = fetch_prefixes(asn, source)

        nets = collapse(raw)

        before = len(raw)
        after = len(nets[4]) + len(nets[6])

        info(f"{used} returned {before} announcements -> {after} after "
             f"collapsing overlaps")

        with conn:
            set_json(conn, key, {
                "source": used,
                "families": {str(v): [str(n) for n in ns]
                             for v, ns in nets.items()},
            })

    # written every run, not just on a fetch: the report reads the table,
    # and a database restored without it would report no space at all
    save_prefixes(conn, nets.get(4, []) + nets.get(6, []))

    wanted = {v: nets.get(v, []) for v in families}

    v4_addrs = sum(n.num_addresses for n in wanted.get(4, []))
    v6_addrs = sum(n.num_addresses for n in wanted.get(6, []))

    if 4 in wanted:
        info(f"IPv4: {len(wanted[4])} prefixes, {fmt(v4_addrs)} addresses")

    if 6 in wanted:
        info(f"IPv6: {len(wanted[6])} prefixes, {v6_addrs:.3e} addresses "
             f"(enumerated by reverse-DNS tree walk, not one by one)")

    return wanted
