#!/usr/bin/env python3
"""
Offline self-test: everything that can be checked without touching DNS.

    python selftest.py

Covers the parts where a silent mistake would produce a plausible but
wrong report - nibble arithmetic, zone matching, run collapsing - rather
than the parts that would fail loudly.
"""

import ipaddress
import sys

from asnscan.classify import Classifier
from asnscan.prefixes import build, select
from asnscan.probe import make_row, relabel, set_classifier
from asnscan.report import iter_report, prefix_rows
from asnscan.scan6 import (children, network_to_node, node_to_address,
                           node_to_network, random_deep_node)
from asnscan.store import open_db, save_prefixes, set_state, write_rows
from asnscan.util import (int_to_key, key_to_int, parse_asn, parse_duration,
                          registrable_domain, summarize_run)


PASS = 0
FAIL = 0


def check(name, got, want):

    global PASS, FAIL

    if got == want:
        PASS += 1
    else:
        FAIL += 1
        print(f"  FAIL  {name}\n        got  {got!r}\n        want {want!r}")


def section(title):
    print(f"\n{title}")


# --- addresses ----------------------------------------------------------

section("addresses")

check("parse_asn AS32934", parse_asn("AS32934"), 32934)
check("parse_asn 32934", parse_asn(" as32934 "), 32934)

check("v4 key round trip",
      key_to_int(int_to_key(3232235777, 4)), 3232235777)

check("v6 key round trip",
      key_to_int(int_to_key(2 ** 127 + 5, 6)), 2 ** 127 + 5)

check("v4 key is 4 bytes", len(int_to_key(1, 4)), 4)
check("v6 key is 16 bytes", len(int_to_key(1, 6)), 16)

# packed keys must sort numerically, or every range in the report is wrong
keys = [int_to_key(n, 4) for n in (10, 2, 300, 1)]
check("v4 keys sort numerically",
      [key_to_int(k) for k in sorted(keys)], [1, 2, 10, 300])

check("summarize v4 run",
      [str(b) for b in summarize_run(
          int(ipaddress.IPv4Address("192.0.2.10")),
          int(ipaddress.IPv4Address("192.0.2.19")), 4)],
      ["192.0.2.10/31", "192.0.2.12/30", "192.0.2.16/30"])

check("summarize v6 run",
      [str(b) for b in summarize_run(
          int(ipaddress.IPv6Address("2001:db8::")),
          int(ipaddress.IPv6Address("2001:db8::3")), 6)],
      ["2001:db8::/126"])


# --- hostnames ----------------------------------------------------------

section("hostnames")

check("registrable simple", registrable_domain("host.example.com"),
      "example.com")
check("registrable co.uk", registrable_domain("mail.bt.co.uk"), "bt.co.uk")
check("registrable deep",
      registrable_domain("a.b.c.fra16s49-in-x0e.1e100.net"), "1e100.net")
check("registrable trailing dot", registrable_domain("x.example.com."),
      "example.com")
check("registrable empty", registrable_domain(""), "")


# --- classification -----------------------------------------------------

section("classification")

plain = Classifier()

check("no rules: label is the domain", plain("edge.fbcdn.net"),
      ("fbcdn.net", True))
check("no rules: empty host", plain(""), ("", False))

meta = Classifier.from_file("rules/meta.json")

check("zone match", meta("edge-star-shv-01-atl3.facebook.com"),
      ("Facebook", True))
check("token beats zone", meta("instagram-p42-1.fna.fbcdn.net"),
      ("Instagram", True))
check("token beats zone (whatsapp)",
      meta("whatsapp-cdn-shv-01-atl3.fbcdn.net"), ("WhatsApp", True))
check("longest zone wins", meta("scontent.cdninstagram.com"),
      ("Instagram", True))

# the reason zones are matched as suffixes and never as substrings
check("suffix only, not substring", meta("notfacebook.com.example.net"),
      ("example.net", False))
check("unrelated host", meta("host.att.net"), ("att.net", False))


# --- ip6.arpa nibble arithmetic -----------------------------------------

section("ip6.arpa tree")

net32 = ipaddress.ip_network("2001:4860::/32")

check("network -> node", network_to_node(net32), "0.6.8.4.1.0.0.2")
check("node -> network", node_to_network("0.6.8.4.1.0.0.2"), net32)

check("node -> address",
      node_to_address("8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0"
                      ".0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2"),
      ipaddress.IPv6Address("2001:4860:4860::8888"))

check("16 children", len(children("0.6.8.4.1.0.0.2")), 16)
check("child prepends the nibble", children("0.6.8.4.1.0.0.2")[10],
      "a.0.6.8.4.1.0.0.2")

# a prefix off the nibble boundary rounds down to the enclosing node;
# hits outside the real announcement are filtered when recorded
odd = ipaddress.ip_network("2a03:2880:f002::/47")
check("odd prefix rounds down", node_to_network(network_to_node(odd)),
      ipaddress.ip_network("2a03:2880:f000::/44"))
check("rounded node contains the real prefix",
      odd.subnet_of(node_to_network(network_to_node(odd))), True)

probe_node = random_deep_node("0.6.8.4.1.0.0.2", 8)
check("wildcard probe is full depth", len(probe_node.split(".")), 32)
check("wildcard probe stays under the prefix",
      probe_node.endswith("0.6.8.4.1.0.0.2"), True)


# --- announcement freshness ---------------------------------------------

section("announcement freshness")

check("duration days", parse_duration("7d").total_seconds(), 604800.0)
check("duration hours", parse_duration("36h").total_seconds(), 129600.0)
check("duration weeks", parse_duration("2w").total_seconds(), 1209600.0)
check("bare number means days", parse_duration("3").total_seconds(), 259200.0)

WINDOW = {"start": "2026-07-28T00:00:00", "end": "2026-08-11T00:00:00"}

END = WINDOW["end"]

records = [
    # two halves that collapse into one /24, both still announced
    {"prefix": "192.0.2.0/25", "first_seen": WINDOW["start"], "last_seen": END},
    {"prefix": "192.0.2.128/25", "first_seen": WINDOW["start"], "last_seen": END},
    # withdrawn ten days before the window closed
    {"prefix": "198.51.100.0/24", "first_seen": WINDOW["start"],
     "last_seen": "2026-08-01T00:00:00"},
    # a /24 dropped from inside a /16 that is still announced: the space
    # is still routed, so the collapsed block stays live
    {"prefix": "203.0.0.0/16", "first_seen": WINDOW["start"], "last_seen": END},
    {"prefix": "203.0.113.0/24", "first_seen": WINDOW["start"],
     "last_seen": "2026-07-30T00:00:00"},
    {"prefix": "2001:db8::/32", "first_seen": WINDOW["start"], "last_seen": END},
]

entries = build(records, WINDOW)

check("overlaps collapse", [str(e["net"]) for e in entries],
      ["192.0.2.0/24", "198.51.100.0/24", "203.0.0.0/16", "2001:db8::/32"])

states = {str(e["net"]): e["state"] for e in entries}

check("still announced is live", states["192.0.2.0/24"], "live")
check("gone before the window closed is recent",
      states["198.51.100.0/24"], "recent")
check("most recent evidence wins inside a block",
      states["203.0.0.0/16"], "live")
check("v6 block state", states["2001:db8::/32"], "live")

kept, dropped = select(entries, WINDOW, "all")
check("'all' keeps everything", (len(kept), len(dropped)), (4, 0))

kept, dropped = select(entries, WINDOW, "live")
check("'live' drops the withdrawn block",
      ([str(e["net"]) for e in kept], [str(e["net"]) for e in dropped]),
      (["192.0.2.0/24", "203.0.0.0/16", "2001:db8::/32"],
       ["198.51.100.0/24"]))

kept, _ = select(entries, WINDOW, "30d")
check("a wide age window keeps it", len(kept), 4)

kept, _ = select(entries, WINDOW, "5d")
check("a narrow age window drops it", len(kept), 3)


# --- withdrawal is recorded, never silently dropped ---------------------

section("withdrawal")

conn = open_db(":memory:")

save_prefixes(conn, entries)

check("all blocks recorded",
      conn.execute("SELECT COUNT(*) FROM prefixes").fetchone()[0], 4)

# the ASN stops announcing 203.0.0.0/16 entirely
save_prefixes(conn, [e for e in entries if str(e["net"]) != "203.0.0.0/16"])

check("vanished block is kept, not deleted",
      conn.execute("SELECT COUNT(*) FROM prefixes").fetchone()[0], 4)

check("vanished block is marked withdrawn",
      conn.execute("SELECT state FROM prefixes WHERE prefix='203.0.0.0/16'"
                   ).fetchone()[0], "withdrawn")

check("the others keep their state",
      conn.execute("SELECT state FROM prefixes WHERE prefix='192.0.2.0/24'"
                   ).fetchone()[0], "live")

# and it comes back if the ASN announces it again
save_prefixes(conn, entries)

check("re-announced block goes back to live",
      conn.execute("SELECT state FROM prefixes WHERE prefix='203.0.0.0/16'"
                   ).fetchone()[0], "live")

conn.close()


# --- store + report end to end ------------------------------------------

section("store and report")

set_classifier(plain)

conn = open_db(":memory:")

with conn:
    set_state(conn, "asn", "64500")

    rows = []

    # one contiguous run of 10, then a gap, then 2 more
    for n in list(range(10, 20)) + [30, 31]:
        addr = ipaddress.IPv4Address(f"192.0.2.{n}")
        rows.append(make_row(addr, "web.example.com", "ok"))

    # a different label in the same prefix must not join the run
    rows.append(make_row(ipaddress.IPv4Address("192.0.2.20"),
                         "mail.other.net", "ok"))

    # no hostname: must never reach the report
    rows.append(make_row(ipaddress.IPv4Address("192.0.2.21"), "", "nxdomain"))

    # an IPv6 hit in the same database
    rows.append(make_row(ipaddress.IPv6Address("2001:db8::1"),
                         "v6.example.com", "ok"))

    write_rows(conn, "192.0.2.0/24", rows)

save_prefixes(conn, [e for e in entries if str(e["net"]) == "192.0.2.0/24"])

prow = prefix_rows(conn)[0]

check("prefix row joins to the scan results",
      (prow[0], prow[2], prow[8], prow[9]),
      ("192.0.2.0/24", "live", 15, 14))

report = list(iter_report(conn))

details = [r for kind, r in report if kind == "detail"]
ranges = [r for kind, r in report if kind == "range"]

check("addresses without a hostname are excluded", len(details), 14)

check("runs collapse to minimal CIDRs",
      sorted(r[2] for r in ranges),
      sorted(["192.0.2.10/31", "192.0.2.12/30", "192.0.2.16/30",
              "192.0.2.30/31", "192.0.2.20/32", "2001:db8::1/128"]))

check("a gap splits the run",
      [r[2] for r in ranges if r[0] == "example.com"],
      ["192.0.2.10/31", "192.0.2.12/30", "192.0.2.16/30", "192.0.2.30/31",
       "2001:db8::1/128"])

check("labels group correctly",
      sorted({r[0] for r in details}),
      ["example.com", "other.net"])

check("family column",
      sorted({r[2] for r in details}), ["IPv4", "IPv6"])

check("detail rows carry their range",
      details[0][5] in {r[2] for r in ranges}, True)


# --- relabelling without rescanning -------------------------------------

section("relabel")

set_classifier(Classifier({"zones": {"example.com": "My Web"}}))

total, changed = relabel(conn)

check("every named row is re-examined", total, 14)

# all 14 move: 13 take the new label, and other.net keeps its label but
# flips matched 1 -> 0, because "no rules loaded" and "rules loaded, no
# match" are different answers
check("rows that moved are written", changed, 14)

check("the new rule is applied",
      conn.execute("SELECT label, matched FROM results "
                   "WHERE ip = '192.0.2.10'").fetchone(), ("My Web", 1))

check("v6 rows are relabelled too",
      conn.execute("SELECT label FROM results "
                   "WHERE ip = '2001:db8::1'").fetchone()[0], "My Web")

check("rows outside the rules keep their domain label",
      conn.execute("SELECT label, matched FROM results "
                   "WHERE ip = '192.0.2.20'").fetchone(), ("other.net", 0))

check("unnamed rows are left alone",
      conn.execute("SELECT label FROM results "
                   "WHERE ip = '192.0.2.21'").fetchone()[0], "")

# running it again with the same rules must be a no-op
check("relabel is idempotent", relabel(conn)[1], 0)

conn.close()


# --- result -------------------------------------------------------------

print(f"\n{PASS} passed, {FAIL} failed")

sys.exit(1 if FAIL else 0)
