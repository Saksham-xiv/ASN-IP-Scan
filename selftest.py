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
from asnscan.probe import make_row, set_classifier
from asnscan.report import iter_report
from asnscan.scan6 import (children, network_to_node, node_to_address,
                           node_to_network, random_deep_node)
from asnscan.store import open_db, set_state, write_rows
from asnscan.util import (int_to_key, key_to_int, parse_asn,
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

conn.close()


# --- result -------------------------------------------------------------

print(f"\n{PASS} passed, {FAIL} failed")

sys.exit(1 if FAIL else 0)
