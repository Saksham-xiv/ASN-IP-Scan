# asn-ip-scan

Find every named IPv4 **and IPv6** address that any ASN announces, by reverse DNS.

Give it an AS number. It pulls the ASN's announced prefixes from the global BGP
table, resolves the address space to hostnames, groups the results by who owns
the names, collapses them into exact CIDR ranges, and writes a spreadsheet.

```powershell
python asn_scan.py --asn 32934                 # Meta,  IPv4 + IPv6
python asn_scan.py --asn AS15169 --family 6    # Google, IPv6 only
python asn_scan.py --asn 13335 --prefixes-only # just the announced space
```

Everything is checkpointed to SQLite as it goes, so a scan can be interrupted
and resumed exactly where it stopped, and the report can be rebuilt at any time
without re-querying anything.

It sends no packets to the addresses themselves — only DNS queries to
nameservers whose job is to answer them. Nothing here scans ports or probes
hosts.

---

## Install

```powershell
pip install -r requirements.txt
python selftest.py          # 63 offline checks, no network needed
```

`dnspython` is the one dependency that really matters. It is the only way to
tell *"this name does not exist"* (NXDOMAIN) from *"the resolver gave up"*
(timeout) — a distinction the whole design rests on, and the basis of the IPv6
walk. Without it the tool falls back to `socket.gethostbyaddr`, which is far
slower, cannot separate those two cases, and cannot do IPv6 at all.

---

## How it finds addresses

### IPv4 — sweep every address

4.3 billion addresses is small enough to walk one by one, so every address in
every announced prefix gets a PTR lookup. If an address in the ASN has a name,
this finds it.

One optimisation matters: plenty of announced space has `in-addr.arpa`
delegation that answers nothing at all, and each of those lookups costs the
full timeout, so a single dead /22 can dominate an entire run. The scanner
samples the head of each /24 first (`--probe-n`, default 4); if not one sample
answers, the rest of that /24 is recorded as `no_zone` without being queried.
`--no-breaker` turns this off, and `--retry-errors --include-dead` revisits
everything that was skipped.

### IPv6 — walk the ip6.arpa tree

A single IPv6 /32 holds 79 octillion addresses. Sweeping it is not slow, it is
impossible. What *is* finite is the reverse-DNS tree: PTR records live 32
nibbles deep under `ip6.arpa`, and a compliant nameserver answers three
distinguishable ways:

| Answer | Meaning | What the walk does |
| --- | --- | --- |
| `NOERROR` + PTR | a name lives here | at depth 32, record the address |
| `NOERROR`, no PTR | *empty non-terminal* — nothing here, but there are children below | descend, 16 queries |
| `NXDOMAIN` | nothing exists at or under this node | prune — one answer can eliminate 16ⁿ addresses |

So the walk starts at the prefix's node, asks 16 questions per level, and
follows only the branches that exist. It runs **depth-first**, which is not a
preference but the difference between working and not: breadth-first would
expand every node at a level before touching the next, growing the frontier 16×
per level and finding nothing until the very end.

On Google's `2001:4860::/32` that turns an impossible enumeration into real
results in seconds:

```text
[+] IPv6 pass: 2,500 tree nodes queried, 972 addresses found

  2001:4860:4809:2::1     ig-in-x01.1e100.net
  2001:4860:4801:10::a    crawl-...-000a.googlebot.com
  ...
```

Two things can defeat a walk, and both are handled rather than ignored:

* **wildcard zones** answer "yes" to every name, which would send the walk
  descending forever. Each prefix is probed with a random deep name first; a
  zone that answers is recorded in the report and not walked.
* **servers that return NXDOMAIN for empty non-terminals** cannot be walked at
  all — the prefix comes back empty after ~17 queries and is marked done.
  Meta and Cloudflare both behave this way: `2a03:2880:f18a:188:face:b00c:0:25de`
  has a PTR, but every ancestor node from depth 10 to 28 is NXDOMAIN, because
  the names are synthesised on demand rather than stored in a zone. Google and
  Hurricane Electric publish real zones and walk fine. **For a network like
  Meta's, use IPv4** — the addresses are there, and the reverse tree is not.

The frontier is stored in the database, so `--v6-max-nodes` is a per-run budget,
not a limit: rerun with a bigger one and it continues from where it stopped.

---

## What "announced" means

The prefix list is what the ASN **announces in BGP**, not what it is allocated.
Space an organisation owns but does not route is not here — that is an
RDAP/whois question — and neither is space announced under a different ASN.

It is also a *window*, not a snapshot. RIPEstat reports what was announced over
a lookback period (two weeks by default) and tags each prefix with the timelines
it was actually visible for, so a prefix withdrawn ten days ago is still in the
list. Those timelines are kept and turned into a state:

| State | Meaning |
| --- | --- |
| `live` | still announced at the end of the window |
| `recent` | announced during the window, gone before it closed |
| `withdrawn` | present on an earlier run, absent from this one |

```powershell
python asn_scan.py --asn 13335 --live-only              # skip anything not live
python asn_scan.py --asn 13335 --announced-within 3d    # or an age
```

On Cloudflare that currently excludes 52 of 2,429 blocks (~2%). Overlaps are
collapsed *before* the states are worked out, which gives the right answer: a
/24 withdrawn from inside a /17 that is still announced is still routed space,
so the collapsed block stays `live`.

Nothing is ever silently dropped. Blocks the filter skips still appear on the
Prefixes sheet with their state and last-seen date, and a block the ASN stops
announcing between runs is marked `withdrawn` rather than deleted — its scan
results are real findings from when that space was still routed there, and the
Overview says how many addresses are affected.

## Output

`output/AS<n>_report.xlsx`, with `--format csv|json|all` for the same content
without the spreadsheet row ceiling.

| Sheet | What is in it |
| --- | --- |
| **Overview** | ASN, holder, announced space, coverage, per-status counts, breakdown by label |
| **Prefixes** | every announced block: state (`live` / `recent` / `withdrawn`), first and last seen, size, how much was probed, how much answered |
| **IP Details** | one row per named address: label, IP, family, prefix, hostname, its contiguous range |
| **Ranges** | those addresses collapsed into exact minimal CIDR blocks |
| **IPv6 Networks** | networks proved in use when `--v6-max-depth` stopped the descent early |
| **IPv6 Wildcards** | reverse zones that answer for everything |

Ranges are exact: consecutive addresses sharing a label collapse into the
minimal set of CIDRs that covers them and nothing else, so
`192.0.2.10`–`192.0.2.19` comes out as `.10/31 .12/30 .16/30`, never as a
rounded-up `/28`.

With `--verify`, every hostname is forward-confirmed (FCrDNS): the report says
whether the name actually resolves back to the address. It catches things like
`8.8.8.53 → dns.google` where the forward records do not agree — an unverified
PTR proves nothing, since the owner of an address can point it anywhere.

---

## Labelling

Without a rules file, results are grouped by the hostname's registrable domain
(public-suffix aware via `tldextract`), which is immediately useful on an ASN
you know nothing about:

```text
googleusercontent.com   4,096
google.com                665
googlebot.com             267
1e100.net                  39
```

A rules file splits one owner's space into products. `rules/meta.json` is the
worked example — zones prove who owns a name, tokens in the labels to the left
say which product it serves:

```powershell
python asn_scan.py --asn 32934 --rules rules/meta.json --only-matching
```

```text
instagram-p42-1.fna.fbcdn.net        -> Instagram
whatsapp-cdn-shv-01-atl3.fbcdn.net   -> WhatsApp
edge-star-shv-01-atl3.facebook.com   -> Facebook
notfacebook.com.example.net          -> no match   (suffixes, never substrings)
```

Labels are decided during the scan, so editing a rules file does nothing to
results already in the database. `--relabel` re-applies the rules to hostnames
already on record and rebuilds the report — no DNS, a second or two, instead of
rescanning:

```powershell
python asn_scan.py --asn 32934 --rules rules/meta.json --relabel
```

The format is just JSON — copy `rules/cloud.json` and add your own:

```json
{
  "name": "My rules",
  "zones":  {"fbcdn.net": "Facebook", "cdninstagram.com": "Instagram"},
  "tokens": {"whatsapp": "WhatsApp", "msgr": "Messenger"}
}
```

---

## Resuming, and stopping safely

Ctrl+C commits the current chunk and exits; press it twice to force quit. Rerun
the same command and it picks up from the same address — or the same ip6.arpa
node.

```powershell
python asn_scan.py --asn 32934                 # start (or resume)
python asn_scan.py --asn 32934 --retry-errors  # re-query only what never answered
python asn_scan.py --asn 32934 --report-only   # rebuild the report, no DNS at all
python asn_scan.py --asn 32934 --relabel       # re-apply edited rules, no DNS
```powershell

An `error` row is not "no PTR" — it is "we do not know", and a busy resolver can
leave millions of them. `--retry-errors` re-queries exactly those, and requeues
the ip6.arpa nodes that timed out (each of which may hide a whole subtree).

One database holds exactly one ASN. Results and progress have no ASN column, so
mixing two would blend two networks into one plausible, wrong report; the tool
refuses rather than allow it.

---

## Options worth knowing

| Option | Why |
| --- | --- |
| `--family 4 \| 6 \| both` | skip a family entirely |
| `--live-only` | scan only blocks still announced at the end of the lookback window |
| `--announced-within 3d` | same idea, by age — `3d`, `36h`, `2w` |
| `--resolvers 1.1.1.1,8.8.8.8` | one fast resolver beats three slow ones; your ISP's is often the slowest |
| `--rate 500` | cap queries/second across all threads. A resolver that starts refusing turns a scan into a field of false "unresolved" rows |
| `--threads` | default 256 with dnspython |
| `--v6-threads` | default 32, deliberately lower — a whole zone is usually served by one set of nameservers |
| `--v6-max-depth 16` | stop at /64 and just record which networks are in use, instead of enumerating hosts |
| `--verify` | forward-confirm every hostname (roughly doubles the queries) |
| `--expect-holder Google` | refuse to run unless the ASN is registered to who you think it is |
| `--limit 5000` | stop after N IPv4 lookups, for a quick look |
| `--relabel` | re-apply an edited rules file to results already scanned, no DNS |
| `--format csv` | past ~1M results, skip Excel entirely |

`--max-addresses` (default 5,000,000) asks for confirmation before sweeping a
very large ASN — AS7018 announces 92.9 million addresses, which is days of
queries. `--yes` skips the prompt; unattended runs refuse without it.

---

## Layout

```text
asn_scan.py         entry point  (also: python -m asnscan)
selftest.py         63 offline checks
asnscan/
  cli.py            arguments, run order, safety rails
  prefixes.py       RIPEstat -> BGPView fallback, collapse overlaps, freshness
  store.py          SQLite schema, checkpoints, the IPv6 frontier
  resolve.py        PTR / FCrDNS / the single ip6.arpa query, rate limiter
  probe.py          the per-address unit of work
  scan4.py          IPv4 sweep + circuit breaker + retry
  scan6.py          ip6.arpa depth-first tree walk
  classify.py       hostname -> label
  report.py         xlsx / csv / json, streamed
  util.py           address keys, registrable domains, range summarising
rules/
  meta.json         Facebook / Instagram / WhatsApp / Threads / Quest ...
  cloud.json        AWS / Google / Azure / Cloudflare / Akamai ...
```

---

## Limits

* A PTR record is a claim by whoever controls the address, not proof of
  anything. Use `--verify` when it matters.
* Addresses with no reverse DNS are invisible to this tool. It maps the *named*
  parts of a network, which for CDN and hosting ASNs is most of it, and for a
  residential ISP is often nearly all of it.
* IPv6 coverage depends entirely on the operator publishing PTRs in a walkable
  zone. Many do; some do not; the report says which prefixes came back empty.
* Prefix lists come from BGP, over a two-week lookback window — see
  [What "announced" means](#what-announced-means). `--refresh-prefixes`
  re-fetches; the cached list is otherwise reused so a resumed scan stays
  consistent with the one it is resuming, states included.
