"""
DNS layer: PTR lookups, forward confirmation, and the single ip6.arpa
query the IPv6 tree walk is built on.

dnspython is the real path. It is the only way to tell "this name does
not exist" (NXDOMAIN) from "the resolver gave up" (timeout/SERVFAIL) -
a distinction the whole design depends on, because the first is a final
answer and the second must be retried. socket.gethostbyaddr collapses
both into one error on most platforms and is only a fallback.
"""

import ipaddress
import socket
import threading
import time

try:
    import dns.exception
    import dns.rdatatype
    import dns.resolver
    import dns.reversename

    HAVE_DNSPYTHON = True

except ImportError:                                 # pragma: no cover
    HAVE_DNSPYTHON = False


# Filled in once by configure(); read by every worker thread.
CFG = {
    "timeout": 1.5,
    "attempts": 2,
    "resolvers": [],
    "verify": False,
    "rate": 0,
}

STOP = threading.Event()

_local = threading.local()


class RateLimiter:
    """
    Token bucket shared by every worker thread.

    A public resolver that starts refusing queries turns a scan into a
    field of false "unresolved" rows, which is worse than a slower scan.
    Capacity is one second of queries, so short bursts still go at full
    speed.
    """

    def __init__(self, rate):

        self.rate = float(rate)
        self.tokens = float(rate)
        self.updated = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self):

        while True:

            with self.lock:

                now = time.monotonic()

                self.tokens = min(self.rate,
                                  self.tokens + (now - self.updated) * self.rate)
                self.updated = now

                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return

                wait = (1.0 - self.tokens) / self.rate

            time.sleep(min(wait, 0.25))


LIMITER = None


def configure(timeout=1.5, attempts=2, resolvers=(), verify=False, rate=0):

    global LIMITER

    CFG.update({
        "timeout": timeout,
        "attempts": max(1, attempts),
        "resolvers": list(resolvers),
        "verify": verify,
        "rate": rate,
    })

    LIMITER = RateLimiter(rate) if rate and rate > 0 else None


def resolver():
    """One dnspython Resolver per thread - they are not thread-safe."""

    res = getattr(_local, "res", None)

    if res is None:
        res = dns.resolver.Resolver(configure=not CFG["resolvers"])

        if CFG["resolvers"]:
            res.nameservers = list(CFG["resolvers"])

        res.timeout = CFG["timeout"]

        # a little headroom, so one slow nameserver in the list does not
        # abort a query the next one would have answered
        res.lifetime = CFG["timeout"] * 1.5

        res.cache = None
        res.retry_servfail = False

        _local.res = res

    return res


# --- one query ----------------------------------------------------------

# status vocabulary, used everywhere downstream:
#   ok       - a PTR came back
#   nxdomain - the name provably does not exist (never retry)
#   empty    - the name exists but has no PTR (an ip6.arpa branch node)
#   error    - timeout / SERVFAIL / refused (retryable, NOT "no PTR")

def query_ptr(name):
    """Raw PTR query for an already-formed reverse name."""

    if LIMITER is not None:
        LIMITER.acquire()

    try:
        answer = resolver().resolve(name, "PTR", raise_on_no_answer=False)

        if answer.rrset is None or not len(answer.rrset):
            return "empty", ""

        return "ok", str(answer[0]).rstrip(".").lower()

    except dns.resolver.NXDOMAIN:
        return "nxdomain", ""

    except dns.resolver.NoAnswer:
        return "empty", ""

    except (dns.exception.Timeout, dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout, OSError):
        return "error", ""

    except dns.exception.DNSException:
        return "error", ""


def _ptr_dnspython(ip):

    status, host = query_ptr(dns.reversename.from_address(ip))

    # for an address, "exists but has no PTR" and "does not exist" are
    # the same answer: there is no name here
    return (host, "ok") if status == "ok" else \
           ("", "nxdomain" if status in ("nxdomain", "empty") else "error")


def _ptr_socket(ip):

    try:
        return socket.gethostbyaddr(ip)[0].rstrip(".").lower(), "ok"

    except socket.herror as e:
        # 1 = HOST_NOT_FOUND (definitive); 2/3 = TRY_AGAIN / NO_RECOVERY
        return "", ("nxdomain" if e.errno == 1 else "error")

    except (socket.gaierror, OSError):
        return "", "error"


def reverse_dns(ip):
    """(hostname, status) with backoff. status: ok | nxdomain | error."""

    lookup = _ptr_dnspython if HAVE_DNSPYTHON else _ptr_socket

    delay = 0.25

    for attempt in range(CFG["attempts"]):

        if STOP.is_set():
            return "", "error"

        host, status = lookup(ip)

        if status != "error":
            return host, status

        if attempt + 1 < CFG["attempts"]:
            time.sleep(delay)
            delay *= 2

    return "", "error"


def forward_confirm(host, ip, version):
    """
    FCrDNS: does the PTR name resolve back to this address?

    1 = yes, 0 = no (the PTR is unverified and may be anyone's), -1 = the
    forward lookup itself failed, so nothing was proven either way.
    """

    if not host:
        return -1

    rdtype = "A" if version == 4 else "AAAA"

    try:
        if HAVE_DNSPYTHON:
            answer = resolver().resolve(host, rdtype)
            addrs = {r.address for r in answer}

        else:
            family = socket.AF_INET if version == 4 else socket.AF_INET6
            addrs = {i[4][0] for i in socket.getaddrinfo(host, None, family)}

    except Exception:
        return -1

    # compare numerically: 2a03:2880:f003:c07:face:b00c::2 and its
    # long form are the same address but not the same string
    target = ipaddress.ip_address(ip)

    for a in addrs:
        try:
            if ipaddress.ip_address(a) == target:
                return 1
        except ValueError:
            continue

    return 0


# --- the ip6.arpa tree walk primitive -----------------------------------

def query_node(node):
    """
    Ask about one node of the ip6.arpa tree.

    Returns (status, hostname):

      ok       - the node has a PTR. At full depth that is a live address;
                 above it, a wildcard covering everything underneath.
      empty    - NOERROR with no answer: an "empty non-terminal", which
                 means the node has children. This is the signal that
                 makes the walk possible - descend here.
      nxdomain - nothing exists at or below this node. Prune the whole
                 subtree; that single answer can skip 16^n addresses.
      error    - no usable answer; retry, then give up and record it.
    """

    return query_ptr(node + ".ip6.arpa.")
