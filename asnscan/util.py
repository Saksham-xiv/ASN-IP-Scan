"""Address, size and hostname helpers shared by the rest of the package."""

import ipaddress


# Past 2**53 an integer no longer survives a round trip through a
# spreadsheet cell or a JSON float, and an IPv6 /64 is already far past
# it, so counts above this are written as digit strings instead.
EXACT_INT_MAX = 2 ** 53


def addr_class(version):
    return ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address


def addr_from_int(value, version):
    return addr_class(version)(value)


def to_key(addr):
    """
    Primary key for an address: its packed bytes.

    Packed bytes sort in numeric order, which an integer column cannot do
    for IPv6 - 128 bits does not fit in SQLite's 64-bit INTEGER. Keys are
    4 bytes for IPv4 and 16 for IPv6, so any query that orders by key
    should order by version first.
    """

    return addr.packed


def int_to_key(value, version):
    return value.to_bytes(4 if version == 4 else 16, "big")


def key_to_int(key):
    return int.from_bytes(key, "big")


def key_to_str(key):
    return str(ipaddress.ip_address(key))


def count_cell(n):
    """Address counts too large for a spreadsheet cell become text."""

    return n if n <= EXACT_INT_MAX else str(n)


DURATION_UNITS = {"m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_duration(text):
    """'36h', '7d', '2w' -> timedelta. Bare numbers are days."""

    import datetime

    text = str(text).strip().lower()

    if not text:
        raise ValueError("empty duration")

    unit = DURATION_UNITS.get(text[-1])

    value = text[:-1] if unit else text

    try:
        amount = float(value)
    except ValueError:
        raise ValueError(f"not a duration: {text!r}") from None

    return datetime.timedelta(seconds=amount * (unit or DURATION_UNITS["d"]))


def parse_asn(text):
    """Accept 32934, AS32934 or as32934."""

    text = str(text).strip().upper()

    if text.startswith("AS"):
        text = text[2:]

    if not text.isdigit():
        raise ValueError(f"not an AS number: {text!r}")

    return int(text)


# --- registrable domain -------------------------------------------------
#
# tldextract carries a public-suffix snapshot, which gets bt.co.uk and
# storage.googleapis.com right where "last two labels" does not. It is
# pinned to the bundled snapshot (suffix_list_urls=()) so importing this
# module never reaches for the network.

try:
    import tldextract

    _extract = tldextract.TLDExtract(suffix_list_urls=())

    HAVE_TLDEXTRACT = True

except Exception:                                   # pragma: no cover
    _extract = None

    HAVE_TLDEXTRACT = False


# Fallback list, used only when tldextract is not installed.
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.in", "net.in", "org.in", "com.br", "net.br", "org.br",
    "co.jp", "ne.jp", "or.jp", "ad.jp", "co.kr", "or.kr",
    "co.za", "com.cn", "net.cn", "org.cn", "com.mx", "com.ar",
    "com.tr", "com.tw", "com.hk", "com.sg", "com.my", "com.ph",
    "com.vn", "com.pk", "com.ua", "com.pl", "co.nz", "net.nz",
    "co.th", "co.id",
}


def registrable_domain(host):
    """Registrable domain of a PTR hostname - what the report groups by."""

    if not host:
        return ""

    host = host.rstrip(".").lower()

    if HAVE_TLDEXTRACT:
        parts = _extract(host)

        if parts.domain and parts.suffix:
            return f"{parts.domain}.{parts.suffix}"

        # no recognised suffix (a bare hostname, or .local): keep it whole
        return parts.domain or host

    labels = host.split(".")

    if len(labels) < 2:
        return labels[0]

    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])

    return ".".join(labels[-2:])


def summarize_run(first_int, last_int, version):
    """Minimal, exact set of CIDR blocks covering a contiguous IP range."""

    cls = addr_class(version)

    return list(ipaddress.summarize_address_range(cls(first_int),
                                                  cls(last_int)))


def fmt(n):
    return f"{n:,}"


def fmt_duration(seconds):

    seconds = int(seconds)

    if seconds < 60:
        return f"{seconds}s"

    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"

    if seconds < 86400:
        return f"{seconds // 3600}h {(seconds % 3600) // 60}m"

    return f"{seconds // 86400}d {(seconds % 86400) // 3600}h"
