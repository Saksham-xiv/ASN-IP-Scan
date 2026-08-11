"""The per-address unit of work, shared by the IPv4 and IPv6 scanners."""

from .classify import Classifier
from .resolve import CFG, forward_confirm, reverse_dns
from .util import addr_from_int, to_key


CLASSIFIER = Classifier()


def set_classifier(classifier):

    global CLASSIFIER

    CLASSIFIER = classifier


def make_row(addr, hostname, status, verified=-1):
    """(ip_key, version, ip, hostname, label, matched, status, verified)."""

    label, matched = CLASSIFIER(hostname)

    return (to_key(addr), addr.version, str(addr), hostname, label,
            int(matched), status, verified)


def probe(job):
    """Worker: resolve one address. job = (version, ip_int)."""

    version, ip_int = job

    addr = addr_from_int(ip_int, version)
    ip = str(addr)

    hostname, status = reverse_dns(ip)

    verified = -1

    if CFG["verify"] and hostname:
        verified = forward_confirm(hostname, ip, version)

    return make_row(addr, hostname, status, verified)


def confirm_row(row):
    """Forward-confirm an address the IPv6 walk already found a name for."""

    if not CFG["verify"] or not row[3]:
        return row

    verified = forward_confirm(row[3], row[2], row[1])

    return row[:7] + (verified,)


def skipped_row(version, ip_int, status="no_zone"):
    """An address inside a block that was skipped without being queried."""

    addr = addr_from_int(ip_int, version)

    return (to_key(addr), version, str(addr), "", "", 0, status, -1)
