"""
Turning a PTR hostname into a label the report can group by.

Two modes:

  * no rules file - the label is the hostname's registrable domain, so an
    unknown ASN still produces a useful breakdown (amazonaws.com: 4,102,
    att.net: 1,988, ...);

  * a rules file - zones say who owns the name and tokens in the labels
    to the left say which product it belongs to. `rules/meta.json` is the
    worked example: it reproduces the Facebook/Instagram/WhatsApp split
    the original Meta-only scanner produced.

Rules file format (both sections optional):

    {
      "name": "Meta",
      "zones":  {"fbcdn.net": "Facebook", "cdninstagram.com": "Instagram"},
      "tokens": {"whatsapp": "WhatsApp", "msgr": "Messenger"}
    }
"""

import json

from .util import registrable_domain


class Classifier:
    """(label, matched) for a PTR hostname."""

    def __init__(self, rules=None):

        rules = rules or {}

        self.name = rules.get("name", "")

        # lower-cased once here so the hot path only lowers the hostname
        self.zones = {
            zone.strip(".").lower(): label
            for zone, label in (rules.get("zones") or {}).items()
        }

        self.tokens = {
            token.lower(): label
            for token, label in (rules.get("tokens") or {}).items()
        }

        self.active = bool(self.zones or self.tokens)

    @classmethod
    def from_file(cls, path):

        if not path:
            return cls()

        with open(path, encoding="utf-8") as f:
            return cls(json.load(f))

    def __call__(self, host):

        if not host:
            return "", False

        host = host.rstrip(".").lower()

        if not self.active:
            return registrable_domain(host), True

        # A hostname belongs to a zone only if it *ends* in it. Substring
        # matching would accept "notfacebook.com.example.net".
        best = None

        for zone, label in self.zones.items():
            if host == zone or host.endswith("." + zone):
                # longest match wins: cdninstagram.com over instagram.com
                if best is None or len(zone) > len(best[0]):
                    best = (zone, label)

        if best is None:
            return registrable_domain(host), False

        zone, label = best

        # Tokens live in the labels left of the zone, e.g.
        #   instagram-p42-1.fna.fbcdn.net
        #   whatsapp-cdn-shv-01-atl3.fbcdn.net
        # The zone proves who owns it; the tokens say which product.
        prefix_labels = host[: -len(zone)].rstrip(".")

        for token in prefix_labels.replace("-", ".").split("."):
            if token in self.tokens:
                return self.tokens[token], True

        return label, True
