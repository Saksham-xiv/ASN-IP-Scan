#!/usr/bin/env python3
"""
asn-ip-scan - entry point.

    python asn_scan.py --asn 32934
    python asn_scan.py --help

Equivalent to `python -m asnscan`.
"""

import sys

from asnscan.cli import main

if __name__ == "__main__":
    sys.exit(main())
