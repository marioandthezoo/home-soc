"""Vulnerability management (SPEC section 8).

Turns discovered services into CVE knowledge from three sources, cheapest first:
CISA KEV (already on disk via the feeds package), NVD 2.0 (network, cached, rate
limited and time-boxed) and EPSS (on disk). The public entry point is
``matcher.match_services``; ``cpe`` and ``enrich`` are its pure helpers.
"""

from homesoc.vulns.cpe import CPE, compare_versions, guess_cpe, parse_cpe
from homesoc.vulns.matcher import match_services, run

__all__ = ["CPE", "compare_versions", "guess_cpe", "parse_cpe", "match_services", "run"]
