"""Home SOC web dashboard (SPEC section 15).

The package exposes a single Flask app factory. Everything the dashboard shows is read
straight from the SQLite tables in SPEC section 4 so it keeps working while the other
packages are still being built; the handful of writes are routed through the owning
package when it is importable.
"""

from homesoc.web.app import create_app

__all__ = ["create_app"]
