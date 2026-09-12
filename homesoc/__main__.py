"""Entry point for ``python -m homesoc``.

Kept to a single call so the argparse wiring (and its testability) stays in
:mod:`homesoc.cli`.
"""

from __future__ import annotations

import sys

from homesoc.cli import main

if __name__ == "__main__":
    sys.exit(main())
