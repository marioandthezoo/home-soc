"""Regression tests added by the live smoke run (2026-09-04).

Each test pins a behaviour that the end-to-end smoke on the real machine relied on,
so a later refactor cannot silently take it away again.
"""

from __future__ import annotations

import pytest

from homesoc import cli


def test_scan_accepts_explicit_full_flag():
    """`scan --full` is the documented dashboard wording for a bare `scan`; it must not exit 2."""
    args = cli.build_parser().parse_args(["scan", "--full"])
    assert args.command == "scan"
    assert args.full is True and args.quick is False and args.only is None


def test_scan_quick_and_full_are_exclusive():
    with pytest.raises(SystemExit) as exc:
        cli.build_parser().parse_args(["scan", "--quick", "--full"])
    assert exc.value.code == cli.EXIT_USAGE
