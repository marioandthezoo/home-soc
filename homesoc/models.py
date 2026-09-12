"""Plain data records shared by every package.

These are deliberately dumb dataclasses (no DB access) so scanners can be unit
tested by constructing them directly, and so the findings engine can accept
drafts from any source without importing the scanners.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

# SPEC-GAP: the spec names SEVERITY_ORDER but not its shape. A mapping
# severity -> rank (0 = most severe) works for sorting (`key=SEVERITY_ORDER.get`),
# membership tests and iteration, which covers every consumer we know of.
SEVERITY_ORDER: dict[str, int] = {name: rank for rank, name in enumerate(SEVERITIES)}


def severity_rank(severity: str | None) -> int:
    """Rank for sorting; unknown/None sorts after ``info`` instead of raising."""
    if severity is None:
        return len(SEVERITIES)
    return SEVERITY_ORDER.get(severity.lower(), len(SEVERITIES))


def is_severity(value: Any) -> bool:
    return isinstance(value, str) and value.lower() in SEVERITY_ORDER


@dataclass
class Device:
    id: int | None
    mac: str
    ip: str
    hostname: str | None
    vendor: str | None
    kind: str | None
    first_seen: str
    last_seen: str
    online: bool
    trusted: bool = False
    nickname: str | None = None

    @property
    def subject(self) -> str:
        """Finding subject for this device, as used throughout the findings catalog."""
        return f"device:{self.mac}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Service:
    device_id: int
    port: int
    proto: str
    state: str
    name: str | None
    product: str | None
    version: str | None
    extrainfo: str | None
    cpe: str | None
    tunnel: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Vuln:
    device_id: int
    service_id: int | None
    cve: str
    source: str
    kev: bool
    cvss: float | None
    epss: float | None
    title: str | None
    published: str | None
    matched_on: str
    remediation: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HostCheck:
    check_id: str
    status: str
    value: str | None = None
    expected: str | None = None
    needs_admin: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FindingDraft:
    """A finding as emitted by a scanner, before the engine assigns lifecycle state.

    ``subject`` examples: ``host``, ``device:<mac>``, ``device:<mac>:443``, ``wan``,
    ``dns:<client>``, ``feed:<name>``. ``evidence['key']`` (optional) participates in
    the dedupe key so one finding ID can exist several times per subject.
    """

    finding_id: str
    subject: str
    evidence: dict = field(default_factory=dict)
    detail: str | None = None
    severity: str | None = None
    device_id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    kind: str
    findings: list[FindingDraft]
    summary: dict
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "findings": [f.to_dict() for f in self.findings],
            "summary": dict(self.summary),
            "error": self.error,
        }


__all__ = [
    "SEVERITIES",
    "SEVERITY_ORDER",
    "severity_rank",
    "is_severity",
    "Device",
    "Service",
    "Vuln",
    "HostCheck",
    "FindingDraft",
    "ScanResult",
]
