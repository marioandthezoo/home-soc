"""Tolerant parser for nmap ``-oX`` output.

nmap is killed by ``--host-timeout`` or by our own subprocess timeout often
enough that we regularly receive a document with no closing ``</nmaprun>``.
A strict ``ElementTree.fromstring`` would throw the whole scan away, so this
module streams the document with a pull parser and keeps every host - and
every port inside a half-written host - that was complete when the stream
stopped.  Output is plain dicts so callers (and tests) need no nmap types.
"""

from __future__ import annotations

import logging
from typing import Any
from xml.etree import ElementTree as ET

logger = logging.getLogger(__name__)

__all__ = ["parse"]


def _new_host() -> dict[str, Any]:
    return {
        "ip": None,
        "mac": None,
        "vendor": None,
        "hostnames": [],
        "status": None,
        "ports": [],
        "partial": False,
        "timedout": False,
        "has_ports_section": False,
    }


def _port_from_element(port_el: ET.Element) -> dict[str, Any] | None:
    """Flatten ``<port>`` into one dict; ``None`` when the element lacks a port id."""
    try:
        portid = int(port_el.get("portid", ""))
    except ValueError:
        return None
    state_el = port_el.find("state")
    svc_el = port_el.find("service")
    cpes = [c.text.strip() for c in (svc_el.findall("cpe") if svc_el is not None else []) if c.text]
    return {
        "port": portid,
        "proto": port_el.get("protocol", "tcp"),
        "state": state_el.get("state", "unknown") if state_el is not None else "unknown",
        "reason": state_el.get("reason") if state_el is not None else None,
        "name": svc_el.get("name") if svc_el is not None else None,
        "product": svc_el.get("product") if svc_el is not None else None,
        "version": svc_el.get("version") if svc_el is not None else None,
        "extrainfo": svc_el.get("extrainfo") if svc_el is not None else None,
        "tunnel": svc_el.get("tunnel") if svc_el is not None else None,
        "method": svc_el.get("method") if svc_el is not None else None,
        "conf": svc_el.get("conf") if svc_el is not None else None,
        "cpe": cpes[0] if cpes else None,
        "cpes": cpes,
    }


def _apply_address(host: dict[str, Any], el: ET.Element) -> None:
    kind = el.get("addrtype", "")
    addr = el.get("addr")
    if not addr:
        return
    if kind in ("ipv4", "ipv6"):
        host["ip"] = addr
    elif kind == "mac":
        host["mac"] = addr.lower()
        if el.get("vendor"):
            host["vendor"] = el.get("vendor")


class _Collector:
    """Turns the pull-parser event stream into host dicts.

    Kept as a tiny state machine so the same code runs whether the document
    parsed cleanly or the parser raised part-way through.
    """

    def __init__(self) -> None:
        self.hosts: list[dict[str, Any]] = []
        self.current: dict[str, Any] | None = None

    def finish(self, partial: bool) -> None:
        cur = self.current
        if cur is None:
            return
        if cur["ip"] is not None or cur["ports"]:
            # A host nmap gave up on (--host-timeout) or one without any <ports> section is not a
            # complete "everything is closed" answer; callers must keep their previous state.
            cur["partial"] = partial or cur["timedout"] or not cur["has_ports_section"]
            self.hosts.append(cur)
        self.current = None

    def consume(self, events) -> None:
        for event, el in events:
            if event == "start":
                if el.tag == "host":
                    self.finish(partial=True)  # previous host never closed
                    self.current = _new_host()
                    if el.get("timedout") == "true":
                        self.current["timedout"] = True
                continue
            cur = self.current
            if cur is None:
                continue
            if el.tag == "host":
                if el.get("timedout") == "true":
                    cur["timedout"] = True
                self.finish(partial=False)
            elif el.tag == "ports":
                cur["has_ports_section"] = True
            elif el.tag == "address":
                _apply_address(cur, el)
            elif el.tag == "hostname":
                name = el.get("name")
                if name and name not in cur["hostnames"]:
                    cur["hostnames"].append(name)
            elif el.tag == "status":
                cur["status"] = el.get("state")
            elif el.tag == "port":
                port = _port_from_element(el)
                if port is not None:
                    cur["ports"].append(port)


def parse(xml_text: str) -> list[dict[str, Any]]:
    """Return one dict per ``<host>`` seen, even when the document is truncated.

    A host that was still open when the input ended is returned with
    ``partial=True`` so callers can decide whether to trust "closed" states.
    Garbage or empty input yields ``[]`` rather than an exception - the caller
    already knows nmap misbehaved and just needs an empty result.
    """
    if not xml_text or not xml_text.strip():
        return []
    text = xml_text.lstrip(chr(0xFEFF))  # strip a UTF-8 BOM without embedding one in source

    parser = ET.XMLPullParser(events=("start", "end"))
    collector = _Collector()
    truncated = False
    try:
        parser.feed(text)
    except ET.ParseError as exc:
        truncated = True
        logger.debug("nmap XML malformed (%s); keeping partial result", exc)
    # Events queued before an error are still readable (read_events re-raises
    # the error once it reaches it); the "end host" of a complete host is among them.
    collector.consume(_safe_events(parser))
    if not truncated:
        try:
            parser.close()
        except ET.ParseError as exc:
            truncated = True
            logger.debug("nmap XML truncated (%s); keeping partial result", exc)
        collector.consume(_safe_events(parser))
    collector.finish(partial=True)
    return collector.hosts


def _safe_events(parser: ET.XMLPullParser):
    """Yield queued events and stop quietly at the first queued ParseError."""
    it = parser.read_events()
    while True:
        try:
            yield next(it)
        except StopIteration:
            return
        except ET.ParseError:
            return
