"""
Attack-schedule loading and flow labelling for CIC-IDS2017-style datasets.

Flows are labelled by us from the published attacker/victim IPs and time windows. Third-party CSV labels
are never read. Window times are local lab times; `utc_offset_hours` converts them to the epoch times that
PCAP packets carry.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

BENIGN = "BENIGN"
DEFAULT_SCHEDULE = Path(__file__).resolve().parent / "schedules" / "cicids2017.json"


@dataclass(frozen=True)
class AttackWindow:
    cls: str
    start_ts: float
    end_ts: float
    attackers: frozenset[str]
    victims: frozenset[str]
    attacker_nets: tuple[Any, ...] = ()
    victim_nets: tuple[Any, ...] = ()

    def _in(self, ip: str, exact: frozenset[str], nets: tuple[Any, ...]) -> bool:
        if ip in exact:
            return True
        if not nets:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in nets)

    def matches(self, src_ip: str, dst_ip: str, ts: float, slack: float = 0.0) -> bool:
        if not (self.start_ts - slack <= ts <= self.end_ts + slack):
            return False
        fwd = self._in(src_ip, self.attackers, self.attacker_nets) and self._in(dst_ip, self.victims, self.victim_nets)
        rev = self._in(dst_ip, self.attackers, self.attacker_nets) and self._in(src_ip, self.victims, self.victim_nets)
        return fwd or rev


def _split_ips(items: list[str]) -> tuple[frozenset[str], tuple[Any, ...]]:
    if "*" in items:  # wildcard endpoint (e.g. spoofed or distributed sources in synthetic scenarios)
        return frozenset(), (ipaddress.ip_network("0.0.0.0/0"), ipaddress.ip_network("::/0"))
    exact = frozenset(i for i in items if "/" not in i)
    nets = tuple(ipaddress.ip_network(i, strict=False) for i in items if "/" in i)
    return exact, nets


def _epoch(date: str, hhmm: str, utc_offset_hours: float) -> float:
    hour, minute = (int(x) for x in hhmm.split(":"))
    local = datetime.fromisoformat(date).replace(hour=hour, minute=minute, tzinfo=UTC)
    return (local - timedelta(hours=utc_offset_hours)).timestamp()


def load_schedule(path: Path | str = DEFAULT_SCHEDULE, utc_offset_hours: float | None = None) -> list[AttackWindow]:
    """Load attack windows from a schedule JSON; epoch times use the schedule's (or the overriding) UTC offset."""
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    offset = float(raw["utc_offset_hours"] if utc_offset_hours is None else utc_offset_hours)
    aliases = list(raw.get("attacker_aliases", []))
    windows: list[AttackWindow] = []
    for w in raw["windows"]:
        attackers = list(w["attackers"]) + (aliases if w.get("attacker_aliases", True) else [])
        a_exact, a_nets = _split_ips(attackers)
        v_exact, v_nets = _split_ips(list(w["victims"]))
        windows.append(
            AttackWindow(
                cls=w["class"],
                start_ts=_epoch(w["date"], w["start"], offset),
                end_ts=_epoch(w["date"], w["end"], offset),
                attackers=a_exact,
                victims=v_exact,
                attacker_nets=a_nets,
                victim_nets=v_nets,
            )
        )
    windows.sort(key=lambda x: (x.start_ts, x.cls))
    return windows


def label_flow(windows: list[AttackWindow], src_ip: str, dst_ip: str, start_ts: float, slack: float = 0.0) -> str:
    """Attack class of the first matching window, else BENIGN. Matched on flow start time."""
    for w in windows:
        if w.matches(src_ip, dst_ip, start_ts, slack):
            return w.cls
    return BENIGN


def scenario_windows(labels: list[dict[str, Any]]) -> list[AttackWindow]:
    """Phase 4 scenario ground-truth labels -> AttackWindow (used by the CI smoke path)."""
    out: list[AttackWindow] = []
    for lbl in labels:
        attackers = list(lbl.get("attacker_ips") or ["*"])
        victims = list(lbl.get("victim_ips") or ([lbl["victim_ip"]] if lbl.get("victim_ip") else ["*"]))
        a_exact, a_nets = _split_ips(attackers)
        v_exact, v_nets = _split_ips(victims)
        cls = str(lbl.get("attack_type") or lbl.get("threat_type") or "ATTACK")
        if lbl.get("scan_type"):
            cls = f"{cls}-{lbl['scan_type']}"
        out.append(
            AttackWindow(
                cls=cls,
                start_ts=float(lbl["start_ts"]),
                end_ts=float(lbl["end_ts"]),
                attackers=a_exact,
                victims=v_exact,
                attacker_nets=a_nets,
                victim_nets=v_nets,
            )
        )
    return out
