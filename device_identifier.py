"""Module 5: Device Identification via DNS Fingerprinting.

Pulls a large query sample from Pi-hole, groups domains by client IP,
then matches against a signature database to infer device types.

Manual overrides via devices.json always take priority over fingerprinting.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from client import PiholeClient


# ---------------------------------------------------------------------------
# Signature database
# ---------------------------------------------------------------------------

@dataclass
class _Signature:
    device_type: str
    patterns: list[str]   # exact domain or *.suffix.com wildcard
    privacy_risk: str     # "high" | "medium" | "low" | "minimal"
    notes: str


DEVICE_SIGNATURES: list[_Signature] = [
    _Signature(
        device_type="Apple Device (iPhone/iPad/Mac)",
        patterns=[
            "mesu.apple.com",
            "*.apple.com",
            "*.icloud.com",
            "configuration.apple.com",
            "setup.icloud.com",
            "*.mzstatic.com",
            "*.itunes.com",
        ],
        privacy_risk="low",
        notes="Apple devices send minimal telemetry relative to peers. "
              "iCloud sync traffic is end-to-end encrypted.",
    ),
    _Signature(
        device_type="Windows PC",
        patterns=[
            "*.windowsupdate.com",
            "ctldl.windowsupdate.com",
            "*.microsoft.com",
            "*.msftconnecttest.com",
            "*.msftncsi.com",
            "*.live.com",
            "*.windows.com",
        ],
        privacy_risk="medium",
        notes="Windows sends telemetry to Microsoft by default. "
              "Consider blocking telemetry.microsoft.com and vortex.data.microsoft.com.",
    ),
    _Signature(
        device_type="Android Phone/Tablet",
        patterns=[
            "*.googleapis.com",
            "*.gstatic.com",
            "*.android.com",
            "connectivitycheck.gstatic.com",
            "*.play.googleapis.com",
            "*.google.com",
            "android.clients.google.com",
        ],
        privacy_risk="medium",
        notes="Android devices send significant telemetry to Google. "
              "Blocking connectivitycheck.gstatic.com may break network detection.",
    ),
    _Signature(
        device_type="Samsung TV",
        patterns=[
            "samsungads.com",
            "*.samsungotn.net",
            "log-config.samsungacr.com",
            "*.samsungcloudsolution.com",
            "cdn.samsungcloudsolution.com",
            "*.samsungacr.com",
            "*.samsungqbe.com",
            "*.smarttv.samsung.com",
        ],
        privacy_risk="high",
        notes="Samsung Smart TVs serve ads, track viewing habits via ACR "
              "(Automatic Content Recognition), and send data to third-party advertisers.",
    ),
    _Signature(
        device_type="LG TV",
        patterns=[
            "*.lgsmartad.com",
            "*.lgappstv.com",
            "lgtvsdp.com",
            "*.lge.com",
            "smartshare.lgtvsdp.com",
            "*.lgtvcommon.com",
            "aic-ngfts.lge.com",
        ],
        privacy_risk="high",
        notes="LG WebOS TVs collect viewing data and serve targeted ads via LG Ad Solutions. "
              "ACR tracking is enabled by default.",
    ),
    _Signature(
        device_type="Roku",
        patterns=[
            "*.roku.com",
            "scribe.logs.roku.com",
            "*.rokucontent.com",
            "ads.roku.com",
            "cooper.roku.com",
            "logs.roku.com",
            "*.rokusearch.com",
        ],
        privacy_risk="high",
        notes="Roku sells viewing data and serves targeted ads. "
              "Blocking ads.roku.com may break the Roku Channel store.",
    ),
    _Signature(
        device_type="Amazon Echo/Alexa",
        patterns=[
            "*.amazonalexa.com",
            "*.amazon.com",
            "*.amazontrust.com",
            "bob.whisperplay.com",
            "*.media-amazon.com",
            "*.alexa.com",
            "avs-alexa-na.amazon.com",
            "*.device-messaging.amazon.com",
        ],
        privacy_risk="high",
        notes="Amazon Echo devices continuously listen for wake words and send voice "
              "data to AWS. Purchase history and usage patterns are used for ad targeting.",
    ),
    _Signature(
        device_type="Amazon Fire TV",
        patterns=[
            "*.amazon.com",
            "*.amazontrust.com",
            "*.firetv.amazon.com",
            "device-metrics-us.amazon.com",
            "*.amazonvideo.com",
            "*.aiv-cdn.net",
        ],
        privacy_risk="medium",
        notes="Fire TV tracks viewing habits for ad targeting. "
              "Shares infrastructure with Amazon Echo — distinguish by domain mix.",
    ),
    _Signature(
        device_type="Nintendo Switch",
        patterns=[
            "*.nintendo.net",
            "ctest.cdn.nintendo.net",
            "eshop.nintendo.net",
            "*.nintendo-europe.com",
            "npns-dev.c.nintendo.com",
            "*.accounts.nintendo.com",
        ],
        privacy_risk="low",
        notes="Nintendo collects gameplay telemetry but does not run ads or sell data. "
              "Privacy posture is significantly better than smart TVs.",
    ),
    _Signature(
        device_type="Sony PlayStation",
        patterns=[
            "*.playstation.net",
            "*.playstation.com",
            "*.sonyentertainmentnetwork.com",
            "*.dl.playstation.net",
            "telemetry.pes.playstation.net",
            "*.np.community.playstation.net",
        ],
        privacy_risk="low",
        notes="PlayStation consoles send gameplay telemetry to Sony. "
              "Advertising is limited compared to smart TV platforms.",
    ),
    _Signature(
        device_type="Sonos Speaker",
        patterns=[
            "*.sonos.com",
            "spdiscovery.sonos.com",
            "*.sonos.net",
            "logs.sonos.com",
            "music.sonos.com",
        ],
        privacy_risk="low",
        notes="Sonos collects usage and diagnostic data. "
              "Blocking logs.sonos.com reduces telemetry without breaking functionality.",
    ),
    _Signature(
        device_type="Raspberry Pi",
        patterns=[
            "*.raspberrypi.org",
            "*.debian.org",
            "*.raspbian.org",
            "archive.raspberrypi.org",
            "deb.debian.org",
            "security.debian.org",
        ],
        privacy_risk="minimal",
        notes="Raspberry Pis typically query package repos and update servers. "
              "No ad or tracking infrastructure.",
    ),
    _Signature(
        device_type="Linux Workstation/Server",
        patterns=[
            "*.archlinux.org",
            "*.ubuntu.com",
            "*.debian.org",
            "*.fedoraproject.org",
            "*.centos.org",
            "mirrors.kernel.org",
            "*.launchpad.net",
            "ppa.launchpad.net",
        ],
        privacy_risk="minimal",
        notes="Linux systems query package mirrors and update servers. "
              "No embedded telemetry by default.",
    ),
    _Signature(
        device_type="Router/Network Device",
        patterns=[
            "*.pool.ntp.org",
            "time.cloudflare.com",
            "time.google.com",
            "time.apple.com",
            "time.windows.com",
            "ntp.ubuntu.com",
            "0.pool.ntp.org",
            "1.pool.ntp.org",
            "2.pool.ntp.org",
            "3.pool.ntp.org",
        ],
        privacy_risk="minimal",
        notes="Network infrastructure devices primarily query NTP servers and "
              "make very few DNS requests overall.",
    ),
    _Signature(
        device_type="Ring/Nest Doorbell/Camera",
        patterns=[
            "*.ring.com",
            "*.nest.com",
            "*.dropcam.com",
            "fw-static.ring.com",
            "*.ring-prod.com",
            "home.nest.com",
            "*.nestlabs.com",
        ],
        privacy_risk="high",
        notes="Ring and Nest devices upload continuous video/audio data to cloud servers. "
              "Ring has shared footage with law enforcement without warrants historically.",
    ),
    _Signature(
        device_type="Printer",
        patterns=[
            "*.hp.com",
            "*.hpconnected.com",
            "*.epson.com",
            "*.canon.com",
            "*.brother.com",
            "*.lexmark.com",
            "*.xerox.com",
            "print.epson.net",
        ],
        privacy_risk="minimal",
        notes="Printers occasionally query manufacturer domains for firmware updates "
              "and cloud print services.",
    ),
]

# Map privacy_risk → sort order (for display)
_RISK_ORDER = {"high": 0, "medium": 1, "low": 2, "minimal": 3}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DeviceInfo:
    ip: str
    hostname: str                       # from Pi-hole client names, else IP
    device_type: str
    confidence: float                   # 0.0–1.0
    matched_patterns: list[str]
    privacy_risk: str                   # "high" | "medium" | "low" | "minimal"
    notes: str
    manual_override: bool = False       # True when sourced from devices.json
    alternatives: list[tuple[str, float]] = field(default_factory=list)  # (type, confidence)


# ---------------------------------------------------------------------------
# Pattern matching
# ---------------------------------------------------------------------------

def _matches_pattern(domain: str, pattern: str) -> bool:
    """Return True if domain matches the pattern.

    Patterns starting with ``*.`` match any subdomain (including the bare
    apex). All other patterns are treated as exact matches.
    """
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return domain == suffix or domain.endswith("." + suffix)
    return domain == pattern


def _score_signature(
    client_domains: set[str],
    sig: _Signature,
) -> tuple[float, list[str]]:
    """Return (confidence, matched_pattern_list) for a client against a signature."""
    matched: list[str] = []
    for pattern in sig.patterns:
        if any(_matches_pattern(d, pattern) for d in client_domains):
            matched.append(pattern)
    confidence = len(matched) / len(sig.patterns) if sig.patterns else 0.0
    return confidence, matched


# ---------------------------------------------------------------------------
# Alias loading
# ---------------------------------------------------------------------------

def _load_aliases(path: str = "devices.json") -> dict[str, str]:
    """Load IP → label overrides from an optional devices.json file.

    Returns {} if the file does not exist or cannot be parsed.
    """
    p = Path(path)
    if not p.exists():
        # Also try relative to this file
        p = Path(__file__).parent / path
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except Exception:
        pass
    return {}


# ---------------------------------------------------------------------------
# Query fetching
# ---------------------------------------------------------------------------

async def _fetch_queries(client: PiholeClient, max_queries: int) -> list[dict[str, Any]]:
    """Paginate /api/queries newest-first until we have max_queries records."""
    collected: list[dict[str, Any]] = []
    cursor: int | None = None

    while len(collected) < max_queries:
        params: dict[str, Any] = {}
        if cursor is not None:
            params["cursor"] = cursor

        page = await client.get("/api/queries", **params)
        batch: list[dict[str, Any]] = page.get("queries", [])
        if not batch:
            break

        collected.extend(batch)
        oldest_id: int = batch[-1]["id"]
        if oldest_id <= 1:
            break
        cursor = oldest_id - 1

    return collected[:max_queries]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

CONFIDENCE_THRESHOLD = 0.20
ALTERNATIVE_THRESHOLD = 0.15   # show alt if confidence within this delta of winner


async def identify_devices(
    client: PiholeClient,
    client_names: dict[str, str] | None = None,
    mac_vendors: dict[str, str] | None = None,
    max_queries: int = 10_000,
    aliases_path: str = "devices.json",
) -> dict[str, DeviceInfo]:
    """Identify devices on the network by their DNS query patterns.

    Returns a dict mapping IP address → DeviceInfo.
    Manual aliases from devices.json always override fingerprinting.
    mac_vendors is an IP → vendor string map used as a hint when DNS
    confidence is below threshold.
    """
    names = client_names or {}
    vendors = mac_vendors or {}
    aliases = _load_aliases(aliases_path)

    queries = await _fetch_queries(client, max_queries)

    # Build IP → set of unique lowercased queried domains
    client_domains: dict[str, set[str]] = defaultdict(set)
    for q in queries:
        ip = q.get("client", {}).get("ip", "")
        domain = q.get("domain", "").lower()
        if ip and domain:
            client_domains[ip].add(domain)

    # Collect all IPs seen (queries may include IPs with no alias/name)
    all_ips: set[str] = set(client_domains.keys()) | set(aliases.keys())

    result: dict[str, DeviceInfo] = {}

    for ip in all_ips:
        hostname = names.get(ip, ip)
        vendor   = vendors.get(ip)

        # Manual override takes priority
        if ip in aliases:
            alias_label = aliases[ip]
            result[ip] = DeviceInfo(
                ip=ip,
                hostname=hostname,
                device_type=alias_label,
                confidence=1.0,
                matched_patterns=[],
                privacy_risk=_infer_risk_from_label(alias_label),
                notes="Manually labeled in devices.json.",
                manual_override=True,
            )
            continue

        domains = client_domains.get(ip, set())

        if not domains:
            device_type = f"{vendor} device" if vendor else "Unknown device"
            result[ip] = DeviceInfo(
                ip=ip,
                hostname=hostname,
                device_type=device_type,
                confidence=0.0,
                matched_patterns=[],
                privacy_risk=_infer_risk_from_label(device_type),
                notes=(
                    f"No DNS queries observed. MAC vendor: {vendor}."
                    if vendor else "No DNS queries observed for this client."
                ),
            )
            continue

        # Score every signature
        scores: list[tuple[float, list[str], _Signature]] = []
        for sig in DEVICE_SIGNATURES:
            conf, matched = _score_signature(domains, sig)
            scores.append((conf, matched, sig))

        scores.sort(key=lambda x: x[0], reverse=True)
        best_conf, best_matched, best_sig = scores[0]

        if best_conf < CONFIDENCE_THRESHOLD:
            # Use MAC vendor as a fallback hint when DNS is ambiguous
            device_type = f"{vendor} device" if vendor else "Unknown device"
            result[ip] = DeviceInfo(
                ip=ip,
                hostname=hostname,
                device_type=device_type,
                confidence=best_conf,
                matched_patterns=best_matched,
                privacy_risk=_infer_risk_from_label(device_type),
                notes=(
                    f"Low DNS confidence. MAC vendor hint: {vendor}. "
                    "Add a manual label to devices.json for a definitive match."
                    if vendor else
                    "No strong signature match. Add a manual label to devices.json."
                ),
            )
            continue

        # Collect close alternatives (exclude winner)
        alternatives: list[tuple[str, float]] = []
        for conf, _, sig in scores[1:3]:
            if conf > 0 and (best_conf - conf) <= ALTERNATIVE_THRESHOLD:
                alternatives.append((sig.device_type, conf))

        vendor_note = f" (MAC vendor: {vendor})" if vendor else ""
        result[ip] = DeviceInfo(
            ip=ip,
            hostname=hostname,
            device_type=best_sig.device_type,
            confidence=best_conf,
            matched_patterns=best_matched,
            privacy_risk=best_sig.privacy_risk,
            notes=best_sig.notes + vendor_note,
            alternatives=alternatives,
        )

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_LABEL_RISK_HINTS: list[tuple[str, str]] = [
    ("samsung", "high"),
    ("lg tv", "high"),
    ("roku", "high"),
    ("echo", "high"),
    ("alexa", "high"),
    ("ring", "high"),
    ("nest", "high"),
    ("fire tv", "medium"),
    ("android", "medium"),
    ("windows", "medium"),
    ("apple", "low"),
    ("iphone", "low"),
    ("ipad", "low"),
    ("mac", "low"),
    ("nintendo", "low"),
    ("playstation", "low"),
    ("sonos", "low"),
    ("linux", "minimal"),
    ("raspberry", "minimal"),
    ("router", "minimal"),
    ("printer", "minimal"),
    ("opnsense", "minimal"),
    ("pihole", "minimal"),
    ("pi-hole", "minimal"),
]


def _infer_risk_from_label(label: str) -> str:
    """Guess a privacy risk level from a human-provided device label."""
    lower = label.lower()
    for hint, risk in _LABEL_RISK_HINTS:
        if hint in lower:
            return risk
    return "minimal"


# ---------------------------------------------------------------------------
# Network risk summary
# ---------------------------------------------------------------------------

@dataclass
class NetworkRiskSummary:
    total_devices: int
    identified: int
    unknown: int
    manual: int
    high_risk: int
    medium_risk: int
    low_risk: int
    minimal_risk: int
    overall_risk: str   # "high" | "medium" | "low" | "minimal"


def network_risk_summary(device_map: dict[str, DeviceInfo]) -> NetworkRiskSummary:
    """Compute an aggregate privacy risk summary across all identified devices."""
    counts: dict[str, int] = {"high": 0, "medium": 0, "low": 0, "minimal": 0}
    identified = 0
    unknown = 0
    manual = 0

    for info in device_map.values():
        if info.device_type == "Unknown device":
            unknown += 1
        else:
            identified += 1
        if info.manual_override:
            manual += 1
        counts[info.privacy_risk] = counts.get(info.privacy_risk, 0) + 1

    total = len(device_map)

    if counts["high"] > 0:
        overall = "high"
    elif counts["medium"] > 0:
        overall = "medium"
    elif counts["low"] > 0:
        overall = "low"
    else:
        overall = "minimal"

    return NetworkRiskSummary(
        total_devices=total,
        identified=identified,
        unknown=unknown,
        manual=manual,
        high_risk=counts["high"],
        medium_risk=counts["medium"],
        low_risk=counts["low"],
        minimal_risk=counts["minimal"],
        overall_risk=overall,
    )
