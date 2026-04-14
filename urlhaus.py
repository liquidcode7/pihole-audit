"""Module: Abuse.ch URLhaus malware domain detection.

Downloads the URLhaus online URL feed daily (no API key required),
extracts hostnames, and cross-references against the Pi-hole top-allowed
domain list to detect active malware C2 or distribution domains.

Feed: https://urlhaus.abuse.ch/downloads/text_online/
Cache: data/urlhaus_cache.txt (refreshed when >23 hours old)
"""

from __future__ import annotations

import datetime
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv

load_dotenv()

URLHAUS_FEED_URL = "https://urlhaus.abuse.ch/downloads/text_online/"
_CACHE_MAX_AGE_SECONDS = 23 * 3600


@dataclass
class URLhausHit:
    domain: str
    query_count: int
    sample_urls: list[str] = field(default_factory=list)


@dataclass
class URLhausData:
    hits: list[URLhausHit] = field(default_factory=list)
    domains_checked: int = 0
    feed_domain_count: int = 0
    from_cache: bool = False
    error: str | None = None


def _cache_path() -> Path:
    base = Path(os.environ.get("REPORTS_DIR", "data/reports")).parent
    return base / "urlhaus_cache.txt"


def _cache_is_fresh(path: Path) -> bool:
    if not path.exists():
        return False
    age = datetime.datetime.now().timestamp() - path.stat().st_mtime
    return age < _CACHE_MAX_AGE_SECONDS


async def _get_feed(cache: Path) -> tuple[str, bool]:
    """Return (feed_text, from_cache). Downloads if cache is stale."""
    if _cache_is_fresh(cache):
        return cache.read_text(encoding="utf-8"), True
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(URLHAUS_FEED_URL, follow_redirects=True)
        resp.raise_for_status()
        text = resp.text
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(text, encoding="utf-8")
    return text, False


def _parse_feed(text: str) -> dict[str, list[str]]:
    """Extract {hostname: [urls]} from URLhaus feed text."""
    result: dict[str, list[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            host = urlparse(line).hostname
            if host:
                result.setdefault(host, []).append(line)
        except Exception:
            continue
    return result


async def check(allowed_domains) -> URLhausData:
    """Cross-reference Pi-hole top-allowed domains against the URLhaus feed.

    allowed_domains: list of TopDomain objects with .domain and .count attributes.
    Returns URLhausData with any hits found.
    """
    data = URLhausData()
    cache = _cache_path()

    try:
        feed_text, data.from_cache = await _get_feed(cache)
    except Exception as exc:
        data.error = f"URLhaus feed download failed: {exc}"
        return data

    feed_map = _parse_feed(feed_text)
    data.feed_domain_count = len(feed_map)
    data.domains_checked = len(allowed_domains)

    for td in allowed_domains:
        if td.domain in feed_map:
            data.hits.append(URLhausHit(
                domain=td.domain,
                query_count=td.count,
                sample_urls=feed_map[td.domain][:5],
            ))

    # Sort by query count descending — highest-traffic hits are most alarming
    data.hits.sort(key=lambda h: h.query_count, reverse=True)
    return data
