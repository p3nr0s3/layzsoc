"""
Cyber Threat Intelligence RSS Feed Aggregator for LazySOC.
Fetches and caches live security advisories and news from top cybersecurity feeds.
"""

import time
import re
import requests
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional

FEED_SOURCES = {
    "thehackernews": {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "badge_color": "amber",
    },
    "bleepingcomputer": {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "badge_color": "blue",
    },
    "cisa": {
        "name": "CISA Advisories",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "badge_color": "emerald",
    },
    "krebs": {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "badge_color": "purple",
    },
}

CACHE_TTL_SECONDS = 300  # 5 minutes cache
_FEED_CACHE: Dict[str, Any] = {
    "timestamp": 0.0,
    "items": [],
}


def _strip_html(text: str) -> str:
    """Removes HTML tags and cleans up whitespace."""
    if not text:
        return ""
    clean = re.sub(r"<[^>]+>", " ", text)
    clean = re.sub(r"&[a-z]+;", " ", clean)
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean[:280] + ("..." if len(clean) > 280 else "")


def _classify_category(title: str, summary: str) -> str:
    """Classifies news category based on title and summary content."""
    text = (title + " " + summary).lower()
    if any(k in text for k in ["0-day", "zero-day", "cve-", "vulnerability", "flaw", "rce", "bypass"]):
        return "Vulnerability"
    if any(k in text for k in ["ransomware", "extortion", "encryptor", "lockbit", "blackcat"]):
        return "Ransomware"
    if any(k in text for k in ["malware", "trojan", "infostealer", "backdoor", "c2", "stealer"]):
        return "Malware"
    if any(k in text for k in ["breach", "leak", "stolen", "database", "hack", "compromised"]):
        return "Data Breach"
    if any(k in text for k in ["cisa", "advisory", "alert", "warning", "patch", "update"]):
        return "Advisory"
    return "Cyber News"


def fetch_single_feed(source_key: str, meta: Dict[str, str], timeout: int = 8) -> List[Dict[str, Any]]:
    """Fetches and parses a single RSS feed."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 LazySOC/3.0"
    }
    articles = []
    try:
        resp = requests.get(meta["url"], headers=headers, timeout=timeout)
        if resp.status_code != 200:
            return []

        root = ET.fromstring(resp.content)
        items = root.findall(".//item")
        for item in items[:15]:
            title = (item.findtext("title") or "").strip()
            link = (item.findtext("link") or "").strip()
            pub_date = (item.findtext("pubDate") or item.findtext("{http://purl.org/dc/elements/1.1/}date") or "").strip()
            raw_desc = item.findtext("description") or ""
            summary = _strip_html(raw_desc)

            if not title:
                continue

            category = _classify_category(title, summary)

            articles.append({
                "title": title,
                "link": link,
                "source": meta["name"],
                "source_key": source_key,
                "badge_color": meta["badge_color"],
                "pub_date": pub_date,
                "summary": summary,
                "category": category,
            })
    except Exception as e:
        # Graceful fallback per feed failure
        pass

    return articles


def get_cyber_news(source: str = "all", limit: int = 30) -> Dict[str, Any]:
    """Retrieves aggregated and cached cyber news feeds."""
    global _FEED_CACHE
    now = time.time()

    # Return cached results if still fresh
    if now - _FEED_CACHE["timestamp"] < CACHE_TTL_SECONDS and _FEED_CACHE["items"]:
        all_items = _FEED_CACHE["items"]
    else:
        all_items = []
        for sk, meta in FEED_SOURCES.items():
            all_items.extend(fetch_single_feed(sk, meta))

        # Sort roughly by date or keep balanced interleaved order
        if all_items:
            _FEED_CACHE["timestamp"] = now
            _FEED_CACHE["items"] = all_items

    # Filter by source if requested
    source = source.lower().strip()
    if source != "all" and source in FEED_SOURCES:
        filtered = [item for item in all_items if item["source_key"] == source]
    else:
        filtered = all_items

    return {
        "total": len(filtered[:limit]),
        "sources": [s["name"] for s in FEED_SOURCES.values()],
        "cached": (now - _FEED_CACHE["timestamp"] < CACHE_TTL_SECONDS),
        "items": filtered[:limit],
    }
