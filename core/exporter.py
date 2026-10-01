"""Export utilities for Slothery triage results."""

import csv
import io
import json
from typing import List, Dict, Any
from core.parser import refang_string


def export_to_csv(results: List[Dict[str, Any]], defang_output: bool = True) -> str:
    """Exports list of result dictionaries to CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Headers
    writer.writerow([
        "Indicator",
        "Type",
        "Verdict",
        "VirusTotal Stats",
        "AbuseIPDB Score",
        "Notes",
        "Cached",
    ])

    for item in results:
        ioc_val = item.get("ioc", "")
        ioc_type = item.get("type", "")
        if defang_output:
            ioc_val = refang_string(ioc_val, ioc_type)

        writer.writerow([
            ioc_val,
            ioc_type.upper(),
            item.get("verdict", "Unknown"),
            item.get("vt_stats", "N/A"),
            item.get("abuse_score", "N/A"),
            item.get("notes", ""),
            "Yes" if item.get("is_cached") else "No",
        ])

    return output.getvalue()


def export_to_json(results: List[Dict[str, Any]], defang_output: bool = False) -> str:
    """Exports list of result dictionaries to formatted JSON string."""
    clean_results = []
    for item in results:
        entry = dict(item)
        if defang_output:
            entry["ioc"] = refang_string(entry.get("ioc", ""), entry.get("type", ""))
        clean_results.append(entry)

    return json.dumps(clean_results, indent=2)
