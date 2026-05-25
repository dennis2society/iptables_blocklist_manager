#!/usr/bin/env python3
"""
update_asn_blocklists.py — Refresh ASN blocklist CSVs from the latest asn_cache.

For every AS*_v4.csv / AS*_v6.csv in blocklist_csvs/ that corresponds to an
ASN present in asn_cache/, this script:

  • Replaces the network list with the networks from the cache.
  • Keeps the original added_at timestamp for networks that already existed.
  • Assigns the current UTC timestamp to newly-appearing networks.
  • Networks that vanished from the cache are dropped.

Usage:
    python3 update_asn_blocklists.py              # update all ASN blocklists
    python3 update_asn_blocklists.py --dry-run    # show what would change, no writes
    python3 update_asn_blocklists.py --asn AS1234 # single ASN
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR      = Path(__file__).resolve().parent.parent   # …/logwatch_tables/
BLOCKLIST_DIR = BASE_DIR / "blocklist_csvs"
CACHE_DIR     = BASE_DIR / "asn_cache"

BLOCKLIST_HEADER = ["network", "asn", "org", "country_code", "country", "added_at"]
CACHE_HEADER     = ["network", "ip_version", "country", "country_code", "asn", "org", "source"]


# ── helpers ───────────────────────────────────────────────────────────────────

def now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def find_cache_file(asn: str) -> Path | None:
    """Return the single cache CSV for *asn* (e.g. 'AS1234'), or None."""
    # glob pattern: AS1234_*.csv
    matches = list(CACHE_DIR.glob(f"{asn}_*.csv"))
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        # shouldn't happen, but pick the first and warn
        print(f"  WARNING: multiple cache files for {asn}, using {matches[0].name}", file=sys.stderr)
        return matches[0]
    return None


def read_cache(path: Path) -> dict[str, list[dict]]:
    """
    Read an ASN cache CSV and return a dict keyed by ip_version:
        {"IPv4": [{"network":…, "asn":…, "org":…, "country_code":…, "country":…}, …],
         "IPv6": […]}
    """
    result: dict[str, list[dict]] = {"IPv4": [], "IPv6": []}
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            ver = row.get("ip_version", "").strip()
            if ver not in result:
                continue
            result[ver].append({
                "network":      row["network"].strip(),
                "asn":          row["asn"].strip(),
                "org":          row["org"].strip(),
                "country_code": row["country_code"].strip(),
                "country":      row["country"].strip(),
            })
    return result


def read_blocklist(path: Path) -> dict[str, str]:
    """Return {network: added_at} for an existing blocklist CSV."""
    timestamps: dict[str, str] = {}
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            net = row.get("network", "").strip()
            at  = row.get("added_at", "").strip()
            if net:
                timestamps[net] = at
    return timestamps


def write_blocklist(path: Path, rows: list[dict], dry_run: bool) -> None:
    if dry_run:
        return
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=BLOCKLIST_HEADER, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        writer.writerows(rows)


# ── core update logic ──────────────────────────────────────────────────────────

def update_asn(asn: str, dry_run: bool) -> None:
    cache_path = find_cache_file(asn)
    if cache_path is None:
        print(f"  SKIP  {asn}: no cache file found")
        return

    cache_data = read_cache(cache_path)
    ts_now = now_ts()

    for version_label, ip_suffix in [("IPv4", "v4"), ("IPv6", "v6")]:
        bl_path = BLOCKLIST_DIR / f"{asn}_{ip_suffix}.csv"
        if not bl_path.exists():
            continue

        cache_rows = cache_data[version_label]
        if not cache_rows:
            print(f"  WARN  {asn}_{ip_suffix}.csv: cache has no {version_label} networks — leaving file untouched")
            continue

        old_timestamps = read_blocklist(bl_path)

        new_rows: list[dict] = []
        for entry in cache_rows:
            net = entry["network"]
            new_rows.append({
                "network":      net,
                "asn":          entry["asn"],
                "org":          entry["org"],
                "country_code": entry["country_code"],
                "country":      entry["country"],
                "added_at":     old_timestamps.get(net, ts_now),
            })

        added   = sum(1 for r in new_rows if r["network"] not in old_timestamps)
        removed = len(old_timestamps) - (len(new_rows) - added)

        has_changes = added > 0 or removed > 0
        if not dry_run or has_changes:
            action = "DRY-RUN" if dry_run else "UPDATE"
            print(f"  {action} {bl_path.name}: {len(new_rows)} networks "
                  f"(+{added} added, -{removed} removed)")

        write_blocklist(bl_path, new_rows, dry_run)


# ── entry point ───────────────────────────────────────────────────────────────

def collect_asns(target: str | None) -> list[str]:
    """Return sorted unique ASN strings that have at least one blocklist file."""
    if target:
        # normalise: accept 'AS1234' or just '1234'
        asn = target.upper() if target.upper().startswith("AS") else f"AS{target}"
        return [asn]

    pattern = re.compile(r"^(AS\d+)_v[46]\.csv$")
    asns: set[str] = set()
    for p in BLOCKLIST_DIR.iterdir():
        m = pattern.match(p.name)
        if m:
            asns.add(m.group(1))
    return sorted(asns, key=lambda x: int(x[2:]))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="Show what would change without writing files")
    parser.add_argument("--asn", metavar="ASNUMBER", help="Process a single ASN only (e.g. AS1234)")
    args = parser.parse_args()

    asns = collect_asns(args.asn)
    if not asns:
        sys.exit("No ASN blocklist files found.")

    print(f"Processing {len(asns)} ASN(s){'  [DRY RUN]' if args.dry_run else ''}…")
    for asn in asns:
        update_asn(asn, dry_run=args.dry_run)

    print("Done.")


if __name__ == "__main__":
    main()
