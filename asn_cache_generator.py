#!/usr/bin/env python3
"""
asn_cache_generator.py — Precompute ASN → network CSV cache files from all MMDB databases.

Iterates all MMDB files in the parent directory, collects every network block
per ASN, deduplicates overlapping subnets, cross-references country data, and
writes one CSV file per ASN into this directory (asn_cache/).

IPv4: all blocks up to and including /24 (more-specific blocks are too noisy)
IPv6: blocks between /32 and /48 inclusive (broader = too much, narrower = too small)

Usage:
    python3 asn_cache_generator.py                   # process all ASNs
    python3 asn_cache_generator.py --force           # overwrite existing CSVs
    python3 asn_cache_generator.py --workers 4       # parallel workers (default: cpu count, max 8)
    python3 asn_cache_generator.py --asn AS204548    # single ASN (for testing/debugging)
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import multiprocessing
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from multiprocessing import cpu_count
from pathlib import Path

# ── Dependency check ──────────────────────────────────────────────────────────
_missing = []
try:
    import maxminddb
except ImportError:
    _missing.append("maxminddb")
try:
    from tqdm import tqdm
except ImportError:
    _missing.append("tqdm")

if _missing:
    sys.exit(f"ERROR: Missing packages. Run: pip install {' '.join(_missing)}")

# ── Paths ─────────────────────────────────────────────────────────────────────
DATA_DIR  = Path(__file__).resolve().parent   # .../ip-lookup/
CACHE_DIR = DATA_DIR / "asn_cache"            # CSV files written here

# ── Prefix limits ─────────────────────────────────────────────────────────────
IPV4_MAX_PREFIX = 24   # skip IPv4 networks more specific than /24
IPV6_MIN_PREFIX = 32   # skip IPv6 networks less specific than /32
IPV6_MAX_PREFIX = 48   # skip IPv6 networks more specific than /48

# ── Database configuration ────────────────────────────────────────────────────
ASN_SOURCES: list[dict] = [
    {"file": "GeoLite2-ASN.mmdb",  "source": "maxmind",  "type": "maxmind_asn"},
    {"file": "ip-to-asn.mmdb",     "source": "iplocate", "type": "iplocate_asn"},
    {"file": "ipinfo_lite.mmdb",   "source": "ipinfo",   "type": "ipinfo"},
]

COUNTRY_SOURCES: list[dict] = [
    {"file": "GeoLite2-Country.mmdb", "source": "maxmind",  "type": "maxmind_country"},
    {"file": "ip-to-country.mmdb",    "source": "iplocate", "type": "iplocate_country"},
    {"file": "ipinfo_lite.mmdb",      "source": "ipinfo",   "type": "ipinfo"},
]

COUNTRY_PRIORITY: dict[str, int] = {"ipinfo": 1, "iplocate": 2, "maxmind": 3}

# ── Per-worker persistent readers (opened once per worker process) ─────────────
_country_readers: list[tuple] = []  # [(maxminddb.Reader, db_type, source), ...]


def _worker_init(data_dir_str: str, country_cfg: list[dict]) -> None:
    """Pool initializer — opens country MMDB readers once and keeps them alive."""
    global _country_readers
    _country_readers = []
    for cfg in country_cfg:
        p = Path(data_dir_str) / cfg["file"]
        if p.exists():
            try:
                _country_readers.append((
                    maxminddb.open_database(str(p)),
                    cfg["type"],
                    cfg["source"],
                ))
            except Exception:
                pass


def _worker_cleanup() -> None:
    """Worker cleanup — close all MMDB readers to free file handles."""
    global _country_readers
    for reader, _, _ in _country_readers:
        try:
            reader.close()
        except Exception:
            pass
    _country_readers = []


# ── ASN extraction helpers ─────────────────────────────────────────────────────
def _extract_asn(record: dict, db_type: str) -> tuple[str, str] | None:
    """Return (asn_str, org_str) or None."""
    if db_type == "maxmind_asn":
        num = record.get("autonomous_system_number")
        org = record.get("autonomous_system_organization") or ""
        return (f"AS{num}", org) if num else None
    if db_type == "iplocate_asn":
        num = record.get("asn")
        org = record.get("org") or record.get("name") or ""
        return (f"AS{num}", org) if num else None
    if db_type == "ipinfo":
        asn = record.get("asn") or ""
        org = record.get("as_name") or ""
        return (asn, org) if re.match(r"^AS\d+$", asn) else None
    return None


def _extract_country(record: dict, db_type: str) -> tuple[str, str]:
    """Return (country_name, country_code) or ('', '')."""
    if db_type == "maxmind_country":
        node = record.get("country") or record.get("registered_country") or {}
        return node.get("names", {}).get("en", ""), node.get("iso_code", "")
    if db_type == "iplocate_country":
        return record.get("country_name", ""), record.get("country_code", "")
    if db_type == "ipinfo":
        return record.get("country", ""), record.get("country_code", "")
    return "", ""


# ── Network filter ─────────────────────────────────────────────────────────────
def _include(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    if isinstance(net, ipaddress.IPv4Network):
        return 1 <= net.prefixlen <= IPV4_MAX_PREFIX
    return IPV6_MIN_PREFIX <= net.prefixlen <= IPV6_MAX_PREFIX


# ── Deduplication ──────────────────────────────────────────────────────────────
def _dedup_family(nets: list[tuple]) -> list[tuple]:
    """
    Within a single address family (all IPv4 or all IPv6):
    sort by prefix length ascending (larger/broader first), then accept each
    network only if it is not already covered by an accepted supernet.
    Input/output: [(cidr_str, source, ip_version), ...]
    """
    parsed: list[tuple] = []
    for cidr, src, ver in nets:
        try:
            parsed.append((ipaddress.ip_network(cidr, strict=False), src, ver, cidr))
        except ValueError:
            continue

    parsed.sort(key=lambda x: x[0].prefixlen)

    accepted: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    result: list[tuple] = []

    for net_obj, src, ver, cidr in parsed:
        if not any(net_obj.subnet_of(a) for a in accepted):
            accepted.append(net_obj)
            result.append((cidr, src, ver))

    return result


def deduplicate(nets: list[tuple]) -> list[tuple]:
    """
    Full deduplication pipeline:
    1. Same CIDR from multiple sources → keep preferred source (iplocate > ipinfo > maxmind)
    2. Subnet of a broader block in same ASN → remove
    Input/output: [(cidr_str, source, ip_version), ...]
    """
    if not nets:
        return []

    # Step 1: source dedup
    priority = {"iplocate": 1, "ipinfo": 2, "maxmind": 3}
    best: dict[str, tuple] = {}
    for cidr, src, ver in nets:
        p = priority.get(src, 99)
        if cidr not in best or p < best[cidr][1]:
            best[cidr] = ((cidr, src, ver), p)
    unique = [v[0] for v in best.values()]

    # Step 2: subnet removal per address family
    v4 = _dedup_family([(c, s, v) for c, s, v in unique if ":" not in c])
    v6 = _dedup_family([(c, s, v) for c, s, v in unique if ":" in c])
    return v4 + v6


# ── Country lookup (uses persistent per-worker readers) ───────────────────────
def _lookup_country(ip: str) -> tuple[str, str]:
    best = ("", "", 999)  # name, code, priority
    for reader, db_type, source in _country_readers:
        prio = COUNTRY_PRIORITY.get(source, 99)
        if prio >= best[2]:
            continue
        try:
            rec = reader.get(ip)
        except Exception:
            continue
        if not rec:
            continue
        cn, cc = _extract_country(rec, db_type)
        if cc:
            best = (cn, cc, prio)
    return best[0], best[1]


# ── Filename sanitizer ────────────────────────────────────────────────────────
def _safe_name(s: str, maxlen: int = 40) -> str:
    s = re.sub(r"[^\w\s-]", "", s)
    s = re.sub(r"[\s_]+", "_", s).strip("_")
    return s[:maxlen] or "Unknown"


# ── Phase 1: collect all ASN networks from MMDB files ─────────────────────────
def collect_all_networks(
    data_dir: Path,
    only_asn: str | None = None,
    use_vote: bool = False,
) -> dict[str, dict]:
    """
    Iterates every ASN MMDB file and returns:
        { "AS12345": {"org": "ISP Name", "networks": [(cidr, source, ip_version), ...]}, ... }

    use_vote=True:  majority vote across sources; ties broken by source priority.
    use_vote=False: ipinfo wins if present, then iplocate, then maxmind (no voting).
    """
    # cidr → { asn_str → {"org": str, "ip_ver": str, "sources": set[str]} }
    cidr_votes: dict[str, dict[str, dict]] = {}
    # Priority for tie-breaking votes, and sole criterion when use_vote=False.
    # vote mode:    iplocate > ipinfo > maxmind  (all three equally weighted)
    # no-vote mode: ipinfo   > iplocate > maxmind
    _src_priority = (
        {"iplocate": 1, "ipinfo": 2, "maxmind": 3}
        if use_vote
        else {"ipinfo": 1, "iplocate": 2, "maxmind": 3}
    )

    total_accepted = 0

    for src in ASN_SOURCES:
        path = data_dir / src["file"]
        if not path.exists():
            tqdm.write(f"  ⚠  Skipping {src['file']} (not found)")
            continue

        size_mb = path.stat().st_size // (1024 * 1024)
        tqdm.write(f"\n  Reading {src['file']}  ({size_mb} MB)…")

        accepted = 0
        filtered = 0
        seen_cidr: set[str] = set()   # one vote per CIDR per source

        with maxminddb.open_database(str(path)) as reader:
            for network, record in tqdm(
                reader,
                desc=f"    {src['source']:8s}",
                unit=" nets",
                leave=True,
                position=0,
            ):
                if record is None:
                    continue

                result = _extract_asn(record, src["type"])
                if result is None:
                    continue

                asn_str, org = result

                if not _include(network):
                    filtered += 1
                    continue

                net_str = str(network)
                if net_str in seen_cidr:
                    continue
                seen_cidr.add(net_str)

                ip_ver = "IPv6" if ":" in net_str else "IPv4"

                if net_str not in cidr_votes:
                    cidr_votes[net_str] = {}
                if asn_str not in cidr_votes[net_str]:
                    cidr_votes[net_str][asn_str] = {
                        "org": "", "ip_ver": ip_ver, "sources": set()
                    }
                entry = cidr_votes[net_str][asn_str]
                if not entry["org"] and org:
                    entry["org"] = org
                entry["sources"].add(src["source"])
                accepted += 1

        tqdm.write(
            f"    → {accepted:,} networks accepted  |  {filtered:,} filtered by prefix limit"
        )
        total_accepted += accepted

    # ── Resolution ────────────────────────────────────────────────────────────
    def _vote_score(item: tuple) -> tuple:
        """Most votes wins; ties broken by best source priority."""
        _, d = item
        best_prio = min(_src_priority.get(s, 99) for s in d["sources"])
        return (-len(d["sources"]), best_prio)

    def _priority_score(item: tuple) -> int:
        """Single best-source priority (ipinfo > iplocate > maxmind)."""
        _, d = item
        return min(_src_priority.get(s, 99) for s in d["sources"])

    resolver = _vote_score if use_vote else _priority_score

    asn_data: dict[str, dict] = defaultdict(lambda: {"org": "", "networks": []})
    disputed = 0

    for net_str, asn_map in cidr_votes.items():
        if len(asn_map) > 1:
            disputed += 1
            winner_asn, winner_data = min(asn_map.items(), key=resolver)
        else:
            winner_asn, winner_data = next(iter(asn_map.items()))

        # Apply --asn filter after vote resolution so the tally is always complete
        if only_asn and winner_asn != only_asn:
            continue

        best_src = min(winner_data["sources"], key=lambda s: _src_priority.get(s, 99))
        asn_data[winner_asn]["networks"].append((net_str, best_src, winner_data["ip_ver"]))
        if not asn_data[winner_asn]["org"] and winner_data["org"]:
            asn_data[winner_asn]["org"] = winner_data["org"]

    if disputed:
        mode_label = "majority-vote" if use_vote else "priority (ipinfo>iplocate>maxmind)"
        print(f"\n  Disputed CIDRs resolved    : {disputed:,}  [{mode_label}]")
    print(f"  Total unique CIDRs         : {len(cidr_votes):,}  (before per-ASN dedup)")
    print(f"  Total unique ASNs          : {len(asn_data):,}")
    return dict(asn_data)


# ── Phase 2: per-ASN worker ───────────────────────────────────────────────────
def _process_one(args: tuple) -> dict:
    """
    Worker function (runs in a Pool worker process).
    args = (asn_str, data_dict, cache_dir_str, force)
    Uses _country_readers opened by _worker_init.
    """
    asn_str, data, cache_dir, force = args

    # Skip if already computed unless --force
    existing = list(Path(cache_dir).glob(f"{asn_str}_*.csv"))
    if existing and not force:
        return {"asn": asn_str, "status": "skipped", "count": 0,
                "file": existing[0].name}

    try:
        org      = data["org"]
        networks = data["networks"]   # [(cidr, source, ip_version)]

        deduped = deduplicate(networks)

        if not deduped:
            return {"asn": asn_str, "status": "empty", "count": 0}

        # Country lookup + determine primary country (most frequent)
        country_counts: dict[str, int] = defaultdict(int)
        enriched: list[dict] = []
        for cidr, src, ipver in deduped:
            base_ip = cidr.split("/")[0]
            country_name, cc = _lookup_country(base_ip)
            if cc:
                country_counts[cc] += 1
            enriched.append({
                "cidr": cidr, "ip_version": ipver, "source": src,
                "org": org, "country": country_name, "country_code": cc,
            })

        primary_cc = (
            max(country_counts, key=lambda k: country_counts[k])
            if country_counts else "XX"
        )

        # Write CSV
        safe_org = _safe_name(org)
        filename = f"{asn_str}_{primary_cc}_{safe_org}.csv"
        out_path = Path(cache_dir) / filename

        with open(out_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow([
                "network", "ip_version", "country", "country_code",
                "asn", "org", "source",
            ])
            for n in enriched:
                writer.writerow([
                    n["cidr"], n["ip_version"], n["country"], n["country_code"],
                    asn_str, org, n["source"],
                ])
        
        # Explicitly flush and close to prevent file handle accumulation
        out_path = None

        return {"asn": asn_str, "status": "ok", "count": len(enriched),
                "file": filename}

    except Exception as exc:
        return {"asn": asn_str, "status": "error", "count": 0, "error": str(exc)}


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--force",   action="store_true",
                    help="Overwrite existing CSV files")
    ap.add_argument("--workers", type=int, default=min(cpu_count(), 8),
                    help="Parallel worker processes (default: cpu count, max 8)")
    ap.add_argument("--asn",     default=None,
                    help="Process only one ASN, e.g. AS204548 (for testing)")
    ap.add_argument("--vote",    action="store_true",
                    help="Resolve ASN conflicts by majority vote across sources "
                         "(default: ipinfo takes priority)")
    args = ap.parse_args()

    if args.asn:
        args.asn = args.asn.upper()
        if not re.match(r"^AS\d+$", args.asn):
            sys.exit(f"ERROR: invalid ASN '{args.asn}'")

    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    sep = "=" * 64
    print(sep)
    print("  ASN Network Cache Builder")
    print(f"  MMDB source  : {DATA_DIR}")
    print(f"  Output dir   : {CACHE_DIR}")
    print(f"  Workers      : {args.workers}")
    print(f"  IPv4 limit   : up to /{IPV4_MAX_PREFIX}")
    print(f"  IPv6 range   : /{IPV6_MIN_PREFIX} – /{IPV6_MAX_PREFIX}")
    if args.asn:
        print(f"  Filter ASN   : {args.asn}")
    if args.force:
        print("  Mode         : --force (overwrite existing files)")
    print(f"  Conflict resolution: {'majority vote' if args.vote else 'ipinfo priority'}")
    print(sep)

    # ── Phase 1: collect ──────────────────────────────────────────────────────
    print("\n[1/2] Collecting networks from MMDB files…")
    asn_data = collect_all_networks(DATA_DIR, only_asn=args.asn, use_vote=args.vote)

    asn_list = sorted(asn_data.keys(), key=lambda x: int(x[2:]))
    if not asn_list:
        print("  No ASNs found — check that at least one MMDB file exists.")
        return

    # ── Phase 2: parallel dedup + country + write ─────────────────────────────
    print(f"\n[2/2] Deduplicating, enriching with country data, and writing CSVs…")
    print(f"      {len(asn_list):,} ASNs  ×  {args.workers} workers")

    worker_args = [
        (asn, asn_data[asn], str(CACHE_DIR), args.force)
        for asn in asn_list
    ]

    written  = 0
    skipped  = 0
    empty    = 0
    errors   = 0

    # Use an explicit fork context — Python 3.14+ changed the default on Linux
    # to 'forkserver', which causes pool shutdown to hang with open file handles.
    ctx  = multiprocessing.get_context("fork")
    pool = ctx.Pool(
        processes=args.workers,
        initializer=_worker_init,
        initargs=(str(DATA_DIR), COUNTRY_SOURCES),
    )
    bar = tqdm(
        total=len(asn_list),
        desc="  Processing ASNs",
        unit=" ASN",
        position=0,
    )
    try:
        for result in pool.imap_unordered(_process_one, worker_args, chunksize=20):
            bar.update(1)
            status = result.get("status")

            if status == "ok":
                written += 1
                if args.asn:
                    tqdm.write(
                        f"  ✓ {result['asn']}  →  {result['file']}"
                        f"  ({result['count']} networks)"
                    )
            elif status == "skipped":
                skipped += 1
            elif status == "empty":
                empty += 1
            elif status == "error":
                errors += 1
                tqdm.write(f"  ✗ {result['asn']}: {result.get('error', '?')}")
        
        # Close pool after successful completion of all tasks
        pool.close()
    except (KeyboardInterrupt, Exception) as e:
        # On error/interrupt, terminate workers immediately
        pool.terminate()
        raise
    finally:
        bar.close()
        pool.join()

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print(f"\n{sep}")
    print(f"  Completed at : {now}")
    print(f"  Written      : {written:,} CSV files")
    print(f"  Skipped      : {skipped:,}  (already exist — use --force to overwrite)")
    print(f"  Empty        : {empty:,}   (no networks after dedup)")
    print(f"  Errors       : {errors:,}")
    print(f"  Output dir   : {CACHE_DIR}")
    print(sep)


if __name__ == "__main__":
    main()
