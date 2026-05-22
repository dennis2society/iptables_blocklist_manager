# This Python script parses the CSV files to get the network ranges to block
# Outputs a JSON object mapping each CSV stem to a dict with:
#   "networks": list of CIDR strings
#   "org": organisation name (ASN files only)
#   "country_code": two-letter country code (ASN files only)
import json
import os
import sys

import pandas as pd

# Default CSV directory is in the same folder as this script
DEFAULT_CSV_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blocklist_csvs")
# CSV_DIR can be overridden via command-line argument
CSV_DIR = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CSV_DIR


def get_networks() -> dict[str, dict]:
    result: dict[str, dict] = {}

    if not os.path.isdir(CSV_DIR):
        print(f"ERROR: CSV directory not found: {CSV_DIR}", file=sys.stderr)
        sys.exit(1)

    for filename in sorted(os.listdir(CSV_DIR)):
        if not filename.endswith(".csv"):
            continue
        stem = filename[:-4]  # strip .csv extension
        filepath = os.path.join(CSV_DIR, filename)
        is_asn = stem.startswith("AS")
        try:
            cols = ["network", "org", "country_code"] if is_asn else ["network"]
            # Some ASN CSVs may not have all columns; read gracefully.
            df = pd.read_csv(filepath)
            entry: dict = {"networks": df["network"].dropna().tolist()}
            if is_asn:
                for col in ("org", "country_code"):
                    if col in df.columns:
                        val = df[col].dropna().iloc[0] if not df[col].dropna().empty else None
                        if val is not None:
                            entry[col] = str(val)
            result[stem] = entry
        except Exception as exc:
            import traceback
            print(f"ERROR reading {filepath}: {exc}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)

    return result


if __name__ == "__main__":
    print(json.dumps(get_networks()))