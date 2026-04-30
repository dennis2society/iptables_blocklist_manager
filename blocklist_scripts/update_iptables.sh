#!/bin/sh
# Re-execute with bash if invoked via sh/dash or if bash is running in POSIX
# mode (which happens when bash is called as "sh").  Both cases disable
# associative arrays which this script requires.
# shellcheck disable=SC2128
if [ -z "${BASH_VERSION:-}" ] || shopt -oq posix 2>/dev/null; then
    exec bash "$0" "$@"
    printf 'ERROR: bash is required but was not found in PATH.\n' >&2
    exit 1
fi

# From here on we are guaranteed to be running under non-POSIX bash.
# Guard against bash < 4 (associative arrays require bash 4+).
if (( BASH_VERSINFO[0] < 4 )); then
    echo "ERROR: bash 4.0+ is required (found $BASH_VERSION). Please upgrade bash." >&2
    exit 1
fi

# This script runs the get_networks_from_CSVs.py to get the latest IP addresses
# and then updates the iptables rules accordingly.
# Each CSV file shall have its own iptables blocklist, and the rules will be updated based on the contents of the CSV files.
# Add a function to clear all blocklists from iptables (IPv4 and IPv6).
# Do not double-add rules if they already exist, and ensure that the script can be run multiple times without causing issues.
# If a CSV file is removed, the corresponding iptables rules should also be removed.
# If an existing network block is removed from the CSV file, the corresponding iptables rule should also be removed.
# The script should be idempotent, meaning that running it multiple times should not cause duplicate rules or errors.
# The script should also handle both IPv4 and IPv6 addresses appropriately.
# The script should log its actions to a file for debugging purposes.
# The script should be run with appropriate permissions to modify iptables rules (e.g., as root or with sudo).
# The script should also handle any errors gracefully, such as issues with reading the CSV files or problems 
# with iptables commands, and log these errors for troubleshooting.
# An example rule for a non-country specific blocklist might look like this:
# sudo iptables -I droplist -s $IPRANGE -j DROP
# where droplist is the blocklist chain (replace that with the appropriate chain name for each CSV file), and $IPRANGE is the network range to block.

set -uo pipefail

LOG_FILE="./qqxq_blocklist.log"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/get_networks_from_CSVs.py"
CHAIN_PREFIX="bl_"
# Path to the Python virtual environment used to run get_networks_from_CSVs.py.
VENV_DIR="/home/wakko/venv"
# Path to the directory containing CSV blocklists.
#CSV_DIR="$SCRIPT_DIR/blocklist_csvs"
CSV_DIR="/home/wakko/htdocs/logwatch_tables/blocklist_csvs"

# DRY_RUN is set to true by --dry-run and checked throughout; declare it here
# so it is always defined even if main() is somehow not the entry point.
DRY_RUN=false

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" | tee -a "$LOG_FILE" >&2
}

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Updates iptables/ip6tables DROP rules from CSV blocklists in $CSV_DIR.
Each CSV file gets its own chain named bl_<stem> (e.g. bl_RU_v4, bl_AS12389_v6).
Chains are kept in sync with the CSVs: rules are added/removed as needed.

Options:
  --dry-run   Show what changes would be made without touching iptables.
              Does not require root.
  --clear     Remove all bl_* chains from iptables and ip6tables.
              Supports --dry-run --clear for a preview.
  --help      Show this help message and exit.

Configuration (edit at the top of this script):
  VENV_DIR    Path to the Python venv with pandas installed.
              Currently: $VENV_DIR
              Create:    python3 -m venv $VENV_DIR && $VENV_DIR/bin/pip install pandas
  CSV_DIR     Path to the blocklist CSV files directory.
              Currently: $CSV_DIR
  LOG_FILE    Log output destination.  Currently: $LOG_FILE
  CHAIN_PREFIX  Prefix for all managed chains.  Currently: $CHAIN_PREFIX

Examples:
  sudo $(basename "$0")               # apply all changes
  $(basename "$0") --dry-run          # preview without root
  sudo $(basename "$0") --clear       # remove all managed chains
  $(basename "$0") --dry-run --clear  # preview clear without root
EOF
}

# ---------------------------------------------------------------------------
# ipt_write – execute an iptables write command, or log + skip in dry-run.
# Read-only iptables commands (-S, -C, -L) must NOT go through this helper.
# ---------------------------------------------------------------------------
ipt_write() {
    if [[ "$DRY_RUN" == true ]]; then
        log "[DRY-RUN] $*"
        return 0
    fi
    "$@"
}

# ---------------------------------------------------------------------------
# clear_all_blocklists  – remove every bl_* chain from iptables and ip6tables
# ---------------------------------------------------------------------------
clear_all_blocklists() {
    if [[ "$DRY_RUN" == true ]]; then
        log "[DRY-RUN] Would clear all blocklists from iptables and ip6tables:"
    else
        log "Clearing all blocklists from iptables and ip6tables..."
    fi

    for ipt in iptables ip6tables; do
        mapfile -t _chains < <("$ipt" -S 2>/dev/null | grep "^-N ${CHAIN_PREFIX}" | awk '{print $2}')
        for chain in "${_chains[@]:-}"; do
            [[ -z "$chain" ]] && continue
            for hook in INPUT FORWARD; do
                if "$ipt" -C "$hook" -j "$chain" 2>/dev/null; then
                    ipt_write "$ipt" -D "$hook" -j "$chain"
                    [[ "$DRY_RUN" != true ]] && log "$ipt: Removed jump $hook -> $chain"
                fi
            done
            ipt_write "$ipt" -F "$chain"
            ipt_write "$ipt" -X "$chain"
            [[ "$DRY_RUN" != true ]] && log "$ipt: Deleted chain $chain"
        done
    done

    [[ "$DRY_RUN" != true ]] && log "All blocklists cleared."
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Sanitize a string for use as a segment in an iptables chain name:
# replace non-alphanumeric runs with a single _, strip leading/trailing _.
sanitize_chain_seg() {
    printf '%s' "$1" | tr -cs 'a-zA-Z0-9' '_' | sed 's/__*/_/g; s/^_*//; s/_*$//'
}

# Build the full chain name for a stem.
# For ASN stems (AS*) the org name and country_code from NETWORKS_JSON are
# appended, truncated so the total stays within the 28-char iptables limit.
make_chain_name() {
    local stem="$1"
    if [[ "$stem" != AS* ]]; then
        printf '%s' "${CHAIN_PREFIX}${stem}"
        return
    fi
    local org cc org_s cc_s budget
    org=$(printf '%s' "$NETWORKS_JSON" | jq -r --arg s "$stem" '.[$s].org // ""')
    cc=$(printf '%s'  "$NETWORKS_JSON" | jq -r --arg s "$stem" '.[$s].country_code // ""')
    org_s=$(sanitize_chain_seg "$org")
    cc_s=$(sanitize_chain_seg "$cc")
    if [[ -n "$org_s" && -n "$cc_s" ]]; then
        # Budget chars available for org_s: 28 - prefix - stem - 2 separators - cc
        budget=$(( 28 - ${#CHAIN_PREFIX} - ${#stem} - 2 - ${#cc_s} ))
        (( budget < 0 )) && budget=0
        org_s="${org_s:0:$budget}"
        if [[ -n "$org_s" ]]; then
            printf '%s' "${CHAIN_PREFIX}${stem}_${org_s}_${cc_s}"
        else
            printf '%s' "${CHAIN_PREFIX}${stem}_${cc_s}"
        fi
    elif [[ -n "$org_s" ]]; then
        budget=$(( 28 - ${#CHAIN_PREFIX} - ${#stem} - 1 ))
        printf '%s' "${CHAIN_PREFIX}${stem}_${org_s:0:$budget}"
    elif [[ -n "$cc_s" ]]; then
        budget=$(( 28 - ${#CHAIN_PREFIX} - ${#stem} - 1 ))
        printf '%s' "${CHAIN_PREFIX}${stem}_${cc_s:0:$budget}"
    else
        printf '%s' "${CHAIN_PREFIX}${stem}"
    fi
}

# Return "iptables" for _v4 stems, "ip6tables" for _v6 stems.
get_ipt_cmd() {
    if [[ "$1" == *_v6 ]]; then
        echo "ip6tables"
    else
        echo "iptables"
    fi
}

# Create a chain if it does not yet exist.
ensure_chain() {
    local ipt="$1" chain="$2"
    if ! "$ipt" -S "$chain" &>/dev/null; then
        ipt_write "$ipt" -N "$chain"
        [[ "$DRY_RUN" != true ]] && log "$ipt: Created chain $chain"
    fi
}

# Insert a jump rule into hook if one does not already exist.
ensure_jump() {
    local ipt="$1" hook="$2" chain="$3"
    if ! "$ipt" -C "$hook" -j "$chain" 2>/dev/null; then
        ipt_write "$ipt" -I "$hook" -j "$chain"
        [[ "$DRY_RUN" != true ]] && log "$ipt: Added jump $hook -> $chain"
    fi
}

# Print every source network currently in a chain (one per line).
get_chain_networks() {
    local ipt="$1" chain="$2"
    "$ipt" -S "$chain" 2>/dev/null \
        | grep "^-A ${chain} " \
        | sed -n 's/.*-s \([^ ]*\).*/\1/p'
}

# Flush jump rules from INPUT/FORWARD, then flush and delete the chain.
remove_chain() {
    local ipt="$1" chain="$2"
    for hook in INPUT FORWARD; do
        if "$ipt" -C "$hook" -j "$chain" 2>/dev/null; then
            ipt_write "$ipt" -D "$hook" -j "$chain"
            [[ "$DRY_RUN" != true ]] && log "$ipt: Removed jump $hook -> $chain"
        fi
    done
    ipt_write "$ipt" -F "$chain"
    ipt_write "$ipt" -X "$chain"
    [[ "$DRY_RUN" != true ]] && log "$ipt: Deleted chain $chain"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    # ---- Parse flags -------------------------------------------------------
    local do_clear=false
    for arg in "$@"; do
        case "$arg" in
            --dry-run) DRY_RUN=true ;;
            --clear)   do_clear=true ;;
            --help|-h) usage; exit 0 ;;
            *) echo "ERROR: Unknown option: $arg" >&2; usage >&2; exit 1 ;;
        esac
    done

    # ---- Prerequisite checks (after flag parsing so --help always works) ---
    if [[ ! -x "$VENV_DIR/bin/python3" ]]; then
        log_error "Python venv not found at $VENV_DIR."
        log_error "Create it with: python3 -m venv $VENV_DIR && $VENV_DIR/bin/pip install pandas"
        exit 1
    fi
    if ! command -v jq &>/dev/null; then
        log_error "Required command not found: jq"
        exit 1
    fi
    # iptables/ip6tables are only needed when actually applying rules.
    if [[ "$DRY_RUN" != true ]]; then
        for _cmd in iptables ip6tables; do
            if ! command -v "$_cmd" &>/dev/null; then
                log_error "Required command not found: $_cmd"
                exit 1
            fi
        done
    fi

    # ---- Root is only required when actually writing iptables rules --------
    if [[ "$DRY_RUN" != true && $EUID -ne 0 ]]; then
        log_error "Root is required to modify iptables rules. Run with sudo, or use --dry-run to preview."
        exit 1
    fi

    # ---- Handle --clear (supports --dry-run --clear) -----------------------
    if [[ "$do_clear" == true ]]; then
        clear_all_blocklists
        exit 0
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log "===== Starting blocklist dry-run (no iptables changes will be made) ====="
    else
        log "===== Starting blocklist update ====="
    fi

    # Run Python script via the venv; stderr goes straight to the log file.
    log "Running get_networks_from_CSVs.py from: $CSV_DIR"
    NETWORKS_JSON=$("$VENV_DIR/bin/python3" "$PYTHON_SCRIPT" "$CSV_DIR" 2>>"$LOG_FILE") || {
        log_error "Python script failed. Aborting."
        exit 1
    }

    # Collect all stems present in the JSON output.
    mapfile -t STEMS < <(echo "$NETWORKS_JSON" | jq -r 'keys[]')

    # Build lists of expected chains for iptables (v4) and ip6tables (v6).
    # Plain indexed arrays avoid any declare -A compatibility issues.
    expected_ipt=()   # chains expected in iptables  (v4)
    expected_ip6t=()  # chains expected in ip6tables (v6)

    for stem in "${STEMS[@]:-}"; do
        [[ -z "$stem" ]] && continue
        chain=$(make_chain_name "$stem")
        if [[ "$stem" == *_v6 ]]; then
            expected_ip6t+=("$chain")
        else
            expected_ipt+=("$chain")
        fi
    done

    # Helper: returns 0 if $1 appears in the array passed as subsequent args.
    _in_array() { local needle="$1"; shift; printf '%s\n' "$@" | grep -qxF "$needle"; }

    # -----------------------------------------------------------------------
    # Remove (or report) chains whose CSV files have been deleted.
    # -----------------------------------------------------------------------
    mapfile -t _existing_ipt < <(iptables -S 2>/dev/null | grep "^-N ${CHAIN_PREFIX}" | awk '{print $2}')
    for chain in "${_existing_ipt[@]:-}"; do
        [[ -z "$chain" ]] && continue
        if ! _in_array "$chain" "${expected_ipt[@]:-}"; then
            log "iptables: $chain has no CSV – removing..."
            remove_chain iptables "$chain"
        fi
    done

    mapfile -t _existing_ip6t < <(ip6tables -S 2>/dev/null | grep "^-N ${CHAIN_PREFIX}" | awk '{print $2}')
    for chain in "${_existing_ip6t[@]:-}"; do
        [[ -z "$chain" ]] && continue
        if ! _in_array "$chain" "${expected_ip6t[@]:-}"; then
            log "ip6tables: $chain has no CSV – removing..."
            remove_chain ip6tables "$chain"
        fi
    done

    # -----------------------------------------------------------------------
    # Process each CSV stem.
    # -----------------------------------------------------------------------
    total_blocklists=0
    blocklists_with_changes=0

    for stem in "${STEMS[@]:-}"; do
        [[ -z "$stem" ]] && continue
        chain=$(make_chain_name "$stem")
        ipt=$(get_ipt_cmd "$stem")

        total_blocklists=$((total_blocklists + 1))

        ensure_chain "$ipt" "$chain"
        ensure_jump  "$ipt" INPUT   "$chain"
        ensure_jump  "$ipt" FORWARD "$chain"

        # Desired networks (from CSV via Python/jq).
        mapfile -t desired < <(echo "$NETWORKS_JSON" | jq -r --arg s "$stem" '.[$s].networks[]')
        # Networks currently in the chain (empty in dry-run if chain is new).
        mapfile -t current < <(get_chain_networks "$ipt" "$chain")

        # Use sort+comm to compute additions and removals without associative arrays.
        # comm -23: lines only in desired (to add); comm -13: lines only in current (to remove).
        mapfile -t to_add < <(
            comm -23 \
                <(printf '%s\n' "${desired[@]:-}" | grep -v '^$' | sort) \
                <(printf '%s\n' "${current[@]:-}" | grep -v '^$' | sort)
        )
        mapfile -t to_remove < <(
            comm -13 \
                <(printf '%s\n' "${desired[@]:-}" | grep -v '^$' | sort) \
                <(printf '%s\n' "${current[@]:-}" | grep -v '^$' | sort)
        )

        # Add rules for networks not yet in the chain.
        added=0
        for net in "${to_add[@]:-}"; do
            [[ -z "$net" ]] && continue
            if ipt_write "$ipt" -I "$chain" -s "$net" -j DROP; then
                added=$((added + 1))
            else
                log_error "$ipt: failed to add $net to $chain"
            fi
        done

        # Remove rules for networks no longer in the CSV.
        removed=0
        for net in "${to_remove[@]:-}"; do
            [[ -z "$net" ]] && continue
            if ipt_write "$ipt" -D "$chain" -s "$net" -j DROP; then
                removed=$((removed + 1))
            else
                log_error "$ipt: failed to remove $net from $chain"
            fi
        done

        # Only log if there were changes to this blocklist.
        if [[ $added -gt 0 || $removed -gt 0 ]]; then
            blocklists_with_changes=$((blocklists_with_changes + 1))
            local dr_tag=""
            [[ "$DRY_RUN" == true ]] && dr_tag="[DRY-RUN] "
            log "  ${dr_tag}$stem: +$added to add / -$removed to remove"
        fi
    done

    if [[ "$DRY_RUN" == true ]]; then
        log "===== Dry-run complete: $blocklists_with_changes of $total_blocklists blocklists have changes ====="
    else
        log "===== Blocklist update complete: $blocklists_with_changes of $total_blocklists blocklists updated ====="
    fi
}

main "$@"
