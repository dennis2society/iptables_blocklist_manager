#!/bin/sh
# Re-execute with bash if invoked via sh/dash or if bash is running in POSIX
# mode (which happens when bash is called as "sh").  Both cases disable
# arrays which this script requires.
# shellcheck disable=SC2128
if [ -z "${BASH_VERSION:-}" ] || shopt -oq posix 2>/dev/null; then
    exec bash "$0" "$@"
    printf 'ERROR: bash is required but was not found in PATH.\n' >&2
    exit 1
fi

# Guard against bash < 4.
if (( BASH_VERSINFO[0] < 4 )); then
    echo "ERROR: bash 4.0+ is required (found $BASH_VERSION). Please upgrade bash." >&2
    exit 1
fi

# This script uses ipset for high-performance IP/network blocklists.
# Each CSV file gets its own ipset hash:net set; a single iptables/ip6tables
# -m set --match-set rule per set replaces the per-CIDR rules used by
# update_iptables.sh.  Set contents are replaced atomically via a temp-set
# swap so packets are never matched against a partially-updated set.

set -uo pipefail

LOG_FILE="./qqxq_blocklist.log"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/get_networks_from_CSVs.py"
SET_PREFIX="bl_"
# Path to the Python virtual environment used to run get_networks_from_CSVs.py.
VENV_DIR="/home/wakko/venv"
# Path to the directory containing CSV blocklists.
#CSV_DIR="$SCRIPT_DIR/blocklist_csvs"
CSV_DIR="/home/wakko/htdocs/logwatch_tables/blocklist_csvs"
#CSV_DIR="/var/www/html/ip-lookup/logwatch_tables/blocklist_csvs"

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

Updates ipset sets and iptables/ip6tables DROP rules from CSV blocklists in
$CSV_DIR.  Each CSV file gets its own ipset hash:net set named bl_<stem>
(e.g. bl_RU_v4, bl_AS12389_v6).  A single iptables -m set --match-set rule
per set replaces the per-CIDR chain rules used by update_iptables.sh.  Set
contents are replaced atomically via a temp-set swap.

Options:
  --dry-run   Show what changes would be made without touching ipset or
              iptables.  Does not require root.
  --clear     Remove all bl_* ipsets and their iptables/ip6tables rules.
              Supports --dry-run --clear for a preview.
  --help      Show this help message and exit.

Configuration (edit at the top of this script):
  VENV_DIR    Path to the Python venv with pandas installed.
              Currently: $VENV_DIR
              Create:    python3 -m venv $VENV_DIR && $VENV_DIR/bin/pip install pandas
  CSV_DIR     Path to the blocklist CSV files directory.
              Currently: $CSV_DIR
  LOG_FILE    Log output destination.  Currently: $LOG_FILE
  SET_PREFIX  Prefix for all managed ipset names.  Currently: $SET_PREFIX

Examples:
  sudo $(basename "$0")               # apply all changes
  $(basename "$0") --dry-run          # preview without root
  sudo $(basename "$0") --clear       # remove all managed sets
  $(basename "$0") --dry-run --clear  # preview clear without root
EOF
}

# ---------------------------------------------------------------------------
# ipset_write / ipt_write – execute write commands, or log + skip in dry-run.
# Read-only commands (ipset list, iptables -C, etc.) must NOT use these.
# ---------------------------------------------------------------------------
ipset_write() {
    if [[ "$DRY_RUN" == true ]]; then
        log "[DRY-RUN] ipset $*"
        return 0
    fi
    ipset "$@"
}

ipt_write() {
    if [[ "$DRY_RUN" == true ]]; then
        log "[DRY-RUN] $*"
        return 0
    fi
    "$@"
}

# ---------------------------------------------------------------------------
# clear_all_blocklists – destroy every bl_* ipset and its iptables rules
# ---------------------------------------------------------------------------
clear_all_blocklists() {
    if [[ "$DRY_RUN" == true ]]; then
        log "[DRY-RUN] Would clear all bl_* ipsets and their iptables/ip6tables rules:"
    else
        log "Clearing all bl_* ipsets and their iptables/ip6tables rules..."
    fi

    mapfile -t _sets < <(ipset list -n 2>/dev/null | grep "^${SET_PREFIX}" || true)

    if [[ "${#_sets[@]}" -eq 0 ]]; then
        log "No ${SET_PREFIX}* sets found."
        return 0
    fi

    for setname in "${_sets[@]:-}"; do
        [[ -z "$setname" ]] && continue
        remove_set "$setname"
    done

    [[ "$DRY_RUN" != true ]] && log "All ${SET_PREFIX}* ipsets cleared."
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Build the ipset set name for a stem.
# ipset allows up to 31 characters; we cap at 27 to leave room for the "_tmp"
# suffix (4 chars) appended during atomic swaps.
make_set_name() {
    local name="${SET_PREFIX}${1}"
    printf '%s' "${name:0:27}"
}

# Return "iptables" for _v4 stems, "ip6tables" for _v6 stems.
get_ipt_cmd() {
    if [[ "$1" == *_v6 ]]; then
        echo "ip6tables"
    else
        echo "iptables"
    fi
}

# Return "inet6" for _v6 stems, "inet" otherwise.
get_family() {
    if [[ "$1" == *_v6 ]]; then
        echo "inet6"
    else
        echo "inet"
    fi
}

# Print the current members of an ipset (one CIDR per line).
# Returns nothing if the set does not exist.
get_set_networks() {
    local setname="$1"
    ipset list "$setname" 2>/dev/null \
        | awk '/^Members:/{found=1; next} found && NF{print $1}'
}

# Ensure the iptables -m set --match-set rule exists for a given hook.
ensure_iptables_rule() {
    local ipt="$1" hook="$2" setname="$3"
    if ! "$ipt" -C "$hook" -m set --match-set "$setname" src -j DROP 2>/dev/null; then
        ipt_write "$ipt" -I "$hook" -m set --match-set "$setname" src -j DROP
        [[ "$DRY_RUN" != true ]] && log "$ipt: Added $hook match-set rule for $setname"
    fi
}

# Atomically replace the contents of setname with the caller's `desired` array.
# The live set is created if it does not yet exist.
# A temp set <name>_tmp is used and always cleaned up.
# NOTE: Only call this in live (non-dry-run) mode.
atomic_update_set() {
    local setname="$1" family="$2"
    local tmpset="${setname}_tmp"

    # Remove any leftover temp set from a previous aborted run.
    ipset destroy "$tmpset" 2>/dev/null || true

    # Create and populate the temp set.
    ipset create "$tmpset" hash:net family "$family" hashsize 1024 maxelem 1048576
    for net in "${desired[@]:-}"; do
        [[ -z "$net" ]] && continue
        ipset add "$tmpset" "$net" || log_error "ipset: failed to add $net to $tmpset"
    done

    # Create the live set if it does not exist yet (swap requires both sides).
    if ! ipset list "$setname" &>/dev/null; then
        ipset create "$setname" hash:net family "$family" hashsize 1024 maxelem 1048576
        log "ipset: Created new set $setname"
    fi

    # Atomic swap: setname now has new content, tmpset has the old content.
    ipset swap "$tmpset" "$setname"

    # Discard the old content.
    ipset destroy "$tmpset"
}

# Remove all iptables/ip6tables rules for a set, then destroy the set.
# Uses ipset_write / ipt_write so it is dry-run aware.
remove_set() {
    local setname="$1"
    for ipt in iptables ip6tables; do
        for hook in INPUT FORWARD; do
            if "$ipt" -C "$hook" -m set --match-set "$setname" src -j DROP 2>/dev/null; then
                ipt_write "$ipt" -D "$hook" -m set --match-set "$setname" src -j DROP
                [[ "$DRY_RUN" != true ]] && log "$ipt: Removed $hook rule for $setname"
            fi
        done
    done
    ipset_write destroy "$setname"
    [[ "$DRY_RUN" != true ]] && log "ipset: Destroyed set $setname"
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
    if ! command -v ipset &>/dev/null; then
        log_error "Required command not found: ipset"
        log_error "Install with: apt-get install ipset  (Debian/Ubuntu)"
        exit 1
    fi
    # iptables/ip6tables are only needed when actually writing rules.
    if [[ "$DRY_RUN" != true ]]; then
        for _cmd in iptables ip6tables; do
            if ! command -v "$_cmd" &>/dev/null; then
                log_error "Required command not found: $_cmd"
                exit 1
            fi
        done
    fi

    # ---- Root is only required when actually writing rules -----------------
    if [[ "$DRY_RUN" != true && $EUID -ne 0 ]]; then
        log_error "Root is required to modify ipset/iptables rules. Run with sudo, or use --dry-run to preview."
        exit 1
    fi

    # ---- Handle --clear (supports --dry-run --clear) -----------------------
    if [[ "$do_clear" == true ]]; then
        clear_all_blocklists
        exit 0
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log "===== Starting blocklist dry-run (no ipset/iptables changes will be made) ====="
    else
        log "===== Starting blocklist update (ipset) ====="
    fi

    # Run Python script via the venv; stderr goes to the log file and
    # (for visibility) the terminal so parse errors are not silently buried.
    log "Running get_networks_from_CSVs.py from: $CSV_DIR"
    NETWORKS_JSON=$("$VENV_DIR/bin/python3" "$PYTHON_SCRIPT" "$CSV_DIR" 2> >(tee -a "$LOG_FILE" >&2)) || {
        log_error "Python script failed. Aborting."
        exit 1
    }

    # Collect all stems present in the JSON output.
    mapfile -t STEMS < <(echo "$NETWORKS_JSON" | jq -r 'keys[]')
    log "DEBUG: Python returned ${#STEMS[@]} stems; CSV dir has $(find "$CSV_DIR" -maxdepth 1 -name '*.csv' | wc -l) CSV files"

    # Build a flat list of expected set names for stale-set detection.
    # We scan the CSV directory on disk rather than relying on the Python JSON
    # keys so that a CSV which fails to parse never causes its existing ipset
    # to be falsely treated as stale and needlessly destroyed and re-created.
    declare -A expected_sets
    for _csv in "$CSV_DIR"/*.csv; do
        [[ -f "$_csv" ]] || continue
        _stem="$(basename "${_csv%.csv}")"
        [[ -z "$_stem" ]] && continue
        expected_sets["$(make_set_name "$_stem")"]=1
    done

    log "DEBUG: expected_sets has ${#expected_sets[@]} entries; Python returned ${#STEMS[@]} stems"

    # -----------------------------------------------------------------------
    # Remove (or report) sets whose CSV files have been deleted.
    # -----------------------------------------------------------------------
    mapfile -t _existing_sets < <(ipset list -n 2>/dev/null | grep "^${SET_PREFIX}" || true)
    for setname in "${_existing_sets[@]:-}"; do
        [[ -z "$setname" ]] && continue
        # Skip any leftover temp sets; they are cleaned up by atomic_update_set.
        [[ "$setname" == *_tmp ]] && continue
        if [[ -z "${expected_sets[$setname]+x}" ]]; then
            # Check if the backing CSV exists despite not being in expected_sets.
            _stale_csv="$CSV_DIR/${setname#${SET_PREFIX}}.csv"
            [[ -f "$_stale_csv" ]] && log "DEBUG: $setname flagged stale but CSV exists: $_stale_csv"
            if [[ "$DRY_RUN" == true ]]; then
                log "[DRY-RUN] Would remove stale set $setname (no corresponding CSV)"
            else
                log "Removing stale set $setname (no corresponding CSV)..."
                remove_set "$setname"
            fi
        fi
    done

    # -----------------------------------------------------------------------
    # Process each CSV stem.
    # -----------------------------------------------------------------------
    total_blocklists=0
    blocklists_with_changes=0

    for stem in "${STEMS[@]:-}"; do
        [[ -z "$stem" ]] && continue
        setname=$(make_set_name "$stem")
        ipt=$(get_ipt_cmd "$stem")
        family=$(get_family "$stem")

        total_blocklists=$((total_blocklists + 1))

        # Desired networks (from CSV via Python/jq).
        mapfile -t desired < <(echo "$NETWORKS_JSON" | jq -r --arg s "$stem" '.[$s].networks[]')
        # Current set members (empty if the set does not yet exist).
        mapfile -t current < <(get_set_networks "$setname")

        # Use sort+comm to compute additions and removals.
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

        # Count non-empty elements.
        added=0; removed=0
        for n in "${to_add[@]:-}";    do [[ -n "$n" ]] && added=$((added+1));    done
        for n in "${to_remove[@]:-}"; do [[ -n "$n" ]] && removed=$((removed+1)); done

        if [[ $added -gt 0 || $removed -gt 0 ]]; then
            blocklists_with_changes=$((blocklists_with_changes + 1))
            if [[ "$DRY_RUN" == true ]]; then
                log "[DRY-RUN] $stem ($setname): +$added to add / -$removed to remove"
            else
                # Atomically replace the set content, then ensure the iptables rules exist.
                atomic_update_set "$setname" "$family"
                ensure_iptables_rule "$ipt" INPUT   "$setname"
                ensure_iptables_rule "$ipt" FORWARD "$setname"
                log "  $stem ($setname): +$added added / -$removed removed"
            fi
        else
            # Content is up to date; still ensure the set and rules exist.
            if [[ "$DRY_RUN" != true ]]; then
                if ! ipset list "$setname" &>/dev/null; then
                    ipset create "$setname" hash:net family "$family" hashsize 1024 maxelem 1048576
                    log "ipset: Created empty set $setname (CSV has no networks)"
                fi
                ensure_iptables_rule "$ipt" INPUT   "$setname"
                ensure_iptables_rule "$ipt" FORWARD "$setname"
            fi
        fi
    done

    if [[ "$DRY_RUN" == true ]]; then
        log "===== Dry-run complete: $blocklists_with_changes of $total_blocklists blocklists have changes ====="
    else
        log "===== Blocklist update complete: $blocklists_with_changes of $total_blocklists blocklists updated ====="
    fi
}

main "$@"
