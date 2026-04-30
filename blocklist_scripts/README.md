# Blocklist Scripts

This folder contains helper scripts for managing and applying IP blocklists via iptables.

## ⚠️ Security Notice

**This folder is protected from web browser access** by the `.htaccess` file, which denies all HTTP requests to this directory. Scripts here are designed to be executed from the terminal/command line only, not via the web and will require root permissions!

### Protection

- The `.htaccess` file blocks all web access to this folder
- All script file types (.py, .sh) are explicitly denied
- PHP execution is disabled

### Script Descriptions

- **`get_networks_from_CSVs.py`** - Parses CSV files and outputs network ranges as JSON
  - Usage: `python3 get_networks_from_CSVs.py [CSV_DIR]`
  - Default CSV directory: `../blocklist_csvs`

- **`update_iptables.sh`** - Applies network blocks to iptables rules
  - Usage: `sudo sh update_iptables.sh [CSV_DIR]`
  - Requires: bash 4.0+, root/sudo privileges

- **`ipv4_count_rules.sh`** - Counts IPv4 blocklist rules

- **`ipv6_count_rules.sh`** - Counts IPv6 blocklist rules

### Usage Example

```bash
# From terminal - web access is blocked by .htaccess
cd /var/www/html/$REPO/blocklist_scripts

# Get networks from CSVs
python3 get_networks_from_CSVs.py ../blocklist_csvs

# Update iptables (requires sudo)
sudo bash update_iptables.sh ../blocklist_csvs
```

### Why This Matters

- Scripts in this folder execute system commands (iptables modifications)
- The `.htaccess` file provides essential protection against unauthorized web access
- Terminal-only execution ensures proper user authentication and maintains audit logs
- This prevents accidental or malicious network rule changes via HTTP requests
