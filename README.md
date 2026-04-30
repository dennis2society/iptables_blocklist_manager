# IPTables Blocklist Manager

![Screenshot](screenshot.jpg)

This is a PHP web app to manage per country/ASN blocklists.
There is also a search form to test a list of IP addresses against local GeoIP databases
printing country, ASN and network range.
Supports MaxMind GeoLite2, iplocate.io, and ipinfo Lite databases.

## Features

- Manages per country/ASN blocklists for IPv4/6
- Query multiple GeoIP databases per IP
- Select networks to export by country and IP version (IPv4/IPv6)
- Generate presistent blocklists as separate CSV files per country code or ASN
- Deduplication: prevents duplicate entries when exporting or updating
- Locally cached network ranges per ASN list (offline generation using asn_cache_generator.py)
- manual/cron-controlled update of iptables rules after changes to the local blocklists

## Disclaimer

<b>This thing is mostly AI generated</b> by throwing a more or less sophisticated streak
of prompts at github copilot. Considering this, it works well enough for me because
  1. I run this locally and am only feeding it input I trust (my own server's Logwatch reports). 
  2. Would I trust this to run publicly exposed?
     Better not...

<b>Use with care! Better do not expose to public access!</b>

## Requirements

- PHP 8.0+ with `maxminddb` extension
- MMDB database files (MaxMind, iplocate.io, and/or ipinfo)
- Web server with write access to configured blocklist directory
- (Optional) bash 4.0+ and root/sudo for running iptables scripts

## Setup

### 1. Download and Configure MMDB Databases

**Download MMDB database files** (not all are necessary; the app will ignore missing DBs):
- **iplocate.io**: https://iplocate.io/ (Community/Premium, mmdb files available via github)
- **ipinfo Lite**: https://ipinfo.io/ (Requires registration)
- **MaxMind GeoLite2**: https://www.maxmind.com/en/products/geoip2/geolite2 (Commercial)

Place `.mmdb` files in the same directory as `index.php`.

### 2. Configure Paths and Services

Edit `config.php` to:
- Set database `'enabled'` flags (default: all enabled)
- Adjust blocklist CSV directory path (`blocklist_csvs_dir`)
- Specify correct MMDB file names if different from defaults

```php
'blocklist_csvs_dir' => __DIR__ . '/blocklist_csvs',
'databases' => [
    [
        'id'      => 'maxmind',
        'enabled' => true,   // Set to false to disable this service
        'databases' => [...]
    ],
    // ...
]
```

### 3. Create Blocklist Directory

Ensure the blocklist directory exists and is writable by the web server user:

```bash
mkdir -p blocklist_csvs
chmod 755 blocklist_csvs
```

For production deployments, see [blocklist_scripts/README.md](blocklist_scripts/README.md) for security recommendations.

## Usage

### Web Interface

1. Paste a "Fail2Ban hosts found:" section from Logwatch reports (or similar log data with IPs)
   - Supports formats with service/jail headers: `apache-d2s:`, `Logout/aborts:`, etc.
   - Automatically detects and tags IPs with their source service
2. View lookup results across enabled GeoIP databases
3. Select networks to block by checking checkboxes (one per row)
4. Click "Create/Update blocklist CSV" to save selections
5. CSV files are saved to configured blocklist directory as `{CC}_v4.csv` and `{CC}_v6.csv`

### Command-Line Tools

After updating blocklists, run scripts from `blocklist_scripts/` to apply rules:

```bash
cd blocklist_scripts/

# Get networks from CSVs (generates JSON output)
python3 get_networks_from_CSVs.py ../blocklist_csvs

# Update iptables rules (requires sudo)
sudo bash update_iptables.sh ../blocklist_csvs

# Count current rules
bash ipv4_count_rules.sh
bash ipv6_count_rules.sh
```

See [blocklist_scripts/README.md](blocklist_scripts/README.md) for detailed script documentation.

## CSV Format

```
network,added_at,country,asn,org,source
1.2.3.0/24,2026-04-24 12:00:00,China,AS4134,CHINANET-BACKBONE,maxmind
```

- **source**: Database used (maxmind, iplocate, ipinfo)
- Files append; existing CIDRs are skipped to prevent duplicates

