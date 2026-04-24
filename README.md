# logwatch_fail2ban_blocklist_generator

![Screenshot](screenshot.jpg)

A PHP web app for generating per-country, per-IP-version CSV blocklists by looking up IPs against local GeoIP databases. 
Supports MaxMind GeoLite2, iplocate.io, and ipinfo Lite databases.

## Features

- Query multiple GeoIP databases per IP
- Select networks to export by country and IP version (IPv4/IPv6)
- Generate blocklists as separate CSV files per country code
- Each CSV includes network, date added, country, ASN, organization, and source database
- Deduplication: prevents duplicate entries when exporting or re-exporting

## Disclaimer

I have not thoroughly tested this for security issues!
I am only running this on a local machine.
<b>Use with care! Do not expose to public access!</b>

## Requirements

- PHP 8.0+ with `maxminddb` extension
- MMDB database files (MaxMind, iplocate.io, or ipinfo)
- Web server with write access to `blocklist_csvs/` directory

## Setup

1. **Download MMDB database files manually:**
  (not all are necessary, app will ignore missing DBs)
   - iplocate.io: https://iplocate.io/
   - ipinfo Lite: https://ipinfo.io/
   - (Commercial) MaxMind GeoLite2: https://www.maxmind.com/en/products/geoip2/geolite2
2. Place `.mmdb` files in the same directory as `index.php`
3. Adjust file paths/names in `mmdb_config.php` if needed
4. Create the folder "blocklist_csvs/" and make sure is writable by the web server user

## Usage

1. Paste "Fail2Ban hosts found:" section from the Logwatch report in the input field
2. Select a result set by checking one checkbox per row
3. Click "Export to blocklist CSVs"
4. CSV files are saved to `blocklist_csvs/{CC}_v4.csv` and `blocklist_csvs/{CC}_v6.csv`

## CSV Format

```
network,added_at,country,asn,org,source
1.2.3.0/24,2026-04-24 12:00:00,China,AS4134,CHINANET-BACKBONE,maxmind
```

- **source**: Database used (maxmind, iplocate, ipinfo)
- Files append; existing CIDRs are skipped to prevent duplicates

