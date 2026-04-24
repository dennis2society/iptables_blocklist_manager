<?php
declare(strict_types=1);

session_start();

if (!extension_loaded('maxminddb')) {
    die('<p style="font-family:monospace;color:red">Error: PHP <code>maxminddb</code> extension not loaded.<br>'
      . 'Uncomment <code>extension=maxminddb.so</code> in <code>/etc/php/conf.d/maxminddb.ini</code> and restart the web server.</p>');
}

$DATA_DIR = __DIR__ . '/';
$MMDB_CONFIG = require __DIR__ . '/mmdb_config.php';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function h(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function countryFlag(string $code): string {
    if (strlen($code) !== 2) return '';
    $out = '';
    foreach (str_split(strtoupper($code)) as $c) {
        $out .= mb_chr(0x1F1E6 + ord($c) - ord('A'));
    }
    return $out;
}

// ─── IP extraction ────────────────────────────────────────────────────────────

function extractIPs(string $text): array {
    $ips  = [];
    $seen = [];

    // IPv4
    preg_match_all(
        '/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/',
        $text, $m
    );
    foreach ($m[0] as $ip) {
        if (!isset($seen[$ip]) && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $seen[$ip] = true;
            $ips[] = $ip;
        }
    }

    // IPv6 — broad match then validate; strip trailing single colon (not ::)
    preg_match_all(
        '/[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}/',
        $text, $m
    );
    foreach ($m[0] as $raw) {
        // Remove a trailing colon only if it is not preceded by another colon
        $ip = preg_replace('/(?<!:):$/', '', $raw);
        if (!isset($seen[$ip]) && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $seen[$ip] = true;
            $ips[] = $ip;
        }
    }

    return $ips;
}

// ─── Network helpers ────────────────────────────────────────────────────────────

function prefixToCidr(string $ip, int $prefix): string {
    $packed = inet_pton($ip);
    if ($packed === false) return '';
    $bytes = array_values(unpack('C*', $packed));
    $len   = count($bytes);
    for ($i = 0; $i < $len; $i++) {
        $bits = max(0, min(8, $prefix - $i * 8));
        $mask = $bits >= 8 ? 0xff : ($bits > 0 ? (0xff << (8 - $bits)) & 0xff : 0);
        $bytes[$i] &= $mask;
    }
    return inet_ntop(pack('C*', ...$bytes)) . '/' . $prefix;
}

// ─── Database lookups ─────────────────────────────────────────────────────────

function getAvailableSources(string $dataDir, array $mmdbConfig): array {
    $sources = [];
    foreach ($mmdbConfig as $service) {
        $allFilesExist = true;
        foreach ($service['databases'] as $db) {
            if (!file_exists($dataDir . $db['file'])) {
                $allFilesExist = false;
                break;
            }
        }
        if ($allFilesExist) {
            $sources[$service['id']] = true;
        }
    }
    return $sources;
}

function lookupAll(array $ips, string $dataDir, array $mmdbConfig, array $availableSources): array {
    $empty = ['cidr' => '', 'country' => '', 'country_code' => '', 'asn' => '', 'org' => ''];
    $out   = [];
    foreach ($ips as $ip) {
        $initialOut = [];
        foreach ($mmdbConfig as $service) {
            $initialOut[$service['id']] = $empty;
        }
        $out[$ip] = $initialOut;
    }

    foreach ($mmdbConfig as $service) {
        if (!($availableSources[$service['id']] ?? false)) continue;
        
        foreach ($service['databases'] as $db) {
            $path = $dataDir . $db['file'];
            if (!file_exists($path)) continue;
            $reader = new \MaxMind\Db\Reader($path);
            $src    = $service['id'];

            foreach ($ips as $ip) {
                try {
                    [$rec, $prefixLen] = $reader->getWithPrefixLen($ip);
                } catch (\Exception $e) {
                    continue;
                }
                if (!$rec) continue;

                switch ($db['type']) {
                case 'maxmind_country':
                    $out[$ip][$src]['country']      = $rec['country']['names']['en']
                        ?? $rec['registered_country']['names']['en'] ?? '';
                    $out[$ip][$src]['country_code'] = $rec['country']['iso_code']
                        ?? $rec['registered_country']['iso_code'] ?? '';
                    if ($prefixLen && empty($out[$ip][$src]['cidr']))
                        $out[$ip][$src]['cidr'] = prefixToCidr($ip, $prefixLen);
                    break;

                case 'maxmind_asn':
                    $out[$ip][$src]['asn'] = isset($rec['autonomous_system_number'])
                        ? 'AS' . $rec['autonomous_system_number'] : '';
                    $out[$ip][$src]['org'] = $rec['autonomous_system_organization'] ?? '';
                    if ($prefixLen)
                        $out[$ip][$src]['cidr'] = prefixToCidr($ip, $prefixLen);
                    break;

                case 'iplocate_country':
                    $out[$ip][$src]['country']      = $rec['country_name'] ?? '';
                    $out[$ip][$src]['country_code'] = $rec['country_code'] ?? '';
                    if ($prefixLen && empty($out[$ip][$src]['cidr']))
                        $out[$ip][$src]['cidr'] = prefixToCidr($ip, $prefixLen);
                    break;

                case 'iplocate_asn':
                    $out[$ip][$src]['asn'] = isset($rec['asn']) ? 'AS' . $rec['asn'] : '';
                    $out[$ip][$src]['org'] = $rec['org'] ?? ($rec['name'] ?? '');
                    if ($prefixLen)
                        $out[$ip][$src]['cidr'] = prefixToCidr($ip, $prefixLen);
                    break;

                case 'ipinfo':
                    $out[$ip][$src]['country']      = $rec['country'] ?? '';
                    $out[$ip][$src]['country_code'] = $rec['country_code'] ?? '';
                    $out[$ip][$src]['asn']          = $rec['asn'] ?? '';
                    $out[$ip][$src]['org']          = $rec['as_name'] ?? '';
                    if ($prefixLen)
                        $out[$ip][$src]['cidr'] = prefixToCidr($ip, $prefixLen);
                    break;
                }
            }
            $reader->close();
        }
    }

    return $out;
}

// ─── Scan ASNs (optionally filtered by country) ───────────────────────────────

// $countryCode: 2-letter ISO code to filter by, or '' to return all countries
function scanCountryASNs(string $countryCode, string $dataDir, array $mmdbConfig, array $availableSources): array {
    $asnNetworks = [];
    
    foreach ($mmdbConfig as $service) {
        if (!($availableSources[$service['id']] ?? false)) continue;
        
        // Get country and ASN database readers
        $countryDb = null;
        $asnDb = null;
        
        foreach ($service['databases'] as $db) {
            $path = $dataDir . $db['file'];
            if (!file_exists($path)) continue;
            
            if (in_array($db['type'], ['maxmind_country', 'iplocate_country', 'ipinfo'])) {
                try {
                    $countryDb = new \MaxMind\Db\Reader($path);
                } catch (\Exception $e) {
                    continue;
                }
            }
            if (in_array($db['type'], ['maxmind_asn', 'iplocate_asn', 'ipinfo'])) {
                try {
                    if ($asnDb) $asnDb->close();
                    $asnDb = new \MaxMind\Db\Reader($path);
                } catch (\Exception $e) {
                    continue;
                }
            }
        }
        
        if (!$countryDb || !$asnDb) continue;

        $extractCountry = function($rec, string $serviceId): array {
            switch ($serviceId) {
                case 'maxmind':
                    return [
                        $rec['country']['iso_code'] ?? $rec['registered_country']['iso_code'] ?? '',
                        $rec['country']['names']['en'] ?? $rec['registered_country']['names']['en'] ?? '',
                    ];
                case 'iplocate':
                    return [$rec['country_code'] ?? '', $rec['country_name'] ?? ''];
                case 'ipinfo':
                    return [$rec['country_code'] ?? '', $rec['country'] ?? ''];
                default:
                    return ['', ''];
            }
        };

        $extractASN = function($rec, string $serviceId): array {
            switch ($serviceId) {
                case 'maxmind':
                    return [
                        isset($rec['autonomous_system_number']) ? 'AS' . $rec['autonomous_system_number'] : '',
                        $rec['autonomous_system_organization'] ?? '',
                    ];
                case 'iplocate':
                    return [
                        isset($rec['asn']) ? 'AS' . $rec['asn'] : '',
                        $rec['org'] ?? ($rec['name'] ?? ''),
                    ];
                case 'ipinfo':
                    return [$rec['asn'] ?? '', $rec['as_name'] ?? ''];
                default:
                    return ['', ''];
            }
        };

        $processIp = function(string $ip) use (&$asnNetworks, $countryDb, $asnDb, $service, $countryCode, $extractCountry, $extractASN): void {
            try {
                [$countryRec] = $countryDb->getWithPrefixLen($ip);
                if (!$countryRec) return;

                [$cc, $countryName] = $extractCountry($countryRec, $service['id']);
                if ($countryCode !== '' && $cc !== $countryCode) return;

                [$asnRec, $asnPrefix] = $asnDb->getWithPrefixLen($ip);
                if (!$asnRec) return;

                [$asn, $org] = $extractASN($asnRec, $service['id']);
                if (!$asn) return;

                $cidr = $asnPrefix ? prefixToCidr($ip, $asnPrefix) : '';
                if (!$cidr) return;

                $key = $asn . '|' . $cidr . '|' . $service['id'];
                if (!isset($asnNetworks[$key])) {
                    $asnNetworks[$key] = [
                        'asn'          => $asn,
                        'org'          => $org,
                        'cidr'         => $cidr,
                        'ip_version'   => str_contains($cidr, ':') ? 'IPv6' : 'IPv4',
                        'source'       => $service['id'],
                        'country_code' => $cc,
                        'country'      => $countryName,
                    ];
                }
            } catch (\Exception $e) {
                // skip
            }
        };

        // Scan IPv4 space: sample /8 blocks
        for ($i = 1; $i <= 255; $i++) {
            for ($j = 0; $j <= 255; $j += 8) {
                $processIp("$i.$j.0.1");
                $processIp("$i.$j.128.1");
            }
        }
        
        // Scan IPv6 space: sample representative blocks
        $ipv6Ranges = [
            '2001:400::', '2001:4860::', '2401:4000::', '2600::', 
            '2603::', '2604::', '2605::', '2606::', '2607::', '2609::',
            '2620::', '2800::', '2803::', '2804::', '2805::', '2806::',
            '2a00::', '2a01::', '2a02::', '2a03::', '2a04::', '2a05::',
            '2a06::', '2a07::', '2a09::', '2a0b::', '2a0d::',
        ];
        foreach ($ipv6Ranges as $base) {
            for ($i = 0; $i < 5; $i++) {
                $processIp($base . dechex($i * 0x1000));
            }
        }
        
        $countryDb->close();
        $asnDb->close();
    }
    
    return $asnNetworks;
}

// ─── Request handling ──────────────────────────────────────────────────────────

$countryFilter   = '';
$asnFilter       = '';
$filteredResults = [];
$asnDetails      = [];
$showResults     = false;
$isPost          = ($_SERVER['REQUEST_METHOD'] === 'POST');
$availableSources = getAvailableSources($DATA_DIR, $MMDB_CONFIG);
$hasDatabases    = count($availableSources) > 0;

function buildUniqueASNs(array $asnNetworks): array {
    $uniqueASNs = [];
    foreach ($asnNetworks as $data) {
        $key = $data['asn'];
        if (!isset($uniqueASNs[$key])) {
            $uniqueASNs[$key] = [
                'asn'          => $data['asn'],
                'org'          => $data['org'],
                'country_code' => $data['country_code'],
                'country'      => $data['country'],
            ];
        }
    }
    uksort($uniqueASNs, fn($a, $b) => strnatcmp($a, $b));
    return array_values($uniqueASNs);
}

// Check if viewing ASN details (GET parameters)
if (isset($_GET['asn'])) {
    $countryFilter = strtoupper(preg_replace('/[^A-Za-z]/', '', $_GET['country'] ?? ''));
    $asnFilter     = strtoupper(preg_replace('/[^A-Z0-9]/', '', $_GET['asn']));
    
    if (strlen($asnFilter) >= 2 && $hasDatabases) {
        $asnNetworks = scanCountryASNs($countryFilter, $DATA_DIR, $MMDB_CONFIG, $availableSources);
        
        foreach ($asnNetworks as $data) {
            if ($data['asn'] === $asnFilter) {
                $asnDetails[] = $data;
            }
        }
        
        usort($asnDetails, function($a, $b) {
            $vCmp = strcmp($a['ip_version'], $b['ip_version']);
            if ($vCmp !== 0) return $vCmp;
            return strnatcmp($a['cidr'], $b['cidr']);
        });
    }
}
// Back button from ASN details, or GET-based country list
elseif (isset($_GET['country'])) {
    $countryFilter = strtoupper(preg_replace('/[^A-Za-z]/', '', $_GET['country']));
    
    if ($hasDatabases) {
        $asnNetworks   = scanCountryASNs($countryFilter, $DATA_DIR, $MMDB_CONFIG, $availableSources);
        $filteredResults = buildUniqueASNs($asnNetworks);
        $showResults   = true;
    }
}
// Main form submission
elseif ($isPost && isset($_POST['country_code'])) {
    $countryFilter = strtoupper(preg_replace('/[^A-Za-z]/', '', $_POST['country_code']));
    // PRG: redirect to GET so back button works without "document expired"
    header('Location: ' . $_SERVER['PHP_SELF'] . '?country=' . urlencode($countryFilter));
    exit;
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Country ASN Lookup</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<h1>Country ASN Lookup</h1>
<p><a href="index.php">← Back to IP Lookup</a></p>
<p>Find all ASNs (Autonomous System Numbers) and their associated network ranges for a given country.</p>

<?php if (!empty($_GET['asn'])): ?>
    <!-- ASN Details View -->
    <p><a href="?country=<?= h(urlencode($countryFilter)) ?>">← Back to <?= h($countryFilter) ?></a></p>
    
    <?php if (!$hasDatabases): ?>
        <p class="error-msg">Error: No GeoIP databases found.</p>
    <?php elseif (strlen($countryFilter) !== 2): ?>
        <p class="error-msg">Error: Invalid country code.</p>
    <?php elseif (empty($asnDetails)): ?>
        <p class="no-ips">No networks found for <?= h($asnFilter) ?> in <?= h($countryFilter) ?></p>
    <?php else: ?>
        <div class="table-controls">
            <span class="summary"><?= count(array_unique(array_map(fn($r) => $r['ip_version'], $asnDetails))) > 1 ? 'IPv4 and IPv6 networks' : (strpos($asnDetails[0]['ip_version'], 'IPv6') !== false ? 'IPv6 networks' : 'IPv4 networks') ?> for <?= h($asnFilter) ?> (<?= h($asnDetails[0]['org'] ?? 'Unknown') ?>)</span>
        </div>
        <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Network (CIDR)</th>
                    <th>IP Version</th>
                    <th>Source</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($asnDetails as $row): ?>
                <tr>
                    <td class="cidr"><code><?= h($row['cidr']) ?></code></td>
                    <td><?= h($row['ip_version']) ?></td>
                    <td><?= h($row['source']) ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>
    <?php endif; ?>

<?php else: ?>
    <!-- ASN List View -->
    <form method="post">
        <div class="form-row">
            <div class="form-left">
                <label for="country_code">Country Code (optional, e.g. CN, RU, US — leave blank to search all):</label>
                <input type="text" id="country_code" name="country_code" maxlength="2" 
                    placeholder="CN" value="<?= h($countryFilter) ?>" 
                    style="padding: 8px; font-size: 1em; margin-bottom: 1em; width: 100px;">
                <div class="form-left-btns">
                    <button type="submit">Look up ASNs</button>
                    <button type="button" id="clear-input-btn">Clear</button>
                </div>
            </div>
        </div>
    </form>

    <?php if ($showResults): ?>
    <?php if (!$hasDatabases): ?>
        <p class="error-msg">Error: No GeoIP databases found. Please upload the .mmdb files to the application directory.</p>
    <?php elseif (empty($filteredResults)): ?>
        <p class="no-ips">No ASNs found<?= $countryFilter ? ' for country code: ' . h($countryFilter) : '' ?>.</p>
    <?php else: ?>
        <div class="table-controls">
            <span class="summary"><?= count($filteredResults) ?> unique ASN<?= count($filteredResults) !== 1 ? 's' : '' ?> found<?= $countryFilter ? ' for ' . countryFlag($countryFilter) . '&nbsp;' . h($countryFilter) : ' (all countries)' ?></span>
            <input type="text" id="asn-search" placeholder="Filter by ASN or organization…" style="padding: 6px 10px; font-size: 0.95em; margin-left: 1em; width: 260px;">
            <span id="asn-filter-count" style="margin-left: 0.75em; color: #888;"></span>
        </div>
        <div class="table-wrap">
        <table id="asn-table">
            <thead>
                <tr>
                    <th>ASN</th>
                    <th>Organization</th>
                    <?php if (!$countryFilter): ?><th>Country</th><?php endif; ?>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($filteredResults as $row): ?>
                <tr>
                    <td class="asn"><a href="asn_view.php?asn=<?= h(urlencode($row['asn'])) ?>"><?= h($row['asn']) ?></a></td>
                    <td class="org"><?= h($row['org']) ?></td>
                    <?php if (!$countryFilter): ?><td><?= countryFlag($row['country_code']) ?>&nbsp;<?= h($row['country'] ?: $row['country_code']) ?></td><?php endif; ?>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>
    <?php endif; ?>
    <?php endif; ?>

<?php endif; ?>

<script>
document.getElementById('clear-input-btn')?.addEventListener('click', function() {
    window.location.href = 'country_asn_lookup.php';
});

(function () {
    const searchInput = document.getElementById('asn-search');
    if (!searchInput) return;

    const table   = document.getElementById('asn-table');
    const rows    = Array.from(table.querySelectorAll('tbody tr'));
    const counter = document.getElementById('asn-filter-count');

    // Fuzzy match: every character of `needle` must appear in `haystack` in order
    function fuzzyMatch(needle, haystack) {
        needle   = needle.toLowerCase();
        haystack = haystack.toLowerCase();
        // Fast path: substring match
        if (haystack.includes(needle)) return true;
        // Subsequence match
        let hi = 0;
        for (let ni = 0; ni < needle.length; ni++) {
            hi = haystack.indexOf(needle[ni], hi);
            if (hi === -1) return false;
            hi++;
        }
        return true;
    }

    searchInput.addEventListener('input', function () {
        const query = this.value.trim();
        let visible = 0;
        rows.forEach(row => {
            const asn = row.cells[0]?.textContent || '';
            const org = row.cells[1]?.textContent || '';
            const show = !query || fuzzyMatch(query, asn) || fuzzyMatch(query, org);
            row.style.display = show ? '' : 'none';
            if (show) visible++;
        });
        counter.textContent = query ? visible + ' of ' + rows.length + ' shown' : '';
    });
})();
</script>
</body>
</html>