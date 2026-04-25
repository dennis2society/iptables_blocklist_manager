<?php
declare(strict_types=1);

session_start();

if (!extension_loaded('maxminddb')) {
    die('<p style="font-family:monospace;color:red">Error: PHP <code>maxminddb</code> extension not loaded.<br>'
      . 'Uncomment <code>extension=maxminddb.so</code> in <code>/etc/php/conf.d/maxminddb.ini</code> and restart the web server.</p>');
}

$DATA_DIR = __DIR__ . '/';
$MMDB_CONFIG = require __DIR__ . '/mmdb_config.php';

// Handle database enable/disable toggles
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['toggle_service'])) {
    $serviceId = $_POST['toggle_service'];
    if (!isset($_SESSION['service_enabled'])) {
        $_SESSION['service_enabled'] = [];
    }
    $_SESSION['service_enabled'][$serviceId] = !($_SESSION['service_enabled'][$serviceId] ?? true);
}

// ─── CSV blocklist export ─────────────────────────────────────────────────────

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['export_blocklist'])) {
    $csvDir = __DIR__ . '/blocklist_csvs';
    if (!is_dir($csvDir) && !mkdir($csvDir, 0755, true)) {
        http_response_code(500);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Cannot create blocklist_csvs directory']);
        exit;
    }

    $raw     = json_decode($_POST['export_blocklist'], true) ?? [];
    $written = 0;
    $skipped = 0;

    // Validate and group entries by country code
    $grouped = [];
    foreach ($raw as $entry) {
        $cidr        = trim($entry['cidr']        ?? '');
        $countryCode = strtoupper(preg_replace('/[^A-Za-z]/', '', $entry['country_code'] ?? ''));
        $country     = trim($entry['country']     ?? '');
        $asn         = trim($entry['asn']         ?? '');
        $org         = trim($entry['org']         ?? '');

        $source      = preg_replace('/[^A-Za-z0-9_\-]/', '', $entry['source'] ?? '');

        if (!preg_match('#^[0-9a-fA-F:.]+/\d{1,3}$#', $cidr)) continue;
        if (strlen($countryCode) !== 2) continue;

        $ipVersion = str_contains($cidr, ':') ? 'v6' : 'v4';
        $groupKey  = $countryCode . '_' . $ipVersion;

        $grouped[$groupKey][] = [
            'cidr'    => $cidr,
            'country' => $country,
            'asn'     => $asn,
            'comment' => $org,
            'source'  => $source,
        ];
    }

    // Process one file per country+version — load existing CIDRs once, then append new ones
    foreach ($grouped as $groupKey => $rows) {
        $file        = $csvDir . '/' . $groupKey . '.csv';
        $needsHeader = !file_exists($file);

        // Load all existing CIDRs for this file
        $existing = [];
        if (!$needsHeader) {
            $fh = fopen($file, 'r');
            if ($fh) {
                fgetcsv($fh); // skip header row
                while (($row = fgetcsv($fh)) !== false) {
                    if (isset($row[0])) $existing[$row[0]] = true;
                }
                fclose($fh);
            }
        }

        $fh = fopen($file, 'a');
        if (!$fh) continue;
        if ($needsHeader) fputcsv($fh, ['network', 'added_at', 'country', 'asn', 'org', 'source']);

        foreach ($rows as $r) {
            if (isset($existing[$r['cidr']])) { $skipped++; continue; }
            fputcsv($fh, [
                escapeCsvFormula($r['cidr']),
                date('Y-m-d H:i:s'),
                escapeCsvFormula($r['country']),
                escapeCsvFormula($r['asn']),
                escapeCsvFormula($r['comment']),
                escapeCsvFormula($r['source'])
            ]);
            $existing[$r['cidr']] = true; // prevent within-batch duplicates
            $written++;
        }
        fclose($fh);
    }

    header('Content-Type: application/json');
    echo json_encode(['written' => $written, 'skipped' => $skipped]);
    exit;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function h(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function escapeCsvFormula(string $s): string {
    // Prevent CSV injection by prefixing formula-like content with single quote
    if (strlen($s) > 0 && in_array($s[0], ['=', '+', '-', '@'], true)) {
        return "'" . $s;
    }
    return $s;
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

    // For each found IP, sum up any "( N Times)" occurrences in the text
    $counts = [];
    foreach ($seen as $ip => $_) {
        $pat = '/' . preg_quote($ip, '/') . '\s*\(\s*(\d+)\s+Times?\)/i';
        if (preg_match_all($pat, $text, $cm)) {
            $counts[$ip] = array_sum(array_map('intval', $cm[1]));
        }
    }

    return [$ips, $counts];
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

function cidrToRange(string $cidr): array {
    if ($cidr === '') return ['', ''];
    $parts = explode('/', $cidr, 2);
    if (count($parts) !== 2) return ['', ''];
    [$ip, $pfxStr] = $parts;
    $prefix = (int)$pfxStr;
    $packed = inet_pton($ip);
    if ($packed === false) return ['', ''];
    $len   = strlen($packed);
    $bytes = array_values(unpack('C*', $packed));
    // Start: mask off host bits
    $start = $bytes;
    for ($i = 0; $i < $len; $i++) {
        $bits = max(0, min(8, $prefix - $i * 8));
        $mask = $bits >= 8 ? 0xff : ($bits > 0 ? (0xff << (8 - $bits)) & 0xff : 0);
        $start[$i] &= $mask;
    }
    // End: OR in host bits
    $end = $start;
    for ($i = 0; $i < $len; $i++) {
        $bits = max(0, min(8, $prefix - $i * 8));
        $mask = $bits >= 8 ? 0xff : ($bits > 0 ? (0xff << (8 - $bits)) & 0xff : 0);
        $end[$i] |= (~$mask & 0xff);
    }
    return [
        inet_ntop(pack('C*', ...$start)) ?: '',
        inet_ntop(pack('C*', ...$end))   ?: '',
    ];
}

// ─── Database lookups ─────────────────────────────────────────────────────────

function getAvailableSources(string $dataDir, array $mmdbConfig, array $sessionServiceEnabled = []): array {
    $sources = [];
    foreach ($mmdbConfig as $service) {
        $isEnabled = $sessionServiceEnabled[$service['id']] ?? true; // default enabled
        if (!$isEnabled) continue;
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

function lookupAll(array $ips, string $dataDir, array $mmdbConfig, array $availableSources, array $sessionServiceEnabled = []): array {
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
        $isEnabled = $sessionServiceEnabled[$service['id']] ?? true; // default enabled
        if (!$isEnabled || !($availableSources[$service['id']] ?? false)) continue;
        
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
        }
        $reader->close();
    }

    return $out;
}

// ─── Request ──────────────────────────────────────────────────────────────────

$inputText = '';
$ips       = [];
$counts    = [];
$results   = [];
$isPost    = ($_SERVER['REQUEST_METHOD'] === 'POST');
$isRestore = (!$isPost && isset($_GET['restore']) && !empty($_SESSION['last_input_text'] ?? ''));
$isIpLookup = (!$isPost && !$isRestore && isset($_GET['ip']));
$sessionServiceEnabled = $_SESSION['service_enabled'] ?? [];
$availableSources = getAvailableSources($DATA_DIR, $MMDB_CONFIG, $sessionServiceEnabled);
$hasDatabases = count($availableSources) > 0;

if ($isPost) {
    // If iptext is in POST (main form submission), use it; otherwise restore from session
    if (isset($_POST['iptext'])) {
        $inputText = substr($_POST['iptext'], 0, 500_000);
        $_SESSION['last_input_text'] = $inputText;  // Store in session for persistence across toggling
    } else {
        $inputText = $_SESSION['last_input_text'] ?? '';
    }
    
    if (!isset($_POST['toggle_service'])) {
        [$ips, $counts] = extractIPs($inputText);
        if ($ips && $hasDatabases) {
            $results = lookupAll($ips, $DATA_DIR, $MMDB_CONFIG, $availableSources, $sessionServiceEnabled);
        }
    }
} elseif ($isRestore) {
    $inputText = $_SESSION['last_input_text'];
    [$ips, $counts] = extractIPs($inputText);
    if ($ips && $hasDatabases) {
        $results = lookupAll($ips, $DATA_DIR, $MMDB_CONFIG, $availableSources, $sessionServiceEnabled);
    }
} elseif ($isIpLookup) {
    // Accept a single IP or CIDR network address passed via ?ip=
    $rawIp = substr($_GET['ip'], 0, 64);
    // Allow only characters valid in an IP address or CIDR
    $inputText = preg_replace('#[^0-9a-fA-F.:/]#', '', $rawIp);
    if ($inputText !== '') {
        $_SESSION['last_input_text'] = $inputText;
        [$ips, $counts] = extractIPs($inputText);
        if ($ips && $hasDatabases) {
            $results = lookupAll($ips, $DATA_DIR, $MMDB_CONFIG, $availableSources, $sessionServiceEnabled);
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IP Lookup</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<h1>IP Lookup</h1>
<p><a href="asn_view.php">ASN Network Lookup →</a></p>

<form method="post">
    <div class="form-row">
        <div class="form-left">
            <label for="iptext">Paste text containing IP addresses (Fail2Ban, Logwatch, logs, …):</label>
            <textarea id="iptext" name="iptext"
                placeholder="Fail2Ban hosts found:&#10;   apache-multi-404:&#10;      1.2.3.4    (  5 Times)&#10;      ..."><?= h($inputText) ?></textarea>
            <div class="form-left-btns">
                <button type="submit">Look up IPs</button>
                <button type="button" id="clear-input-btn">Clear input</button>
            </div>
        </div>
        <div class="form-right">
            <label for="net-list">Selected For Blocklist:</label>
            <textarea id="net-list" readonly placeholder="Check networks in the table below to mark for blocklist"></textarea>
            <div class="form-right-btns">
                <button type="button" id="clear-list-btn">Clear selected networks</button>
            </div>
        </div>
    </div>
</form>

<div class="db-controls">
    <h2>Database Selection</h2>
    <div class="db-list">
        <?php foreach ($MMDB_CONFIG as $service):
            $isEnabled = $sessionServiceEnabled[$service['id']] ?? true;
            $allFilesExist = true;
            foreach ($service['databases'] as $db) {
                if (!file_exists($DATA_DIR . $db['file'])) {
                    $allFilesExist = false;
                    break;
                }
            }
            $isDisabled = !$allFilesExist;
        ?>
            <form method="post" class="db-toggle-form">
                <button type="submit" name="toggle_service" value="<?= h($service['id']) ?>" 
                    class="db-toggle <?= $isEnabled ? 'enabled' : 'disabled' ?><?= $isDisabled ? ' unavailable' : '' ?>"
                    <?= $isDisabled ? 'disabled' : '' ?> title="<?= $isDisabled ? 'Missing database files for ' . h($service['label']) : '' ?>">
                    <span class="db-toggle-icon"><?= $isEnabled && !$isDisabled ? '✓' : '✕' ?></span>
                    <span class="db-toggle-label"><?= h($service['label']) ?></span>
                    <?php if (!$allFilesExist): ?><span class="db-toggle-status">(incomplete)</span><?php endif; ?>
                </button>
            </form>
        <?php endforeach; ?>
    </div>
</div>

<?php if ($isPost || $isRestore || $isIpLookup): ?>
<?php if (!$hasDatabases): ?>
    <p class="error-msg">Error: No GeoIP databases found. Please upload the .mmdb files (GeoLite2-Country.mmdb, GeoLite2-ASN.mmdb, ip-to-country.mmdb, ip-to-asn.mmdb, ipinfo_lite.mmdb) to the application directory.</p>
<?php elseif (empty($ips)): ?>
    <p class="no-ips">No IP addresses found in the input.</p>
<?php else: ?>
    <div class="table-controls">
        <span class="summary"><?= count($ips) ?> unique IP address<?= count($ips) !== 1 ? 'es' : '' ?> found.</span>
        <button id="sort-reset" type="button">Reset sort</button>
        <button id="toggle-ranges-btn" type="button">▶ Show IP ranges</button>
        <button id="export-csv-btn" type="button" >Create/Update blocklist CSV</button>
        <span id="export-msg" class="export-msg"></span>
    </div>
    <div class="table-wrap">
    <table>
        <thead>
            <tr>
                <th rowspan="2" class="row-num-col">#</th>
                <th rowspan="2" class="sortable" data-col="ip">IP Address</th>
                <th rowspan="2" class="sortable" data-col="count">#</th>
                <?php foreach ($MMDB_CONFIG as $i => $service):
                    if (!($availableSources[$service['id']] ?? false)) continue;
                    $sep = $i > 0 ? ' src-sep' : '';
                ?>
                <th colspan="4" data-src-hdr="1"<?= $sep ? ' class="' . $sep . '"' : '' ?>><?= h($service['label']) ?></th>
                <?php endforeach; ?>
            </tr>
            <tr>
                <?php foreach ($MMDB_CONFIG as $i => $service):
                    if (!($availableSources[$service['id']] ?? false)) continue;
                    $sep = $i > 0 ? ' src-sep' : '';
                ?>
                <th class="sortable<?= $sep ? ' ' . $sep : '' ?>" data-col="<?= h($service['id']) ?>-cidr">Network</th>
                <th class="range-col">Start IP – End IP</th>
                <th class="sortable" data-col="<?= h($service['id']) ?>-country">Country</th>
                <th class="sortable" data-col="<?= h($service['id']) ?>-asn">ASN</th>
                <th class="sortable" data-col="<?= h($service['id']) ?>-org">Org / ISP</th>
                <?php endforeach; ?>
            </tr>
        </thead>
        <tbody id="main-tbody">
        <?php foreach ($ips as $idx => $ip):
            $d = $results[$ip];
        ?>
            <tr data-index="<?= $idx ?>"
                data-ip="<?= h($ip) ?>"
                data-count="<?= (int)($counts[$ip] ?? 0) ?>"
                <?php foreach ($MMDB_CONFIG as $service):
                    if (!($availableSources[$service['id']] ?? false)) continue;
                ?>data-<?= h($service['id']) ?>-cidr="<?= h($d[$service['id']]['cidr']) ?>"
                data-<?= h($service['id']) ?>-country="<?= h($d[$service['id']]['country']) ?>"
                data-<?= h($service['id']) ?>-country-code="<?= h($d[$service['id']]['country_code']) ?>"
                data-<?= h($service['id']) ?>-asn="<?= h($d[$service['id']]['asn']) ?>"
                data-<?= h($service['id']) ?>-org="<?= h($d[$service['id']]['org']) ?>"
                <?php endforeach; ?>>
                <td class="row-num-col row-num"></td>
                <td class="ip"><code><a href="https://ipinfo.io/<?= h(rawurlencode($ip)) ?>" target="_blank" rel="noopener noreferrer"><?= h($ip) ?></a></code></td>
                <td class="count-col"><?= !empty($counts[$ip]) ? (int)$counts[$ip] : '' ?></td>
                <?php $srcOrder = array_keys(array_filter($availableSources)); foreach ($srcOrder as $i => $serviceId):
                    $service = null;
                    foreach ($MMDB_CONFIG as $svc) {
                        if ($svc['id'] === $serviceId) { $service = $svc; break; }
                    }
                    if (!$service) continue;
                    $s    = $d[$service['id']];
                    $flag = countryFlag($s['country_code']);
                    $cc   = $s['country_code'] ? ' [' . h($s['country_code']) . ']' : '';
                    $disp = $flag ? $flag . '&nbsp;' . h($s['country']) . $cc : h($s['country']) . $cc;
                    $sep  = $i > 0 ? ' src-sep' : '';
                ?>
                <td class="cidr<?= $sep ?>" title="<?= h($s['cidr']) ?>"><?php if ($s['cidr']): ?><label class="cidr-label"><input type="checkbox" class="net-cb" data-src="<?= h($service['id']) ?>"><?= h($s['cidr']) ?></label><?php endif; ?></td>
                <?php [$rStart, $rEnd] = cidrToRange($s['cidr']); ?>
                <td class="range-col"><?php if ($rStart !== ''): ?><code><?= h($rStart) ?></code><br><code><?= h($rEnd) ?></code><?php endif; ?></td>
                <td><?= $disp ?></td>
                <td class="asn"><?php if ($s['asn']): ?><a href="asn_view.php?asn=<?= h(urlencode($s['asn'])) ?>"><?= h($s['asn']) ?></a><?php else: ?><?= h($s['asn']) ?><?php endif; ?></td>
                <td class="org" title="<?= h($s['org']) ?>"><?= h($s['org']) ?></td>
                <?php endforeach; ?>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    </div>
<?php endif; ?>
<?php endif; ?>
<script>
// After showing results, rewrite the URL to ?restore=1 so the browser back
// button returns to a GET page that PHP re-renders from session.
<?php if ((!empty($ips) && $isPost) || $isRestore || $isIpLookup): ?>
if (history.replaceState) {
    history.replaceState(null, '', 'index.php?restore=1');
}
<?php endif; ?>
(function () {
    const table = document.querySelector('table');
    if (!table) return;
    const tbody = table.querySelector('tbody');
    let activeCol = null, activeDir = 1;

    function ipv4ToNum(ip) {
        const p = ip.split('.').map(Number);
        return p[0] * 16777216 + p[1] * 65536 + p[2] * 256 + p[3];
    }

    function cmp(col, a, b) {
        if (col === 'count') return (parseInt(a) || 0) - (parseInt(b) || 0);
        if (col === 'ip' || col.endsWith('-cidr')) {
            const va = col.endsWith('-cidr') ? (a.split('/')[0] || '') : a;
            const vb = col.endsWith('-cidr') ? (b.split('/')[0] || '') : b;
            const v4 = /^\d+\.\d+\.\d+\.\d+$/;
            if (v4.test(va) && v4.test(vb)) return ipv4ToNum(va) - ipv4ToNum(vb);
        }
        if (col.endsWith('-asn')) {
            const na = parseInt((a || '').replace(/^\D+/, '')) || 0;
            const nb = parseInt((b || '').replace(/^\D+/, '')) || 0;
            if (na || nb) return na - nb;
        }
        return (a || '').localeCompare(b || '');
    }

    function toCamel(col) {
        return col.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    }

    function sortBy(col) {
        if (activeCol === col) activeDir *= -1;
        else { activeCol = col; activeDir = 1; }
        const key = toCamel(col);
        [...tbody.querySelectorAll('tr')]
            .sort((ra, rb) => cmp(col, ra.dataset[key] ?? '', rb.dataset[key] ?? '') * activeDir)
            .forEach(r => tbody.appendChild(r));
        updateIndicators();
        updateRowNums(tbody);
    }

    function updateIndicators() {
        table.querySelectorAll('th.sortable').forEach(th => {
            th.classList.remove('sort-asc', 'sort-desc');
            if (th.dataset.col === activeCol)
                th.classList.add(activeDir === 1 ? 'sort-asc' : 'sort-desc');
        });
    }

    table.querySelectorAll('th.sortable').forEach(th =>
        th.addEventListener('click', () => sortBy(th.dataset.col))
    );

    document.getElementById('sort-reset')?.addEventListener('click', () => {
        activeCol = null; activeDir = 1;
        [...tbody.querySelectorAll('tr')]
            .sort((a, b) => +a.dataset.index - +b.dataset.index)
            .forEach(r => tbody.appendChild(r));
        updateIndicators();
        updateRowNums(tbody);
    });

    function updateRowNums(tb) {
        tb.querySelectorAll('tr').forEach((tr, i) => {
            const cell = tr.querySelector('.row-num');
            if (cell) cell.textContent = i + 1;
        });
    }
    updateRowNums(tbody);

    document.getElementById('toggle-ranges-btn')?.addEventListener('click', function () {
        const showing = table.classList.toggle('show-ranges');
        this.textContent = showing ? '▼ Hide IP ranges' : '▶ Show IP ranges';
        table.querySelectorAll('thead tr:first-child th[data-src-hdr]').forEach(th => {
            th.colSpan = showing ? 5 : 4;
        });
    });
})();

function updateNetList() {
    const seen = new Set();
    const values = [];
    document.querySelectorAll('.net-cb:checked').forEach(function (cb) {
        const serviceId = cb.dataset.src;
        const dataKey = serviceId + 'Cidr';  // e.g., 'maxmindCidr', 'iplocateCidr'
        const cidr = cb.closest('tr').dataset[dataKey];
        if (cidr && !seen.has(cidr)) { seen.add(cidr); values.push(cidr); }
    });
    document.getElementById('net-list').value = values.join(' ');
}

// Network checkbox mutual exclusivity (only one per row) + live list update
document.addEventListener('change', function (e) {
    if (!e.target.classList.contains('net-cb')) return;
    if (e.target.checked) {
        e.target.closest('tr').querySelectorAll('.net-cb').forEach(function (cb) {
            if (cb !== e.target) cb.checked = false;
        });
    }
    updateNetList();
});

document.getElementById('clear-input-btn')?.addEventListener('click', function () {
    document.getElementById('iptext').value = '';
});

document.getElementById('export-csv-btn')?.addEventListener('click', function () {
    const entries = [];
    document.querySelectorAll('tbody tr').forEach(function (row) {
        const cb = row.querySelector('.net-cb:checked');
        if (!cb) return;
        const s = cb.dataset.src;
        const get = key => row.dataset[s + key] || '';
        const cidr = get('Cidr');
        const cc   = get('CountryCode');
        if (!cidr || !cc) return;
        entries.push({
            cidr:         cidr,
            country_code: cc,
            country:      get('Country'),
            asn:          get('Asn'),
            org:          get('Org'),
            source:       s,
        });
    });
    if (!entries.length) {
        alert('No networks checked. Check at least one network checkbox first.');
        return;
    }
    const btn = document.getElementById('export-csv-btn');
    const msg = document.getElementById('export-msg');
    btn.disabled = true;
    msg.textContent = 'Exporting…';
    fetch('', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'export_blocklist=' + encodeURIComponent(JSON.stringify(entries))
    })
    .then(r => r.json())
    .then(data => {
        msg.textContent = '✔ ' + data.written + ' new entr' + (data.written === 1 ? 'y' : 'ies') + ' written' +
            (data.skipped ? ', ' + data.skipped + ' duplicate' + (data.skipped === 1 ? '' : 's') + ' skipped' : '') + '.';
    })
    .catch(() => { msg.textContent = '✖ Export failed.'; })
    .finally(() => { btn.disabled = false; });
});


document.getElementById('clear-list-btn')?.addEventListener('click', function () {
    document.getElementById('net-list').value = '';
    document.querySelectorAll('.net-cb').forEach(function (cb) { cb.checked = false; });
});
</script>
</body>
</html>
