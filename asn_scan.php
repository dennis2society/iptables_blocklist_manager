<?php
declare(strict_types=1);
set_time_limit(0);

// ─── SSE setup ────────────────────────────────────────────────────────────────

header('Content-Type: text/event-stream');
header('Cache-Control: no-cache');
header('X-Accel-Buffering: no');

while (ob_get_level()) ob_end_clean();

function sse(array $data): void {
    echo 'data: ' . json_encode($data) . "\n\n";
    flush();
}

// ─── Validate input ───────────────────────────────────────────────────────────

if (!extension_loaded('maxminddb')) {
    sse(['type' => 'error', 'msg' => 'maxminddb extension not loaded']);
    exit;
}

$targetAsn = strtoupper(preg_replace('/[^A-Z0-9]/', '', $_GET['asn'] ?? ''));
if (!preg_match('/^AS\d+$/', $targetAsn)) {
    sse(['type' => 'error', 'msg' => 'Invalid ASN']);
    exit;
}

$DATA_DIR    = __DIR__ . '/';
$MMDB_CONFIG = require __DIR__ . '/mmdb_config.php';
// ─── MMDB Integrity Verification ──────────────────────────────────────────────

$mmdbHashes = [
    'GeoLite2-ASN.mmdb' => '96655ee7c57df0bdca68cc7047abf07daf7b9dba04d72a1d6197944d9228203a',
    'GeoLite2-City.mmdb' => '3b680fc55369da575dadea0d5dd69eb72496c55d2b0de9aee3c24cb96fe2d581',
    'GeoLite2-Country.mmdb' => '0a9a8b654885301a66cb0dc2f90b84fdfdb1c42e29af4c2b25c67b7153ebb8f9',
    'ip-to-asn.mmdb' => 'a5eeff87305c8856eaeb86a43641aa4f757f6a4b9081f5c41cf6df8f8afe372f',
    'ip-to-country.mmdb' => '0607bceef28567cfa59bdabbae403c78de31e72b1e3146d92d1e6fda7cfb5bea',
    'ipinfo_lite.mmdb' => 'e845372d4ecdae1528d2b7c731a77355486d3d502db5eb97a16c32d457883ec8',
];

foreach ($MMDB_CONFIG as $service) {
    foreach ($service['databases'] as $db) {
        $path = $DATA_DIR . $db['file'];
        if (!file_exists($path)) continue;
        
        if (isset($mmdbHashes[$db['file']])) {
            $actualHash = hash_file('sha256', $path);
            if ($actualHash !== $mmdbHashes[$db['file']]) {
                sse(['type' => 'error', 'msg' => 'MMDB integrity check failed: ' . $db['file'] . ' (tampering detected)']);
                exit;
            }
        }
    }
}
// ─── File cache ───────────────────────────────────────────────────────────────

$cacheDir  = __DIR__ . '/cache';
$cacheFile = $cacheDir . '/' . $targetAsn . '.json';
$cacheTtl  = 7 * 24 * 3600; // 7 days

if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < $cacheTtl) {
    $cached = json_decode(file_get_contents($cacheFile), true);
    if (is_array($cached) && isset($cached['networks'])) {
        sse(['type' => 'progress', 'pct' => 0, 'found' => 0, 'msg' => 'Loading from cache…']);
        foreach ($cached['networks'] as $n) {
            sse(['type' => 'network', 'cidr' => $n['cidr'], 'ip_version' => $n['ip_version'],
                 'org' => $cached['org'] ?? '', 'source' => $n['source'],
                 'country' => $n['country'] ?? '', 'country_code' => $n['country_code'] ?? '']);
        }
        sse(['type' => 'done', 'total' => count($cached['networks']),
             'org' => $cached['org'] ?? '', 'cached' => true]);
        exit;
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

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

// ─── Open ASN database readers ────────────────────────────────────────────────

$asnReaders = [];
foreach ($MMDB_CONFIG as $service) {
    foreach ($service['databases'] as $db) {
        $path = $DATA_DIR . $db['file'];
        if (!file_exists($path)) continue;
        if (!in_array($db['type'], ['maxmind_asn', 'iplocate_asn', 'ipinfo'])) continue;
        try {
            $asnReaders[] = [
                'reader' => new \MaxMind\Db\Reader($path),
                'type'   => $db['type'],
                'source' => $service['id'],
            ];
        } catch (\Exception $e) { continue; }
    }
}

if (empty($asnReaders)) {
    sse(['type' => 'error', 'msg' => 'No ASN databases found']);
    exit;
}

// ─── Open country database readers ────────────────────────────────────────────

$countryReaders = [];
foreach ($MMDB_CONFIG as $service) {
    foreach ($service['databases'] as $db) {
        $path = $DATA_DIR . $db['file'];
        if (!file_exists($path)) continue;
        if (!in_array($db['type'], ['maxmind_country', 'iplocate_country', 'ipinfo'])) continue;
        try {
            $countryReaders[] = [
                'reader' => new \MaxMind\Db\Reader($path),
                'type'   => $db['type'],
                'source' => $service['id'],
            ];
        } catch (\Exception $e) { continue; }
    }
}

// ─── ASN extraction ───────────────────────────────────────────────────────────

function extractASN(array $rec, string $type): array {
    switch ($type) {
        case 'maxmind_asn':
            return [
                isset($rec['autonomous_system_number']) ? 'AS' . $rec['autonomous_system_number'] : '',
                $rec['autonomous_system_organization'] ?? '',
            ];
        case 'iplocate_asn':
            return [
                isset($rec['asn']) ? 'AS' . $rec['asn'] : '',
                $rec['org'] ?? ($rec['name'] ?? ''),
            ];
        case 'ipinfo':
            return [$rec['asn'] ?? '', $rec['as_name'] ?? ''];
        default:
            return ['', ''];
    }
}

// ─── Country lookup ───────────────────────────────────────────────────────────

// Prefer iplocate > ipinfo > maxmind for country data.
function lookupCountry(string $ip, array $countryReaders): array {
    $priority = ['iplocate' => 1, 'ipinfo' => 2, 'maxmind' => 3];
    $best = ['', '', PHP_INT_MAX]; // [country, country_code, priority]
    foreach ($countryReaders as $entry) {
        try {
            $prio = $priority[$entry['source']] ?? 99;
            if ($prio >= $best[2]) continue;
            $rec = $entry['reader']->get($ip);
            if (!$rec) continue;
            switch ($entry['type']) {
                case 'maxmind_country':
                    $country = $rec['country']['names']['en'] ?? $rec['registered_country']['names']['en'] ?? '';
                    $cc      = $rec['country']['iso_code']    ?? $rec['registered_country']['iso_code']    ?? '';
                    break;
                case 'iplocate_country':
                    $country = $rec['country_name'] ?? '';
                    $cc      = $rec['country_code']  ?? '';
                    break;
                case 'ipinfo':
                    $country = $rec['country']      ?? '';
                    $cc      = $rec['country_code'] ?? '';
                    break;
                default:
                    continue 2;
            }
            if ($cc) { $best = [$country, $cc, $prio]; }
        } catch (\Exception $e) { continue; }
    }
    return [$best[0], $best[1]];
}

// ─── Overlap helper ──────────────────────────────────────────────────────────

// Returns true if $outerCidr is a strict supernet of $innerCidr
// (outer prefix < inner prefix and inner address falls inside outer block).
function cidrContains(string $outerCidr, string $innerCidr): bool {
    [$outerIp, $outerLen] = explode('/', $outerCidr, 2);
    [$innerIp, $innerLen] = explode('/', $innerCidr, 2);
    $outerLen = (int)$outerLen;
    $innerLen = (int)$innerLen;
    if ($outerLen >= $innerLen) return false;
    $op = inet_pton($outerIp);
    $ip = inet_pton($innerIp);
    if ($op === false || $ip === false || strlen($op) !== strlen($ip)) return false;
    $ob = array_values(unpack('C*', $op));
    $ib = array_values(unpack('C*', $ip));
    for ($i = 0, $len = count($ob); $i < $len; $i++) {
        $bits = max(0, min(8, $outerLen - $i * 8));
        $mask = $bits >= 8 ? 0xff : ($bits > 0 ? (0xff << (8 - $bits)) & 0xff : 0);
        if (($ib[$i] & $mask) !== $ob[$i]) return false;
    }
    return true;
}

// Remove any result whose CIDR is fully covered by a broader CIDR already
// present in the result set (regardless of which source DB reported it).
function deduplicateNetworks(array $results): array {
    $cidrs = array_unique(array_column($results, 'cidr'));
    $suppressed = [];
    foreach ($cidrs as $inner) {
        foreach ($cidrs as $outer) {
            if ($outer !== $inner && cidrContains($outer, $inner)) {
                $suppressed[$inner] = true;
                break;
            }
        }
    }
    return array_values(array_filter($results, fn($n) => !isset($suppressed[$n['cidr']])));
}

// For the same CIDR reported by multiple sources, keep only the preferred source:
// iplocate > ipinfo > maxmind.
function preferredSourceDedup(array $results): array {
    $priority = ['iplocate' => 1, 'ipinfo' => 2, 'maxmind' => 3];
    $best = []; // cidr => ['entry' => array, 'prio' => int]
    foreach ($results as $n) {
        $prio = $priority[$n['source']] ?? 99;
        if (!isset($best[$n['cidr']]) || $prio < $best[$n['cidr']]['prio']) {
            $best[$n['cidr']] = ['entry' => $n, 'prio' => $prio];
        }
    }
    return array_values(array_map(fn($v) => $v['entry'], $best));
}

// ─── Scan state ───────────────────────────────────────────────────────────────

$found   = []; // "cidr|source" => true  (dedup during scan)
$org     = '';
$results = []; // raw; will be deduplicated after scan

function probeIp(string $ip, string $targetAsn, array &$found, string &$org, array $asnReaders, array &$results): int {
    // Query ALL readers — do not short-circuit after the first match so that
    // every database gets a chance to contribute its own CIDR for this probe IP.
    // Return the MAX prefix (most-specific) so the skip logic only fires when
    // all matching databases agree on a large block.
    $maxPrefix = 0;
    foreach ($asnReaders as $entry) {
        try {
            [$rec, $prefix] = $entry['reader']->getWithPrefixLen($ip);
            if (!$rec || !$prefix) continue;
            [$asn, $asnOrg] = extractASN($rec, $entry['type']);
            if ($asn !== $targetAsn) continue;

            $cidr = prefixToCidr($ip, $prefix);
            if (!$cidr) continue;
            $key = $cidr . '|' . $entry['source'];
            if (!isset($found[$key])) {
                $found[$key] = true;
                if (!$org && $asnOrg) $org = $asnOrg;
                $ver = str_contains($cidr, ':') ? 'IPv6' : 'IPv4';
                // Buffer result — SSE emission happens after deduplication.
                $results[] = ['cidr' => $cidr, 'ip_version' => $ver,
                               'source' => $entry['source'], 'org' => $asnOrg];
            }
            if ($prefix > $maxPrefix) $maxPrefix = $prefix;
        } catch (\Exception $e) { continue; }
    }
    return $maxPrefix;
}

// ─── IPv4 scan (/24 or larger = prefix ≤ 24) ─────────────────────────────────

sse(['type' => 'progress', 'pct' => 0, 'found' => 0, 'msg' => 'Scanning IPv4…']);

for ($i = 1; $i <= 255; $i++) {
    $skipI = false;
    for ($j = 0; $j <= 255 && !$skipI; $j++) {
        $skipJ = false;
        for ($k = 0; $k <= 255 && !$skipJ; $k++) {
            $prefix = probeIp("$i.$j.$k.1", $targetAsn, $found, $org, $asnReaders, $results);
            if ($prefix > 0 && $prefix <= 8)       { $skipI = true; }
            elseif ($prefix > 0 && $prefix <= 16)  { $skipJ = true; }
            // /17–/24: captured; /25+ is more specific than /24, skip sub-block too
            elseif ($prefix > 24) { /* network smaller than /24, not included */ }
        }
    }
    $pct = (int)round($i / 255 * 90);
    sse(['type' => 'progress', 'pct' => $pct, 'found' => count($found),
         'msg' => "Scanned $i.x.x.x ($pct%)…"]);
}

// ─── IPv6 scan (/48 or larger = prefix ≤ 48) ─────────────────────────────────

sse(['type' => 'progress', 'pct' => 90, 'found' => count($found), 'msg' => 'Scanning IPv6…']);

// Global unicast 2000::/3 — step every /32 within 2000:: – 3fff::
for ($hi = 0x2000; $hi <= 0x3fff; $hi++) {
    for ($lo = 0; $lo <= 0xffff; $lo += 0x100) {
        $base = sprintf('%x:%x::', $hi, $lo);
        $prefix = probeIp($base, $targetAsn, $found, $org, $asnReaders, $results);
        if ($prefix > 0 && $prefix <= 32) {
            // whole /32 is ours — skip remaining /32 sub-blocks (lo already steps by 0x100)
        }
    }
}

// ─── Done ─────────────────────────────────────────────────────────────────────

foreach ($asnReaders as $entry) { $entry['reader']->close(); }

// Step 1: drop any CIDR that is a subnet of a broader CIDR in the results.
sse(['type' => 'progress', 'pct' => 97, 'found' => count($found), 'msg' => 'Deduplicating overlapping networks…']);
$results = deduplicateNetworks($results);

// Step 2: for the same CIDR from multiple sources, keep the preferred source.
$results = preferredSourceDedup($results);

// Step 3: look up country for each remaining CIDR.
sse(['type' => 'progress', 'pct' => 99, 'found' => count($results), 'msg' => 'Looking up countries…']);
foreach ($results as &$n) {
    $firstIp = explode('/', $n['cidr'])[0];
    [$country, $countryCode] = lookupCountry($firstIp, $countryReaders);
    $n['country']      = $country;
    $n['country_code'] = $countryCode;
}
unset($n);

foreach ($countryReaders as $entry) { $entry['reader']->close(); }

// Emit deduplicated networks to the client.
foreach ($results as $n) {
    sse(['type' => 'network', 'cidr' => $n['cidr'], 'ip_version' => $n['ip_version'],
         'org' => $n['org'], 'source' => $n['source'],
         'country' => $n['country'], 'country_code' => $n['country_code']]);
}

if (!empty($results)) {
    if (!is_dir($cacheDir)) mkdir($cacheDir, 0755, true);
    file_put_contents(
        $cacheFile,
        json_encode(['asn' => $targetAsn, 'org' => $org,
                     'cached_at' => time(), 'networks' => $results],
                    JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT)
    );
}

sse(['type' => 'done', 'total' => count($results), 'org' => $org]);
