<?php
declare(strict_types=1);

require __DIR__ . '/headers.php';
require __DIR__ . '/security_utils.php';

session_start();
ensureCsrfToken();

// ─── Clear-cache action ───────────────────────────────────────────────────────

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['clear_cache'])) {
    // Validate CSRF token
    if (!verifyCsrfToken($_POST['csrf_token'] ?? '')) {
        http_response_code(403);
        die('CSRF token validation failed');
    }
    
    // Rate limit: max 1 clear per minute per IP
    $rateLimitFile = __DIR__ . '/cache/.rate_' . md5($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1');
    $lastClear = file_exists($rateLimitFile) ? (int)file_get_contents($rateLimitFile) : 0;
    if (time() - $lastClear < 60) {
        http_response_code(429);
        die('Rate limit: only 1 cache clear per minute allowed');
    }
    file_put_contents($rateLimitFile, (string)time(), LOCK_EX);
    
    $asn = strtoupper(preg_replace('/[^A-Z0-9]/', '', $_POST['clear_cache']));
    if (preg_match('/^AS\d+$/', $asn)) {
        foreach (glob(__DIR__ . '/asn_cache/' . $asn . '_*.csv') ?: [] as $f) {
            if (file_exists($f)) unlink($f);
        }
    }
    header('Location: ' . $_SERVER['PHP_SELF'] . '?asn=' . urlencode($asn));
    exit;
}

// ─── Unblock ASN action (remove from blocklist_csvs) ────────────────────────

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['unblock_asn'])) {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? '')) {
        http_response_code(403);
        die('CSRF token validation failed');
    }
    $asn = strtoupper(preg_replace('/[^A-Z0-9]/', '', $_POST['unblock_asn']));
    if (preg_match('/^AS\d+$/', $asn)) {
        foreach (glob(__DIR__ . '/blocklist_csvs/' . $asn . '_*.csv') ?: [] as $f) {
            if (file_exists($f)) unlink($f);
        }
    }
    header('Location: ' . $_SERVER['PHP_SELF'] . '?asn=' . urlencode($asn));
    exit;
}

// ─── Blocklist CSV export ─────────────────────────────────────────────────────

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['export_blocklist'])) {
    header('Content-Type: application/json');
    $asn     = strtoupper(preg_replace('/[^A-Z0-9]/', '', $_POST['asn'] ?? ''));
    $org     = trim(preg_replace('/[^\x20-\x7E]/', '', $_POST['org'] ?? ''));
    $csvDir  = __DIR__ . '/blocklist_csvs';

    if (!preg_match('/^AS\d+$/', $asn)) {
        echo json_encode(['error' => 'Invalid ASN']); exit;
    }
    if (!is_dir($csvDir) && !mkdir($csvDir, 0755, true)) {
        echo json_encode(['error' => 'Cannot create blocklist_csvs directory']); exit;
    }

    $networks = json_decode($_POST['networks'] ?? '[]', true);
    if (!is_array($networks)) { echo json_encode(['error' => 'Bad data']); exit; }

    // Remove any existing blocklist files for this ASN before writing new ones
    foreach (glob($csvDir . '/' . $asn . '_*.csv') ?: [] as $old) {
        @unlink($old);
    }

    // Group by ip version only → {ASN}_{v4/v6}.csv
    $groups = [];
    foreach ($networks as $n) {
        $cidr = trim($n['cidr'] ?? '');
        if (!preg_match('#^[0-9a-fA-F:.]+/\d{1,3}$#', $cidr)) continue;
        $ver     = str_contains($cidr, ':') ? 'v6' : 'v4';
        $cc      = strtoupper(preg_replace('/[^A-Za-z]/', '', $n['country_code'] ?? ''));
        if (strlen($cc) !== 2) $cc = 'XX';
        $country = trim(preg_replace('/[^\x20-\x7E]/', '', $n['country'] ?? ''));
        $groups[$ver][] = ['cidr' => $cidr, 'country_code' => $cc, 'country' => $country];
    }

    $written = 0;
    foreach ($groups as $groupKey => $rows) {
        if (empty($rows)) continue;
        $file = $csvDir . '/' . $asn . '_' . $groupKey . '.csv';
        $fh   = fopen($file, 'w');
        if (!$fh) continue;
        fputcsv($fh, ['network', 'asn', 'org', 'country_code', 'country', 'added_at']);
        $berlin = new DateTimeZone('Europe/Berlin');
        foreach ($rows as $r) {
            fputcsv($fh, [
                escapeCsvFormula($r['cidr']),
                escapeCsvFormula($asn),
                escapeCsvFormula($org),
                escapeCsvFormula($r['country_code']),
                escapeCsvFormula($r['country']),
                (new DateTime('now', $berlin))->format('Y-m-d H:i:s')
            ]);
            $written++;
        }
        fclose($fh);
    }
    echo json_encode(['written' => $written]);
    exit;
}

// ─── Validate ASN param ───────────────────────────────────────────────────────

function h(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$rawInput = trim($_GET['asn'] ?? '');
// Accept bare numbers (e.g. "204548") as well as "AS204548"
$rawAsn = strtoupper(preg_replace('/[^A-Z0-9]/', '', $rawInput));
if ($rawAsn !== '' && ctype_digit($rawAsn)) {
    $rawAsn = 'AS' . $rawAsn;
}
$hasAsn = preg_match('/^AS\d+$/', $rawAsn);

$csvFiles   = $hasAsn ? (glob(__DIR__ . '/asn_cache/' . $rawAsn . '_*.csv') ?: []) : [];
$hasCached  = !empty($csvFiles);
$cachedTime = $hasCached ? filemtime($csvFiles[0]) : null;

$blocklistFiles = $hasAsn ? (glob(__DIR__ . '/blocklist_csvs/' . $rawAsn . '_*.csv') ?: []) : [];
$isBlocked = !empty($blocklistFiles);

// ─── Load networks from CSV cache ────────────────────────────────────────────

$networks = [];
$orgName  = '';
if (!$hasAsn) { $networks = []; }
foreach ($csvFiles as $csvFile) {
    $fh = fopen($csvFile, 'r');
    if (!$fh) continue;
    $header = fgetcsv($fh);
    if (!$header) { fclose($fh); continue; }
    $cols = array_flip($header);
    $required = ['network', 'ip_version', 'country', 'country_code', 'asn', 'org', 'source'];
    foreach ($required as $col) {
        if (!isset($cols[$col])) { fclose($fh); continue 2; }
    }
    while (($row = fgetcsv($fh)) !== false) {
        $cidr = trim($row[$cols['network']] ?? '');
        if (!preg_match('#^[0-9a-fA-F:.]+/\d{1,3}$#', $cidr)) continue;
        $rowOrg = $row[$cols['org']] ?? '';
        if (!$orgName && $rowOrg) $orgName = $rowOrg;
        $networks[] = [
            'cidr'         => $cidr,
            'ip_version'   => $row[$cols['ip_version']]   ?? '',
            'country'      => $row[$cols['country']]      ?? '',
            'country_code' => $row[$cols['country_code']] ?? '',
            'org'          => $rowOrg,
            'source'       => $row[$cols['source']]       ?? '',
        ];
    }
    fclose($fh);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ASN Lookup<?= $hasAsn ? ' – ' . h($rawAsn) : '' ?></title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<h1 id="page-title">ASN Networks<?= $hasAsn ? ' – ' . h($rawAsn) : '' ?></h1>
<p><a href="index.php">← IP Lookup</a> | <a href="blocklist_search.php">Search Blocklists →</a> | <a href="edit_blocklist.php">Edit Blocklist →</a></p>

<!-- ─── ASN search ──────────────────────────────────────────────────────── -->
<form method="get" class="asn-search-form">
    <input type="search" name="asn" value="<?= $hasAsn ? h($rawAsn) : '' ?>"
           placeholder="ASN — e.g. 204548 or AS204548"
           pattern="[Aa][Ss]?\d+|\d+"
           inputmode="numeric"
           spellcheck="false"
           autofocus
           class="asn-search-input">
    <button type="submit" class="btn-primary">Look up</button>
</form>

<!-- ─── Controls ─────────────────────────────────────────────────────────── -->
<?php if ($hasAsn): ?>
<div class="asn-controls">
    <form method="post" style="display:inline">
        <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
        <input type="hidden" name="clear_cache" value="<?= h($rawAsn) ?>">
        <button type="submit" class="btn-secondary"
                <?= $hasCached ? '' : 'disabled' ?>
                title="<?= $hasCached ? 'Cache from ' . date('Y-m-d H:i', $cachedTime) : 'No cache exists' ?>">
            Clear cache<?= $hasCached ? ' (' . date('Y-m-d H:i', $cachedTime) . ')' : '' ?>
        </button>
    </form>
    <span class="asn-status-badge <?= $isBlocked ? 'status-blocked' : 'status-allowed' ?>">
        <?= $isBlocked ? '🔴 Blocked' : '🟢 Allowed' ?>
    </span>
    <?php if ($isBlocked): ?>
    <form method="post" style="display:inline">
        <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
        <input type="hidden" name="unblock_asn" value="<?= h($rawAsn) ?>">
        <button type="submit" class="btn-warning"
                onclick="return confirm('Remove <?= h($rawAsn) ?> from blocklists?')">
            🔓 Unblock
        </button>
    </form>
    <?php endif; ?>
    <button id="export-btn" class="btn-green" disabled>Export/update blocklist CSVs (overwrites existing)</button>
    <span id="export-msg" class="export-msg"></span>
</div>

<?php if (!$hasCached): ?>
<p class="notice-warn">No precomputed data for <?= h($rawAsn) ?>. Run <code>python3 asn_cache_generator.py</code> to generate it.</p>
<?php endif; ?>
<?php endif; ?>

<!-- ─── Result area ──────────────────────────────────────────────────────── -->
<div id="result-header" style="display:none">
    <div class="table-controls">
        <span id="result-summary" class="summary"></span>
    </div>
</div>
<div id="table-wrap" class="table-wrap" style="display:none">
<table id="net-table">
    <thead>
        <tr>
            <th class="row-num-col">#</th>
            <th class="sortable" data-col="cidr">Network (CIDR)</th>
            <th class="sortable" data-col="version">Version</th>
            <th class="sortable" data-col="country">Country</th>
            <th class="sortable" data-col="source">Source DB</th>
            <th class="sortable" data-col="org">Org / ISP</th>
        </tr>
    </thead>
    <tbody id="net-tbody"></tbody>
</table>
</div>

<script>
(function () {
    const asn      = <?= json_encode($rawAsn) ?>;
    const networks = <?= json_encode($networks, JSON_UNESCAPED_UNICODE) ?>;
    const tbody    = document.getElementById('net-tbody');
    const tableWrap= document.getElementById('table-wrap');
    const resHdr   = document.getElementById('result-header');
    const summary  = document.getElementById('result-summary');
    const exportBtn= document.getElementById('export-btn');
    const exportMsg= document.getElementById('export-msg');

    let orgName   = <?= json_encode($orgName) ?>;
    let activeCol = null, activeDir = 1;

    // ── Render rows from embedded data ────────────────────────────────────────
    networks.forEach(d => appendRow(d));

    if (networks.length > 0) {
        resHdr.style.display    = '';
        tableWrap.style.display = '';
        const n = networks.length;
        summary.textContent = asn + (orgName ? ' — ' + orgName : '') +
            ' — ' + n + ' network' + (n !== 1 ? 's' : '') + ' found.';
        if (orgName) {
            const title = asn + ' — ' + orgName;
            document.getElementById('page-title').textContent = 'ASN Networks – ' + title;
            document.title = 'ASN Networks – ' + title;
        }
        exportBtn.disabled = false;
        updateRowNums();
    }


    // ── Table row ────────────────────────────────────────────────────────────
    function appendRow(d) {
        const tr = document.createElement('tr');
        tr.dataset.cidr        = d.cidr;
        tr.dataset.version     = d.ip_version;
        tr.dataset.source      = d.source;
        tr.dataset.org         = d.org || '';
        tr.dataset.country     = d.country || '';
        tr.dataset.countryCode = d.country_code || '';
        const flag = countryFlag(d.country_code || '');
        const networkIp = d.cidr.split('/')[0];
        tr.innerHTML =
            '<td class="row-num-col row-num"></td>' +
            '<td class="cidr"><code><a href="index.php?ip=' + encodeURIComponent(networkIp) +
                '" title="Look up ' + esc(d.cidr) + ' in IP Lookup">' + esc(d.cidr) + '</a></code></td>' +
            '<td>' + esc(d.ip_version) + '</td>' +
            '<td>' + (flag ? flag + '\u00a0' : '') + esc(d.country || '') + '</td>' +
            '<td>' + esc(d.source) + '</td>' +
            '<td class="org" title="' + esc(d.org || '') + '">' + esc(d.org || '') + '</td>';
        tbody.appendChild(tr);
    }

    function esc(s) {
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    function countryFlag(code) {
        if (!code || code.length !== 2) return '';
        const base = 0x1F1E6;
        return String.fromCodePoint(base + code.toUpperCase().charCodeAt(0) - 65) +
               String.fromCodePoint(base + code.toUpperCase().charCodeAt(1) - 65);
    }

    // ── Sorting ──────────────────────────────────────────────────────────────
    function ipv4ToNum(ip) {
        const p = ip.split('.').map(Number);
        return ((p[0]||0)*16777216)+((p[1]||0)*65536)+((p[2]||0)*256)+(p[3]||0);
    }
    function cmp(col, a, b) {
        if (col === 'cidr') {
            const va = a.split('/')[0] || '', vb = b.split('/')[0] || '';
            const v4 = /^\d+\.\d+\.\d+\.\d+$/;
            if (v4.test(va) && v4.test(vb)) return ipv4ToNum(va) - ipv4ToNum(vb);
        }
        return (a || '').localeCompare(b || '');
    }
    const SORT_KEY = 'asnview_sort_' + asn;

    function _applySort(col, dir) {
        activeCol = col; activeDir = dir;
        [...tbody.querySelectorAll('tr')]
            .sort((ra, rb) => cmp(col, ra.dataset[col] ?? '', rb.dataset[col] ?? '') * dir)
            .forEach(r => tbody.appendChild(r));
        document.querySelectorAll('#net-table th.sortable').forEach(th => {
            th.classList.remove('sort-asc','sort-desc');
            if (th.dataset.col === col)
                th.classList.add(dir === 1 ? 'sort-asc' : 'sort-desc');
        });
        updateRowNums();
    }

    function sortBy(col) {
        const dir = activeCol === col ? activeDir * -1 : 1;
        _applySort(col, dir);
        sessionStorage.setItem(SORT_KEY, JSON.stringify({col, dir}));
    }
    document.querySelectorAll('#net-table th.sortable').forEach(th =>
        th.addEventListener('click', () => sortBy(th.dataset.col))
    );

    // Restore sort on back-navigation (handles bfcache too)
    window.addEventListener('pageshow', () => {
        const saved = sessionStorage.getItem(SORT_KEY);
        if (!saved) return;
        try {
            const {col, dir} = JSON.parse(saved);
            if (col) _applySort(col, dir);
        } catch (_) {}
    });

    function updateRowNums() {
        tbody.querySelectorAll('tr').forEach((tr, i) => {
            const cell = tr.querySelector('.row-num');
            if (cell) cell.textContent = i + 1;
        });
    }

    // ── Export blocklist CSVs ─────────────────────────────────────────────────
    exportBtn.addEventListener('click', function () {
        exportBtn.disabled = true;
        exportMsg.textContent = 'Writing…';
        fetch('asn_view.php', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'export_blocklist=1'
                + '&asn=' + encodeURIComponent(asn)
                + '&org=' + encodeURIComponent(orgName)
                + '&networks=' + encodeURIComponent(JSON.stringify(
                    networks.map(n => ({cidr: n.cidr, country_code: n.country_code || '', country: n.country || ''}))
                ))
        })
        .then(r => r.json())
        .then(data => {
            if (data.error) { exportMsg.textContent = '✖ ' + data.error; return; }
            exportMsg.textContent = '✔ ' + data.written + ' network' +
                (data.written !== 1 ? 's' : '') + ' written to blocklist CSVs.';
        })
        .catch(() => { exportMsg.textContent = '✖ Export failed.'; })
        .finally(() => { exportBtn.disabled = false; });
    });
})();
</script>
</body>
</html>
