<?php
declare(strict_types=1);

session_start();

// Generate CSRF token if not in session
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Escape CSV formula injection (=, +, @, -)
function escapeCsvFormula(string $value): string {
    if (preg_match('/^[=+@-]/', $value)) {
        return "'" . $value;
    }
    return $value;
}

// ─── Clear-cache action ───────────────────────────────────────────────────────

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['clear_cache'])) {
    // Validate CSRF token
    if (empty($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'])) {
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
        $f = __DIR__ . '/cache/' . $asn . '.json';
        if (file_exists($f)) unlink($f);
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

    // Group by country_code + ip version → {ASN}_{CC}_{v4/v6}.csv
    $groups = [];
    foreach ($networks as $n) {
        $cidr = trim($n['cidr'] ?? '');
        if (!preg_match('#^[0-9a-fA-F:.]+/\d{1,3}$#', $cidr)) continue;
        $ver     = str_contains($cidr, ':') ? 'v6' : 'v4';
        $cc      = strtoupper(preg_replace('/[^A-Za-z]/', '', $n['country_code'] ?? ''));
        if (strlen($cc) !== 2) $cc = 'XX';
        $country = trim(preg_replace('/[^\x20-\x7E]/', '', $n['country'] ?? ''));
        $groups[$cc . '_' . $ver][] = ['cidr' => $cidr, 'country_code' => $cc, 'country' => $country];
    }

    $written = 0;
    foreach ($groups as $groupKey => $rows) {
        if (empty($rows)) continue;
        $file = $csvDir . '/' . $asn . '_' . $groupKey . '.csv';
        $fh   = fopen($file, 'w');
        if (!$fh) continue;
        fputcsv($fh, ['network', 'asn', 'org', 'country_code', 'country', 'added_at']);
        foreach ($rows as $r) {
            fputcsv($fh, [
                escapeCsvFormula($r['cidr']),
                escapeCsvFormula($asn),
                escapeCsvFormula($org),
                escapeCsvFormula($r['country_code']),
                escapeCsvFormula($r['country']),
                date('Y-m-d H:i:s')
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

$rawAsn = strtoupper(preg_replace('/[^A-Z0-9]/', '', $_GET['asn'] ?? ''));
if (!preg_match('/^AS\d+$/', $rawAsn)) {
    http_response_code(400);
    echo '<!DOCTYPE html><html><body><p>Invalid ASN.</p></body></html>';
    exit;
}

$cacheFile  = __DIR__ . '/cache/' . $rawAsn . '.json';
$hasCached  = file_exists($cacheFile);
$cachedTime = $hasCached ? filemtime($cacheFile) : null;
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ASN View – <?= h($rawAsn) ?></title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<h1 id="page-title">ASN Networks – <?= h($rawAsn) ?></h1>
<p><a href="index.php">← Back to IP Lookup</a></p>

<!-- ─── Controls ─────────────────────────────────────────────────────────── -->
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
    <button id="export-btn" class="btn-green" disabled>Write blocklist CSVs</button>
    <span id="export-msg" class="export-msg"></span>
</div>

<!-- ─── Progress bar ─────────────────────────────────────────────────────── -->
<div id="progress-wrap" class="progress-wrap">
    <div class="progress-bar-outer">
        <div id="progress-bar" class="progress-bar-inner" style="width:0%"></div>
    </div>
    <div id="progress-label" class="progress-label">Starting scan…</div>
</div>

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
    const tbody    = document.getElementById('net-tbody');
    const bar      = document.getElementById('progress-bar');
    const label    = document.getElementById('progress-label');
    const wrap     = document.getElementById('progress-wrap');
    const tableWrap= document.getElementById('table-wrap');
    const resHdr   = document.getElementById('result-header');
    const summary  = document.getElementById('result-summary');
    const exportBtn= document.getElementById('export-btn');
    const exportMsg= document.getElementById('export-msg');

    let networks = [];
    let orgName  = '';
    let activeCol = null, activeDir = 1;

    // ── SSE ──────────────────────────────────────────────────────────────────
    const es = new EventSource('asn_scan.php?asn=' + encodeURIComponent(asn));

    es.onmessage = function (e) {
        const d = JSON.parse(e.data);

        if (d.type === 'progress') {
            bar.style.width  = d.pct + '%';
            label.textContent = d.msg + (d.found ? ' — ' + d.found + ' network(s) found' : '');

        } else if (d.type === 'network') {
            if (d.org && !orgName) orgName = d.org;
            networks.push(d);
            appendRow(d);

        } else if (d.type === 'done') {
            es.close();
            bar.style.width = '100%';
            if (d.org && !orgName) orgName = d.org;

            const cached = d.cached ? ' (loaded from cache)' : '';
            label.textContent = 'Done' + cached + '.';

            resHdr.style.display   = '';
            tableWrap.style.display = '';
            const n = d.total;
            summary.textContent = asn + (orgName ? ' — ' + orgName : '') +
                ' — ' + n + ' network' + (n !== 1 ? 's' : '') + ' found.';

            if (orgName) {
                const title = asn + ' — ' + orgName;
                document.getElementById('page-title').textContent = 'ASN Networks – ' + title;
                document.title = title;
            }

            if (n > 0) exportBtn.disabled = false;
            updateRowNums();

        } else if (d.type === 'error') {
            es.close();
            label.textContent = 'Error: ' + d.msg;
            bar.style.background = '#ef4444';
        }
    };

    es.onerror = function () {
        es.close();
        if (bar.style.width !== '100%') {
            label.textContent = 'Connection error.';
            bar.style.background = '#ef4444';
        }
    };

    // When navigating back via bfcache the page is not reloaded but the SSE
    // connection is dead. Detect this and reload cleanly to reconnect.
    window.addEventListener('pageshow', function (e) {
        if (e.persisted) { window.location.reload(); }
    });

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
    function sortBy(col) {
        if (activeCol === col) activeDir *= -1; else { activeCol = col; activeDir = 1; }
        [...tbody.querySelectorAll('tr')]
            .sort((ra, rb) => cmp(col, ra.dataset[col] ?? '', rb.dataset[col] ?? '') * activeDir)
            .forEach(r => tbody.appendChild(r));
        document.querySelectorAll('#net-table th.sortable').forEach(th => {
            th.classList.remove('sort-asc','sort-desc');
            if (th.dataset.col === activeCol)
                th.classList.add(activeDir === 1 ? 'sort-asc' : 'sort-desc');
        });
        updateRowNums();
    }
    document.querySelectorAll('#net-table th.sortable').forEach(th =>
        th.addEventListener('click', () => sortBy(th.dataset.col))
    );

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
