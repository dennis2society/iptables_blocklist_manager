<?php
declare(strict_types=1);

require __DIR__ . '/headers.php';
require __DIR__ . '/security_utils.php';

session_start();

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

$csrfToken = ensureCsrfToken();

// ─── Remove entire file handler ─────────────────────────────────────────────

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['remove_file'])) {
    header('Content-Type: application/json');

    if (!verifyCsrfToken($_POST['csrf_token'] ?? '')) {
        http_response_code(403);
        echo json_encode(['error' => 'Invalid CSRF token']);
        exit;
    }

    $fname = basename(trim($_POST['remove_file'] ?? ''));
    // Only allow plain CSV filenames with no directory traversal
    if (!preg_match('/^[A-Za-z0-9_\-]+\.csv$/i', $fname)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid filename']);
        exit;
    }

    $path = __DIR__ . '/blocklist_csvs/' . $fname;
    if (!file_exists($path)) {
        echo json_encode(['error' => 'File not found']);
        exit;
    }

    unlink($path);
    echo json_encode(['removed' => $fname]);
    exit;
}

// ─── Remove handler ───────────────────────────────────────────────────────────

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['remove_entry'])) {
    header('Content-Type: application/json');

    if (!verifyCsrfToken($_POST['csrf_token'] ?? '')) {
        http_response_code(403);
        echo json_encode(['error' => 'Invalid CSRF token']);
        exit;
    }

    $cidrToRemove = trim($_POST['remove_entry'] ?? '');
    if (!preg_match('#^[0-9a-fA-F:.]+/\d{1,3}$#', $cidrToRemove)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid CIDR']);
        exit;
    }

    $csvDir  = __DIR__ . '/blocklist_csvs';
    $removed = 0;

    foreach (glob($csvDir . '/*.csv') ?: [] as $file) {
        $fh = fopen($file, 'r');
        if (!$fh) continue;
        $header = fgetcsv($fh);
        if (!$header) { fclose($fh); continue; }
        $cidrCol = array_search('network', $header, true);
        if ($cidrCol === false) { fclose($fh); continue; }

        $kept  = [];
        $found = false;
        while (($row = fgetcsv($fh)) !== false) {
            if (trim($row[$cidrCol] ?? '') === $cidrToRemove) {
                $found = true;
                $removed++;
            } else {
                $kept[] = $row;
            }
        }
        fclose($fh);

        if ($found) {
            if (empty($kept)) {
                unlink($file);
            } else {
                $fh = fopen($file, 'w');
                if ($fh) {
                    fputcsv($fh, $header);
                    foreach ($kept as $row) fputcsv($fh, $row);
                    fclose($fh);
                }
            }
            // CIDRs are unique across files; stop after first match
            break;
        }
    }

    echo json_encode(['removed' => $removed]);
    exit;
}

// ─── Load all blocklist entries ───────────────────────────────────────────────

$csvDir  = __DIR__ . '/blocklist_csvs';
$entries = [];

foreach (glob($csvDir . '/*.csv') ?: [] as $file) {
    $fname     = basename($file);
    $isAsnFile = (bool) preg_match('/^AS\d+_/', $fname);

    $fh = fopen($file, 'r');
    if (!$fh) continue;
    $header = fgetcsv($fh);
    if (!$header) { fclose($fh); continue; }

    $cidrCol    = array_search('network',      $header, true);
    $addedCol   = array_search('added_at',     $header, true);
    $countryCol = array_search('country',      $header, true);
    $ccCol      = array_search('country_code', $header, true);
    $asnCol     = array_search('asn',          $header, true);
    $orgCol     = array_search('org',          $header, true);
    $sourceCol  = array_search('source',       $header, true);

    if ($cidrCol === false) { fclose($fh); continue; }

    while (($row = fgetcsv($fh)) !== false) {
        $cidr = trim($row[$cidrCol] ?? '');
        if ($cidr === '') continue;

        $cc = ($ccCol !== false) ? strtoupper(trim($row[$ccCol] ?? '')) : '';
        // For country-based files without a country_code column, derive from filename (e.g. CN_v4 → CN)
        if ($cc === '' && !$isAsnFile) {
            preg_match('/^([A-Z]{2})_/', $fname, $m);
            $cc = $m[1] ?? '';
        }

        $entries[] = [
            'cidr'     => $cidr,
            'country'  => ($countryCol !== false) ? trim($row[$countryCol] ?? '') : '',
            'cc'       => $cc,
            'asn'      => ($asnCol     !== false) ? trim($row[$asnCol]     ?? '') : '',
            'org'      => ($orgCol     !== false) ? trim($row[$orgCol]     ?? '') : '',
            'source'   => ($sourceCol  !== false) ? trim($row[$sourceCol]  ?? '') : '',
            'added_at' => ($addedCol   !== false) ? trim($row[$addedCol]   ?? '') : '',
            'file'     => $fname,
            'type'     => $isAsnFile ? 'asn' : 'country',
        ];
    }
    fclose($fh);
}

// Sort: by file, then by network
usort($entries, fn($a, $b) => strcmp($a['file'], $b['file']) ?: strcmp($a['cidr'], $b['cidr']));

// ─── Group by file ────────────────────────────────────────────────────────────

$groups = [];
foreach ($entries as $idx => $e) {
    $groups[$e['file']][] = $idx;
}

// Build group display metadata
$groupMeta = [];
foreach ($groups as $fname => $idxList) {
    $first = $entries[$idxList[0]];
    $ipVer = preg_match('/_v6\.csv$/i', $fname) ? 'IPv6' : 'IPv4';
    if ($first['type'] === 'asn') {
        preg_match('/^(AS\d+)_/i', $fname, $m);
        $asnLabel = $m[1] ?? $first['asn'];
        $label    = $asnLabel . ($first['org'] !== '' ? ' — ' . $first['org'] : '');
        if ($first['cc'] !== '') {
            $flag  = countryFlag($first['cc']);
            $label .= ' ' . ($flag !== '' ? $flag : '[' . $first['cc'] . ']');
        }
        $label .= ' — ' . $ipVer;
    } else {
        $flag  = countryFlag($first['cc']);
        $label = ($flag !== '' ? $flag . ' ' : '')
               . ($first['country'] !== '' ? $first['country'] : $first['cc'])
               . ($first['cc'] !== '' ? ' [' . $first['cc'] . ']' : '')
               . ' — ' . $ipVer;
    }
    $groupMeta[$fname] = [
        'label' => $label,
        'type'  => $first['type'],
        'count' => count($idxList),
    ];
}

$totalEntries = count($entries);
$totalGroups  = count($groups);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Edit Blocklist</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<h1>Edit Blocklist</h1>
<p><a href="index.php">← IP Lookup</a> | <a href="asn_view.php">ASN Network Lookup →</a> | <a href="blocklist_search.php">Search Blocklists →</a></p>

<div class="bl-controls">
    <div class="bl-search-wrap">
        <input id="bl-search" class="bl-search-input" type="search"
               placeholder="Filter by network, ASN, org, source, country, added date…"
               autocomplete="off">
        <button id="bl-search-clear" class="bl-search-clear" type="button">Clear</button>
    </div>
    <button id="bl-expand-all"   class="btn-secondary" type="button">Expand all</button>
    <button id="bl-collapse-all" class="btn-secondary" type="button">Collapse all</button>
    <button id="sort-reset"      class="btn-secondary" type="button">Reset sort</button>
    <span class="bl-summary">
        <span id="bl-count"><?= $totalEntries ?></span> of <?= $totalEntries ?> entr<?= $totalEntries !== 1 ? 'ies' : 'y' ?>
        in <?= $totalGroups ?> group<?= $totalGroups !== 1 ? 's' : '' ?>
    </span>
    <span id="bl-msg" class="bl-msg"></span>
</div>

<?php if (empty($entries)): ?>
<p class="no-entries">No blocklist entries found. Add entries via the <a href="index.php">IP Lookup</a> page.</p>
<?php else: ?>

<?php foreach ($groups as $fname => $idxList):
    $meta = $groupMeta[$fname];
?>
<section class="bl-group" data-file="<?= h($fname) ?>">
    <button class="bl-group-hdr" type="button" aria-expanded="true">
        <span class="bl-group-arrow">▼</span>
        <span class="bl-group-label"><?= h($meta['label']) ?></span>
        <span class="bl-group-count">(<span class="bl-group-vis"><?= $meta['count'] ?></span>&thinsp;/&thinsp;<?= $meta['count'] ?> entries)</span>
        <span class="bl-type-badge <?= $meta['type'] === 'asn' ? 'bl-type-asn' : 'bl-type-country' ?>"><?= $meta['type'] === 'asn' ? 'ASN' : 'CC' ?></span>
        <button class="btn-remove-group" type="button"
                data-file="<?= h($fname) ?>"
                data-label="<?= h($meta['label']) ?>"
                data-count="<?= $meta['count'] ?>"
                title="Remove entire blocklist file">✕ Remove all</button>
    </button>
    <div class="bl-group-body">
        <div class="table-wrap">
        <table class="bl-table" data-type="<?= h($meta['type']) ?>">
            <thead>
                <tr>
                    <th class="row-num-col">#</th>
                    <th class="sortable" data-col="cidr">Network</th>
                    <?php if ($meta['type'] === 'country'): ?>
                    <th class="sortable" data-col="asn">ASN</th>
                    <th class="sortable" data-col="org">Org / ISP</th>
                    <?php else: ?>
                    <th class="sortable" data-col="country">Country</th>
                    <?php endif; ?>
                    <th class="sortable" data-col="source">Source</th>
                    <th class="sortable" data-col="added">Added</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody class="bl-tbody">
            <?php foreach ($idxList as $pos => $idx):
                $e    = $entries[$idx];
                $flag = countryFlag($e['cc']);
                $countryDisp = ($flag !== '' ? $flag . '&nbsp;' : '') . h($e['country'])
                             . ($e['cc'] !== '' ? ' [' . h($e['cc']) . ']' : '');
            ?>
                <tr data-index="<?= $pos ?>"
                    data-cidr="<?= h($e['cidr']) ?>"
                    data-country="<?= h($e['country']) ?>"
                    data-asn="<?= h($e['asn']) ?>"
                    data-org="<?= h($e['org']) ?>"
                    data-source="<?= h($e['source']) ?>"
                    data-added="<?= h($e['added_at']) ?>">
                    <td class="row-num-col row-num"></td>
                    <td class="bl-cidr">
                        <a href="index.php?ip=<?= h(urlencode(explode('/', $e['cidr'])[0])) ?>"
                           title="Look up in IP Lookup"><?= h($e['cidr']) ?></a>
                    </td>
                    <?php if ($meta['type'] === 'country'): ?>
                    <td class="asn"><?php if ($e['asn'] !== ''): ?><a href="asn_view.php?asn=<?= h(urlencode($e['asn'])) ?>"><?= h($e['asn']) ?></a><?php endif; ?></td>
                    <td class="org" title="<?= h($e['org']) ?>"><?= h($e['org']) ?></td>
                    <?php else: ?>
                    <td><?= $countryDisp ?></td>
                    <?php endif; ?>
                    <td class="bl-source"><?= h($e['source']) ?></td>
                    <td class="bl-added"><?= h($e['added_at']) ?></td>
                    <td><button class="btn-remove" data-cidr="<?= h($e['cidr']) ?>" type="button">Remove</button></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>
    </div>
</section>
<?php endforeach; ?>

<?php endif; ?>

<script>
const CSRF_TOKEN = <?= json_encode($csrfToken, JSON_HEX_TAG | JSON_HEX_AMP) ?>;

(function () {
    const countEl = document.getElementById('bl-count');
    const msgEl   = document.getElementById('bl-msg');
    let filterText = '';

    // ── Sort helpers ──────────────────────────────────────────────────────────

    function ipv4ToNum(ip) {
        const p = ip.split('.').map(Number);
        return p[0] * 16777216 + p[1] * 65536 + p[2] * 256 + p[3];
    }

    function cmp(col, a, b) {
        if (col === 'cidr') {
            const va = a.split('/')[0] || '', vb = b.split('/')[0] || '';
            if (/^\d+\.\d+\.\d+\.\d+$/.test(va) && /^\d+\.\d+\.\d+\.\d+$/.test(vb))
                return ipv4ToNum(va) - ipv4ToNum(vb);
        }
        if (col === 'asn') {
            const na = parseInt((a || '').replace(/^\D+/, '')) || 0;
            const nb = parseInt((b || '').replace(/^\D+/, '')) || 0;
            if (na || nb) return na - nb;
        }
        return (a || '').localeCompare(b || '');
    }

    // ── Per-table sort ────────────────────────────────────────────────────────

    const tableSorts = new Map();

    function sortTable(table, col) {
        const state = tableSorts.get(table) || { col: null, dir: 1 };
        if (state.col === col) state.dir *= -1;
        else { state.col = col; state.dir = 1; }
        tableSorts.set(table, state);

        const tbody = table.querySelector('.bl-tbody');
        [...tbody.querySelectorAll('tr')]
            .sort((ra, rb) => cmp(col, ra.dataset[col] ?? '', rb.dataset[col] ?? '') * state.dir)
            .forEach(r => tbody.appendChild(r));

        updateTableIndicators(table);
        updateGroupCounts(table.closest('.bl-group'));
    }

    function updateTableIndicators(table) {
        const state = tableSorts.get(table) || { col: null };
        table.querySelectorAll('th.sortable').forEach(th => {
            th.classList.remove('sort-asc', 'sort-desc');
            if (th.dataset.col === state.col)
                th.classList.add(state.dir === 1 ? 'sort-asc' : 'sort-desc');
        });
    }

    document.querySelectorAll('.bl-table').forEach(table =>
        table.querySelectorAll('th.sortable').forEach(th =>
            th.addEventListener('click', () => sortTable(table, th.dataset.col))
        )
    );

    document.getElementById('sort-reset')?.addEventListener('click', () => {
        document.querySelectorAll('.bl-table').forEach(table => {
            tableSorts.delete(table);
            const tbody = table.querySelector('.bl-tbody');
            [...tbody.querySelectorAll('tr')]
                .sort((a, b) => +a.dataset.index - +b.dataset.index)
                .forEach(r => tbody.appendChild(r));
            updateTableIndicators(table);
        });
        updateAllCounts();
    });

    // ── Collapse / expand ─────────────────────────────────────────────────────

    function setGroupOpen(group, open) {
        const body = group.querySelector('.bl-group-body');
        const hdr  = group.querySelector('.bl-group-hdr');
        body.classList.toggle('bl-collapsed', !open);
        hdr.classList.toggle('bl-collapsed', !open);
        hdr.setAttribute('aria-expanded', open ? 'true' : 'false');
    }

    document.querySelectorAll('.bl-group-hdr').forEach(hdr =>
        hdr.addEventListener('click', () => {
            const group  = hdr.closest('.bl-group');
            const isOpen = !group.querySelector('.bl-group-body').classList.contains('bl-collapsed');
            setGroupOpen(group, !isOpen);
        })
    );

    document.getElementById('bl-expand-all')?.addEventListener('click', () =>
        document.querySelectorAll('.bl-group').forEach(g => setGroupOpen(g, true))
    );
    document.getElementById('bl-collapse-all')?.addEventListener('click', () =>
        document.querySelectorAll('.bl-group').forEach(g => setGroupOpen(g, false))
    );

    // ── Row numbers & counts ──────────────────────────────────────────────────

    function updateGroupCounts(group) {
        let n = 0;
        group.querySelectorAll('.bl-tbody tr').forEach(tr => {
            const cell = tr.querySelector('.row-num');
            if (!cell) return;
            if (tr.classList.contains('bl-hidden')) {
                cell.textContent = '';
            } else {
                cell.textContent = ++n;
            }
        });
        const visEl = group.querySelector('.bl-group-vis');
        if (visEl) visEl.textContent = n;
        group.querySelector('.bl-group-hdr').classList.toggle('bl-group-empty', n === 0);
    }

    function updateAllCounts() {
        let total = 0;
        document.querySelectorAll('.bl-group').forEach(group => {
            updateGroupCounts(group);
            total += parseInt(group.querySelector('.bl-group-vis')?.textContent || '0');
        });
        if (countEl) countEl.textContent = total;
    }

    // ── Filter ────────────────────────────────────────────────────────────────

    function applyFilter() {
        const q = filterText.trim().toLowerCase();
        document.querySelectorAll('.bl-group').forEach(group => {
            let hasVisible = false;
            group.querySelectorAll('.bl-tbody tr').forEach(tr => {
                const show = !q
                    || (tr.dataset.cidr    || '').toLowerCase().includes(q)
                    || (tr.dataset.asn     || '').toLowerCase().includes(q)
                    || (tr.dataset.org     || '').toLowerCase().includes(q)
                    || (tr.dataset.source  || '').toLowerCase().includes(q)
                    || (tr.dataset.added   || '').toLowerCase().includes(q)
                    || (tr.dataset.country || '').toLowerCase().includes(q);
                tr.classList.toggle('bl-hidden', !show);
                if (show) hasVisible = true;
            });
            if (q) setGroupOpen(group, hasVisible);
        });
        updateAllCounts();
    }

    const searchInput = document.getElementById('bl-search');
    searchInput?.addEventListener('input', () => { filterText = searchInput.value; applyFilter(); });
    document.getElementById('bl-search-clear')?.addEventListener('click', () => {
        if (searchInput) searchInput.value = '';
        filterText = '';
        applyFilter();
    });

    // ── Remove ────────────────────────────────────────────────────────────────

    function showMsg(text, isError) {
        msgEl.textContent = text;
        msgEl.style.color = isError ? '#dc2626' : '#065f46';
        clearTimeout(msgEl._timer);
        msgEl._timer = setTimeout(() => { msgEl.textContent = ''; }, 5000);
    }

    // ── Remove entire group ────────────────────────────────────────────────────

    document.addEventListener('click', function (e) {
        const gbtn = e.target.closest('.btn-remove-group');
        if (gbtn) {
            e.stopPropagation(); // don't toggle collapse
            const fname = gbtn.dataset.file;
            const label = gbtn.dataset.label;
            const count = gbtn.dataset.count;
            if (!confirm('Remove the entire "' + label + '" blocklist?\n\n'
                + count + ' entr' + (count === '1' ? 'y' : 'ies') + ' will be deleted and the file will be removed.\n\n'
                + 'This cannot be undone.')) return;

            gbtn.disabled = true;
            const group = gbtn.closest('.bl-group');

            fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'remove_file='  + encodeURIComponent(fname)
                    + '&csrf_token=' + encodeURIComponent(CSRF_TOKEN)
            })
            .then(r => r.json())
            .then(data => {
                if (data.removed) {
                    group.remove();
                    updateAllCounts();
                    showMsg('✔ Removed blocklist: ' + fname, false);
                } else if (data.error) {
                    showMsg('✖ ' + data.error, true);
                    gbtn.disabled = false;
                }
            })
            .catch(() => { showMsg('✖ Remove failed.', true); gbtn.disabled = false; });
            return;
        }
    });

    document.addEventListener('click', function (e) {
        const btn = e.target.closest('.btn-remove');
        if (!btn) return;
        const cidr = btn.dataset.cidr;
        if (!cidr) return;
        if (!confirm('Remove ' + cidr + ' from blocklists?')) return;

        btn.disabled = true;
        const row   = btn.closest('tr');
        const group = btn.closest('.bl-group');

        fetch('', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'remove_entry=' + encodeURIComponent(cidr)
                + '&csrf_token='  + encodeURIComponent(CSRF_TOKEN)
        })
        .then(r => r.json())
        .then(data => {
            if (data.removed) {
                row.remove();
                const remaining = group.querySelectorAll('.bl-tbody tr').length;
                if (remaining === 0) {
                    group.remove();
                } else {
                    updateGroupCounts(group);
                }
                updateAllCounts();
                showMsg('✔ Removed ' + cidr, false);
            } else if (data.error) {
                showMsg('✖ ' + data.error, true);
                btn.disabled = false;
            } else {
                showMsg('⚠ ' + cidr + ' not found in any file.', true);
                btn.disabled = false;
            }
        })
        .catch(() => { showMsg('✖ Remove failed.', true); btn.disabled = false; });
    });

    // ── Init ──────────────────────────────────────────────────────────────────

    updateAllCounts();
})();
</script>
</body>
</html>
