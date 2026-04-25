<?php
declare(strict_types=1);

require __DIR__ . '/headers.php';
require __DIR__ . '/security_utils.php';

session_start();

function h(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function ipInCidr(string $ip, string $cidr): bool {
    [$net, $prefix] = explode('/', $cidr, 2) + [1 => null];
    if ($prefix === null) return false;
    $prefix = (int)$prefix;
    
    $packed_ip = inet_pton($ip);
    $packed_net = inet_pton($net);
    if ($packed_ip === false || $packed_net === false) return false;
    if (strlen($packed_ip) !== strlen($packed_net)) return false;
    
    $len = strlen($packed_ip);
    for ($i = 0; $i < $len; $i++) {
        $bits = max(0, min(8, $prefix - $i * 8));
        $mask = $bits >= 8 ? 0xff : ($bits > 0 ? (0xff << (8 - $bits)) & 0xff : 0);
        if ((ord($packed_ip[$i]) & $mask) !== (ord($packed_net[$i]) & $mask)) {
            return false;
        }
    }
    return true;
}

$searchIp = '';
$results = [];
$isPost = ($_SERVER['REQUEST_METHOD'] === 'POST');

// Handle removal request
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['remove_entry'])) {
    $cidrToRemove = trim($_POST['remove_entry'] ?? '');
    if (!preg_match('#^[0-9a-fA-F:.]+/\d{1,3}$#', $cidrToRemove)) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Invalid CIDR']);
        exit;
    }
    
    $csvDir = __DIR__ . '/blocklist_csvs';
    $removed = 0;
    
    foreach (glob($csvDir . '/*.csv') ?: [] as $file) {
        $fh = fopen($file, 'r');
        if (!$fh) continue;
        $header = fgetcsv($fh);
        if (!$header) { fclose($fh); continue; }
        $cidrCol = array_search('network', $header, true);
        if ($cidrCol === false) { fclose($fh); continue; }

        $kept = [];
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
            break;
        }
    }
    
    header('Content-Type: application/json');
    echo json_encode(['removed' => $removed]);
    exit;
}

if ($isPost && isset($_POST['search_ip'])) {
    $searchIp = trim($_POST['search_ip'] ?? '');
    if (filter_var($searchIp, FILTER_VALIDATE_IP)) {
        $csvDir = __DIR__ . '/blocklist_csvs';
        if (is_dir($csvDir)) {
            foreach (glob($csvDir . '/*.csv') ?: [] as $file) {
                $fh = fopen($file, 'r');
                if (!$fh) continue;
                $header = fgetcsv($fh);
                if (!$header) { fclose($fh); continue; }
                
                $cidrCol = array_search('network', $header, true);
                $addedCol = array_search('added_at', $header, true);
                $countryCol = array_search('country', $header, true);
                $asnCol = array_search('asn', $header, true);
                $orgCol = array_search('org', $header, true);
                $sourceCol = array_search('source', $header, true);
                
                if ($cidrCol === false) { fclose($fh); continue; }
                
                while (($row = fgetcsv($fh)) !== false) {
                    $cidr = trim($row[$cidrCol] ?? '');
                    if ($cidr && ipInCidr($searchIp, $cidr)) {
                        $results[] = [
                            'cidr'    => $cidr,
                            'added_at' => ($addedCol !== false) ? trim($row[$addedCol] ?? '') : '',
                            'country' => ($countryCol !== false) ? trim($row[$countryCol] ?? '') : '',
                            'asn'     => ($asnCol !== false) ? trim($row[$asnCol] ?? '') : '',
                            'org'     => ($orgCol !== false) ? trim($row[$orgCol] ?? '') : '',
                            'source'  => ($sourceCol !== false) ? trim($row[$sourceCol] ?? '') : '',
                            'file'    => basename($file),
                        ];
                    }
                }
                fclose($fh);
            }
            
            // Sort by CIDR (most specific first)
            usort($results, function ($a, $b) {
                $a_prefix = (int)explode('/', $a['cidr'], 2)[1];
                $b_prefix = (int)explode('/', $b['cidr'], 2)[1];
                return $b_prefix - $a_prefix; // descending = most specific first
            });
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Blocklist Search</title>
<link rel="stylesheet" href="style.css">
<style>
.search-container {
    background: #f9f9f9;
    border: 1px solid #ddd;
    border-radius: 4px;
    padding: 15px;
    margin-bottom: 20px;
}
.search-form {
    display: flex;
    gap: 10px;
    align-items: flex-end;
}
.search-form input {
    flex: 1;
    padding: 8px 12px;
    border: 1px solid #ccc;
    border-radius: 4px;
    font-family: monospace;
}
.search-form button {
    padding: 8px 16px;
    background: #007bff;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
}
.search-form button:hover {
    background: #0056b3;
}
.results-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 20px;
}
.results-table thead {
    background: #f0f0f0;
    font-weight: bold;
}
.results-table th,
.results-table td {
    padding: 10px;
    border: 1px solid #ddd;
    text-align: left;
}
.results-table tbody tr:nth-child(odd) {
    background: #f9f9f9;
}
.results-table tbody tr:hover {
    background: #fffacd;
}
.remove-btn {
    padding: 4px 8px;
    background: #dc3545;
    color: white;
    border: none;
    border-radius: 3px;
    cursor: pointer;
    font-size: 12px;
}
.remove-btn:hover {
    background: #c82333;
}
.no-results {
    text-align: center;
    padding: 20px;
    color: #666;
    font-style: italic;
}
.back-link {
    display: inline-block;
    margin-bottom: 15px;
}
.back-link a {
    color: #007bff;
    text-decoration: none;
}
.back-link a:hover {
    text-decoration: underline;
}
</style>
</head>
<body>
<h1>Blocklist Search</h1>
<p class="back-link"><a href="index.php">← Back to IP Lookup</a></p>

<div class="search-container">
    <form method="post" class="search-form">
        <input type="text" name="search_ip" placeholder="Enter an IP address (e.g., 1.2.3.4 or 2001:db8::1)" 
            value="<?= h($searchIp) ?>" required>
        <button type="submit">Search Blocklists</button>
    </form>
</div>

<?php if ($isPost): ?>
    <?php if (empty($searchIp)): ?>
        <p class="no-results">Please enter a valid IP address.</p>
    <?php elseif (empty($results)): ?>
        <p class="no-results">No blocked ranges found for <?= h($searchIp) ?>.</p>
    <?php else: ?>
        <p><strong>Found <?= count($results) ?> blocked range<?= count($results) !== 1 ? 's' : '' ?> containing <?= h($searchIp) ?>:</strong></p>
        <table class="results-table">
            <thead>
                <tr>
                    <th>Network</th>
                    <th>Country</th>
                    <th>ASN</th>
                    <th>Organization</th>
                    <th>Source</th>
                    <th>Added</th>
                    <th>File</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($results as $r): ?>
                <tr>
                    <td><code><?= h($r['cidr']) ?></code></td>
                    <td><?= h($r['country']) ?></td>
                    <td><?= h($r['asn']) ?></td>
                    <td title="<?= h($r['org']) ?>"><?= h(strlen($r['org']) > 30 ? substr($r['org'], 0, 27) . '…' : $r['org']) ?></td>
                    <td><?= h($r['source']) ?></td>
                    <td><?= h($r['added_at']) ?></td>
                    <td><code><?= h($r['file']) ?></code></td>
                    <td><button class="remove-btn" onclick="removeEntry('<?= h($r['cidr']) ?>')">Remove</button></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
<?php endif; ?>

<script>
function removeEntry(cidr) {
    if (!confirm(`Remove ${cidr} from blocklists?`)) return;
    
    fetch('', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'remove_entry=' + encodeURIComponent(cidr)
    })
    .then(r => r.json())
    .then(data => {
        if (data.removed) {
            alert(`Removed ${cidr} from blocklists.`);
            location.reload();
        } else {
            alert('Failed to remove entry.');
        }
    })
    .catch(() => alert('Error communicating with server.'));
}
</script>
</body>
</html>
