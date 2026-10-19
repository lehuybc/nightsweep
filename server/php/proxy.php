<?php
// Proxy tối thiểu cho NIGHT Sweep. Chỉ cho phép đúng 3 lời gọi, không phải proxy mở.
declare(strict_types=1);
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');
header('Content-Type: application/json; charset=utf-8');

function fail(int $code, string $msg): void {
    http_response_code($code);
    echo json_encode(['error' => $msg]);
    exit;
}

// Chặn trang web khác gọi proxy từ trình duyệt của người đang đăng nhập (CSRF/lạm dụng hạn mức).
$sfs = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? '';
if ($sfs !== '' && $sfs !== 'same-origin' && $sfs !== 'none') fail(403, 'không cùng nguồn');

// Giới hạn tốc độ theo IP (băm, không lưu IP thô): chống bị dội yêu cầu. Quá giới hạn -> 429.
define('NS_APP', 1);
require __DIR__ . '/_lib.php';
function rate_limit(string $bucket, int $max): void {
    $d = ns_ensure();
    $min = (string) intdiv(time(), 60);
    $key = substr(hash('sha256', ns_salt($d) . '|rl|' . ($_SERVER['REMOTE_ADDR'] ?? '')), 0, 16) . ':' . $bucket;
    $lk = ns_lock($d);
    foreach (glob($d . '/rl-*.php') ?: [] as $f) { if (basename($f) !== "rl-$min.php") @unlink($f); }
    $f = $d . "/rl-$min.php"; $c = ns_load($f);
    $c[$key] = ($c[$key] ?? 0) + 1;
    if (count($c) > 5000) { $c = [$key => $c[$key]]; } // chống phình file khi bị tấn công nhiều IP
    ns_save($f, $c); ns_unlock($lk);
    if ($c[$key] > $max) { header('Retry-After: 60'); fail(429, 'quá nhiều yêu cầu, thử lại sau 1 phút'); }
}

$t = $_GET['t'] ?? '';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$body = null;
$ctype = null;

if ($t === 'midnight') {
    if ($method !== 'GET') fail(405, 'chỉ GET');
    $a = $_GET['a'] ?? '';
    if (!is_string($a) || !preg_match('/^addr1[0-9a-z]{50,120}$/', $a)) fail(400, 'địa chỉ sai');
    rate_limit('m', 120);
    $url = 'https://mainnet.prod.gd.midnighttge.io/thaws/' . $a . '/schedule';
} elseif ($t === 'koios') {
    if ($method !== 'POST') fail(405, 'chỉ POST');
    $p = $_GET['p'] ?? '';
    if ($p !== '/address_utxos' && $p !== '/submittx') fail(400, 'đường dẫn không được phép');
    $body = file_get_contents('php://input', false, null, 0, 65537);
    if ($body === false || strlen($body) === 0) fail(400, 'thiếu nội dung');
    if (strlen($body) > 65536) fail(413, 'quá lớn');
    $ctype = $p === '/submittx' ? 'application/cbor' : 'application/json';
    rate_limit($p === '/submittx' ? 's' : 'k', $p === '/submittx' ? 30 : 60);
    $url = 'https://api.koios.rest/api/v1' . $p;
} else {
    fail(400, 'thiếu tham số t');
}

$ch = curl_init($url);
$headers = ['Accept: application/json'];
if ($ctype !== null) $headers[] = 'Content-Type: ' . $ctype;
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 30,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_FOLLOWLOCATION => false,
    CURLOPT_HTTPHEADER => $headers,
    // Cổng Midnight nằm sau WAF chặn User-Agent mặc định; dùng UA trình duyệt như khi mở trang redeem.
    CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0',
]);
if ($body !== null) {
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
}
$out = curl_exec($ch);
if ($out === false) {
    fail(502, 'không gọi được máy chủ gốc');
}
$code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
curl_close($ch);
http_response_code($code > 0 ? $code : 502);
echo $out;
