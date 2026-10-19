<?php
// Thư viện dùng chung cho track.php và dashboard.php. Không chạy trực tiếp được.
declare(strict_types=1);
if (!defined('NS_APP')) { http_response_code(404); exit; }

// Chỉ đổi nếu muốn lưu dữ liệu ở thư mục khác. Để trống = tự chọn (ưu tiên NGOÀI thư mục web).
const NS_DATA_DIR_OVERRIDE = '';
const NS_EVENTS = ['view','tab_1','tab_2','tab_3','tab_4','tab_5','thaw_run','find_run','build','sign','submit','lang_en','lang_vi','lang_ja'];
const NS_GUARD = "<?php http_response_code(403); exit; ?>\n";

function ns_dir(): string {
    if (NS_DATA_DIR_OVERRIDE !== '') return NS_DATA_DIR_OVERRIDE;
    $root = $_SERVER['DOCUMENT_ROOT'] ?? '';
    if ($root !== '') { $up = dirname($root); if (is_dir($up) && is_writable($up)) return $up . '/night-data'; }
    return __DIR__ . '/night-data';
}
function ns_ensure(): string {
    $d = ns_dir();
    if (!is_dir($d)) { @mkdir($d, 0700, true); }
    if (!is_dir($d) || !is_writable($d)) { http_response_code(500); echo 'Không ghi được thư mục dữ liệu.'; exit; }
    if (!is_file($d . '/.htaccess')) { @file_put_contents($d . '/.htaccess', "Require all denied\nDeny from all\n"); }
    if (!is_file($d . '/index.html')) { @file_put_contents($d . '/index.html', ''); }
    return $d;
}
function ns_load(string $f): array {
    if (!is_file($f)) return [];
    $s = (string) file_get_contents($f);
    if (strpos($s, NS_GUARD) === 0) $s = substr($s, strlen(NS_GUARD));
    $j = json_decode($s, true);
    return is_array($j) ? $j : [];
}
function ns_save(string $f, array $d): void {
    $tmp = $f . '.' . bin2hex(random_bytes(4)) . '.tmp';
    file_put_contents($tmp, NS_GUARD . json_encode($d), LOCK_EX);
    @chmod($tmp, 0600);
    rename($tmp, $f);
}
function ns_salt(string $d): string {
    $s = ns_load($d . '/salt.php');
    if (empty($s['s'])) { $s = ['s' => bin2hex(random_bytes(32))]; ns_save($d . '/salt.php', $s); }
    return (string) $s['s'];
}
function ns_lock(string $d)  { $h = fopen($d . '/lock', 'c'); if ($h) flock($h, LOCK_EX); return $h; }
function ns_unlock($h): void { if ($h) { flock($h, LOCK_UN); fclose($h); } }

// Quốc gia (mã 2 chữ cái) lấy từ header của CDN/hosting; không tra IP, không lưu IP.
function ns_country(): string {
    foreach (['HTTP_CF_IPCOUNTRY','HTTP_CLOUDFRONT_VIEWER_COUNTRY','HTTP_X_COUNTRY_CODE','HTTP_X_APPENGINE_COUNTRY','GEOIP_COUNTRY_CODE','HTTP_GEOIP_COUNTRY_CODE','MM_COUNTRY_CODE'] as $k) {
        $v = strtoupper(trim((string)($_SERVER[$k] ?? '')));
        if (preg_match('/^[A-Z]{2}$/', $v) && $v !== 'XX' && $v !== 'T1') return $v;
    }
    // Dự phòng kém chính xác: vùng trong ngôn ngữ trình duyệt (vi-VN -> VN)
    if (preg_match('/[a-z]{2,3}-([A-Za-z]{2})\b/', (string)($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''), $m)) return strtoupper($m[1]) . '*';
    return 'ZZ';
}
