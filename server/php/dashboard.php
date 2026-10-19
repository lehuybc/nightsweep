<?php
// Bảng thống kê có đăng nhập cho NIGHT Sweep. Chỉ hiển thị số liệu tổng hợp ẩn danh do track.php ghi.
declare(strict_types=1);
define('NS_APP', 1);
require __DIR__ . '/_lib.php';

// Mã cài đặt: chuỗi bí mật do bạn chọn, chỉ dùng 1 lần để tạo tài khoản. Để trống = tắt cài đặt.
const SETUP_KEY = '';
const SESSION_TTL = 7200;       // 2 giờ
const MAX_FAILS = 5;            // sai quá số lần này -> khóa
const LOCK_SECONDS = 900;       // 15 phút

header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');
header('Referrer-Policy: no-referrer');
header('X-Frame-Options: DENY');
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
header('X-Robots-Tag: noindex, nofollow');

$https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
session_name('ns_admin');
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => $https, 'httponly' => true, 'samesite' => 'Strict']);
session_start();
if (isset($_SESSION['t']) && time() - $_SESSION['t'] > SESSION_TTL) { $_SESSION = []; }
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));

$D = ns_ensure();
$admin = ns_load($D . '/admin.php');
$h = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
$msg = '';

function csrf_ok(): bool { return hash_equals($_SESSION['csrf'] ?? '', (string)($_POST['csrf'] ?? '')); }
function ipkey(string $D): string { return substr(hash('sha256', ns_salt($D) . '|login|' . ($_SERVER['REMOTE_ADDR'] ?? '')), 0, 20); }
function locked(string $D): int {
    $a = ns_load($D . '/login.php'); $k = ipkey($D); $r = $a[$k] ?? null;
    return ($r && $r['n'] >= MAX_FAILS && time() - $r['t'] < LOCK_SECONDS) ? LOCK_SECONDS - (time() - $r['t']) : 0;
}
function fail(string $D): void {
    $lk = ns_lock($D); $a = ns_load($D . '/login.php'); $k = ipkey($D);
    foreach ($a as $kk => $r) if (time() - $r['t'] > LOCK_SECONDS) unset($a[$kk]);
    $r = $a[$k] ?? ['n' => 0, 't' => 0];
    if (time() - $r['t'] > LOCK_SECONDS) $r['n'] = 0;
    $a[$k] = ['n' => $r['n'] + 1, 't' => time()];
    ns_save($D . '/login.php', $a); ns_unlock($lk);
}
function clear_fails(string $D): void { $lk = ns_lock($D); $a = ns_load($D . '/login.php'); unset($a[ipkey($D)]); ns_save($D . '/login.php', $a); ns_unlock($lk); }

$authed = !empty($_SESSION['ok']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $act = $_POST['a'] ?? '';
    if (!csrf_ok()) { $msg = 'Phiên không hợp lệ, hãy thử lại.'; }
    elseif ($act === 'setup' && !$admin && SETUP_KEY !== '') {
        usleep(400000);
        $u = trim((string)($_POST['u'] ?? '')); $p = (string)($_POST['p'] ?? '');
        if (!hash_equals(SETUP_KEY, (string)($_POST['k'] ?? ''))) { fail($D); $msg = 'Mã cài đặt sai.'; }
        elseif (!preg_match('/^[A-Za-z0-9_.-]{3,32}$/', $u)) $msg = 'Tên đăng nhập 3–32 ký tự (chữ, số, _ . -).';
        elseif (strlen($p) < 12) $msg = 'Mật khẩu tối thiểu 12 ký tự.';
        else {
            ns_save($D . '/admin.php', ['u' => $u, 'h' => password_hash($p, PASSWORD_DEFAULT)]);
            $admin = ns_load($D . '/admin.php'); $msg = 'Đã tạo tài khoản. Hãy đăng nhập.';
        }
    }
    elseif ($act === 'login' && $admin) {
        $w = locked($D);
        if ($w > 0) $msg = 'Thử sai quá nhiều lần. Đợi ' . ceil($w / 60) . ' phút.';
        else {
            usleep(400000);
            $okU = hash_equals((string)$admin['u'], (string)($_POST['u'] ?? ''));
            $okP = password_verify((string)($_POST['p'] ?? ''), (string)$admin['h']);
            if ($okU && $okP) { session_regenerate_id(true); $_SESSION['ok'] = 1; $_SESSION['t'] = time(); $_SESSION['csrf'] = bin2hex(random_bytes(16)); clear_fails($D); header('Location: dashboard.php'); exit; }
            fail($D); $msg = 'Sai tên đăng nhập hoặc mật khẩu.';
        }
    }
    elseif ($act === 'logout') { $_SESSION = []; session_destroy(); header('Location: dashboard.php'); exit; }
    elseif ($act === 'passwd' && $authed) {
        $old = (string)($_POST['o'] ?? ''); $new = (string)($_POST['p'] ?? '');
        if (!password_verify($old, (string)$admin['h'])) $msg = 'Mật khẩu hiện tại sai.';
        elseif (strlen($new) < 12) $msg = 'Mật khẩu mới tối thiểu 12 ký tự.';
        else { $admin['h'] = password_hash($new, PASSWORD_DEFAULT); ns_save($D . '/admin.php', $admin); $msg = 'Đã đổi mật khẩu.'; }
    }
    $authed = !empty($_SESSION['ok']);
}
if ($authed) $_SESSION['t'] = time();

$CSS = '<style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0a0b14;color:#e8e8f2;font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
.w{max-width:1000px;margin:0 auto;padding:20px 16px 60px}h1{font-size:20px;margin:0}h2{font-size:13px;color:#9a9ab5;text-transform:uppercase;letter-spacing:.06em;margin:28px 0 10px}
.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
.card{background:#12131f;border:1px solid #23243a;border-radius:12px;padding:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.k{font:600 26px ui-monospace,Menlo,monospace;color:#fff;white-space:nowrap}.l{color:#9a9ab5;font-size:12px}.s{font-size:12px;color:#5ed6a0}
input,select,button,a.b{background:#181a2b;color:#e8e8f2;border:1px solid #2c2e4a;border-radius:8px;padding:9px 12px;font:inherit;text-decoration:none}
button,a.b{cursor:pointer}button.p{background:#a89bff;color:#0a0b14;border:0;font-weight:600}
input{width:100%;margin:4px 0 12px}label{font-size:12px;color:#9a9ab5}.lg{max-width:360px;margin:12vh auto 0}
.m{color:#f2b84b;margin:0 0 12px}table{width:100%;border-collapse:collapse;font:12px ui-monospace,Menlo,monospace}
th,td{text-align:right;padding:6px 8px;border-bottom:1px solid #1e1f33}th:first-child,td:first-child{text-align:left}th{color:#9a9ab5;font-weight:500}
.bar{height:8px;background:#23243a;border-radius:4px;overflow:hidden}.bar i{display:block;height:100%;background:#a89bff}
.fr{display:grid;grid-template-columns:150px 1fr 90px;gap:10px;align-items:center;margin:8px 0}.sc{overflow-x:auto}</style>';
$head = '<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>NIGHT Sweep – Thống kê</title>' . $CSS . '</head><body><div class="w">';
$foot = '</div></body></html>';
$csrf = '<input type="hidden" name="csrf" value="' . $h($_SESSION['csrf']) . '">';

if (!$authed) {
    echo $head . '<div class="lg card"><h1>Thống kê NIGHT Sweep</h1><p class="l">Chỉ số liệu ẩn danh, không có địa chỉ ví.</p>';
    if ($msg) echo '<p class="m">' . $h($msg) . '</p>';
    if (!$admin) {
        if (SETUP_KEY === '') echo '<p class="m">Chưa cài đặt: hãy đặt SETUP_KEY trong dashboard.php rồi tải lại.</p>';
        else echo '<form method="post"><input type="hidden" name="a" value="setup">' . $csrf .
            '<label>Mã cài đặt (SETUP_KEY)</label><input type="password" name="k" autocomplete="off" required>
             <label>Tên đăng nhập mới</label><input name="u" autocomplete="username" required>
             <label>Mật khẩu mới (≥ 12 ký tự)</label><input type="password" name="p" autocomplete="new-password" minlength="12" required>
             <button class="p">Tạo tài khoản</button></form>';
    } else {
        echo '<form method="post"><input type="hidden" name="a" value="login">' . $csrf .
            '<label>Tên đăng nhập</label><input name="u" autocomplete="username" required>
             <label>Mật khẩu</label><input type="password" name="p" autocomplete="current-password" required>
             <button class="p">Đăng nhập</button></form>';
    }
    echo '</div>' . $foot; exit;
}

// ---- Đã đăng nhập ----
$all = ns_load($D . '/stats.php'); ksort($all);
$range = $_GET['r'] ?? '30';
$days = $range === 'all' ? 100000 : max(1, min(400, (int)$range));
$keys = array_slice(array_keys($all), -$days);
$sel = []; foreach ($keys as $d) $sel[$d] = $all[$d];

$fmt = $_GET['f'] ?? '';
if ($fmt === 'json') { header('Content-Type: application/json; charset=utf-8'); echo json_encode($sel, JSON_PRETTY_PRINT); exit; }
if ($fmt === 'csv') {
    header('Content-Type: text/csv; charset=utf-8'); header('Content-Disposition: attachment; filename="night-stats.csv"');
    echo 'date,uniq,' . implode(',', NS_EVENTS) . "\n";
    foreach ($sel as $d => $r) { echo $d . ',' . (int)$r['uniq']; foreach (NS_EVENTS as $e) echo ',' . (int)($r['ev'][$e] ?? 0); echo "\n"; }
    exit;
}

if ($fmt === 'ccsv') {
    $c2 = []; foreach ($sel as $r) foreach (($r['cc'] ?? []) as $c => $x) { $c2[$c]['u'] = ($c2[$c]['u'] ?? 0) + (int)$x['u']; $c2[$c]['v'] = ($c2[$c]['v'] ?? 0) + (int)$x['v']; }
    uasort($c2, fn($a, $b) => $b['u'] <=> $a['u']);
    header('Content-Type: text/csv; charset=utf-8'); header('Content-Disposition: attachment; filename="night-countries.csv"');
    echo "country,visitors,views\n"; foreach ($c2 as $c => $x) echo $c . ',' . $x['u'] . ',' . $x['v'] . "\n"; exit;
}
$tot = array_fill_keys(NS_EVENTS, 0); $uniq = 0; $cct = [];
foreach ($sel as $r) { foreach (($r['cc'] ?? []) as $c => $x) { $cct[$c]['u'] = ($cct[$c]['u'] ?? 0) + (int)$x['u']; $cct[$c]['v'] = ($cct[$c]['v'] ?? 0) + (int)$x['v']; } $uniq += (int)$r['uniq']; foreach ($r['ev'] as $e => $n) if (isset($tot[$e])) $tot[$e] += (int)$n; }
$today = gmdate('Y-m-d'); $tr = $all[$today] ?? ['uniq' => 0, 'ev' => []];
$n = fn($x) => number_format((int)$x);
$pct = fn($a, $b) => $b > 0 ? round($a * 100 / $b, 1) . '%' : '–';

// biểu đồ SVG: lượt xem (cột) + khách (đường)
$W = 940; $H = 220; $pl = 36; $pb = 22; $pw = $W - $pl - 8; $ph = $H - $pb - 8;
$cnt = max(1, count($sel)); $mx = 1;
foreach ($sel as $r) { $mx = max($mx, (int)($r['ev']['view'] ?? 0), (int)$r['uniq']); }
$bw = $pw / $cnt; $svg = '<svg viewBox="0 0 ' . $W . ' ' . $H . '" width="100%" role="img" aria-label="Biểu đồ theo ngày">';
for ($g = 0; $g <= 4; $g++) { $y = 8 + $ph - $ph * $g / 4; $svg .= '<line x1="' . $pl . '" x2="' . ($W - 8) . '" y1="' . $y . '" y2="' . $y . '" stroke="#23243a"/><text x="' . ($pl - 6) . '" y="' . ($y + 4) . '" fill="#9a9ab5" font-size="10" text-anchor="end">' . round($mx * $g / 4) . '</text>'; }
$pts = []; $i = 0;
foreach ($sel as $d => $r) {
    $v = (int)($r['ev']['view'] ?? 0); $bh = $ph * $v / $mx; $x = $pl + $i * $bw;
    $svg .= '<rect x="' . round($x + $bw * .15, 1) . '" y="' . round(8 + $ph - $bh, 1) . '" width="' . round($bw * .7, 1) . '" height="' . round($bh, 1) . '" fill="#3a3a6a"><title>' . $h($d) . ': ' . $v . ' lượt xem, ' . (int)$r['uniq'] . ' khách</title></rect>';
    $pts[] = round($x + $bw / 2, 1) . ',' . round(8 + $ph - $ph * (int)$r['uniq'] / $mx, 1);
    if ($cnt <= 12 || $i % (int)ceil($cnt / 8) === 0) $svg .= '<text x="' . round($x + $bw / 2, 1) . '" y="' . ($H - 6) . '" fill="#9a9ab5" font-size="10" text-anchor="middle">' . $h(substr($d, 5)) . '</text>';
    $i++;
}
if ($pts) $svg .= '<polyline points="' . implode(' ', $pts) . '" fill="none" stroke="#5ed6a0" stroke-width="2"/>';
$svg .= '</svg>';

$fun = [['Truy cập (view)', 'view'], ['Chạy kiểm tra thaw', 'thaw_run'], ['Tìm NIGHT', 'find_run'], ['Dựng giao dịch', 'build'], ['Ký', 'sign'], ['Gửi lên mạng', 'submit']];
$fmx = max(1, $tot['view'], $tot['thaw_run']);
$ls = $tot['lang_en'] + $tot['lang_vi'] + $tot['lang_ja'];

echo $head . '<div class="top"><div><h1>Thống kê NIGHT Sweep</h1><div class="l">Ẩn danh · giờ UTC · ' . count($sel) . ' ngày có dữ liệu</div></div><div style="display:flex;gap:8px;flex-wrap:wrap">
<form method="get" style="display:flex;gap:8px"><select name="r" onchange="this.form.submit()">';
foreach (['7' => '7 ngày', '30' => '30 ngày', '90' => '90 ngày', '400' => '400 ngày', 'all' => 'Tất cả'] as $v => $t) echo '<option value="' . $v . '"' . ((string)$range === (string)$v ? ' selected' : '') . '>' . $t . '</option>';
echo '</select><noscript><button>Xem</button></noscript></form>
<a class="b" href="?r=' . $h($range) . '&f=csv">CSV</a><a class="b" href="?r=' . $h($range) . '&f=json">JSON</a>
<form method="post">' . $csrf . '<input type="hidden" name="a" value="logout"><button>Đăng xuất</button></form></div></div>';
if ($msg) echo '<p class="m" style="margin-top:12px">' . $h($msg) . '</p>';

echo '<h2>Tổng quan</h2><div class="grid">
<div class="card"><div class="k">' . $n($tr['uniq']) . '</div><div class="l">Khách hôm nay</div><div class="s">' . $n($tr['ev']['view'] ?? 0) . ' lượt xem</div></div>
<div class="card"><div class="k">' . $n($uniq) . '</div><div class="l">Khách (cộng theo ngày)</div></div>
<div class="card"><div class="k">' . $n($tot['view']) . '</div><div class="l">Lượt xem</div></div>
<div class="card"><div class="k">' . $n($tot['thaw_run']) . '</div><div class="l">Lần kiểm tra thaw</div><div class="s">' . $pct($tot['thaw_run'], $tot['view']) . ' / lượt xem</div></div>
<div class="card"><div class="k">' . $n($tot['submit']) . '</div><div class="l">Lần gửi giao dịch</div><div class="s">' . $pct($tot['submit'], $tot['view']) . ' / lượt xem</div></div></div>
<h2>Theo ngày <span style="text-transform:none">· cột = lượt xem, đường xanh = khách</span></h2><div class="card">' . $svg . '</div>
<h2>Phễu sử dụng</h2><div class="card">';
foreach ($fun as [$lab, $e]) {
    $v = $tot[$e]; echo '<div class="fr"><span>' . $h($lab) . '</span><div class="bar"><i style="width:' . round(100 * min(1, $v / $fmx), 1) . '%"></i></div><span style="text-align:right;font-family:ui-monospace,monospace">' . $n($v) . '</span></div>';
}
echo '<p class="l" style="margin:8px 0 0">Số lần thao tác, không phải số người. Tỉ lệ so với lượt xem chỉ mang tính tham khảo.</p></div>';
echo '<h2>Quốc gia</h2><div class="card sc">';
uasort($cct, fn($a, $b) => $b['u'] <=> $a['u']);
$sumU = max(1, array_sum(array_column($cct, 'u')));
function cc_name(string $c): string {
    if ($c === 'ZZ') return 'Không xác định';
    $est = substr($c, -1) === '*'; $b = rtrim($c, '*');
    $nm = function_exists('locale_get_display_region') ? (string)locale_get_display_region('-' . $b, 'vi') : $b;
    $fl = ''; if (preg_match('/^[A-Z]{2}$/', $b)) foreach (str_split($b) as $ch) $fl .= mb_chr(0x1F1E6 + ord($ch) - 65, 'UTF-8');
    return $fl . ' ' . ($nm !== '' ? $nm : $b) . ' (' . $b . ')' . ($est ? ' · ước tính' : '');
}
if (!$cct) echo '<p class="l">Chưa có dữ liệu quốc gia (chỉ ghi cho lượt truy cập mới).</p>';
else {
    echo '<table><tr><th>Quốc gia</th><th>Khách</th><th>%</th><th style="width:30%"></th><th>Lượt xem</th></tr>';
    foreach (array_slice($cct, 0, 60, true) as $c => $x) { $p = 100 * $x['u'] / $sumU;
        echo '<tr><td style="font-family:system-ui,sans-serif;font-size:13px">' . $h(cc_name((string)$c)) . '</td><td>' . $n($x['u']) . '</td><td>' . round($p, 1) . '%</td><td><div class="bar"><i style="width:' . round($p, 1) . '%"></i></div></td><td>' . $n($x['v']) . '</td></tr>'; }
    echo '</table>';
}
echo '<p class="l" style="margin:8px 0 0"><a class="b" href="?r=' . $h($range) . '&f=ccsv">CSV quốc gia</a> Quốc gia lấy từ header của CDN/hosting (Cloudflare…); không lưu IP. Dấu * = đoán theo ngôn ngữ trình duyệt, kém chính xác.</p></div>';
echo '<h2>Ngôn ngữ &amp; tab</h2><div class="grid">';
foreach (['lang_en' => 'English', 'lang_vi' => 'Tiếng Việt', 'lang_ja' => '日本語'] as $e => $t) echo '<div class="card"><div class="k">' . $n($tot[$e]) . '</div><div class="l">Chọn ' . $t . ' · ' . $pct($tot[$e], $ls) . '</div></div>';
for ($t = 1; $t <= 5; $t++) echo '<div class="card"><div class="k">' . $n($tot["tab_$t"]) . '</div><div class="l">Mở tab ' . $t . '</div></div>';
echo '</div><h2>Bảng chi tiết</h2><div class="card sc"><table><tr><th>Ngày</th><th>khách</th>';
foreach (NS_EVENTS as $e) echo '<th>' . $h($e) . '</th>';
echo '</tr>';
foreach (array_reverse($sel, true) as $d => $r) { echo '<tr><td>' . $h($d) . '</td><td>' . (int)$r['uniq'] . '</td>'; foreach (NS_EVENTS as $e) echo '<td>' . (int)($r['ev'][$e] ?? 0) . '</td>'; echo '</tr>'; }
echo '</table></div><h2>Đổi mật khẩu</h2><div class="card" style="max-width:360px"><form method="post">' . $csrf . '<input type="hidden" name="a" value="passwd">
<label>Mật khẩu hiện tại</label><input type="password" name="o" autocomplete="current-password" required>
<label>Mật khẩu mới (≥ 12 ký tự)</label><input type="password" name="p" autocomplete="new-password" minlength="12" required><button>Đổi</button></form></div>' . $foot;
