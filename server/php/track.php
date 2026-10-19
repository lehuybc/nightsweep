<?php
// Bộ thu thống kê ẩn danh cho NIGHT Sweep: chỉ đếm sự kiện thuộc danh sách cố định.
// KHÔNG lưu địa chỉ ví, nội dung giao dịch, cookie hay IP thô. "Khách duy nhất" chỉ tính bằng băm có muối đổi mỗi ngày;
// băm của ngày cũ bị xóa, về lâu dài chỉ còn các con số tổng hợp theo ngày. Xem số liệu tại dashboard.php (có đăng nhập).
declare(strict_types=1);
define('NS_APP', 1);
require __DIR__ . '/_lib.php';

const MAX_EVENTS_PER_VISITOR_PER_DAY = 300;
const KEEP_DAYS = 400;

header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');
function out(int $code, string $body = ''): void { http_response_code($code); header('Content-Type: text/plain; charset=utf-8'); echo $body; exit; }

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') out(405, 'chỉ POST');
$sfs = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? '';
if ($sfs !== '' && $sfs !== 'same-origin') out(403, 'không cùng nguồn');
if (($_SERVER['HTTP_DNT'] ?? '') === '1' || ($_SERVER['HTTP_SEC_GPC'] ?? '') === '1') out(204);

$raw = file_get_contents('php://input', false, null, 0, 513);
if ($raw === false || $raw === '' || strlen($raw) > 512) out(400, 'nội dung sai');
$j = json_decode($raw, true);
$ev = is_array($j) ? ($j['e'] ?? null) : null;
if (!is_string($ev) || !in_array($ev, NS_EVENTS, true)) out(400, 'sự kiện không hợp lệ');

$D = ns_ensure();
$day = gmdate('Y-m-d');
$vid = substr(hash('sha256', ns_salt($D) . '|' . $day . '|' . ($_SERVER['REMOTE_ADDR'] ?? '') . '|' . substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 200)), 0, 20);

$lk = ns_lock($D);
foreach (glob($D . '/c-*.php') ?: [] as $f) { if (basename($f) !== "c-$day.php") @unlink($f); }
$cf = $D . "/c-$day.php";
$counts = ns_load($cf);
$isNew = !isset($counts[$vid]);
$cc = ns_country();
if (($counts[$vid] ?? 0) >= MAX_EVENTS_PER_VISITOR_PER_DAY) { ns_unlock($lk); out(204); }
$counts[$vid] = ($counts[$vid] ?? 0) + 1;
ns_save($cf, $counts);

$sf = $D . '/stats.php';
$all = ns_load($sf);
if (!isset($all[$day])) $all[$day] = ['uniq' => 0, 'ev' => []];
if ($isNew) $all[$day]['uniq']++;
if (!isset($all[$day]['cc'][$cc])) $all[$day]['cc'][$cc] = ['u' => 0, 'v' => 0];
if ($isNew) $all[$day]['cc'][$cc]['u']++;
if ($ev === 'view') $all[$day]['cc'][$cc]['v']++;
$all[$day]['ev'][$ev] = ($all[$day]['ev'][$ev] ?? 0) + 1;
ksort($all);
while (count($all) > KEEP_DAYS) { array_shift($all); }
ns_save($sf, $all);
ns_unlock($lk);
out(204);
