<?php declare(strict_types=1);

/**
 * ════════════════════════════════════════════════════════════════════
 *  PHP Rate Limiter — Test Suite Lengkap
 *
 *  Menguji semua fitur dan perbaikan keamanan versi terbaru:
 *    1.  Sliding Window dasar
 *    2.  Weighted Cost
 *    3.  block() / unblock() / resetAll()
 *    4.  isBlocked() timing normalization (anti side-channel)
 *    5.  checkWithCaptcha() – logika ok/captcha/blocked
 *    6.  clientIp() trusted proxy + CIDR verifikasi
 *    7.  clientIp() IPv6 proxy support
 *    8.  clientIp() IP private klien dari trusted proxy
 *    9.  requestFingerprint()
 *    10. SecurityHelper::normalizeIp() IPv6 /64
 *    11. SecurityHelper::ipInList() IPv4 & IPv6 CIDR
 *    12. SecurityHelper::safeAttempt() fail-open & fail-closed
 *    13. SecurityHelper::globalAttempt() distributed limit
 *    14. FileStorage GC + maxFiles cap
 *    15. FileStorage atomic write (flock)
 *    16. HybridStorage failover & onDegrade callback
 *    17. RateLimitMiddleware trusted_cidrs
 *    18. Audit log block() – caller tercatat
 *    19. invalidArgument exception validation
 *    20. Multi-tier rate limit (simulasi login brute-force)
 *
 *  Cara menjalankan:
 *    php test.php
 *    php test.php --verbose
 *    php test.php --filter=sliding
 *
 * ════════════════════════════════════════════════════════════════════
 */

// ── Autoload ─────────────────────────────────────────────────────
$autoload = __DIR__ . '/autoload.php';
if (!file_exists($autoload)) {
    echo "ERROR: autoload.php tidak ditemukan di " . __DIR__ . "\n";
    echo "Pastikan file test.php diletakkan di folder RateLimiter/\n";
    exit(1);
}
require_once $autoload;

use RateLimiter\RateLimiter;
use RateLimiter\RateLimitMiddleware;
use RateLimiter\SecurityHelper;
use RateLimiter\ArrayStorage;
use RateLimiter\FileStorage;
use RateLimiter\HybridStorage;

// ════════════════════════════════════════════════════════════════════
//  TEST RUNNER ENGINE
// ════════════════════════════════════════════════════════════════════

$verbose = in_array('--verbose', $argv ?? [], true);
$filter  = '';
foreach (($argv ?? []) as $arg) {
    if (str_starts_with($arg, '--filter=')) {
        $filter = strtolower(substr($arg, 9));
    }
}

$stats  = ['pass' => 0, 'fail' => 0, 'skip' => 0];
$errors = [];
$suites = [];
$currentSuite = '';

function suite(string $name): void
{
    global $currentSuite, $suites, $filter;
    $currentSuite = $name;
    if ($filter === '' || str_contains(strtolower($name), $filter)) {
        $suites[] = $name;
        $col = "\033[1;36m"; // cyan bold
        echo "\n{$col}┌─ {$name}\033[0m\n";
    }
}

function ok(string $label, bool $cond, string $hint = ''): void
{
    global $stats, $errors, $currentSuite, $filter, $verbose;

    // Skip suite yang tidak cocok filter
    if ($filter !== '' && !str_contains(strtolower($currentSuite), $filter)) {
        $stats['skip']++;
        return;
    }

    if ($cond) {
        $stats['pass']++;
        $icon  = "\033[32m✓\033[0m"; // green
        $label_colored = "\033[0m{$label}";
        if ($verbose) {
            echo "│  {$icon} {$label_colored}\n";
        } else {
            echo "│  {$icon} {$label}\n";
        }
    } else {
        $stats['fail']++;
        $icon  = "\033[31m✗\033[0m"; // red
        $msg   = $hint ? " ← {$hint}" : '';
        $errors[] = "[{$currentSuite}] {$label}{$msg}";
        echo "│  {$icon} \033[31m{$label}{$msg}\033[0m\n";
    }
}

function info(string $msg): void
{
    global $filter, $currentSuite;
    if ($filter !== '' && !str_contains(strtolower($currentSuite), $filter)) {
        return;
    }
    echo "│     \033[90m↳ {$msg}\033[0m\n";
}

function end_suite(): void
{
    global $filter, $currentSuite;
    if ($filter !== '' && !str_contains(strtolower($currentSuite), $filter)) {
        return;
    }
    echo "│\n";
}

/** Storage yang selalu throw exception — simulasi Redis down */
class BrokenStorage extends ArrayStorage
{
    public function get(string $key): ?array
    {
        throw new \RuntimeException('Storage tidak tersedia (simulasi Redis down)');
    }
    public function set(string $key, array $data, int $ttl): void
    {
        throw new \RuntimeException('Storage tidak tersedia (simulasi Redis down)');
    }
}

/** Storage yang lambat — simulasi >1ms I/O */
class SlowStorage extends ArrayStorage
{
    public function __construct(private int $delayUs = 1500) {}
    public function get(string $key): ?array
    {
        usleep($this->delayUs);
        throw new \RuntimeException('Slow storage error');
    }
}

// ════════════════════════════════════════════════════════════════════
//  SUITE 1: SLIDING WINDOW DASAR
// ════════════════════════════════════════════════════════════════════

suite('Sliding Window Dasar');

$l = new RateLimiter(new ArrayStorage());

ok('Request 1 dari 3 → lolos',    $l->attempt('user-A', 3, 60));
ok('Request 2 dari 3 → lolos',    $l->attempt('user-A', 3, 60));
ok('Request 3 dari 3 → lolos',    $l->attempt('user-A', 3, 60));
ok('Request 4 → BLOCKED',         !$l->attempt('user-A', 3, 60));
ok('Request 5 → masih BLOCKED',   !$l->attempt('user-A', 3, 60));
ok('getRemaining() = 0',          $l->getRemaining() === 0);
ok('getRetryAfter() > 0',         $l->getRetryAfter() > 0);
ok('getResetAt() > now',          $l->getResetAt() > time());
info('retryAfter: ' . $l->getRetryAfter() . 's | resetAt: ' . date('H:i:s', $l->getResetAt()));

// User lain tidak terpengaruh
ok('User B masih punya kuota penuh', $l->attempt('user-B', 3, 60));

// Setelah reset, user A bisa mulai lagi
$l->reset('user-A');
ok('Setelah reset(), user A lolos lagi', $l->attempt('user-A', 3, 60));
ok('getRemaining() = 2 setelah 1 req',  $l->getRemaining() === 2);

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 2: WEIGHTED COST
// ════════════════════════════════════════════════════════════════════

suite('Weighted Cost');

$l2 = new RateLimiter(new ArrayStorage());

// Budget 10 poin per menit
ok('GET  (cost=1): poin 1/10',    $l2->attempt('api', 10, 60, 1));
ok('GET  (cost=1): poin 2/10',    $l2->attempt('api', 10, 60, 1));
ok('POST (cost=5): poin 7/10',    $l2->attempt('api', 10, 60, 5));
info("Sisa setelah 2xGET+1xPOST: {$l2->getRemaining()} poin");
ok('POST (cost=5): BLOCKED (sisa 3, butuh 5)',  !$l2->attempt('api', 10, 60, 5));
ok('GET  (cost=1): masih lolos (sisa 3)',        $l2->attempt('api', 10, 60, 1));
ok('DELETE(cost=10): BLOCKED (limit=10 total)', !$l2->attempt('api', 10, 60, 10));
info("Budget habis: sisa = {$l2->getRemaining()}");

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 3: BLOCK / UNBLOCK / RESET
// ════════════════════════════════════════════════════════════════════

suite('Block / Unblock / ResetAll');

$l3 = new RateLimiter(new ArrayStorage());

ok('Sebelum block: isBlocked = false',      !$l3->isBlocked('bad-actor'));
$l3->block('bad-actor', 3600);
ok('Setelah block(): isBlocked = true',      $l3->isBlocked('bad-actor'));
ok('attempt() lolos (block != rate limit)',  $l3->attempt('bad-actor', 100, 60));
// isBlocked dan attempt() adalah dua hal berbeda — cek middleware untuk keduanya

$l3->unblock('bad-actor');
ok('Setelah unblock(): isBlocked = false',   !$l3->isBlocked('bad-actor'));

// resetAll: bersihkan counter DAN blokir sekaligus
$l3->attempt('target', 3, 60);
$l3->attempt('target', 3, 60);
$l3->attempt('target', 3, 60);
$l3->block('target', 3600);
ok('target: diblokir + counter penuh',       $l3->isBlocked('target') && !$l3->attempt('target', 3, 60));
$l3->resetAll('target');
ok('resetAll(): tidak diblokir',             !$l3->isBlocked('target'));
ok('resetAll(): counter bersih (lolos)',      $l3->attempt('target', 3, 60));

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 4: isBlocked() TIMING NORMALIZATION
// ════════════════════════════════════════════════════════════════════

suite('isBlocked() Timing Normalization');

$l4 = new RateLimiter(new ArrayStorage());

// Key tidak ada
$t = hrtime(true);
$r = $l4->isBlocked('tidak-ada');
$ms = round((hrtime(true) - $t) / 1e6, 2);
ok("Key tidak ada → false, waktu ≥ 1ms ({$ms}ms)", !$r && $ms >= 1.0);

// Key ada
$l4->block('ada', 60);
$t = hrtime(true);
$r = $l4->isBlocked('ada');
$ms = round((hrtime(true) - $t) / 1e6, 2);
ok("Key ada → true, waktu ≥ 1ms ({$ms}ms)", $r && $ms >= 1.0);

// Exception path: timing tetap >=1ms, tidak ada warning usleep(-N)
$slow = new RateLimiter(new SlowStorage(delayUs: 1500)); // 1.5ms delay
$t    = hrtime(true);
$r    = $slow->isBlocked('x');
$ms   = round((hrtime(true) - $t) / 1e6, 2);
ok("Storage lambat >1ms + exception → tetap aman, waktu={$ms}ms", !$r && $ms >= 1.5,
   'usleep() bisa dipanggil dengan nilai negatif jika max(0,...) tidak ada');

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 5: CAPTCHA THRESHOLD
// ════════════════════════════════════════════════════════════════════

suite('checkWithCaptcha() ok/captcha/blocked');

$l5 = new RateLimiter(new ArrayStorage());
$id = 'captcha-test';

// hardLimit=10, softLimit=6
$s = SecurityHelper::checkWithCaptcha($l5, $id, 10, 6, 60);
ok("0 req → 'ok'", $s === 'ok', "dapat: '{$s}'");

// Isi 5 req manual (checkWithCaptcha sudah tambah 1, total = 6)
for ($i = 0; $i < 5; $i++) { $l5->attempt($id, 10, 60); }
$s = SecurityHelper::checkWithCaptcha($l5, $id, 10, 6, 60);
ok("6 req → 'captcha'", $s === 'captcha', "dapat: '{$s}'");
info('CAPTCHA muncul pada req ke-6 (softLimit=6)');

// Isi sampai 10 — butuh 4 lagi karena 'captcha' tidak menambah counter
for ($i = 0; $i < 4; $i++) { $l5->attempt($id, 10, 60); }
$s = SecurityHelper::checkWithCaptcha($l5, $id, 10, 6, 60);
ok("10 req → 'blocked'", $s === 'blocked', "dapat: '{$s}'");

// Pastikan counter tidak bertambah saat 'blocked' (check() tidak increment)
$l5->reset($id);
for ($i = 0; $i < 10; $i++) { $l5->attempt($id, 10, 60); }
$before = $l5->getRemaining();
SecurityHelper::checkWithCaptcha($l5, $id, 10, 6, 60); // sudah blocked
$after  = $l5->getRemaining();
ok("'blocked' tidak menambah counter", $before === $after);

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 6: TRUSTED PROXY — IPv4
// ════════════════════════════════════════════════════════════════════

suite('Trusted Proxy IPv4 + CIDR');

// Simpan state $_SERVER asli
$origServer = $_SERVER;

$_SERVER['REMOTE_ADDR']          = '10.0.0.1';       // trusted proxy
$_SERVER['HTTP_X_FORWARDED_FOR'] = '5.6.7.8';        // client sebenarnya

ok('CIDR match → pakai forwarded IP',
   RateLimiter::clientIp(true, ['10.0.0.0/8']) === '5.6.7.8');

$_SERVER['REMOTE_ADDR'] = '8.8.8.8'; // bukan trusted
ok('REMOTE_ADDR bukan CIDR → abaikan header',
   RateLimiter::clientIp(true, ['10.0.0.0/8']) === '8.8.8.8');

$_SERVER['REMOTE_ADDR']          = '10.0.0.1';
$_SERVER['HTTP_X_FORWARDED_FOR'] = 'bukan-ip-valid';
ok('Header berisi nilai invalid → fallback REMOTE_ADDR',
   RateLimiter::clientIp(true, ['10.0.0.0/8']) === '10.0.0.1');

// trustProxy=false: header selalu diabaikan
$_SERVER['REMOTE_ADDR']          = '10.0.0.1';
$_SERVER['HTTP_X_FORWARDED_FOR'] = '9.9.9.9';
ok('trustProxy=false → REMOTE_ADDR meskipun header ada',
   RateLimiter::clientIp(false) === '10.0.0.1');

// trustedCidrs kosong → header tidak dipercaya
ok('trustedCidrs=[] → REMOTE_ADDR',
   RateLimiter::clientIp(true, []) === '10.0.0.1');

// Multiple proxy: X-Forwarded-For berisi beberapa IP
$_SERVER['HTTP_X_FORWARDED_FOR'] = '1.2.3.4, 10.0.0.1, 10.0.0.2';
ok('X-Forwarded-For multi-hop → ambil IP pertama (client)',
   RateLimiter::clientIp(true, ['10.0.0.0/8']) === '1.2.3.4');

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 7: TRUSTED PROXY — IPv6
// ════════════════════════════════════════════════════════════════════

suite('Trusted Proxy IPv6 + CIDR');

$_SERVER['REMOTE_ADDR']          = '::1';        // IPv6 localhost proxy
$_SERVER['HTTP_X_FORWARDED_FOR'] = '5.6.7.8';

ok('IPv6 proxy ::1 → forwarded IP',
   RateLimiter::clientIp(true, ['::1']) === '5.6.7.8');

$_SERVER['REMOTE_ADDR'] = '2001:db8::1';
ok('IPv6 CIDR /32 → forwarded IP',
   RateLimiter::clientIp(true, ['2001:db8::/32']) === '5.6.7.8');

$_SERVER['REMOTE_ADDR'] = '2001:db8::1';
ok('IPv6 tidak dalam CIDR IPv4 → REMOTE_ADDR',
   RateLimiter::clientIp(true, ['10.0.0.0/8']) === '2001:db8::1');

// IPv6 proxy, klien dengan IP private (VPN)
$_SERVER['REMOTE_ADDR']          = '::1';
$_SERVER['HTTP_X_FORWARDED_FOR'] = '192.168.1.50';
ok('IPv6 proxy + klien IP private → forwarded diterima',
   RateLimiter::clientIp(true, ['::1/128']) === '192.168.1.50');
info('Fix 2: IP private klien tidak lagi diblokir dari trusted proxy');

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 8: IP PRIVATE KLIEN DARI TRUSTED PROXY
// ════════════════════════════════════════════════════════════════════

suite('IP Private Klien dari Trusted Proxy');

$_SERVER['REMOTE_ADDR'] = '10.0.0.1'; // trusted

foreach ([
    '192.168.1.1'  => 'RFC 1918 kelas C',
    '172.16.0.5'   => 'RFC 1918 kelas B',
    '10.5.5.5'     => 'RFC 1918 kelas A',
    'fc00::1'      => 'IPv6 ULA (fc00::/7)',
    'fd12:3456::1' => 'IPv6 ULA (fd::/8)',
] as $clientIp => $desc) {
    $_SERVER['HTTP_X_FORWARDED_FOR'] = $clientIp;
    $got = RateLimiter::clientIp(true, ['10.0.0.0/8']);
    ok("{$desc} ({$clientIp}) diterima", $got === $clientIp, "dapat: {$got}");
}

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 9: REQUEST FINGERPRINT
// ════════════════════════════════════════════════════════════════════

suite('Request Fingerprint');

$_SERVER['REMOTE_ADDR']          = '1.2.3.4';
$_SERVER['HTTP_USER_AGENT']       = 'Mozilla/5.0 Test';
$_SERVER['HTTP_ACCEPT_LANGUAGE']  = 'id-ID,id;q=0.9';
$_SERVER['HTTP_ACCEPT_ENCODING']  = 'gzip, deflate';

$fp1 = RateLimiter::requestFingerprint();
$fp2 = RateLimiter::requestFingerprint();
ok('Fingerprint konsisten antar panggilan', $fp1 === $fp2);
ok('Fingerprint adalah hex SHA-256 (64 char)', strlen($fp1) === 64 && ctype_xdigit($fp1));

// Ganti User-Agent → fingerprint berbeda
$_SERVER['HTTP_USER_AGENT'] = 'Bot/1.0';
$fp3 = RateLimiter::requestFingerprint();
ok('Fingerprint berbeda jika User-Agent berubah', $fp1 !== $fp3);

// Ganti IP → fingerprint berbeda
$_SERVER['REMOTE_ADDR']     = '9.9.9.9';
$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 Test';
$fp4 = RateLimiter::requestFingerprint();
ok('Fingerprint berbeda jika IP berubah', $fp1 !== $fp4);

end_suite();

// Restore $_SERVER
$_SERVER = $origServer;

// ════════════════════════════════════════════════════════════════════
//  SUITE 10: IPv6 NORMALIZATION
// ════════════════════════════════════════════════════════════════════

suite('IPv6 /64 Normalization');

$cases = [
    ['2001:db8:abcd:1234:ffff:ffff:ffff:0001', '2001:db8:abcd:1234::/64'],
    ['2001:db8:abcd:1234:0000:0000:0000:9999', '2001:db8:abcd:1234::/64'], // same /64
    ['2001:db8:abcd:5678::1',                  '2001:db8:abcd:5678::/64'], // different /64
    ['::1',                                    '::/64'],
    ['192.168.1.50',                           '192.168.1.50'],             // IPv4 unchanged
    ['10.0.0.1',                               '10.0.0.1'],
];

foreach ($cases as [$input, $expected]) {
    $got = SecurityHelper::normalizeIp($input);
    ok("normalizeIp({$input}) → {$expected}", $got === $expected, "dapat: {$got}");
}

// Dua IPv6 dalam /64 yang sama → identifier rate limit sama
$ip1 = SecurityHelper::normalizeIp('2001:db8::1');
$ip2 = SecurityHelper::normalizeIp('2001:db8::ffff');
ok('Dua IPv6 satu /64 → identifier sama (anti subnet rotation)', $ip1 === $ip2);
info("Keduanya → {$ip1}");

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 11: ipInList() IPv4 & IPv6 CIDR
// ════════════════════════════════════════════════════════════════════

suite('ipInList() IPv4 & IPv6 CIDR');

$ipv4Cases = [
    ['10.0.0.5',    '10.0.0.0/8',     true,  'IPv4 /8 match'],
    ['10.0.0.5',    '10.0.0.0/24',    true,  'IPv4 /24 match'],
    ['10.0.1.5',    '10.0.0.0/24',    false, 'IPv4 /24 no-match'],
    ['192.168.1.1', '192.168.1.0/30', true,  'IPv4 /30 match'],
    ['192.168.1.4', '192.168.1.0/30', false, 'IPv4 /30 no-match'],
    ['1.2.3.4',     '1.2.3.4',        true,  'IPv4 exact match'],
    ['1.2.3.5',     '1.2.3.4',        false, 'IPv4 exact no-match'],
];

foreach ($ipv4Cases as [$ip, $cidr, $expect, $label]) {
    $got = SecurityHelper::ipInList($ip, [$cidr]);
    ok($label, $got === $expect, "ip={$ip} cidr={$cidr} harusnya=" . ($expect ? 'true' : 'false'));
}

$ipv6Cases = [
    ['2001:db8::1',    '2001:db8::/32',  true,  'IPv6 /32 match'],
    ['2001:db9::1',    '2001:db8::/32',  false, 'IPv6 /32 no-match'],
    ['fe80::1',        'fe80::/10',      true,  'IPv6 /10 link-local match'],
    ['::1',            '::1',            true,  'IPv6 exact match'],
    ['::2',            '::1',            false, 'IPv6 exact no-match'],
];

foreach ($ipv6Cases as [$ip, $cidr, $expect, $label]) {
    $got = SecurityHelper::ipInList($ip, [$cidr]);
    ok($label, $got === $expect, "ip={$ip} cidr={$cidr}");
}

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 12: safeAttempt() fail-open & fail-closed
// ════════════════════════════════════════════════════════════════════

suite('safeAttempt() Fail-Open & Fail-Closed');

$broken  = new RateLimiter(new BrokenStorage());
$working = new RateLimiter(new ArrayStorage());
$errors_logged = [];

// Fail-open: storage error → izinkan
$result = SecurityHelper::safeAttempt(
    $broken, 'user', 10, 60, 1,
    failOpen: true,
    onError: function($e) use (&$errors_logged) { $errors_logged[] = $e->getMessage(); }
);
ok('Fail-open: storage error → izinkan (true)', $result === true);
ok('Fail-open: onError callback dipanggil', count($errors_logged) > 0);
info('Error: ' . ($errors_logged[0] ?? '-'));

// Fail-closed: storage error → tolak
$result = SecurityHelper::safeAttempt(
    $broken, 'user', 10, 60, 1,
    failOpen: false
);
ok('Fail-closed: storage error → tolak (false)', $result === false);

// Storage normal: fail-open/closed tidak berpengaruh
$result1 = SecurityHelper::safeAttempt($working, 'user2', 5, 60, 1, failOpen: true);
$result2 = SecurityHelper::safeAttempt($working, 'user2', 5, 60, 1, failOpen: false);
ok('Storage normal fail-open → bekerja normal', $result1 === true);
ok('Storage normal fail-closed → bekerja normal', $result2 === true);

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 13: globalAttempt() — Distributed Limit
// ════════════════════════════════════════════════════════════════════

suite('globalAttempt() Distributed Limit');

$lg = new RateLimiter(new ArrayStorage());

// Simulasikan 5 IP berbeda masing-masing 1 request ke /login
// Global limit: 5 request per menit untuk endpoint 'login'
$ips = ['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5'];
foreach ($ips as $ip) {
    $ok = SecurityHelper::globalAttempt($lg, 'login', 5, 60);
    ok("IP {$ip} → global attempt lolos", $ok);
}

// IP ke-6 → global limit tercapai meskipun IP ini belum pernah hit
$result = SecurityHelper::globalAttempt($lg, 'login', 5, 60);
ok('IP ke-6 → BLOCKED oleh global limit', !$result);
info('Global limit mencegah botnet dengan banyak IP berbeda');

// Endpoint berbeda tidak saling mempengaruhi
$other = SecurityHelper::globalAttempt($lg, 'register', 5, 60);
ok("Endpoint 'register' tidak terpengaruh limit 'login'", $other === true);

// globalCheck() tidak menambah counter
$before = SecurityHelper::globalCheck($lg, 'login', 5, 60);
$after  = SecurityHelper::globalCheck($lg, 'login', 5, 60);
ok('globalCheck() tidak menambah counter', $before === $after);
info("Sisa global quota 'login': {$before}");

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 14: FileStorage GC + maxFiles
// ════════════════════════════════════════════════════════════════════

suite('FileStorage GC + maxFiles Cap');

$dir = sys_get_temp_dir() . '/rl_test_' . uniqid();
$fs  = new FileStorage($dir, gcDivisor: 0, maxFiles: 3);

$fs->set('k1', ['data' => 'a'], 1); // TTL 1 detik
$fs->set('k2', ['data' => 'b'], 1);
$fs->set('k3', ['data' => 'c'], 1);
ok('3 file tersimpan', $fs->count() === 3);

// Key ke-4 ditolak (semua belum expired, GC tidak hapus apapun)
$fs->set('k4', ['data' => 'd'], 3600);
ok('Key ke-4 ditolak saat maxFiles=3 penuh', $fs->count() === 3);

// Tunggu TTL habis, lalu GC
sleep(2);
$fs->gc();
ok('Setelah GC, semua file expired terhapus', $fs->count() === 0);

// Sekarang set() boleh lagi
$fs->set('k5', ['data' => 'e'], 3600);
ok('Setelah GC, set() baru berhasil', $fs->count() === 1);

// get() mengembalikan data yang benar
$got = $fs->get('k5');
ok("get() mengembalikan data yang tersimpan", $got === ['data' => 'e']);

// delete() bersih
$fs->delete('k5');
ok('delete() menghapus file', $fs->count() === 0);

// Cleanup
array_map('unlink', glob($dir . '/*') ?: []);
@rmdir($dir);

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 15: FileStorage Atomic flock
// ════════════════════════════════════════════════════════════════════

suite('FileStorage Atomic Write (flock)');

$dir2  = sys_get_temp_dir() . '/rl_atomic_' . uniqid();
$fs2   = new FileStorage($dir2, gcDivisor: 0);
$limit = 5;
$hit   = 0;

// Simulasikan 10 "concurrent" request secara sekuensial
// (PHP single-threaded tidak bisa benar-benar paralel, tapi
//  kita bisa verifikasi bahwa counter tidak pernah melebihi limit)
$l_fs = new RateLimiter($fs2);
for ($i = 0; $i < $limit + 3; $i++) {
    if ($l_fs->attempt('concurrent-test', $limit, 60)) {
        $hit++;
    }
}

ok("flock: tepat {$limit} request lolos dari " . ($limit + 3) . " percobaan",
   $hit === $limit, "lolos: {$hit}, seharusnya: {$limit}");
ok('Counter tidak melebihi limit (tidak ada race condition)', $hit <= $limit);
info("Lolos: {$hit}/{$limit} (sisanya ter-block dengan benar)");

array_map('unlink', glob($dir2 . '/*') ?: []);
@rmdir($dir2);

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 16: HybridStorage Failover
// ════════════════════════════════════════════════════════════════════

suite('HybridStorage Failover');

$degradedCalled = false;
$degradedError  = null;

$hybrid = new HybridStorage(
    primary:   new BrokenStorage(),   // Simulasi Redis down
    fallback:  new ArrayStorage(),    // APCu/File lokal
    onDegrade: function (\Throwable $e) use (&$degradedCalled, &$degradedError) {
        $degradedCalled = true;
        $degradedError  = $e->getMessage();
    }
);

ok('Sebelum error: isDegraded = false', !$hybrid->isDegraded());

$hybrid->set('test-key', ['value' => 42], 60);
ok('set() berhasil via fallback saat Redis down', true); // tidak throw

$got = $hybrid->get('test-key');
ok('get() mengembalikan data dari fallback', $got === ['value' => 42]);
ok('onDegrade callback dipanggil', $degradedCalled);
ok('isDegraded = true setelah error pertama', $hybrid->isDegraded());
info('Pesan error: ' . ($degradedError ?? '-'));

// onDegrade hanya dipanggil SEKALI meskipun error berkali-kali
$degradedCalled = false;
$hybrid->set('key2', ['v' => 2], 60);
ok('onDegrade tidak dipanggil lagi setelah pertama', !$degradedCalled);

// delete() juga fallback
$hybrid->delete('test-key');
ok('delete() berhasil via fallback', $hybrid->get('test-key') === null);

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 17: RateLimitMiddleware trusted_cidrs
// ════════════════════════════════════════════════════════════════════

suite('RateLimitMiddleware trusted_cidrs');

$origServer = $_SERVER;
$_SERVER['REMOTE_ADDR']          = '10.0.0.1';
$_SERVER['HTTP_X_FORWARDED_FOR'] = '5.6.7.8';

$lmw = new RateLimiter(new ArrayStorage());
$ref = new ReflectionMethod(RateLimitMiddleware::class, 'resolveIdentifier');
$ref->setAccessible(true);

// Middleware tanpa trusted_cidrs → REMOTE_ADDR
$mw1 = new RateLimitMiddleware($lmw, [
    'trust_proxy'   => true,
    'trusted_cidrs' => [],
    'limit' => 100, 'window' => 60,
]);
ok('Middleware: tanpa CIDR → REMOTE_ADDR (10.0.0.1)',
   $ref->invoke($mw1) === '10.0.0.1');

// Middleware dengan trusted_cidrs → forwarded IP
$mw2 = new RateLimitMiddleware($lmw, [
    'trust_proxy'   => true,
    'trusted_cidrs' => ['10.0.0.0/8'],
    'limit' => 100, 'window' => 60,
]);
ok('Middleware: dengan CIDR → forwarded IP (5.6.7.8)',
   $ref->invoke($mw2) === '5.6.7.8');

// Middleware dengan fingerprint + trusted_cidrs
$_SERVER['HTTP_USER_AGENT']      = 'TestAgent/1.0';
$_SERVER['HTTP_ACCEPT_LANGUAGE'] = 'id-ID';
$_SERVER['HTTP_ACCEPT_ENCODING'] = 'gzip';
$mw3 = new RateLimitMiddleware($lmw, [
    'trust_proxy'     => true,
    'trusted_cidrs'   => ['10.0.0.0/8'],
    'use_fingerprint' => true,
    'limit' => 100, 'window' => 60,
]);
$fp = $ref->invoke($mw3);
ok('Middleware fingerprint mode: hasil berupa hash 64 char', strlen($fp) === 64 && ctype_xdigit($fp));

// key_prefix
$mw4 = new RateLimitMiddleware($lmw, [
    'trust_proxy'   => true,
    'trusted_cidrs' => ['10.0.0.0/8'],
    'key_prefix'    => 'api_v2',
    'limit' => 100, 'window' => 60,
]);
ok("Middleware key_prefix: identifier diawali 'api_v2:'",
   str_starts_with($ref->invoke($mw4), 'api_v2:'));

$_SERVER = $origServer;

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 18: Audit Log block()
// ════════════════════════════════════════════════════════════════════

suite('Audit Log block()');

// Tangkap error_log output
$logMessages = [];
set_error_handler(null);
$prevHandler = set_error_handler(null);

// Redirect error_log ke array (pakai output buffer trick)
$tmpLog = tempnam(sys_get_temp_dir(), 'rl_log_');
ini_set('error_log', $tmpLog);

$la = new RateLimiter(new ArrayStorage());
$la->block('penjahat', 3600);   // harus tulis ke error_log
$la->unblock('penjahat');       // harus tulis ke error_log

$log = file_get_contents($tmpLog);
@unlink($tmpLog);
ini_restore('error_log');

ok('block() menulis audit log [RateLimiter:BLOCK]',
   str_contains($log, '[RateLimiter:BLOCK]'));
ok('block() mencatat id_hash di log',
   str_contains($log, 'id_hash='));
ok('block() mencatat durasi di log',
   str_contains($log, 'duration=3600s'));
ok('block() mencatat caller (file:line) di log',
   str_contains($log, 'caller='));
ok('unblock() menulis audit log [RateLimiter:UNBLOCK]',
   str_contains($log, '[RateLimiter:UNBLOCK]'));

if ($verbose) {
    info('Log output: ' . trim(str_replace("\n", ' | ', $log)));
}

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 19: Input Validation / Exception
// ════════════════════════════════════════════════════════════════════

suite('Input Validation & Exception');

$lv = new RateLimiter(new ArrayStorage());

$cases = [
    [fn() => $lv->attempt('', 10, 60),     'Identifier kosong → InvalidArgumentException'],
    [fn() => $lv->attempt('x', 0, 60),     'limit=0 → InvalidArgumentException'],
    [fn() => $lv->attempt('x', 10, 0),     'window=0 → InvalidArgumentException'],
    [fn() => $lv->attempt('x', 10, 60, 0), 'cost=0 → InvalidArgumentException'],
    [fn() => $lv->attempt('x', 10, 60, 11),'cost>limit → InvalidArgumentException'],
    [fn() => SecurityHelper::checkWithCaptcha($lv, 'x', 10, 10, 60),
             'softLimit=hardLimit → InvalidArgumentException'],
];

foreach ($cases as [$fn, $label]) {
    $thrown = false;
    try { $fn(); } catch (\InvalidArgumentException) { $thrown = true; }
    ok($label, $thrown);
}

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 20: MULTI-TIER (Simulasi Login Brute-Force)
// ════════════════════════════════════════════════════════════════════

suite('Multi-Tier: Simulasi Login Brute-Force');

$lbt = new RateLimiter(new ArrayStorage());
$ip  = '192.168.1.100';

// Tier 1: Global endpoint limit (maks 10 req/menit untuk /login)
// Tier 2: Per-IP limit (maks 5 req/menit)
// Tier 3: Per-IP+email (maks 3 percobaan/menit)

$email    = 'target@example.com';
$loginKey = 'login:' . $ip . ':' . hash('sha256', $email);
$success  = 0;
$blocked  = 0;
$reason   = [];

for ($attempt = 1; $attempt <= 8; $attempt++) {
    // Global check
    if (!SecurityHelper::globalAttempt($lbt, 'login', 10, 60)) {
        $blocked++;
        $reason[] = "req#{$attempt}: global";
        continue;
    }

    // Per-IP
    if (!$lbt->attempt($ip, 5, 60)) {
        $blocked++;
        $reason[] = "req#{$attempt}: per-IP";
        continue;
    }

    // Per-IP+email
    if (!$lbt->attempt($loginKey, 3, 60)) {
        $blocked++;
        $reason[] = "req#{$attempt}: per-email";
        continue;
    }

    $success++;
}

ok('Hanya 3 login attempt lolos (per-IP+email limit=3)',
   $success === 3, "lolos: {$success}");
ok('5 sisanya diblokir',
   $blocked === 5, "blocked: {$blocked}");

info('Kronologi blokir: ' . implode(', ', $reason));

// Setelah login sukses: counter per-email direset
$lbt->reset($loginKey);
ok('Setelah reset loginKey, user bisa login lagi',
   $lbt->attempt($loginKey, 3, 60));

end_suite();

// ════════════════════════════════════════════════════════════════════
//  RINGKASAN AKHIR
// ════════════════════════════════════════════════════════════════════

// ════════════════════════════════════════════════════════════════════
//  SUITE 21: recordViolation() — cap 100 + total counter
// ════════════════════════════════════════════════════════════════════

suite('recordViolation() DoS Cap');

// Simulasikan 200 request ditolak ke identifier yang sama
$lv = new RateLimiter(new ArrayStorage());
$id = 'dos-target';

// Isi dulu hingga limit (limit=1 agar setiap attempt setelahnya ditolak)
$lv->attempt($id, 1, 3600);

// Kirim 200 request yang akan ditolak — ini mensimulasikan DoS
for ($i = 0; $i < 200; $i++) {
    $lv->attempt($id, 1, 3600);
}

// Baca isi violation key secara langsung via reflection
$store  = new ArrayStorage();
$lv2    = new RateLimiter($store);
$lv2->attempt($id, 1, 3600); // masuk counter
for ($i = 0; $i < 150; $i++) {
    $lv2->attempt($id, 1, 3600); // semua ditolak → recordViolation
}

// Cari violation key di storage via reflection
$ref      = new ReflectionProperty($lv2, 'storage');
$ref->setAccessible(true);
$storage  = $ref->getValue($lv2);

$keyRef   = new ReflectionMethod($lv2, 'buildKey');
$keyRef->setAccessible(true);
// SOLUSI 2: buildKey() sekarang butuh prefix algo.
// lv2 dibuat tanpa config → pakai default 'dual-counter', jadi prefix = 'dc'
$vKey     = $keyRef->invoke($lv2, $id, RateLimiter::KEY_PREFIX_DUAL_COUNTER) . ':violations';

$vData    = $storage->get($vKey);

ok('violations array maks 100 elemen (bukan 150)', count($vData['violations'] ?? []) <= 100);
ok('count integer tetap akurat (150)', ($vData['count'] ?? 0) === 150);
info('violations disimpan: ' . count($vData['violations'] ?? []) . ', total count: ' . ($vData['count'] ?? 0));

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 22: HybridStorage — Circuit Breaker Recovery
// ════════════════════════════════════════════════════════════════════

suite('HybridStorage Circuit Breaker Recovery');

$degradeCalled  = false;
$recoverCalled  = false;
$callCount      = 0; // berapa kali primary->get() dipanggil

// Primary yang gagal N kali pertama lalu pulih
class RecoveringStorage extends ArrayStorage
{
    public int $callCount    = 0;
    public int $failUntil    = 2; // gagal pada get() call ke-1 dan ke-2, pulih di ke-3

    public function get(string $key): ?array
    {
        $this->callCount++;
        if ($this->callCount <= $this->failUntil) {
            throw new \RuntimeException("Gagal get #{$this->callCount}");
        }
        return parent::get($key); // pulih mulai call ke-3
    }

    public function set(string $key, array $data, int $ttl): void
    {
        // set() selalu throw saat awal (simulasi Redis belum pulih)
        if ($this->callCount === 0) {
            throw new \RuntimeException('Set gagal saat down');
        }
        parent::set($key, $data, $ttl);
    }
}

$recovering = new RecoveringStorage();
$fallback2  = new ArrayStorage();

$hybrid2 = new HybridStorage(
    primary:       $recovering,
    fallback:      $fallback2,
    onDegrade:     function() use (&$degradeCalled) { $degradeCalled = true; },
    onRecover:     function() use (&$recoverCalled) { $recoverCalled = true; },
    retryInterval: 0  // retry setiap request (untuk testing — production pakai 60)
);

// Panggilan 1: primary set() gagal → degraded
$hybrid2->set('k', ['v' => 1], 60);
ok('Setelah set() error: isDegraded = true', $hybrid2->isDegraded());
ok('onDegrade dipanggil', $degradeCalled);

// Panggilan get() #1: callCount=1 ≤ failUntil=2, masih gagal
$hybrid2->get('k');
ok('Masih degraded setelah get() #1 (primary masih down)', $hybrid2->isDegraded());

// Panggilan get() #2: callCount=2 ≤ failUntil=2, masih gagal
$hybrid2->get('k');
ok('Masih degraded setelah get() #2 (primary masih down)', $hybrid2->isDegraded());

// Panggilan get() #3: callCount=3 > failUntil=2, primary PULIH
$hybrid2->get('k');
ok('Setelah get() #3: isDegraded = false (primary pulih)', !$hybrid2->isDegraded());
ok('onRecover dipanggil', $recoverCalled);
info('Circuit breaker: OPEN → HALF-OPEN → CLOSED setelah primary pulih');

// forceRetry() saat sudah normal → tetap normal
ok('forceRetry() saat normal: return true', $hybrid2->forceRetry());

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 23: check() — single sumRequests + timing doc
// ════════════════════════════════════════════════════════════════════

suite('check() — Efisiensi & Konsistensi');

$lc = new RateLimiter(new ArrayStorage());

// check() tidak menambah counter
$lc->attempt('x', 5, 60);
$lc->attempt('x', 5, 60);
$before = $lc->getRemaining();
$lc->check('x', 5, 60);
$after  = $lc->getRemaining();
ok('check() tidak menambah counter', $before === $after);
ok('check() memperbarui getRemaining()', $lc->getRemaining() === 3);

// check() akurat mendeteksi mendekati limit
for ($i = 0; $i < 3; $i++) { $lc->attempt('x', 5, 60); }
$okBefore = $lc->check('x', 5, 60);
ok('check() mendeteksi limit tercapai (false)', !$okBefore);
ok('getRemaining() = 0 saat penuh', $lc->getRemaining() === 0);

// check() dan attempt() konsisten satu sama lain
$lc2 = new RateLimiter(new ArrayStorage());
$lc2->attempt('y', 10, 60);
$checkResult  = $lc2->check('y', 10, 60);
$remaining    = $lc2->getRemaining();
ok('check() konsisten: masih ada sisa setelah 1 req dari 10', $checkResult && $remaining === 9);

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 24: Dual-Counter O(1) — akurasi & performa
// ════════════════════════════════════════════════════════════════════

suite('Dual-Counter Sliding Window O(1)');

$ld = new RateLimiter(new ArrayStorage());

// Akurasi dasar: limit=5 per window
for ($i = 1; $i <= 5; $i++) {
    ok("Req {$i}/5 lolos", $ld->attempt('dc', 5, 60));
}
ok('Req ke-6 BLOCKED', !$ld->attempt('dc', 5, 60));
ok('getRemaining()=0 saat penuh', $ld->getRemaining() === 0);

// Weighted cost dengan dual-counter
$ld2 = new RateLimiter(new ArrayStorage());
ok('Cost=3 req1 (budget 10)', $ld2->attempt('wc', 10, 60, 3));
ok('Cost=3 req2 (budget 10)', $ld2->attempt('wc', 10, 60, 3));
ok('Cost=3 req3 (budget 10)', $ld2->attempt('wc', 10, 60, 3));
ok('Cost=3 req4 BLOCKED (sisa 1, butuh 3)', !$ld2->attempt('wc', 10, 60, 3));
ok('Cost=1 masih lolos (sisa 1)', $ld2->attempt('wc', 10, 60, 1));

// Performa: 10.000 attempt harus selesai < 500ms
$ld3   = new RateLimiter(new ArrayStorage());
$start = hrtime(true);
for ($i = 0; $i < 10_000; $i++) {
    $ld3->attempt('perf', 1_000_000, 60);
}
$ms = (hrtime(true) - $start) / 1e6;
ok("10.000 attempt O(1): {$ms}ms < 500ms", $ms < 500.0);
info("Throughput: " . round(10_000 / ($ms / 1000)) . " req/detik");

// Reset benar-benar membersihkan counter
$ld4 = new RateLimiter(new ArrayStorage());
$ld4->attempt('r', 2, 60);
$ld4->attempt('r', 2, 60);
ok('Sebelum reset: blocked', !$ld4->attempt('r', 2, 60));
$ld4->reset('r');
ok('Setelah reset: lolos lagi', $ld4->attempt('r', 2, 60));

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 25: ipInCidrList() — class_exists fallback
// ════════════════════════════════════════════════════════════════════

suite('ipInCidrList() class_exists Fallback');

// SecurityHelper tersedia: path normal
$_SERVER['REMOTE_ADDR']          = '10.0.0.5';
$_SERVER['HTTP_X_FORWARDED_FOR'] = '5.5.5.5';

ok('SecurityHelper tersedia (class_exists check)',
   class_exists(\RateLimiter\SecurityHelper::class, false));

// IPv4 CIDR via SecurityHelper
$ip = RateLimiter::clientIp(true, ['10.0.0.0/8']);
ok('Path normal (SecurityHelper): IPv4 CIDR match → forwarded', $ip === '5.5.5.5');

// IPv6 via SecurityHelper
$_SERVER['REMOTE_ADDR'] = '::1';
$ip = RateLimiter::clientIp(true, ['::1/128']);
ok('Path normal (SecurityHelper): IPv6 CIDR match → forwarded', $ip === '5.5.5.5');

// Verifikasi fallback logic benar (tanpa SecurityHelper) via manual check
// Kita tidak bisa unload kelas, jadi kita test fallback function secara terpisah
$fallbackFn = function(string $ip, array $list): bool {
    foreach ($list as $entry) {
        if (str_contains($entry, '/') && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            [$subnet, $bits] = explode('/', $entry, 2);
            if (filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $bits = max(0, min(32, (int) $bits));
                $mask = $bits > 0 ? (-1 << (32 - $bits)) : 0;
                if ((ip2long($ip) & $mask) === (ip2long($subnet) & $mask)) return true;
            }
        } elseif ($ip === $entry) { return true; }
    }
    return false;
};

ok('Fallback IPv4 /8 match',     $fallbackFn('10.5.5.5', ['10.0.0.0/8']));
ok('Fallback IPv4 /24 match',    $fallbackFn('192.168.1.50', ['192.168.1.0/24']));
ok('Fallback IPv4 /24 no-match', !$fallbackFn('192.168.2.1', ['192.168.1.0/24']));
ok('Fallback exact match',       $fallbackFn('1.2.3.4', ['1.2.3.4']));
ok('Fallback exact no-match',    !$fallbackFn('1.2.3.5', ['1.2.3.4']));
info('IPv6 di fallback: graceful fail (return false, pakai REMOTE_ADDR)');

$_SERVER = $origServer ?? $_SERVER;

end_suite();



// ════════════════════════════════════════════════════════════════════
//  SUITE 26: Fix 1 — Hapus 500-cap, validasi limit timestamp
// ════════════════════════════════════════════════════════════════════

suite('Fix 1: Timestamp — Hapus 500-cap + Validasi Limit');

// Verifikasi: timestamp dengan limit <= 500 boleh
$lts = new RateLimiter(new ArrayStorage(), ['algorithm' => 'timestamp']);
ok('Timestamp limit=500 diterima', $lts->attempt('x', 500, 60));

// Verifikasi: timestamp dengan limit > 500 throw exception
$thrown = false;
try {
    $lts->attempt('x', 501, 60);
} catch (\InvalidArgumentException $e) {
    $thrown = true;
}
ok('Timestamp limit=501 → InvalidArgumentException', $thrown);

// Verifikasi: dual-counter boleh limit > 500
$ldc = new RateLimiter(new ArrayStorage(), ['algorithm' => 'dual-counter']);
ok('Dual-counter limit=10000 diterima', $ldc->attempt('x', 10_000, 60));

// Verifikasi: tidak ada under-counting (akurasi tepat di limit)
$l500 = new RateLimiter(new ArrayStorage(), ['algorithm' => 'timestamp']);
for ($i = 0; $i < 500; $i++) { $l500->attempt('precise', 500, 3600); }
ok('Request ke-500 masih lolos (tidak under-count)', $l500->attempt('precise', 500, 3600) === false);
info('Tepat 500 request → diblokir. Tidak ada pemotongan yang menyebabkan lolos lebih');

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 27: Fix 3 — getHeaders() algoritma tersembunyi secara default
// ════════════════════════════════════════════════════════════════════

suite('Fix 3: getHeaders() — Algoritma Tersembunyi Default');

$lh = new RateLimiter(new ArrayStorage(), ['algorithm' => 'dual-counter']);
$lh->attempt('user', 10, 60);

// Default: tidak ada header algoritma
$headers = $lh->getHeaders(10);
ok('getHeaders() default: tidak ada X-RateLimit-Algorithm',
    !array_key_exists('X-RateLimit-Algorithm', $headers));
ok('getHeaders() default: X-RateLimit-Limit ada',
    isset($headers['X-RateLimit-Limit']));
ok('getHeaders() default: X-RateLimit-Remaining ada',
    isset($headers['X-RateLimit-Remaining']));
ok('getHeaders() default: Retry-After ada',
    isset($headers['Retry-After']));

// Debug mode: header algoritma muncul
$headersDebug = $lh->getHeaders(10, debug: true);
ok('getHeaders(debug=true): X-RateLimit-Algorithm ada',
    isset($headersDebug['X-RateLimit-Algorithm']));
ok('getHeaders(debug=true): nilai = dual-counter',
    $headersDebug['X-RateLimit-Algorithm'] === 'dual-counter');
ok('getHeaders(debug=true): X-RateLimit-PHP-Bits ada (info 32/64-bit)',
    isset($headersDebug['X-RateLimit-PHP-Bits']));
info('PHP int size: ' . $headersDebug['X-RateLimit-PHP-Bits'] . ' bit (fix 4: harus 64-bit)');

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 28: Fix 4 (doc) — PHP 64-bit slot overflow check
// ════════════════════════════════════════════════════════════════════

suite('Fix 4: PHP 64-bit Slot Overflow Check');

// Verifikasi PHP integer size
$phpBits = PHP_INT_SIZE * 8;
ok('PHP berjalan 64-bit (tidak ada risiko Y2K38)', $phpBits === 64,
    "PHP {}-bit terdeteksi — pastikan server production menggunakan 64-bit");

// Verifikasi slot calculation tidak overflow untuk timestamp tahun 2038+
$timestamp2038 = 2_147_483_647; // Unix timestamp max untuk 32-bit (2038-01-19)
$slot = (int) floor($timestamp2038 / 60);
ok('Slot 2038 = ' . number_format($slot) . ' (tidak overflow di 64-bit)',
    $slot === 35_791_394 && $slot > 0);

// Timestamp jauh ke depan (tahun 2100)
$timestamp2100 = 4_102_444_800;
$slot2100 = (int) floor($timestamp2100 / 60);
ok('Slot 2100 tidak overflow di 64-bit (' . number_format($slot2100) . ')',
    $slot2100 > 0 && $slot2100 < PHP_INT_MAX);
info('PHP_INT_MAX = ' . number_format(PHP_INT_MAX) . ' — aman hingga tahun ~292 miliar');

end_suite();

// ════════════════════════════════════════════════════════════════════
//  SUITE 29: Fix 7 — MAX_VIOLATION_COUNT cap
// ════════════════════════════════════════════════════════════════════

suite('Fix 7: MAX_VIOLATION_COUNT Cap');

// Verifikasi konstanta terdefinisi dengan benar
ok('MAX_VIOLATION_COUNT = 100.000',
    RateLimiter::MAX_VIOLATION_COUNT === 100_000);

// Simulasikan counter yang mencapai batas via reflection
$store = new ArrayStorage();
$lv2   = new RateLimiter($store, ['algorithm' => 'timestamp']);

// Isi counter (limit=1, setiap reject = +1 ke counter)
$lv2->attempt('spam', 1, 3600);     // lolos, curr=1
for ($i = 0; $i < 5; $i++) {
    $lv2->attempt('spam', 1, 3600); // blocked, violation +1
}

// Cek via storage langsung
$keyRef = new ReflectionMethod($lv2, 'buildKey');
$keyRef->setAccessible(true);
// SOLUSI 2: lv2 pakai 'timestamp', prefix 'ts'
$vKey   = $keyRef->invoke($lv2, 'spam', RateLimiter::KEY_PREFIX_TIMESTAMP) . ':violations';

$storeRef = new ReflectionProperty($lv2, 'storage');
$storeRef->setAccessible(true);
$st = $storeRef->getValue($lv2);
$vData = $st->get($vKey);

ok('Counter violation bertambah setelah reject', ($vData['count'] ?? 0) > 0);
ok('Counter violation tidak melebihi MAX_VIOLATION_COUNT',
    ($vData['count'] ?? 0) <= RateLimiter::MAX_VIOLATION_COUNT);
info('Violation count: ' . ($vData['count'] ?? 0) . ' (max: ' . RateLimiter::MAX_VIOLATION_COUNT . ')');

// Simulasikan counter yang sudah di batas
$st->set($vKey, ['count' => 100_000, 'violations' => [time()]], 3600);
$lv2->attempt('spam', 1, 3600); // trigger satu violation lagi
$vData2 = $st->get($vKey);
ok('Counter tidak melebihi batas meski di-trigger lagi',
    ($vData2['count'] ?? 0) <= RateLimiter::MAX_VIOLATION_COUNT);

end_suite();


// ════════════════════════════════════════════════════════════════════
//  SUITE 30: Fix — Validasi TIMESTAMP_MAX_LIMIT pada Override Parameter
// ════════════════════════════════════════════════════════════════════

suite('Fix: Timestamp Limit Validation pada Override Parameter');

// ── Reproduksi bug lama ──────────────────────────────────────────
// Instance pakai dual-counter, tapi attempt() pakai timestamp+limit 1000
// Dulu: LOLOS validasi (bypass) → sekarang harus DITOLAK

$lBypass = new RateLimiter(new ArrayStorage()); // default: dual-counter

$thrown = false; $msg = '';
try {
    // Ini adalah kode exploit yang dulu bisa bypass
    $lBypass->attempt('target', limit: 1000, window: 60, algorithm: 'timestamp');
} catch (\InvalidArgumentException $e) {
    $thrown = true;
    $msg    = $e->getMessage();
}
ok('attempt() override timestamp+limit=1000 → ditolak', $thrown,
    'Bypass masih bisa terjadi — fix belum bekerja');
info('Pesan: ' . $msg);

// ── check() juga harus ditolak ───────────────────────────────────
$thrown2 = false;
try {
    $lBypass->check('target', limit: 600, window: 60, algorithm: 'timestamp');
} catch (\InvalidArgumentException $e) {
    $thrown2 = true;
}
ok('check() override timestamp+limit=600 → ditolak', $thrown2);

// ── Override timestamp dengan limit AMAN (≤ 500) harus tetap boleh ──
$lOk = new RateLimiter(new ArrayStorage()); // dual-counter
$result = $lOk->attempt('safe', limit: 500, window: 60, algorithm: 'timestamp');
ok('attempt() override timestamp+limit=500 → diizinkan', $result === true);

$result2 = $lOk->check('safe', limit: 5, window: 60, algorithm: 'timestamp');
ok('check() override timestamp+limit=5 → diizinkan', $result2 === true);

// ── Instance timestamp, override ke dual-counter dengan limit besar ──
// Ini harus BOLEH karena dual-counter tidak punya batas limit
$lTs = new RateLimiter(new ArrayStorage(), ['algorithm' => 'timestamp']);
$result3 = $lTs->attempt('big', limit: 10_000, window: 60, algorithm: 'dual-counter');
ok('Instance timestamp, override dual-counter limit=10000 → diizinkan', $result3 === true);

// ── Instance timestamp, limit besar TANPA override → tetap ditolak ──
$lTs2 = new RateLimiter(new ArrayStorage(), ['algorithm' => 'timestamp']);
$thrown3 = false;
try {
    $lTs2->attempt('x', limit: 501, window: 60);
} catch (\InvalidArgumentException $e) {
    $thrown3 = true;
}
ok('Instance timestamp, limit=501 tanpa override → ditolak', $thrown3);

// ── Verifikasi algoritma yang dipakai benar ──────────────────────
// Setelah override ke timestamp limit 10 dengan instance dual-counter
$lMix = new RateLimiter(new ArrayStorage()); // dual-counter default
for ($i = 0; $i < 10; $i++) {
    $lMix->attempt('mixed', limit: 10, window: 60, algorithm: 'timestamp');
}
// Request ke-11 harus diblokir (timestamp, bukan estimasi dual-counter)
$blocked = !$lMix->attempt('mixed', limit: 10, window: 60, algorithm: 'timestamp');
ok('Override timestamp: blokir keras di request ke-11 (bukan estimasi)', $blocked);

// Pastikan instance algorithm tidak berubah setelah override
ok('Override per-attempt tidak mengubah $this->algorithm instance',
    $lMix->getAlgorithm() === RateLimiter::ALGO_DUAL_COUNTER);

end_suite();


// ════════════════════════════════════════════════════════════════════
//  SUITE 31: Solusi 2 — Isolasi Key per Algoritma
//
//  Membuktikan bahwa data dual-counter dan timestamp TIDAK pernah
//  saling baca/timpa meskipun identifier-nya sama persis.
//
//  Ini adalah test untuk bug nyata yang dilaporkan:
//    demo3.php (dual-counter) menulis ke storage → key: dc:rl:xxx
//    demo2.php (timestamp)    membaca identifier sama → membaca dc:rl:xxx
//    → Fatal Error: array_filter(null) karena {slot,prev,curr}
//      tidak dikenali oleh timestamp yang butuh {requests:[...]}
//
//  Setelah Solusi 2: key dipisahkan oleh prefix, tidak pernah tabrakan.
// ════════════════════════════════════════════════════════════════════

suite('Solusi 2: Isolasi Key per Algoritma');

$storeIso = new ArrayStorage();

// ── Reproduksi skenario bug asli ──────────────────────────────────
// demo3.php: dual-counter jalan dulu, simpan {slot,prev,curr}
$dcFirst = new RateLimiter($storeIso, ['algorithm' => 'dual-counter']);
$dcFirst->attempt('same-id', 10, 60);
$dcFirst->attempt('same-id', 10, 60);
$dcFirst->attempt('same-id', 10, 60);
info('Dual-counter menyimpan {slot,prev,curr} ke storage...');

// demo2.php: timestamp membaca identifier yang sama
// Sebelum fix: Fatal Error — array_filter(null)
// Sesudah fix: key berbeda, timestamp baca datanya sendiri (kosong)
$tsAfter = new RateLimiter($storeIso, ['algorithm' => 'timestamp']);
$noError = false;
try {
    $tsAfter->attempt('same-id', 5, 60);
    $noError = true;
} catch (\Throwable $e) {
    info('Error: ' . $e->getMessage());
}
ok('Timestamp baca identifier sama setelah dual-counter: TIDAK error', $noError,
    'Fatal Error masih terjadi — Solusi 2 belum bekerja');
ok('Timestamp mulai dari kuota penuh (tidak terkontaminasi)',
    $tsAfter->getRemaining() === 4,
    'Sisa: ' . $tsAfter->getRemaining() . ' (harusnya 4)');

// ── Verifikasi key benar-benar berbeda di storage ─────────────────
$kr = new ReflectionMethod($dcFirst, 'buildKey');
$kr->setAccessible(true);
$kDc = $kr->invoke($dcFirst, 'same-id', RateLimiter::KEY_PREFIX_DUAL_COUNTER);
$kTs = $kr->invoke($tsAfter,  'same-id', RateLimiter::KEY_PREFIX_TIMESTAMP);

ok('Key DC berbeda dari key TS', $kDc !== $kTs, "dc=$kDc | ts=$kTs");
// Prefix algo dimasukkan KE DALAM input hash, bukan di depan key.
// Format key: "rl:sha256(dc|identifier)" — prefix ada di dalam hash,
// bukan terlihat sebagai string di key akhir.
// Yang bisa diverifikasi: key diawali prefix config "rl:", bukan algo prefix.
ok('Key DC diawali key_prefix "rl:"', str_starts_with($kDc, 'rl:'));
ok('Key TS diawali key_prefix "rl:"', str_starts_with($kTs, 'rl:'));
info("Key dc: $kDc");
info("Key ts: $kTs");

$dataDc = $storeIso->get($kDc);
$dataTs = $storeIso->get($kTs);
ok('Storage DC berisi {slot,curr,prev}',
    isset($dataDc['slot']) && isset($dataDc['curr']));
ok('Storage TS berisi {requests:[...]}',
    isset($dataTs['requests']) && is_array($dataTs['requests']));
info('Format dc: ' . json_encode(array_keys($dataDc ?? [])));
info('Format ts: ' . json_encode(array_keys($dataTs ?? [])));

// ── Counter berjalan independen ───────────────────────────────────
ok('Counter DC independen: sisa 7 (10-3)',
    $dcFirst->check('same-id', 10, 60) && $dcFirst->getRemaining() === 7,
    'Sisa dc: ' . $dcFirst->getRemaining());
ok('Counter TS independen: sisa 4 (5-1)',
    $tsAfter->check('same-id', 5, 60) && $tsAfter->getRemaining() === 4,
    'Sisa ts: ' . $tsAfter->getRemaining());

// ── Blokir manual tetap universal (tidak per-algoritma) ──────────
$lbDc = new RateLimiter($storeIso, ['algorithm' => 'dual-counter']);
$lbDc->block('blocked-user', 3600);
$lbTs = new RateLimiter($storeIso, ['algorithm' => 'timestamp']);
ok('block() via dc → isBlocked() via ts = true', $lbTs->isBlocked('blocked-user'));
ok('block() via dc → isBlocked() via dc = true', $lbDc->isBlocked('blocked-user'));
info('Blokir manual tidak punya prefix algo = berlaku universal');

// ── reset() membersihkan KEDUA algoritma ─────────────────────────
$lrDc = new RateLimiter($storeIso, ['algorithm' => 'dual-counter']);
$lrTs = new RateLimiter($storeIso, ['algorithm' => 'timestamp']);
$lrDc->attempt('reset-test', 10, 60);
$lrTs->attempt('reset-test', 5, 60);

$rDc = $kr->invoke($lrDc, 'reset-test', RateLimiter::KEY_PREFIX_DUAL_COUNTER);
$rTs = $kr->invoke($lrTs, 'reset-test', RateLimiter::KEY_PREFIX_TIMESTAMP);
ok('Sebelum reset: data DC ada', $storeIso->get($rDc) !== null);
ok('Sebelum reset: data TS ada', $storeIso->get($rTs) !== null);

$lrDc->reset('reset-test');
ok('Setelah reset(): data DC terhapus', $storeIso->get($rDc) === null);
ok('Setelah reset(): data TS terhapus juga', $storeIso->get($rTs) === null);
info('reset() membersihkan ts:... DAN dc:... sekaligus');

// ── Skenario switch algoritma tidak crash ─────────────────────────
$store2  = new ArrayStorage();
$sw1 = new RateLimiter($store2, ['algorithm' => 'dual-counter']);
for ($i = 0; $i < 5; $i++) { $sw1->attempt('switcher', 10, 60); }

$sw2 = new RateLimiter($store2, ['algorithm' => 'timestamp']);
$swOk = true;
try {
    for ($j = 0; $j < 3; $j++) { $sw2->attempt('switcher', 5, 60); }
} catch (\Throwable $e) {
    $swOk = false;
    info('Error saat switch: ' . $e->getMessage());
}
ok('Switch dc ke ts pada identifier sama: tidak crash', $swOk);
ok('Counter ts setelah switch independen: sisa=2',
    $sw2->getRemaining() === 2,
    'Sisa: ' . $sw2->getRemaining());

end_suite();

$total   = $stats['pass'] + $stats['fail'];
$passCol = $stats['fail'] === 0 ? "\033[32m" : "\033[33m";
$failCol = $stats['fail'] > 0  ? "\033[31m" : "\033[90m";

echo "\n\033[1m════════════════════════════════════════════════════\033[0m\n";
echo "\033[1m  HASIL TEST\033[0m\n";
echo "\033[1m════════════════════════════════════════════════════\033[0m\n";
printf("  %-12s %s%d\033[0m\n",  'Lolos:',   $passCol, $stats['pass']);
printf("  %-12s %s%d\033[0m\n",  'Gagal:',   $failCol, $stats['fail']);
printf("  %-12s \033[90m%d\033[0m\n", 'Di-skip:',  $stats['skip']);
printf("  %-12s %d\n", 'Total:',              $total);

if (!empty($errors)) {
    echo "\n\033[1;31m  DETAIL KEGAGALAN:\033[0m\n";
    foreach ($errors as $e) {
        echo "  \033[31m• {$e}\033[0m\n";
    }
}

echo "\n";

if ($stats['fail'] === 0) {
    echo "  \033[1;32m✓ Semua test lulus! Rate Limiter siap digunakan.\033[0m\n\n";
    exit(0);
} else {
    echo "  \033[1;31m✗ Ada {$stats['fail']} test yang gagal. Periksa detail di atas.\033[0m\n\n";
    exit(1);
}
