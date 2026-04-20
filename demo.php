<?php
/**
 * Demo Rate Limiter — Satu File, Tiga Contoh + Pilihan Algoritma
 * ─────────────────────────────────────────────────────────────────
 *  Letakkan file ini di: RateLimiter/demo.php
 *  Akses via: http://localhost/RateLimiter/demo.php
 *
 *  Storage: FileStorage → folder /temp/ (dibuat otomatis)
 *  Tidak butuh Redis, APCu, atau ekstensi tambahan apapun.
 *
 *  Algoritma (bisa dipilih per tab):
 *    timestamp    → Akurat, hard blocking. Cocok untuk login/keamanan.
 *    dual-counter → Ringan, estimasi. Cocok untuk API publik.
 *
 *  ─── JIKA ANDA MENDUPLIKASI FILE INI (demo2.php, demo3.php, dll) ───
 *  Ganti nilai DEMO_KEY_PREFIX di bawah agar setiap file punya
 *  "ruang" counter sendiri di storage. Tanpa ini, counter antar file
 *  akan bercampur karena menggunakan identifier yang sama (IP yang sama).
 *
 *  Contoh:
 *    demo.php  → DEMO_KEY_PREFIX = 'demo1'
 *    demo2.php → DEMO_KEY_PREFIX = 'demo2'
 *    demo3.php → DEMO_KEY_PREFIX = 'demo3'
 * ─────────────────────────────────────────────────────────────────
 */

declare(strict_types=1);
require_once __DIR__ . '/autoload.php';

use RateLimiter\RateLimiter;
use RateLimiter\FileStorage;

// ══════════════════════════════════════════════════════════
//  KONFIGURASI — WAJIB DIUBAH JIKA MENDUPLIKASI FILE INI
// ══════════════════════════════════════════════════════════

/**
 * Prefix unik untuk file demo ini.
 *
 * MENGAPA INI PENTING:
 * Rate limiter mengidentifikasi user berdasarkan IP address.
 * Jika demo.php dan demo2.php menggunakan prefix yang sama,
 * dan IP Anda adalah ::1 (localhost), maka:
 *
 *   demo.php  → menyimpan counter untuk "login:::1:hash" → kuota 5
 *   demo2.php → membaca counter yang SAMA                → kuota sudah berkurang!
 *
 * Dengan prefix berbeda:
 *   demo.php  key_prefix='demo1' → "demo1:sha256(login:::1:hash)" → counter sendiri
 *   demo2.php key_prefix='demo2' → "demo2:sha256(login:::1:hash)" → counter sendiri
 *
 * CATATAN: Ini BERBEDA dari Solusi 2 (isolasi algoritma).
 * Solusi 2 mencegah tabrakan antar ALGORITMA pada file yang sama.
 * key_prefix mencegah tabrakan antar FILE yang berbeda.
 * Keduanya bekerja bersama sebagai dua lapis isolasi.
 */
const DEMO_KEY_PREFIX = 'demo1'; // ← Ganti ke 'demo2', 'demo3', dst. jika menduplikasi

/**
 * Folder temp terpusat — gunakan path ABSOLUT agar semua file demo
 * menulis ke folder yang SAMA, bukan masing-masing punya /temp/ sendiri.
 *
 * MASALAH JIKA PAKAI __DIR__ . '/temp':
 *   demo.php  di /htdocs/ratelimiting2/ → /htdocs/ratelimiting2/temp/
 *   demo2.php di /htdocs/ratelimiting2/ → /htdocs/ratelimiting2/temp/ (sama ✓)
 *   (tapi jika di subfolder berbeda, bisa beda folder!)
 *
 * SOLUSI: Gunakan dirname(__DIR__) atau path absolut eksplisit
 * agar semua file selalu menulis ke folder yang sama.
 * Dengan DEMO_KEY_PREFIX berbeda, data tetap terisolasi meski satu folder.
 */
$tempDir = __DIR__ . '/temp'; // Ganti ke path absolut jika file ada di subfolder berbeda

$storage = new FileStorage(
    dir:       $tempDir,
    gcDivisor: 50,
    maxFiles:  5_000
);

$clientIp = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$demo     = $_GET['demo'] ?? 'login';
$method   = $_SERVER['REQUEST_METHOD'] ?? 'GET';

// Algoritma dipilih user via query string, default sesuai tab
$defaultAlgo = match($demo) {
    'login', 'kontak' => RateLimiter::ALGO_TIMESTAMP,    // default ketat untuk form
    default           => RateLimiter::ALGO_DUAL_COUNTER,  // default ringan untuk API
};
$algo = in_array($_GET['algo'] ?? '', [
    RateLimiter::ALGO_TIMESTAMP,
    RateLimiter::ALGO_DUAL_COUNTER,
], true) ? $_GET['algo'] : $defaultAlgo;

// Buat limiter dengan algoritma yang dipilih + key_prefix unik per file.
// key_prefix memastikan counter file ini tidak bercampur dengan file demo lain.
$limiter = new RateLimiter($storage, [
    'algorithm'  => $algo,
    'key_prefix' => DEMO_KEY_PREFIX, // ← Isolasi antar file demo
]);

// ══════════════════════════════════════════════════════════
//  HELPER FUNGSI
// ══════════════════════════════════════════════════════════

function formatWaktu(int $detik): string
{
    if ($detik <= 0) return '0 detik';
    $menit = intdiv($detik, 60);
    $sisa  = $detik % 60;
    if ($menit > 0 && $sisa > 0) return "{$menit} menit {$sisa} detik";
    if ($menit > 0)               return "{$menit} menit";
    return "{$sisa} detik";
}

function jsonResponse(int $status, array $data): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

// ══════════════════════════════════════════════════════════
//  DEMO API — tangani sebelum HTML output
// ══════════════════════════════════════════════════════════

if ($demo === 'api') {
    $allowed = $limiter->attempt("api:{$clientIp}", limit: 10, window: 60);

    header('X-RateLimit-Limit: 10');
    header('X-RateLimit-Remaining: ' . $limiter->getRemaining());
    header('X-RateLimit-Reset: '     . $limiter->getResetAt());
    header('X-RateLimit-Algorithm: ' . $limiter->getAlgorithm());

    if (!$allowed) {
        header('Retry-After: ' . $limiter->getRetryAfter());
        jsonResponse(429, [
            'status'      => 'error',
            'kode'        => 429,
            'pesan'       => 'Terlalu banyak request. Coba lagi nanti.',
            'retry_after' => $limiter->getRetryAfter(),
            'tunggu'      => formatWaktu($limiter->getRetryAfter()),
            'algoritma'   => $limiter->getAlgorithm(),
        ]);
    }

    $sisa = $limiter->getRemaining();
    jsonResponse(200, [
        'status'      => 'ok',
        'pesan'       => $sisa === 0
                            ? 'Request diproses. Kuota habis — request berikutnya akan diblokir.'
                            : 'Request berhasil diproses.',
        'data'        => ['waktu' => date('Y-m-d H:i:s'), 'ip' => $clientIp],
        'sisa_kuota'  => $sisa,
        'kuota_habis' => $sisa === 0,
        'reset_at'    => date('H:i:s', $limiter->getResetAt()),
        'algoritma'   => $limiter->getAlgorithm(),
    ]);
}

// ══════════════════════════════════════════════════════════
//  PROSES FORM POST
// ══════════════════════════════════════════════════════════

$pesan       = '';
$error       = '';
$rateLimited = false;
$retryAfter  = 0;

if ($method === 'POST') {

    if ($demo === 'login') {
        $email    = trim($_POST['email']    ?? '');
        $password = trim($_POST['password'] ?? '');
        $kunci    = "login:{$clientIp}:" . hash('sha256', strtolower($email));
        $boleh    = $limiter->attempt($kunci, limit: 5, window: 900);

        if (!$boleh) {
            $rateLimited = true;
            $retryAfter  = $limiter->getRetryAfter();
            $error       = 'Terlalu banyak percobaan login. Tunggu ' . formatWaktu($retryAfter) . '.';
        } else {
            $valid = ($email === 'admin@demo.com' && $password === 'password123');
            if ($valid) {
                $limiter->reset($kunci);
                $pesan = "Login berhasil! Selamat datang, {$email}.";
            } else {
                $sisa  = $limiter->getRemaining();
                $error = "Email atau password salah. Sisa percobaan: {$sisa}x.";
                if ($sisa === 0) $error .= ' Akun sementara dikunci.';
            }
        }
    }

    if ($demo === 'kontak') {
        $nama         = trim($_POST['nama']  ?? '');
        $emailKontak  = trim($_POST['email'] ?? '');
        $pesanKontak  = trim($_POST['pesan'] ?? '');
        $kunci        = "kontak:{$clientIp}";
        $boleh        = $limiter->attempt($kunci, limit: 3, window: 600);

        if (!$boleh) {
            $rateLimited = true;
            $retryAfter  = $limiter->getRetryAfter();
            $error       = 'Pesan terlalu sering dikirim. Tunggu ' . formatWaktu($retryAfter) . '.';
        } elseif (empty($nama) || empty($emailKontak) || empty($pesanKontak)) {
            $error = 'Semua kolom wajib diisi.';
        } else {
            $sisa  = $limiter->getRemaining();
            $pesan = "Pesan dari {$nama} berhasil dikirim! Sisa kuota: {$sisa}x dalam 10 menit.";
        }
    }
}

// Ambil status kuota untuk UI
function getStatusKuota(RateLimiter $l, string $kunci, int $limit, int $window): array
{
    $l->check($kunci, $limit, $window);
    return [
        'sisa'  => $l->getRemaining(),
        'limit' => $limit,
        'persen'=> $limit > 0 ? round(($l->getRemaining() / $limit) * 100) : 0,
    ];
}

$kuotaLogin  = getStatusKuota($limiter,
    "login:{$clientIp}:" . hash('sha256', 'admin@demo.com'), 5, 900);
$kuotaKontak = getStatusKuota($limiter, "kontak:{$clientIp}", 3, 600);

// Sesudah (Opsi 1 - paling bersih)
function warnaKuota(float $persen): string
{
    if ($persen > 60) return '#22c55e';
    if ($persen > 25) return '#f59e0b';
    return '#ef4444';
}

// Label & deskripsi algoritma untuk UI
$algoLabel = $algo === RateLimiter::ALGO_TIMESTAMP
    ? ['nama' => 'Timestamp', 'warna' => '#3b82f6',
       'desc' => 'Akurat & hard blocking. retry_after dijamin. Cocok untuk keamanan.']
    : ['nama' => 'Dual-Counter', 'warna' => '#8b5cf6',
       'desc' => 'Ringan & O(1). Kuota bisa naik sendiri. Cocok untuk API publik.'];

// URL helper untuk switch algoritma
function algoUrl(string $demo, string $algo): string
{
    return '?demo=' . urlencode($demo) . '&algo=' . urlencode($algo);
}

?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Demo Rate Limiter — <?= htmlspecialchars(ucfirst($demo)) ?></title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: system-ui, -apple-system, sans-serif;
    background: #0f172a;
    color: #e2e8f0;
    min-height: 100vh;
    padding: 24px 16px;
  }

  .container { max-width: 580px; margin: 0 auto; }

  .header { text-align: center; margin-bottom: 28px; }
  .header h1 { font-size: 1.6rem; font-weight: 700; color: #f8fafc; }
  .header p  { font-size: .82rem; color: #64748b; margin-top: 6px; }

  /* Tab navigasi */
  .tabs {
    display: flex; gap: 8px;
    background: #1e293b; border-radius: 12px;
    padding: 6px; margin-bottom: 16px;
  }
  .tabs a {
    flex: 1; text-align: center; padding: 8px 10px;
    border-radius: 8px; text-decoration: none;
    font-size: .82rem; font-weight: 500;
    color: #94a3b8; transition: all .15s;
  }
  .tabs a:hover { background: #334155; color: #e2e8f0; }
  .tabs a.aktif { background: #3b82f6; color: #fff; }

  /* Pilihan algoritma */
  .algo-switch {
    display: flex; gap: 8px; margin-bottom: 20px;
  }
  .algo-btn {
    flex: 1; padding: 10px 12px; border-radius: 10px;
    text-decoration: none; text-align: center;
    font-size: .8rem; font-weight: 600;
    border: 2px solid transparent;
    transition: all .15s; line-height: 1.4;
  }
  .algo-btn .algo-nama { font-size: .88rem; display: block; }
  .algo-btn .algo-sub  { font-size: .72rem; font-weight: 400; opacity: .8; display: block; margin-top: 2px; }
  .algo-btn-ts {
    background: #1e3a5f; border-color: #1e3a5f; color: #93c5fd;
  }
  .algo-btn-ts.aktif {
    background: #1d4ed8; border-color: #3b82f6; color: #fff;
  }
  .algo-btn-dc {
    background: #2e1f5e; border-color: #2e1f5e; color: #c4b5fd;
  }
  .algo-btn-dc.aktif {
    background: #6d28d9; border-color: #8b5cf6; color: #fff;
  }

  /* Badge algoritma aktif */
  .algo-badge {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 4px 10px; border-radius: 99px;
    font-size: .72rem; font-weight: 600;
    margin-bottom: 16px;
  }
  .algo-badge .dot {
    width: 7px; height: 7px; border-radius: 50%;
    display: inline-block; flex-shrink: 0;
  }

  /* Card */
  .card {
    background: #1e293b; border-radius: 16px;
    padding: 24px; margin-bottom: 16px;
    border: 1px solid #334155;
  }
  .card-judul {
    font-size: 1rem; font-weight: 600; color: #f1f5f9;
    margin-bottom: 4px;
  }
  .card-sub { font-size: .78rem; color: #64748b; margin-bottom: 16px; }

  /* Info algo */
  .algo-info {
    background: #0f172a; border-radius: 8px;
    padding: 10px 14px; margin-bottom: 16px;
    border-left: 3px solid;
    font-size: .78rem; color: #94a3b8; line-height: 1.5;
  }

  /* Form */
  label { display: block; font-size: .8rem; color: #94a3b8; margin-bottom: 5px; }
  input, textarea {
    width: 100%; padding: 10px 14px;
    background: #0f172a; border: 1px solid #334155;
    border-radius: 8px; color: #e2e8f0; font-size: .88rem;
    outline: none; transition: border-color .15s;
  }
  input:focus, textarea:focus { border-color: #3b82f6; }
  textarea { resize: vertical; min-height: 88px; }
  .field { margin-bottom: 14px; }

  .btn {
    width: 100%; padding: 11px;
    border: none; border-radius: 8px;
    color: #fff; font-size: .92rem; font-weight: 600;
    cursor: pointer; transition: filter .15s; margin-top: 2px;
  }
  .btn:hover:not(:disabled) { filter: brightness(1.1); }
  .btn:disabled { opacity: .55; cursor: not-allowed; }
  .btn-blue   { background: #3b82f6; }
  .btn-purple { background: #6d28d9; }

  /* Alert */
  .alert {
    padding: 11px 14px; border-radius: 8px;
    font-size: .82rem; margin-bottom: 14px;
    display: flex; align-items: flex-start; gap: 10px; line-height: 1.5;
  }
  .alert-ok    { background: #052e16; border: 1px solid #166534; color: #86efac; }
  .alert-error { background: #2d0a0a; border: 1px solid #991b1b; color: #fca5a5; }
  .alert-warn  { background: #2d1b00; border: 1px solid #92400e; color: #fcd34d; }
  .alert-icon  { flex-shrink: 0; }

  /* Kuota bar */
  .kuota-wrap  { margin-top: 18px; }
  .kuota-label {
    display: flex; justify-content: space-between;
    font-size: .76rem; color: #64748b; margin-bottom: 5px;
  }
  .kuota-bar-bg {
    background: #0f172a; border-radius: 99px; height: 8px; overflow: hidden;
  }
  .kuota-bar-fill {
    height: 100%; border-radius: 99px; transition: width .4s, background .4s;
  }

  /* Info grid */
  .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 14px; }
  .info-box {
    background: #0f172a; border-radius: 10px;
    padding: 11px 14px; border: 1px solid #1e293b;
  }
  .info-box-label { font-size: .7rem; color: #64748b; margin-bottom: 3px; }
  .info-box-nilai { font-size: 1.05rem; font-weight: 700; color: #f1f5f9; }

  .hint {
    font-size: .76rem; color: #475569;
    background: #1e293b; border-radius: 8px;
    padding: 9px 13px; margin-bottom: 14px;
    border-left: 3px solid #334155; line-height: 1.5;
  }
  .hint b { color: #94a3b8; }

  .storage-info {
    font-size: .72rem; color: #475569;
    text-align: center; margin-top: 6px;
  }
  .storage-info code {
    background: #1e293b; padding: 1px 6px;
    border-radius: 4px; color: #94a3b8; font-size: .7rem;
  }

  .flex-row { display: flex; gap: 8px; }
  .btn-spam {
    flex: 0 0 auto; width: auto; padding: 11px 16px;
    background: #7c3aed; white-space: nowrap;
  }

  #api-result {
    background: #0f172a; border-radius: 8px; padding: 14px;
    font-family: monospace; font-size: .76rem; color: #94a3b8;
    min-height: 110px; margin-bottom: 14px;
    border: 1px solid #334155; white-space: pre-wrap; line-height: 1.6;
  }

  .compare-box {
    background: #0f172a; border-radius: 10px;
    padding: 14px; border: 1px solid #1e293b;
    font-size: .76rem; color: #64748b; line-height: 1.8;
    margin-top: 14px;
  }
  .compare-box strong { color: #94a3b8; }
  .tag-ts { color: #93c5fd; font-weight: 600; }
  .tag-dc { color: #c4b5fd; font-weight: 600; }
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <h1>🛡️ Demo Rate Limiter</h1>
    <p>FileStorage &rarr; <code style="background:#1e293b;padding:2px 7px;border-radius:4px;font-size:.75rem">/temp/</code> &nbsp;|&nbsp; Pilih algoritma per tab</p>
  </div>

  <!-- Navigasi Tab -->
  <div class="tabs">
    <a href="?demo=login&algo=<?= urlencode($algo) ?>"  class="<?= $demo==='login'  ? 'aktif' : '' ?>">🔐 Login</a>
    <a href="?demo=api&algo=<?= urlencode($algo) ?>"    class="<?= $demo==='api'    ? 'aktif' : '' ?>">⚡ API</a>
    <a href="?demo=kontak&algo=<?= urlencode($algo) ?>" class="<?= $demo==='kontak' ? 'aktif' : '' ?>">✉️ Kontak</a>
  </div>

  <!-- Pilihan Algoritma -->
  <div class="algo-switch">
    <a href="<?= algoUrl($demo, 'timestamp') ?>"
       class="algo-btn algo-btn-ts <?= $algo === 'timestamp' ? 'aktif' : '' ?>">
      <span class="algo-nama">🔒 Timestamp</span>
      <span class="algo-sub">Akurat · Hard blocking</span>
    </a>
    <a href="<?= algoUrl($demo, 'dual-counter') ?>"
       class="algo-btn algo-btn-dc <?= $algo === 'dual-counter' ? 'aktif' : '' ?>">
      <span class="algo-nama">⚡ Dual-Counter</span>
      <span class="algo-sub">Ringan · O(1) · Estimasi</span>
    </a>
  </div>

<?php if ($demo === 'login'): ?>
<!-- ══════════════════════════════════════════════════════════
     TAB LOGIN
     ══════════════════════════════════════════════════════════ -->
  <div class="card">
    <div class="card-judul">🔐 Form Login</div>
    <div class="card-sub">Limit: 5 percobaan / 15 menit per IP+email</div>

    <div class="algo-info" style="border-color:<?= $algoLabel['warna'] ?>">
      <strong style="color:<?= $algoLabel['warna'] ?>"><?= $algoLabel['nama'] ?></strong> —
      <?= htmlspecialchars($algoLabel['desc']) ?>
    </div>

    <?php if ($pesan): ?>
    <div class="alert alert-ok"><span class="alert-icon">✓</span><?= htmlspecialchars($pesan) ?></div>
    <?php endif; ?>

    <?php if ($error && !$rateLimited): ?>
    <div class="alert alert-error"><span class="alert-icon">✗</span><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <?php if ($rateLimited): ?>
    <div class="alert alert-warn">
      <span class="alert-icon">⚠</span>
      <div>
        <strong>Login dikunci</strong>
        <?= $algo === 'timestamp' ? '— waktu blokir dijamin akurat' : '— perkiraan waktu (dual-counter)' ?><br>
        <?= htmlspecialchars($error) ?>
      </div>
    </div>
    <?php endif; ?>

    <div class="hint">
      <b>Kredensial demo:</b> admin@demo.com / password123<br>
      Masukkan password salah berkali-kali untuk melihat perbedaan perilaku antar algoritma.
    </div>

    <form method="POST" action="?demo=login&algo=<?= urlencode($algo) ?>">
      <div class="field">
        <label>Email</label>
        <input type="email" name="email"
               value="<?= htmlspecialchars($_POST['email'] ?? '') ?>"
               placeholder="admin@demo.com"
               <?= $rateLimited ? 'disabled' : '' ?>>
      </div>
      <div class="field">
        <label>Password</label>
        <input type="password" name="password" placeholder="••••••••"
               <?= $rateLimited ? 'disabled' : '' ?>>
      </div>
      <button class="btn btn-blue" type="submit" <?= $rateLimited ? 'disabled' : '' ?>>
        <?= $rateLimited ? '🔒 Dikunci ' . formatWaktu($retryAfter) : 'Masuk' ?>
      </button>
    </form>

    <div class="kuota-wrap">
      <div class="kuota-label">
        <span>Sisa percobaan</span>
        <span><?= $kuotaLogin['sisa'] ?> / <?= $kuotaLogin['limit'] ?></span>
      </div>
      <div class="kuota-bar-bg">
        <div class="kuota-bar-fill"
             style="width:<?= $kuotaLogin['persen'] ?>%;background:<?= warnaKuota($kuotaLogin['persen']) ?>">
        </div>
      </div>
    </div>

    <div class="compare-box">
      <strong>Perbedaan perilaku saat limit tercapai:</strong><br>
      <span class="tag-ts">Timestamp</span> — blokir keras, retry_after tidak bisa ditembus sebelum habis.<br>
      <span class="tag-dc">Dual-Counter</span> — bisa lolos sebelum retry_after habis jika estimasi turun.
    </div>
  </div>

<?php elseif ($demo === 'api'): ?>
<!-- ══════════════════════════════════════════════════════════
     TAB API
     ══════════════════════════════════════════════════════════ -->
  <div class="card">
    <div class="card-judul">⚡ API Endpoint</div>
    <div class="card-sub">Limit: 10 request / 60 detik per IP</div>

    <div class="algo-info" style="border-color:<?= $algoLabel['warna'] ?>">
      <strong style="color:<?= $algoLabel['warna'] ?>"><?= $algoLabel['nama'] ?></strong> —
      <?= htmlspecialchars($algoLabel['desc']) ?>
    </div>

    <div id="api-result">Klik tombol untuk mengirim request ke API...</div>

    <div class="flex-row">
      <button class="btn btn-blue" onclick="kirimRequest()" id="btn-api">Kirim Request</button>
      <button class="btn btn-spam" onclick="kirimBanyak()" title="Kirim 12 request sekaligus">Spam ×12</button>
    </div>

    <div class="info-grid" id="api-stats" style="display:none">
      <div class="info-box">
        <div class="info-box-label">Sisa Kuota</div>
        <div class="info-box-nilai" id="stat-sisa">—</div>
      </div>
      <div class="info-box">
        <div class="info-box-label">Status HTTP</div>
        <div class="info-box-nilai" id="stat-status">—</div>
      </div>
      <div class="info-box">
        <div class="info-box-label">Algoritma</div>
        <div class="info-box-nilai" id="stat-algo" style="font-size:.8rem">—</div>
      </div>
      <div class="info-box">
        <div class="info-box-label">Reset At</div>
        <div class="info-box-nilai" id="stat-reset" style="font-size:.9rem">—</div>
      </div>
    </div>

    <div class="compare-box">
      <strong>Coba bandingkan:</strong><br>
      <span class="tag-ts">Timestamp</span> — setelah 429, refresh berkali-kali tetap ditolak sampai benar-benar reset.<br>
      <span class="tag-dc">Dual-Counter</span> — setelah 429, diam sebentar lalu refresh bisa lolos lagi.
    </div>
  </div>

  <script>
  const algoParam = '<?= urlencode($algo) ?>';
  const url = '?demo=api&algo=' + algoParam;

  async function kirimRequest() {
    const el  = document.getElementById('api-result');
    const btn = document.getElementById('btn-api');
    btn.disabled = true; btn.textContent = 'Mengirim...';

    try {
      const resp = await fetch(url);
      const data = await resp.json();
      const sisa = resp.headers.get('X-RateLimit-Remaining') ?? data.sisa_kuota ?? '—';

      const warna = resp.ok
        ? (data.kuota_habis ? '#fcd34d' : '#86efac')
        : '#fca5a5';
      el.style.color = warna;
      el.textContent = JSON.stringify(data, null, 2);

      document.getElementById('api-stats').style.display = 'grid';
      document.getElementById('stat-sisa').textContent   = sisa + ' / 10';
      const statusEl = document.getElementById('stat-status');
      statusEl.textContent = resp.status + (resp.ok ? ' OK' : ' Blocked');
      statusEl.style.color = resp.ok ? '#86efac' : '#fca5a5';
      document.getElementById('stat-algo').textContent  = data.algoritma ?? '—';
      document.getElementById('stat-reset').textContent = data.reset_at ?? '—';
    } catch(e) {
      el.style.color   = '#fca5a5';
      el.textContent = 'Error: ' + e.message;
    } finally {
      btn.disabled = false; btn.textContent = 'Kirim Request';
    }
  }

  async function kirimBanyak() {
    const el = document.getElementById('api-result');
    el.style.color = '#94a3b8';
    el.textContent = 'Mengirim 12 request...\n';
    for (let i = 1; i <= 12; i++) {
      try {
        const resp = await fetch(url);
        const data = await resp.json();
        const icon = resp.ok ? (data.kuota_habis ? '⚠' : '✓') : '✗';
        const info = resp.ok
          ? `sisa ${data.sisa_kuota}${data.kuota_habis ? ' (HABIS)' : ''}`
          : `retry ${data.retry_after}s`;
        el.textContent += `${icon} Request #${i}: HTTP ${resp.status} — ${info}\n`;
      } catch(e) {
        el.textContent += `! Request #${i}: Error\n`;
      }
      await new Promise(r => setTimeout(r, 80));
    }
  }
  </script>

<?php elseif ($demo === 'kontak'): ?>
<!-- ══════════════════════════════════════════════════════════
     TAB KONTAK
     ══════════════════════════════════════════════════════════ -->
  <div class="card">
    <div class="card-judul">✉️ Form Kontak</div>
    <div class="card-sub">Limit: 3 pesan / 10 menit per IP</div>

    <div class="algo-info" style="border-color:<?= $algoLabel['warna'] ?>">
      <strong style="color:<?= $algoLabel['warna'] ?>"><?= $algoLabel['nama'] ?></strong> —
      <?= htmlspecialchars($algoLabel['desc']) ?>
    </div>

    <?php if ($pesan): ?>
    <div class="alert alert-ok"><span class="alert-icon">✓</span><?= htmlspecialchars($pesan) ?></div>
    <?php endif; ?>

    <?php if ($error && !$rateLimited): ?>
    <div class="alert alert-error"><span class="alert-icon">✗</span><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <?php if ($rateLimited): ?>
    <div class="alert alert-warn">
      <span class="alert-icon">⚠</span>
      <div>
        <strong>Terlalu sering mengirim</strong>
        <?= $algo === 'timestamp' ? '— blokir dijamin' : '— perkiraan waktu' ?><br>
        <?= htmlspecialchars($error) ?>
      </div>
    </div>
    <?php endif; ?>

    <form method="POST" action="?demo=kontak&algo=<?= urlencode($algo) ?>">
      <div class="field">
        <label>Nama</label>
        <input type="text" name="nama"
               value="<?= htmlspecialchars($_POST['nama'] ?? '') ?>"
               placeholder="Nama lengkap"
               <?= $rateLimited ? 'disabled' : '' ?>>
      </div>
      <div class="field">
        <label>Email</label>
        <input type="email" name="email"
               value="<?= htmlspecialchars($_POST['email'] ?? '') ?>"
               placeholder="email@contoh.com"
               <?= $rateLimited ? 'disabled' : '' ?>>
      </div>
      <div class="field">
        <label>Pesan</label>
        <textarea name="pesan" placeholder="Tulis pesan..."
                  <?= $rateLimited ? 'disabled' : '' ?>><?= htmlspecialchars($_POST['pesan'] ?? '') ?></textarea>
      </div>
      <button class="btn btn-blue" type="submit" <?= $rateLimited ? 'disabled' : '' ?>>
        <?= $rateLimited ? '⏳ Tunggu ' . formatWaktu($retryAfter) : 'Kirim Pesan' ?>
      </button>
    </form>

    <div class="kuota-wrap">
      <div class="kuota-label">
        <span>Sisa kuota pesan</span>
        <span><?= $kuotaKontak['sisa'] ?> / <?= $kuotaKontak['limit'] ?></span>
      </div>
      <div class="kuota-bar-bg">
        <div class="kuota-bar-fill"
             style="width:<?= $kuotaKontak['persen'] ?>%;background:<?= warnaKuota($kuotaKontak['persen']) ?>">
        </div>
      </div>
    </div>

    <div class="compare-box">
      <strong>Perbedaan nyata yang bisa dirasakan:</strong><br>
      <span class="tag-ts">Timestamp</span> — kirim 3 pesan, lalu diam 2 menit, tetap diblokir sampai 10 menit penuh.<br>
      <span class="tag-dc">Dual-Counter</span> — kirim 3 pesan, lalu diam 2 menit, kadang bisa kirim lagi sebelum 10 menit.
    </div>
  </div>

<?php endif; ?>

  <div class="storage-info">
    Storage: <code><?= htmlspecialchars(realpath($tempDir) ?: $tempDir) ?></code>
  </div>

</div>
</body>
</html>
