<?php
/**
 * ════════════════════════════════════════════════════════════
 *  Rate Limiter — Cron Garbage Collector
 *  File: RateLimiter/cron-gc.php
 * ════════════════════════════════════════════════════════════
 *
 *  Menghapus semua file temp rate limiter yang sudah expired.
 *  Jalankan via cron atau Task Scheduler Windows.
 *
 *  ── Linux / Mac (crontab -e) ─────────────────────────────
 *  Setiap 5 menit:
 *    *\/5 * * * * php /path/to/RateLimiter/cron-gc.php >> /var/log/rl-gc.log 2>&1
 *
 *  Setiap jam (traffic rendah):
 *    0 * * * * php /path/to/RateLimiter/cron-gc.php >> /var/log/rl-gc.log 2>&1
 *
 *  ── Windows Task Scheduler (XAMPP) ───────────────────────
 *  Program : C:\xampp8.2\php\php.exe
 *  Argumen : C:\xampp8.2\htdocs\ratelimiting2\cron-gc.php
 *  Trigger : Setiap 5 menit
 *  (Lihat panduan di bawah untuk cara setup)
 *
 *  ── Manual (kapan saja) ──────────────────────────────────
 *  php cron-gc.php
 *  php cron-gc.php --verbose
 *  php cron-gc.php --dry-run      (simulasi, tidak benar-benar hapus)
 *  php cron-gc.php --stats        (tampilkan statistik saja)
 * ════════════════════════════════════════════════════════════
 */

declare(strict_types=1);

// ── Pastikan hanya dijalankan dari CLI ────────────────────
if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('Forbidden: script ini hanya boleh dijalankan dari command line.');
}

// ── Parse argumen ─────────────────────────────────────────
$args    = array_flip($argv ?? []);
$verbose = isset($args['--verbose']) || isset($args['-v']);
$dryRun  = isset($args['--dry-run']);
$statsOnly = isset($args['--stats']);

// ── Konfigurasi ───────────────────────────────────────────
$config = [
    // Direktori temp — sesuaikan dengan lokasi aplikasi
    'dir' => __DIR__ . '/temp',

    // Hapus file yang tidak bisa dibaca (corrupt)?
    'delete_corrupt' => true,

    // Hapus file .lock yang tertinggal (lebih tua dari N detik)?
    // Lock file harusnya terhapus setelah setiap request selesai.
    // Jika masih ada setelah 300 detik (5 menit) → proses crash.
    'delete_stale_locks' => true,
    'stale_lock_age'     => 300,

    // Tampilkan laporan ringkas ke stdout?
    'show_report' => true,
];

// ── Mulai ─────────────────────────────────────────────────
$startTime = microtime(true);
$now       = time();
$dir       = rtrim($config['dir'], '/\\');

$report = [
    'waktu'          => date('Y-m-d H:i:s'),
    'direktori'      => $dir,
    'mode'           => $dryRun ? 'DRY-RUN (simulasi)' : 'LIVE',
    'total_file'     => 0,
    'expired'        => 0,
    'corrupt'        => 0,
    'stale_lock'     => 0,
    'dihapus'        => 0,
    'dipertahankan'  => 0,
    'error'          => 0,
    'detail'         => [],
];

// ── Validasi direktori ────────────────────────────────────
if (!is_dir($dir)) {
    echo "[{$report['waktu']}] ERROR: Direktori tidak ditemukan: {$dir}\n";
    exit(1);
}

if (!is_readable($dir)) {
    echo "[{$report['waktu']}] ERROR: Direktori tidak bisa dibaca: {$dir}\n";
    exit(1);
}

// ── Proses file JSON ──────────────────────────────────────
$jsonFiles = glob($dir . '/*.json') ?: [];
$report['total_file'] = count($jsonFiles);

foreach ($jsonFiles as $path) {
    $filename = basename($path);
    $alasan   = null;
    $hapus    = false;

    $raw  = @file_get_contents($path);
    $data = ($raw !== false) ? json_decode($raw, true) : null;

    if (!is_array($data)) {
        // File corrupt / tidak bisa dibaca
        $report['corrupt']++;
        if ($config['delete_corrupt']) {
            $alasan = 'corrupt';
            $hapus  = true;
        }
    } elseif (isset($data['_expires']) && $now > $data['_expires']) {
        // File sudah expired
        $report['expired']++;
        $alasan = 'expired (habis ' . date('H:i:s', $data['_expires']) . ')';
        $hapus  = true;
    } elseif (!isset($data['_expires'])) {
        // Tidak ada TTL — file lama sebelum versi baru, hapus
        $report['corrupt']++;
        $alasan = 'tidak ada _expires (format lama)';
        $hapus  = true;
    } else {
        $report['dipertahankan']++;
        if ($verbose) {
            $sisaDetik = $data['_expires'] - $now;
            $report['detail'][] = "  ✓ SIMPAN  {$filename} (expire dalam {$sisaDetik}s)";
        }
    }

    if ($hapus) {
        if (!$dryRun) {
            $ok = @unlink($path);
            // Hapus juga file .lock pasangannya jika ada
            $lockPath = $path . '.lock';
            if (file_exists($lockPath)) { @unlink($lockPath); }
        } else {
            $ok = true; // dry-run: anggap berhasil
        }

        if ($ok) {
            $report['dihapus']++;
            $prefix = $dryRun ? '  ~ SKIP   ' : '  ✗ HAPUS  ';
            $report['detail'][] = "{$prefix}{$filename} ({$alasan})";
        } else {
            $report['error']++;
            $report['detail'][] = "  ! ERROR  {$filename} — gagal dihapus";
        }
    }
}

// ── Proses file .lock yang tertinggal ─────────────────────
if ($config['delete_stale_locks']) {
    $lockFiles = glob($dir . '/*.lock') ?: [];

    foreach ($lockFiles as $lockPath) {
        $mtime = @filemtime($lockPath);
        $umur  = $now - ($mtime ?: $now);

        if ($umur > $config['stale_lock_age']) {
            $report['stale_lock']++;
            $filename = basename($lockPath);

            if (!$dryRun) {
                @unlink($lockPath);
            }

            $prefix = $dryRun ? '  ~ SKIP   ' : '  ✗ HAPUS  ';
            $report['detail'][] = "{$prefix}{$filename} (lock tertinggal, umur {$umur}s)";
        }
    }
}

// ── Hitung durasi ─────────────────────────────────────────
$durasi = round((microtime(true) - $startTime) * 1000, 2);

// ── Tampilkan laporan ─────────────────────────────────────
if ($config['show_report'] || $verbose || $statsOnly) {

    $modeLabel = $dryRun ? ' [DRY-RUN]' : '';
    echo "\n";
    echo "╔══════════════════════════════════════════════╗\n";
    echo "║  Rate Limiter — GC Report{$modeLabel}\n";
    echo "╚══════════════════════════════════════════════╝\n";
    echo "  Waktu    : {$report['waktu']}\n";
    echo "  Dir      : {$report['direktori']}\n";
    echo "  Durasi   : {$durasi}ms\n";
    echo "────────────────────────────────────────────────\n";
    echo "  Total file JSON : {$report['total_file']}\n";
    echo "  Expired         : {$report['expired']}\n";
    echo "  Corrupt         : {$report['corrupt']}\n";
    echo "  Lock tertinggal : {$report['stale_lock']}\n";
    echo "────────────────────────────────────────────────\n";

    $hapusLabel = $dryRun ? 'Akan dihapus' : 'Dihapus';
    echo "  {$hapusLabel}        : {$report['dihapus']}\n";
    echo "  Dipertahankan   : {$report['dipertahankan']}\n";
    echo "  Error           : {$report['error']}\n";
    echo "────────────────────────────────────────────────\n";

    if ($verbose && !empty($report['detail'])) {
        echo "\n  Detail:\n";
        foreach ($report['detail'] as $line) {
            echo $line . "\n";
        }
        echo "\n";
    }

    // Rekomendasi jika file menumpuk
    if ($report['total_file'] > 1000) {
        echo "\n  ⚠  File menumpuk ({$report['total_file']} file).\n";
        echo "     Pertimbangkan: jadwalkan cron lebih sering.\n";
    }

    if ($report['error'] > 0) {
        echo "\n  ⚠  {$report['error']} file gagal dihapus.\n";
        echo "     Periksa permission direktori: {$dir}\n";
    }

    if ($dryRun) {
        echo "\n  ℹ  Mode DRY-RUN: tidak ada file yang benar-benar dihapus.\n";
        echo "     Jalankan tanpa --dry-run untuk eksekusi nyata.\n";
    }

    echo "\n";
}

exit($report['error'] > 0 ? 1 : 0);
