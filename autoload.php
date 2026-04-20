<?php

// Autoloader sederhana (tanpa Composer)
spl_autoload_register(function (string $class): void {
    $map = [
        'RateLimiter\\RateLimiter'          => __DIR__ . '/src/RateLimiter.php',
        'RateLimiter\\StorageInterface'     => __DIR__ . '/src/Storage.php',
        'RateLimiter\\FileStorage'          => __DIR__ . '/src/Storage.php',
        'RateLimiter\\RedisStorage'         => __DIR__ . '/src/Storage.php',
        'RateLimiter\\ApcuStorage'          => __DIR__ . '/src/Storage.php',
        'RateLimiter\\HybridStorage'        => __DIR__ . '/src/Storage.php',
        'RateLimiter\\ArrayStorage'         => __DIR__ . '/src/Storage.php',
        'RateLimiter\\RateLimitMiddleware'  => __DIR__ . '/src/RateLimitMiddleware.php',
        'RateLimiter\\SecurityHelper'       => __DIR__ . '/src/SecurityHelper.php',
    ];

    if (isset($map[$class])) {
        require_once $map[$class];
    }
});
