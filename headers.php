<?php
/**
 * Security headers — include at the top of every entry-point file,
 * before session_start() and before any output.
 */
declare(strict_types=1);

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: no-referrer-when-downgrade');
header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');

$_isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
         || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');

if ($_isHttps) {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
}
unset($_isHttps);

$_csp = "default-src 'self'; "
      . "script-src 'self' 'unsafe-inline'; "
      . "style-src 'self' 'unsafe-inline'; "
      . "img-src 'self' data:; "
      . "font-src 'self'; "
      . "connect-src 'self'; "
      . "form-action 'self'; "
      . "frame-ancestors 'none';";
header("Content-Security-Policy: $_csp");
unset($_csp);
