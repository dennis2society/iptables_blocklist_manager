<?php
/**
 * Shared security utilities for the IP Lookup application.
 */
declare(strict_types=1);

/**
 * Escape CSV formula injection — prefix values starting with =, +, -, @ with a single quote.
 */
function escapeCsvFormula(string $value): string {
    if (strlen($value) > 0 && in_array($value[0], ['=', '+', '-', '@'], true)) {
        return "'" . $value;
    }
    return $value;
}

/**
 * Validate a CIDR string (IPv4 or IPv6) with correct prefix-length bounds.
 */
function isValidCidr(string $cidr): bool {
    $parts = explode('/', $cidr, 2);
    if (count($parts) !== 2) {
        return false;
    }
    [$ip, $prefix] = $parts;
    if (!ctype_digit($prefix)) {
        return false;
    }
    $prefix = (int)$prefix;
    $parsed = @inet_pton($ip);
    if ($parsed === false) {
        return false;
    }
    $maxPrefix = strlen($parsed) === 4 ? 32 : 128;
    return $prefix >= 0 && $prefix <= $maxPrefix;
}

/**
 * Ensure a CSRF token exists in the session and return it.
 * Call once after session_start().
 */
function ensureCsrfToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Verify a submitted CSRF token against the session token.
 */
function verifyCsrfToken(string $token): bool {
    return hash_equals($_SESSION['csrf_token'] ?? '', $token);
}
