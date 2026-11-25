<?php
declare(strict_types=1);

const SESSION_IDLE_SECONDS = 1800;

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");

ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
session_name('access_web_session');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();

if (isset($_SESSION['authenticated']) &&
    (!isset($_SESSION['last_activity']) || time() - (int) $_SESSION['last_activity'] > SESSION_IDLE_SECONDS)) {
    $_SESSION = [];
    session_regenerate_id(true);
}

if (!empty($_SESSION['authenticated'])) {
    $_SESSION['last_activity'] = time();
}

if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function csrf_is_valid(): bool
{
    return isset($_POST['csrf_token']) && is_string($_POST['csrf_token']) &&
        hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']);
}

function escape(mixed $value): string
{
    return htmlspecialchars(is_scalar($value) ? (string) $value : '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
