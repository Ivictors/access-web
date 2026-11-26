<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/LoginThrottle.php';

function check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$directory = sys_get_temp_dir() . '/access-web-throttle-test-' . bin2hex(random_bytes(6));
mkdir($directory, 0700);
$file = $directory . '/attempts.json';
$notDirectory = $directory . '/not-a-directory';
$hash = password_hash('correct-password', PASSWORD_DEFAULT);

try {
    $throttle = new LoginThrottle($file);
    for ($attempt = 1; $attempt <= 4; $attempt++) {
        check($throttle->verify('127.0.0.1', 'wrong-password', $hash, 1000)['status'] === 'invalid', 'Early block');
    }

    $fifth = $throttle->verify('127.0.0.1', 'wrong-password', $hash, 1000);
    check($fifth['status'] === 'blocked' && $fifth['retryAfter'] === 900, 'Fifth failure did not block');
    check((new LoginThrottle($file))->verify('127.0.0.1', 'correct-password', $hash, 1001)['status'] === 'blocked',
        'New session bypassed the block');
    check($throttle->verify('127.0.0.2', 'correct-password', $hash, 1001)['status'] === 'valid',
        'One origin blocked another');
    check($throttle->verify('127.0.0.1', 'correct-password', $hash, 1900)['status'] === 'valid', 'Block did not expire');
    check($throttle->verify('127.0.0.1', 'wrong-password', $hash, 1901)['status'] === 'invalid',
        'Successful login did not clear failures');

    file_put_contents($file, json_encode(['origins' => [hash('sha256', '127.0.0.1') =>
        ['failures' => [1000, 1000, 1000, 1000], 'blockedUntil' => 0]]]));
    check($throttle->verify('127.0.0.1', 'wrong-password', $hash, 1901)['status'] === 'invalid',
        'Old failures were not removed from the window');
    check(count(json_decode(file_get_contents($file), true)['origins']) === 1, 'Expired origin was not pruned');

    check(LoginThrottle::originFromServer(['REMOTE_ADDR' => '127.0.0.1',
        'HTTP_X_FORWARDED_FOR' => '192.0.2.1']) === '127.0.0.1', 'Spoofed forwarding header was trusted');
    try {
        LoginThrottle::originFromServer(['HTTP_X_FORWARDED_FOR' => '192.0.2.1']);
        throw new RuntimeException('Missing connection address was accepted');
    } catch (RuntimeException $exception) {
        check($exception->getMessage() !== 'Missing connection address was accepted',
            'Missing connection address was accepted');
    }

    unlink($file);
    $workers = [];
    for ($index = 0; $index < 8; $index++) {
        $process = proc_open(
            [PHP_BINARY, __DIR__ . '/login_throttle_worker.php', $file, $hash],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes
        );
        check(is_resource($process), 'Could not start concurrent login attempt');
        fclose($pipes[0]);
        $workers[] = [$process, $pipes];
    }
    $results = [];
    foreach ($workers as [$process, $pipes]) {
        $results[] = stream_get_contents($pipes[1]);
        $errors = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        check(proc_close($process) === 0, 'Concurrent attempt failed: ' . $errors);
    }
    check(count(array_filter($results, static fn (string $result): bool => $result === 'invalid')) === 4,
        'Concurrent attempts exceeded the failure threshold');
    check(count(array_filter($results, static fn (string $result): bool => $result === 'blocked')) === 4,
        'Concurrent attempts did not share the block');

    file_put_contents($file, '{broken');
    try {
        $throttle->verify('127.0.0.1', 'correct-password', $hash, 2000);
        throw new RuntimeException('Corrupt state was accepted');
    } catch (RuntimeException $exception) {
        check($exception->getMessage() !== 'Corrupt state was accepted', 'Corrupt state was accepted');
    }

    file_put_contents($notDirectory, '');
    try {
        (new LoginThrottle($notDirectory . '/attempts.json'))->verify('127.0.0.1', 'correct-password', $hash, 2000);
        throw new RuntimeException('Unwritable state was accepted');
    } catch (RuntimeException $exception) {
        check($exception->getMessage() !== 'Unwritable state was accepted', 'Unwritable state was accepted');
    }

    file_put_contents($file, str_repeat('x', 1048577));
    try {
        $throttle->verify('127.0.0.1', 'correct-password', $hash, 2000);
        throw new RuntimeException('Oversized state was accepted');
    } catch (RuntimeException $exception) {
        check($exception->getMessage() !== 'Oversized state was accepted', 'Oversized state was accepted');
    }

    $origins = [];
    for ($index = 0; $index < 4096; $index++) {
        $origins[hash('sha256', '192.0.2.' . $index)] = ['failures' => [2000], 'blockedUntil' => 0];
    }
    file_put_contents($file, json_encode(['origins' => $origins]));
    try {
        $throttle->verify('198.51.100.1', 'correct-password', $hash, 2000);
        throw new RuntimeException('Full state allowed a new origin');
    } catch (RuntimeException $exception) {
        check($exception->getMessage() !== 'Full state allowed a new origin', 'Full state allowed a new origin');
    }
    check($throttle->verify('192.0.2.1', 'correct-password', $hash, 2000)['status'] === 'valid',
        'Full state blocked an existing origin');

    file_put_contents($file, json_encode(['failures' => [], 'blockedUntil' => 2900]));
    check($throttle->verify('127.0.0.1', 'correct-password', $hash, 2000)['status'] === 'blocked',
        'Legacy block was bypassed');
    check($throttle->verify('127.0.0.1', 'correct-password', $hash, 2900)['status'] === 'valid',
        'Legacy state was not migrated after block expiry');
    check(isset(json_decode(file_get_contents($file), true)['origins']), 'Legacy state schema remained');

    echo "LoginThrottle tests passed\n";
} finally {
    unlink($file);
    if (is_file($notDirectory)) {
        unlink($notDirectory);
    }
    rmdir($directory);
}
