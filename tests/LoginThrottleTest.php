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
        check($throttle->verify('wrong-password', $hash, 1000)['status'] === 'invalid', 'Early block');
    }

    $fifth = $throttle->verify('wrong-password', $hash, 1000);
    check($fifth['status'] === 'blocked' && $fifth['retryAfter'] === 900, 'Fifth failure did not block');
    check((new LoginThrottle($file))->verify('correct-password', $hash, 1001)['status'] === 'blocked',
        'New session bypassed the block');
    check($throttle->verify('correct-password', $hash, 1900)['status'] === 'valid', 'Block did not expire');
    check($throttle->verify('wrong-password', $hash, 1901)['status'] === 'invalid',
        'Successful login did not clear failures');

    file_put_contents($file, json_encode(['failures' => [1000, 1000, 1000, 1000], 'blockedUntil' => 0]));
    check($throttle->verify('wrong-password', $hash, 1901)['status'] === 'invalid',
        'Old failures were not removed from the window');

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
        $throttle->verify('correct-password', $hash, 2000);
        throw new RuntimeException('Corrupt state was accepted');
    } catch (RuntimeException $exception) {
        check($exception->getMessage() !== 'Corrupt state was accepted', 'Corrupt state was accepted');
    }

    file_put_contents($notDirectory, '');
    try {
        (new LoginThrottle($notDirectory . '/attempts.json'))->verify('correct-password', $hash, 2000);
        throw new RuntimeException('Unwritable state was accepted');
    } catch (RuntimeException $exception) {
        check($exception->getMessage() !== 'Unwritable state was accepted', 'Unwritable state was accepted');
    }

    echo "LoginThrottle tests passed\n";
} finally {
    unlink($file);
    if (is_file($notDirectory)) {
        unlink($notDirectory);
    }
    rmdir($directory);
}
