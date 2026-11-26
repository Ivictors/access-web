<?php
declare(strict_types=1);

final class LoginThrottle
{
    private const MAX_FAILURES = 5;
    private const WINDOW_SECONDS = 900;
    private const BLOCK_SECONDS = 900;
    private const MAX_ORIGINS = 4096;
    private const MAX_STATE_BYTES = 1048576;

    private string $stateFile;

    public function __construct(?string $stateFile = null)
    {
        $this->stateFile = $stateFile ?? sys_get_temp_dir() . '/access-web-login/login-attempts.json';
    }

    public static function originFromServer(array $server): string
    {
        $address = $server['REMOTE_ADDR'] ?? null;
        if (!is_string($address) || filter_var($address, FILTER_VALIDATE_IP) === false) {
            throw new RuntimeException('O login está temporariamente indisponível.');
        }
        return $address;
    }

    /** @return array{status: 'valid'|'invalid'|'blocked', retryAfter: int} */
    public function verify(string $origin, string $password, string $hash, ?int $now = null): array
    {
        if (filter_var($origin, FILTER_VALIDATE_IP) === false) {
            throw new RuntimeException('O login está temporariamente indisponível.');
        }
        $now ??= time();
        $directory = dirname($this->stateFile);
        if ((!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) ||
            is_link($directory) || !is_writable($directory) || is_link($this->stateFile)) {
            throw new RuntimeException('O login está temporariamente indisponível.');
        }

        $previousUmask = umask(0077);
        try {
            $file = @fopen($this->stateFile, 'c+');
        } finally {
            umask($previousUmask);
        }
        if ($file === false) {
            throw new RuntimeException('O login está temporariamente indisponível.');
        }

        try {
            if (!@flock($file, LOCK_EX)) {
                throw new RuntimeException('O login está temporariamente indisponível.');
            }
            $size = fstat($file)['size'] ?? false;
            if (!is_int($size) || $size > self::MAX_STATE_BYTES) {
                throw new RuntimeException('O login está temporariamente indisponível.');
            }
            $contents = @stream_get_contents($file);
            if ($contents === false) {
                throw new RuntimeException('O login está temporariamente indisponível.');
            }
            $state = $contents === '' ? ['origins' => []] : json_decode($contents, true);
            if (is_array($state) && !isset($state['origins']) &&
                isset($state['failures'], $state['blockedUntil']) &&
                is_array($state['failures']) && array_is_list($state['failures']) &&
                is_int($state['blockedUntil'])) {
                foreach ($state['failures'] as $timestamp) {
                    if (!is_int($timestamp)) {
                        throw new RuntimeException('O login está temporariamente indisponível.');
                    }
                }
                // Preserve an active block from the old shared state until its normal expiry.
                if ($state['blockedUntil'] > $now) {
                    return ['status' => 'blocked', 'retryAfter' => $state['blockedUntil'] - $now];
                }
                $state = ['origins' => [hash('sha256', $origin) => $state]];
            }
            if (!is_array($state) || !isset($state['origins']) || !is_array($state['origins'])) {
                throw new RuntimeException('O login está temporariamente indisponível.');
            }

            // Validate every record before pruning. Corrupt state must never reset the limit.
            foreach ($state['origins'] as $key => $record) {
                if (!is_string($key) || !preg_match('/^[a-f0-9]{64}$/D', $key) ||
                    !is_array($record) || !isset($record['failures'], $record['blockedUntil']) ||
                    !is_array($record['failures']) || !array_is_list($record['failures']) ||
                    !is_int($record['blockedUntil'])) {
                    throw new RuntimeException('O login está temporariamente indisponível.');
                }
                foreach ($record['failures'] as $timestamp) {
                    if (!is_int($timestamp)) {
                        throw new RuntimeException('O login está temporariamente indisponível.');
                    }
                }
                $record['failures'] = array_values(array_filter(
                    $record['failures'],
                    static fn (int $timestamp): bool => $timestamp > $now - self::WINDOW_SECONDS && $timestamp <= $now
                ));
                if ($record['blockedUntil'] <= $now) {
                    $record['blockedUntil'] = 0;
                }
                if ($record['failures'] === [] && $record['blockedUntil'] === 0) {
                    unset($state['origins'][$key]);
                } else {
                    $state['origins'][$key] = $record;
                }
            }

            $key = hash('sha256', $origin);
            $record = $state['origins'][$key] ?? ['failures' => [], 'blockedUntil' => 0];
            if ($record['blockedUntil'] > $now) {
                return ['status' => 'blocked', 'retryAfter' => $record['blockedUntil'] - $now];
            }
            if (!isset($state['origins'][$key]) && count($state['origins']) >= self::MAX_ORIGINS) {
                throw new RuntimeException('O login está temporariamente indisponível.');
            }

            if (password_verify($password, $hash)) {
                unset($state['origins'][$key]);
                $status = 'valid';
            } else {
                $record['failures'][] = $now;
                $status = 'invalid';
                if (count($record['failures']) >= self::MAX_FAILURES) {
                    $record = ['failures' => [], 'blockedUntil' => $now + self::BLOCK_SECONDS];
                    $status = 'blocked';
                }
                $state['origins'][$key] = $record;
            }

            $encoded = json_encode($state, JSON_THROW_ON_ERROR);
            if (strlen($encoded) > self::MAX_STATE_BYTES) {
                throw new RuntimeException('O login está temporariamente indisponível.');
            }
            rewind($file);
            if (@fwrite($file, $encoded) !== strlen($encoded) ||
                !@ftruncate($file, strlen($encoded)) || !@fflush($file)) {
                throw new RuntimeException('O login está temporariamente indisponível.');
            }
            return ['status' => $status, 'retryAfter' => $status === 'blocked' ? self::BLOCK_SECONDS : 0];
        } finally {
            @flock($file, LOCK_UN);
            fclose($file);
        }
    }
}
