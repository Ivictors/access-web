<?php
declare(strict_types=1);

final class LoginThrottle
{
    private const MAX_FAILURES = 5;
    private const WINDOW_SECONDS = 900;
    private const BLOCK_SECONDS = 900;

    private string $stateFile;

    public function __construct(?string $stateFile = null)
    {
        $this->stateFile = $stateFile ?? sys_get_temp_dir() . '/access-web-login/login-attempts.json';
    }

    /** @return array{status: 'valid'|'invalid'|'blocked', retryAfter: int} */
    public function verify(string $password, string $hash, ?int $now = null): array
    {
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

            $contents = @stream_get_contents($file);
            if ($contents === false) {
                throw new RuntimeException('O login está temporariamente indisponível.');
            }
            $state = $contents === '' ? ['failures' => [], 'blockedUntil' => 0] : json_decode($contents, true);
            if (!is_array($state) || !isset($state['failures'], $state['blockedUntil']) ||
                !is_array($state['failures']) || !array_is_list($state['failures']) ||
                !is_int($state['blockedUntil'])) {
                throw new RuntimeException('O login está temporariamente indisponível.');
            }
            foreach ($state['failures'] as $timestamp) {
                if (!is_int($timestamp)) {
                    throw new RuntimeException('O login está temporariamente indisponível.');
                }
            }

            if ($state['blockedUntil'] > $now) {
                return ['status' => 'blocked', 'retryAfter' => $state['blockedUntil'] - $now];
            }

            $state['failures'] = array_values(array_filter(
                $state['failures'],
                static fn (int $timestamp): bool => $timestamp > $now - self::WINDOW_SECONDS
            ));
            $state['blockedUntil'] = 0;

            if (password_verify($password, $hash)) {
                $state['failures'] = [];
                $status = 'valid';
            } else {
                $state['failures'][] = $now;
                $status = 'invalid';
                if (count($state['failures']) >= self::MAX_FAILURES) {
                    $state['failures'] = [];
                    $state['blockedUntil'] = $now + self::BLOCK_SECONDS;
                    $status = 'blocked';
                }
            }

            $encoded = json_encode($state, JSON_THROW_ON_ERROR);
            rewind($file);
            if (@fwrite($file, $encoded) !== strlen($encoded) ||
                !@ftruncate($file, strlen($encoded)) || !@fflush($file)) {
                throw new RuntimeException('O login está temporariamente indisponível.');
            }

            return [
                'status' => $status,
                'retryAfter' => $status === 'blocked' ? self::BLOCK_SECONDS : 0,
            ];
        } finally {
            @flock($file, LOCK_UN);
            fclose($file);
        }
    }
}
