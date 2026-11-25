<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/LoginThrottle.php';

echo (new LoginThrottle($argv[1]))->verify('wrong-password', $argv[2], 3000)['status'];
