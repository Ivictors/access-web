<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    exit(1);
}

fwrite(STDOUT, 'Senha da página: ');
$password = trim((string) fgets(STDIN));
if ($password === '') {
    fwrite(STDERR, "A senha não pode ser vazia.\n");
    exit(1);
}

fwrite(STDOUT, password_hash($password, PASSWORD_DEFAULT) . PHP_EOL);
