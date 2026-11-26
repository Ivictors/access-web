<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/../src/GatewayClient.php';
require_once __DIR__ . '/../src/LoginThrottle.php';

$error = null;
$device = null;
$events = [];
$deviceId = '';
$authenticated = !empty($_SESSION['authenticated']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_is_valid()) {
        http_response_code(400);
        $error = 'Formulário expirado. Recarregue a página e tente novamente.';
    } elseif (($_POST['action'] ?? '') === 'logout' && $authenticated) {
        $_SESSION = [];
        session_destroy();
        setcookie(session_name(), '', [
            'expires' => time() - 3600,
            'path' => '/',
            'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        header('Location: /', true, 303);
        exit;
    } elseif (($_POST['action'] ?? '') === 'login' && !$authenticated) {
        $hash = getenv('ACCESS_WEB_PASSWORD_HASH') ?: '';
        $password = $_POST['password'] ?? null;
        if ($hash === '') {
            http_response_code(503);
            $error = 'A senha da página ainda não foi configurada no servidor.';
        } else {
            try {
                $result = (new LoginThrottle())->verify(
                    LoginThrottle::originFromServer($_SERVER),
                    is_string($password) ? $password : '',
                    $hash
                );
                if ($result['status'] === 'blocked') {
                    http_response_code(429);
                    header('Retry-After: ' . $result['retryAfter']);
                    $error = 'Não foi possível entrar. Tente novamente mais tarde.';
                } elseif ($result['status'] === 'invalid') {
                    $error = 'Não foi possível entrar. Confira a senha.';
                } else {
                    session_regenerate_id(true);
                    $_SESSION['authenticated'] = true;
                    $_SESSION['last_activity'] = time();
                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                    header('Location: /', true, 303);
                    exit;
                }
            } catch (RuntimeException $exception) {
                http_response_code(503);
                $error = 'O login está temporariamente indisponível.';
            }
        }
    } else {
        http_response_code(400);
        $error = 'Ação inválida.';
    }
}

if ($authenticated && $_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['device_id'])) {
    $deviceId = is_string($_GET['device_id']) ? trim($_GET['device_id']) : '';
    if (!preg_match('/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/D', $deviceId)) {
        $error = 'Informe um UUID de dispositivo válido.';
    } else {
        try {
            $gateway = new GatewayClient();
            $deviceResult = $gateway->get('/devices/' . $deviceId);
            if ($deviceResult['status'] === 404) {
                $error = 'Dispositivo não encontrado.';
            } elseif ($deviceResult['status'] !== 200 || !is_array($deviceResult['data'])) {
                $error = 'Não foi possível consultar o dispositivo. Confira o acesso ao gateway.';
            } else {
                $eventsResult = $gateway->get('/devices/' . $deviceId . '/events?limit=50');
                if ($eventsResult['status'] === 200 && is_array($eventsResult['data']) && array_is_list($eventsResult['data'])) {
                    $device = $deviceResult['data'];
                    $events = $eventsResult['data'];
                } else {
                    $error = 'Não foi possível consultar os eventos deste dispositivo.';
                }
            }
        } catch (RuntimeException $exception) {
            $error = $exception->getMessage();
        }
    }
}
?>
<!doctype html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Access Gateway · Consultas</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
<main class="container">
    <header class="page-header">
        <div>
            <p class="eyebrow">Access Gateway</p>
            <h1>Consulta de acessos</h1>
            <p class="subtitle">Dados dos dispositivos e seus eventos mais recentes.</p>
        </div>
        <?php if ($authenticated): ?>
            <form method="post" action="/" class="logout-form">
                <input type="hidden" name="csrf_token" value="<?= escape($_SESSION['csrf_token']) ?>">
                <input type="hidden" name="action" value="logout">
                <button type="submit" class="secondary">Sair</button>
            </form>
        <?php endif; ?>
    </header>

    <?php if ($error !== null): ?>
        <p class="message error" role="alert"><?= escape($error) ?></p>
    <?php endif; ?>

    <?php if (!$authenticated): ?>
        <section class="card login-card" aria-labelledby="login-title">
            <h2 id="login-title">Acesso administrativo</h2>
            <p>Entre com a senha da página para consultar o gateway.</p>
            <form method="post" action="/">
                <input type="hidden" name="csrf_token" value="<?= escape($_SESSION['csrf_token']) ?>">
                <input type="hidden" name="action" value="login">
                <label for="password">Senha</label>
                <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
                <button type="submit">Entrar</button>
            </form>
        </section>
    <?php else: ?>
        <section class="card" aria-labelledby="search-title">
            <h2 id="search-title">Dispositivo</h2>
            <p>Informe o UUID do dispositivo para ver seus dados e os últimos 50 eventos.</p>
            <form method="get" action="/" class="search-form">
                <div class="field">
                    <label for="device_id">UUID do dispositivo</label>
                    <input id="device_id" name="device_id" type="text" value="<?= escape($deviceId) ?>" placeholder="00000000-0000-0000-0000-000000000000" pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" required>
                </div>
                <button type="submit">Consultar</button>
            </form>
        </section>

        <?php if ($device !== null): ?>
            <section class="card" aria-labelledby="device-title">
                <h2 id="device-title"><?= escape($device['name'] ?? '') ?></h2>
                <dl class="device-details">
                    <div><dt>ID</dt><dd><?= escape($device['id'] ?? '') ?></dd></div>
                    <div><dt>Número de série</dt><dd><?= escape($device['serialNumber'] ?? '') ?></dd></div>
                    <div><dt>Estado</dt><dd><?= !empty($device['active']) ? 'Ativo' : 'Inativo' ?></dd></div>
                    <div><dt>Criado em</dt><dd><?= escape($device['createdAt'] ?? '') ?></dd></div>
                </dl>
            </section>

            <section class="card" aria-labelledby="events-title">
                <h2 id="events-title">Eventos recentes</h2>
                <?php if ($events === []): ?>
                    <p class="empty">Nenhum evento registrado para este dispositivo.</p>
                <?php else: ?>
                    <div class="table-scroll">
                        <table>
                            <thead><tr><th>Ocorrido em</th><th>Tipo</th><th>Classificação</th><th>Credencial</th><th>ID externo</th><th>Recebido em</th><th>ID do evento</th></tr></thead>
                            <tbody>
                            <?php foreach ($events as $event): ?>
                                <tr>
                                    <td><?= escape($event['occurredAt'] ?? '') ?></td>
                                    <td><?= escape($event['eventType'] ?? '') ?></td>
                                    <td><?= escape($event['classification'] ?? '') ?></td>
                                    <td><?= escape($event['credentialRef'] ?? '') ?></td>
                                    <td><?= escape($event['externalEventId'] ?? '') ?></td>
                                    <td><?= escape($event['receivedAt'] ?? '') ?></td>
                                    <td><?= escape($event['id'] ?? '') ?></td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </section>
        <?php endif; ?>
    <?php endif; ?>
</main>
</body>
</html>
