<?php
declare(strict_types=1);

final class OidcClient
{
    private string $publicBase;
    private string $internalBase;
    private string $clientId;
    private string $clientSecret;
    private string $redirectUri;

    public function __construct()
    {
        $this->publicBase = rtrim(getenv('ACCESS_OIDC_PUBLIC_BASE_URL') ?: '', '/');
        $this->internalBase = rtrim(getenv('ACCESS_OIDC_INTERNAL_BASE_URL') ?: '', '/');
        $this->clientId = getenv('ACCESS_OIDC_CLIENT_ID') ?: '';
        $this->clientSecret = getenv('ACCESS_OIDC_CLIENT_SECRET') ?: '';
        $this->redirectUri = getenv('ACCESS_OIDC_REDIRECT_URI') ?: '';
        if ($this->clientId === '' || $this->clientSecret === '' ||
            $this->redirectUri === '' || !$this->validOrigin($this->publicBase) ||
            !$this->validOrigin($this->internalBase)) {
            throw new RuntimeException('Configuração OIDC indisponível.');
        }
    }

    private function validOrigin(string $value): bool
    {
        $parts = parse_url($value);
        return is_array($parts) && in_array($parts['scheme'] ?? '', ['http', 'https'], true) &&
            !empty($parts['host']) && !isset($parts['user']) && !isset($parts['pass']) &&
            preg_match('#^/realms/[A-Za-z0-9_-]+$#D', $parts['path'] ?? '') === 1 &&
            !isset($parts['query']) && !isset($parts['fragment']);
    }

    public function authorizationUrl(string $state, string $nonce, string $verifier): string
    {
        return $this->publicBase . '/protocol/openid-connect/auth?' . http_build_query([
            'response_type' => 'code', 'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri, 'scope' => 'openid',
            'state' => $state, 'nonce' => $nonce,
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
        ]);
    }

    public function complete(string $code, string $nonce, string $verifier): void
    {
        $tokens = $this->tokenRequest([
            'grant_type' => 'authorization_code', 'code' => $code,
            'redirect_uri' => $this->redirectUri, 'code_verifier' => $verifier,
        ]);
        $idToken = $tokens['id_token'] ?? '';
        $claims = $this->verifiedClaims(is_string($idToken) ? $idToken : '');
        if (!is_array($claims) || !hash_equals($nonce, (string) ($claims['nonce'] ?? '')) ||
            ($claims['iss'] ?? '') !== $this->publicBase ||
            ($claims['aud'] ?? '') !== $this->clientId ||
            (int) ($claims['exp'] ?? 0) <= time() || empty($claims['sub'])) {
            throw new RuntimeException('Resposta OIDC inválida.');
        }
        $userinfo = $this->request($this->internalBase . '/protocol/openid-connect/userinfo',
            [], (string) ($tokens['access_token'] ?? ''));
        if (($userinfo['sub'] ?? '') !== $claims['sub']) {
            throw new RuntimeException('Identidade OIDC inválida.');
        }
        $this->saveTokens($tokens);
        $_SESSION['oidc_id_token'] = $idToken;
        $_SESSION['oidc_subject'] = $claims['sub'];
    }

    public function logoutUrl(string $idToken): string
    {
        return $this->publicBase . '/protocol/openid-connect/logout?' . http_build_query([
            'id_token_hint' => $idToken,
            'client_id' => $this->clientId,
            'post_logout_redirect_uri' => preg_replace('/\?.*$/', '', $this->redirectUri),
        ]);
    }

    private function verifiedClaims(string $token): ?array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }
        $header = json_decode((string) base64_decode(strtr($parts[0], '-_', '+/'), true), true);
        $claims = json_decode((string) base64_decode(strtr($parts[1], '-_', '+/'), true), true);
        if (!is_array($header) || !is_array($claims) || ($header['alg'] ?? '') !== 'RS256' ||
            !is_string($header['kid'] ?? null)) {
            return null;
        }
        $keys = $this->request($this->internalBase . '/protocol/openid-connect/certs', [], '', false);
        foreach ($keys['keys'] ?? [] as $key) {
            if (($key['kid'] ?? null) !== $header['kid'] || ($key['kty'] ?? null) !== 'RSA' ||
                ($key['use'] ?? 'sig') !== 'sig' || !is_string($key['x5c'][0] ?? null)) {
                continue;
            }
            $pem = "-----BEGIN CERTIFICATE-----\n" . chunk_split($key['x5c'][0], 64, "\n") . "-----END CERTIFICATE-----\n";
            $signature = base64_decode(strtr($parts[2], '-_', '+/'), true);
            if ($signature !== false && openssl_verify($parts[0] . '.' . $parts[1], $signature, $pem, OPENSSL_ALGO_SHA256) === 1) {
                return $claims;
            }
        }
        return null;
    }

    public function accessToken(): string
    {
        if (empty($_SESSION['oidc_access_token'])) {
            throw new RuntimeException('Sessão OIDC indisponível.');
        }
        if ((int) ($_SESSION['oidc_expires_at'] ?? 0) <= time() + 30) {
            $refresh = $_SESSION['oidc_refresh_token'] ?? '';
            if (!is_string($refresh) || $refresh === '') {
                throw new RuntimeException('Sessão OIDC expirada.');
            }
            $this->saveTokens($this->tokenRequest(['grant_type' => 'refresh_token', 'refresh_token' => $refresh]));
        }
        return (string) $_SESSION['oidc_access_token'];
    }

    private function saveTokens(array $tokens): void
    {
        if (empty($tokens['access_token']) || !isset($tokens['expires_in']) || empty($tokens['refresh_token'])) {
            throw new RuntimeException('Resposta OIDC incompleta.');
        }
        $_SESSION['oidc_access_token'] = $tokens['access_token'];
        $_SESSION['oidc_refresh_token'] = $tokens['refresh_token'];
        $_SESSION['oidc_expires_at'] = time() + (int) $tokens['expires_in'];
    }

    private function tokenRequest(array $fields): array
    {
        return $this->request($this->internalBase . '/protocol/openid-connect/token',
            $fields + ['client_id' => $this->clientId, 'client_secret' => $this->clientSecret]);
    }

    private function request(string $url, array $fields, string $bearer = '', bool $post = true): array
    {
        $handle = curl_init($url);
        if ($handle === false) {
            throw new RuntimeException('Keycloak indisponível.');
        }
        curl_setopt_array($handle, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 2,
            CURLOPT_TIMEOUT => 8,
            CURLOPT_HTTPHEADER => $bearer !== '' ? ['Authorization: Bearer ' . $bearer] :
                ['Content-Type: application/x-www-form-urlencoded'],
        ]);
        if ($post && $bearer === '') {
            curl_setopt($handle, CURLOPT_POST, true);
            curl_setopt($handle, CURLOPT_POSTFIELDS, http_build_query($fields));
        }
        try {
            $body = curl_exec($handle);
            $status = curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        } finally {
            curl_close($handle);
        }
        $data = is_string($body) ? json_decode($body, true) : null;
        if ($status !== 200 || !is_array($data)) {
            throw new RuntimeException('Keycloak indisponível ou resposta inválida.');
        }
        return $data;
    }
}
