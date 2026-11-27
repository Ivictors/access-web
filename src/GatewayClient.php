<?php
declare(strict_types=1);

final class GatewayClient
{
    private string $baseUrl;
    private string $token;

    public function __construct()
    {
        $this->baseUrl = rtrim(getenv('ACCESS_GATEWAY_BASE_URL') ?: 'http://127.0.0.1:8080', '/');
        $this->token = (getenv('ACCESS_WEB_OIDC_ENABLED') === 'true')
            ? (new OidcClient())->accessToken()
            : (getenv('ACCESS_GATEWAY_ADMIN_TOKEN') ?: '');

        $parts = parse_url($this->baseUrl);
        if ($this->token === '' || !is_array($parts) ||
            !in_array($parts['scheme'] ?? '', ['http', 'https'], true) ||
            empty($parts['host']) || isset($parts['user']) || isset($parts['pass']) ||
            isset($parts['query']) || isset($parts['fragment'])) {
            throw new RuntimeException('Configuração do gateway indisponível.');
        }
    }

    /** @return array{status: int, data: mixed} */
    public function get(string $path): array
    {
        $handle = curl_init($this->baseUrl . $path);
        if ($handle === false) {
            throw new RuntimeException('Não foi possível consultar o gateway.');
        }

        curl_setopt_array($handle, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 2,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_HTTPHEADER => [
                'Accept: application/json',
                'Authorization: Bearer ' . $this->token,
            ],
        ]);

        try {
            $body = curl_exec($handle);
            $status = curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        } finally {
            curl_close($handle);
        }

        if ($body === false || $status === 0) {
            throw new RuntimeException('O gateway não está disponível no momento.');
        }

        $data = json_decode($body, true);
        if ($status === 200 && json_last_error() !== JSON_ERROR_NONE) {
            throw new RuntimeException('O gateway retornou dados inválidos.');
        }

        return ['status' => $status, 'data' => $data];
    }
}
