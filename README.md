# Consulta web do Access Gateway

Interface PHP simples para consultar um dispositivo pelo UUID e mostrar seus 50 eventos mais recentes. O navegador acessa apenas o PHP; o PHP chama o backend Java com o token administrativo. Não há conexão PHP com o banco de dados.

## Requisitos

- PHP 8.1 ou superior, com extensão cURL habilitada.
- Backend Java em execução e um UUID de dispositivo conhecido.

## Executar localmente

Configure no ambiente do processo PHP:

| Variável | Uso |
| --- | --- |
| `ACCESS_WEB_PASSWORD_HASH` | Hash da senha de acesso à página, gerado por `password_hash` do PHP. Use uma senha diferente do token do gateway. |
| `ACCESS_GATEWAY_ADMIN_TOKEN` | Mesmo token administrativo configurado no backend Java. Nunca coloque esse valor na pasta `public`. |
| `ACCESS_GATEWAY_BASE_URL` | URL do backend acessível **pelo servidor PHP**. Padrão: `http://127.0.0.1:8080`. |

Para gerar o hash, execute `php tools/hash-password.php` e coloque somente o resultado em `ACCESS_WEB_PASSWORD_HASH`. A senha digitada não deve ser o token administrativo do Java. O comando pede a senha durante a execução, sem gravá-la no histórico do terminal.

Com as três variáveis configuradas, inicie a página a partir desta pasta:

```powershell
php -S 127.0.0.1:8000 -t public
```

Abra `http://127.0.0.1:8000`, entre com a senha da página e informe o UUID do dispositivo. O servidor embutido do PHP é apenas para desenvolvimento local; mantenha-o vinculado a `127.0.0.1`.

O PHP expira sessões após 30 minutos sem atividade e não armazena o token do gateway na sessão. Na publicação em rede, configure HTTPS e cookies `Secure` no servidor web antes de disponibilizar a página.

### Alternativa com Docker

Se PHP não estiver instalado na máquina, a imagem oficial `php:8.4-cli-alpine` oferece PHP e cURL. Gere o hash com `docker run --rm -it -v "${PWD}:/app:ro" -w /app php:8.4-cli-alpine php tools/hash-password.php`. Depois de definir as variáveis acima no PowerShell, execute:

```powershell
$env:ACCESS_GATEWAY_BASE_URL = 'http://host.docker.internal:8080'
docker run --rm -p 127.0.0.1:8000:8000 -v "${PWD}:/app:ro" -w /app `
  -e ACCESS_WEB_PASSWORD_HASH -e ACCESS_GATEWAY_ADMIN_TOKEN -e ACCESS_GATEWAY_BASE_URL `
  php:8.4-cli-alpine php -S 0.0.0.0:8000 -t public
```

`host.docker.internal` permite ao PHP no contêiner chamar o Java em execução na máquina. A porta da página continua acessível apenas em `127.0.0.1`.
