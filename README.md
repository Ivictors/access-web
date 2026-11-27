# Consulta web do Access Gateway

## Login OIDC opcional

Com `ACCESS_WEB_OIDC_ENABLED=true`, a página usa o Keycloak pelo fluxo Authorization Code com PKCE S256. Configure `ACCESS_OIDC_PUBLIC_BASE_URL`, `ACCESS_OIDC_INTERNAL_BASE_URL`, `ACCESS_OIDC_CLIENT_ID`, `ACCESS_OIDC_CLIENT_SECRET` e `ACCESS_OIDC_REDIRECT_URI`; o `access-infra/compose.oidc.yaml` fornece os valores locais. O navegador é redirecionado ao endereço público do Keycloak, enquanto o PHP troca o código e consulta o usuário pelo endereço interno. A web valida a assinatura do ID token com as chaves do realm. O token de acesso fica apenas na sessão PHP e é enviado ao gateway. A web renova o token quando necessário. O logout encerra a sessão PHP e a sessão SSO no Keycloak.

Sem essa opção, o login por senha e o token administrativo compartilhado continuam disponíveis para os testes existentes. No modo OIDC, `ACCESS_WEB_PASSWORD_HASH` e `ACCESS_GATEWAY_ADMIN_TOKEN` não são usados pela web.

Interface PHP simples para consultar um dispositivo pelo UUID e mostrar seus 50 eventos mais recentes. O PHP chama o backend Java com o token do modo escolhido. Não há conexão PHP com o banco de dados.

Este repositório contém somente a web. A integração local com o gateway e o PostgreSQL está no repositório [access-infra](https://github.com/Ivictors/access-infra).

## Imagem de contêiner

O `Dockerfile` usa PHP 8.4 com Apache e extensão cURL. A raiz HTTP é `public/`; `src/` fica fora dela. Para validar a imagem isoladamente, execute `docker build -t access-web:local .` e confira a sintaxe com `docker run --rm access-web:local php -l /var/www/html/public/index.php`. As variáveis `ACCESS_WEB_PASSWORD_HASH`, `ACCESS_GATEWAY_ADMIN_TOKEN` e `ACCESS_GATEWAY_BASE_URL` devem ser fornecidas em tempo de execução.

A CI valida a imagem, a sintaxe PHP, o bloqueio de tentativas e o fluxo HTTP de login. Um push em `main` deve executar `CI`; uma nova tag Git `v*` apontando para um commit de `main` deve executar `Publish image`. Esse workflow publica `ghcr.io/ivictors/access-web:<tag Git>` e `ghcr.io/ivictors/access-web:sha-<commit completo>`, e registra o digest imutável no resumo da execução. A tag da imagem é um nome móvel; para uma release reproduzível, use `ghcr.io/ivictors/access-web@sha256:<digest>` obtido no workflow. Publicar a imagem não implanta a web. O gatilho automático de push/tag ainda depende de verificação no GitHub (issue #1).

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

O login aceita até quatro senhas incorretas por endereço IP de conexão em uma janela de 15 minutos. A quinta falha bloqueia novas tentativas dessa origem por 15 minutos, inclusive com a senha correta. O servidor usa `REMOTE_ADDR`; cabeçalhos como `X-Forwarded-For` não são aceitos pela aplicação. Atrás de um proxy, configure o Apache para reconhecer o IP somente dos proxies confiáveis e bloqueie o acesso direto ao PHP antes de usar esta proteção em rede. Um IP compartilhado também compartilha o limite.

O estado fica em `access-web-login/login-attempts.json` dentro do diretório temporário do PHP, fora de `public/`. Entradas vencidas são removidas em cada tentativa. O arquivo aceita até 4096 origens e 1 MiB; se atingir o limite ou ficar indisponível/corrompido, novos logins falham de forma fechada. Um login válido limpa o contador da própria origem. O estado em `/tmp` é perdido quando o contêiner é substituído; em implantação com várias instâncias, monte esse diretório em armazenamento persistente e compartilhado.
Ao atualizar da versão com contador global, um bloqueio ainda ativo conserva seu prazo original. Depois disso, o próximo login migra o arquivo para contadores por origem.

### Alternativa com Docker

Se PHP não estiver instalado na máquina, a imagem oficial `php:8.4-cli-alpine` oferece PHP e cURL. Gere o hash com `docker run --rm -it -v "${PWD}:/app:ro" -w /app php:8.4-cli-alpine php tools/hash-password.php`. Depois de definir as variáveis acima no PowerShell, execute:

```powershell
$env:ACCESS_GATEWAY_BASE_URL = 'http://host.docker.internal:8080'
docker run --rm -p 127.0.0.1:8000:8000 -v "${PWD}:/app:ro" -w /app `
  -e ACCESS_WEB_PASSWORD_HASH -e ACCESS_GATEWAY_ADMIN_TOKEN -e ACCESS_GATEWAY_BASE_URL `
  php:8.4-cli-alpine php -S 0.0.0.0:8000 -t public
```

`host.docker.internal` permite ao PHP no contêiner chamar o Java em execução na máquina. A porta da página continua acessível apenas em `127.0.0.1`.

## Padrão de documentação e configuração

Este repositório existe para oferecer a interface web do Access Gateway. O README acima apresenta o escopo, a arquitetura e as tecnologias específicas do projeto; esta seção padroniza o ponto de entrada para quem deseja reproduzi-lo localmente.

### Clonar e configurar

~~~powershell
git clone https://github.com/Ivictors/access-web.git
cd access-web
~~~

Consulte os pré-requisitos e comandos de execução descritos neste README antes de iniciar. Use variáveis de ambiente, arquivos locais ignorados pelo Git e serviços de desenvolvimento para credenciais; não substitua placeholders por segredos no README e não versione chaves, tokens ou senhas.
