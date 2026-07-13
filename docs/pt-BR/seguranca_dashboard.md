# Segurança do Dashboard (Autenticação e HTTPS)

A partir da v0.90.16, o dashboard web (Fleet/Inspector) oferece autenticação
HTTP Basic e HTTPS opcionais. Ambos vêm **desligados por padrão**, então
atualizar não muda o comportamento de instalações existentes. Você habilita pela
seção `network` do `conf/config.yaml` (ou `/etc/sys-inspector/config.yaml`).

## Autenticação HTTP Basic

As credenciais são armazenadas como hash PBKDF2 (nunca em texto puro) e
verificadas com o `werkzeug`. A autenticação funciona igual em HTTP e HTTPS.

### 1. Gerar o hash da senha

Rode o utilitário **na máquina que vai servir o dashboard**, para que o hash
seja compatível com a versão do `werkzeug` daquele host:

```bash
    python3 tools/gen_password.py
```

Ele pede a senha duas vezes e imprime um hash `pbkdf2:sha256:...`.

### 2. Habilitar no config.yaml

```yaml
    network:
      auth:
        enabled: true
        username: "admin"
        password_hash: "pbkdf2:sha256:600000$...$..."
```

Observações:

- O usuário assume `admin` se omitido.
- Se `enabled: true` mas sem `password_hash`, o servidor **falha fechado**:
  rejeita todas as requisições até um hash ser configurado. Isso evita expor um
  dashboard sem autenticação por acidente.
- O endereço de bind continua configurável (`network.bind_address`); a
  autenticação não força `127.0.0.1`, então você mantém o dashboard acessível na
  LAN exigindo login.

## HTTPS (TLS)

```yaml
    network:
      tls_enabled: true
      ssl_cert: "/etc/sys-inspector/server_cert.pem"
      ssl_key: "/etc/sys-inspector/server_key.pem"
```

Comportamento:

- Se os dois arquivos existem, são usados como estão (sua própria PKI / CA
  corporativa).
- Se algum faltar e `tls_enabled: true`, um par certificado/chave autoassinado
  RSA-2048 é gerado automaticamente na primeira execução. O navegador vai
  avisar sobre o emissor desconhecido, o que é esperado para um certificado
  autoassinado em rede confiável.
- Se a configuração de TLS falhar (por exemplo, caminho sem permissão de
  escrita), o servidor registra o erro e volta para HTTP puro em vez de cair.

## Recomendação

Para um dashboard exposto além do `localhost`, habilite os **dois**, Basic Auth
e TLS. O Basic Auth sobre HTTP puro envia a credencial em base64, trivial de
decodificar na rede; o HTTPS a protege em trânsito.
