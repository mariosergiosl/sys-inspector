# Segurança do Dashboard (Autenticação e HTTPS)

> **Atualizado em 2026-08-20.** Duas coisas mudaram e valem ser lidas antes do
> resto: **HTTPS deixou de ser opcional** (decisão D-033) e a autenticação, que
> vivia no painel `local-live`, foi **reimplementada no servidor** quando aquele
> modo foi removido.

O dashboard do servidor oferece autenticação HTTP Basic **opcional** e serve
**sempre** sobre HTTPS. Você configura pela seção `network` do
`conf/config.yaml` (ou `/etc/sys-inspector/config.yaml`).

## Autenticação HTTP Basic

As credenciais são armazenadas como hash PBKDF2 (nunca em texto puro) e
verificadas com o `werkzeug`.

A guarda fica **antes do roteamento**, e não dentro de cada rota: assim uma rota
nova nasce protegida por omissão, em vez de nascer aberta até alguém lembrar de
protegê-la. O nome de usuário é comparado em tempo constante
(`hmac.compare_digest`), porque `==` retorna no primeiro caractere diferente e
vaza, pelo tempo de resposta, quantos caracteres iniciais coincidem.

Dois casos falham **fechados**, de propósito: autenticação ligada sem
`password_hash`, e ausência da biblioteca `werkzeug`. Nos dois o operador pediu
proteção, e seguir aberto o deixaria acreditando estar protegido — pior que
recusar.

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

## HTTPS: único transporte, sem chave para desligar

**Não existe mais `tls_enabled`.** O transporte em texto claro foi removido do
código, e não apenas desligado por padrão (D-033).

```yaml
    network:
      ssl_cert: "/etc/sys-inspector/server_cert.pem"
      ssl_key: "/etc/sys-inspector/server_key.pem"
```

Comportamento:

- Se os dois arquivos existem, são usados como estão (sua própria PKI / CA
  corporativa).
- Se algum faltar, um par certificado/chave autoassinado RSA-2048 é gerado
  automaticamente na primeira execução. O navegador avisa sobre o emissor
  desconhecido, o que é esperado. **Ligar TLS por padrão não quebra a primeira
  subida por causa disso.**
- Se o TLS não puder ser ativado, o servidor **não sobe**. Ele não volta para
  HTTP puro: um servidor que não inicia é um problema visível em trinta
  segundos, enquanto um que serve em claro acreditando-se cifrado pode durar
  meses.

### Por que a opção foi removida, e não apenas invertida

O padrão anterior era pior do que parecia. No agente, o transporte era decidido
pelo **número da porta** (`use_tls = server_port == 443`): qualquer porta
diferente — 8080, o caso comum em laboratório e rede interna — fazia o agente
falar em claro sem avisar, levando junto a captura e o cabeçalho
`Authorization: Bearer <token>`.

Enquanto existir uma chave capaz de desligar a cifra, existem três caminhos de
volta, nenhum deles hipotético: a configuração escrita errada, o exemplo copiado
de um documento antigo, e o *"só nesta rede, só por hoje"* que fica permanente.

### O que continua sendo escolha

A **verificação do certificado** (`daemon.verify_tls`, no agente), porque ela
depende de infraestrutura que nem todo ambiente tem: uma CA que assine o
certificado do servidor. Desligar protege contra escuta passiva e **não** contra
um interceptador ativo, e essa diferença muda o quanto o laudo daquele agente
vale — por isso ela é registrada no **log**, toda vez, e não só no arquivo de
configuração.

## Recomendação

Para um dashboard alcançável além do `localhost`, habilite **também** o Basic
Auth. O HTTPS já protege a credencial em trânsito; o Basic Auth é o que impede
que qualquer um que alcance a porta leia a coleta inteira da frota.
