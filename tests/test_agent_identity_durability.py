# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_agent_identity_durability.py
# DESCRIPTION: A identidade que ASSINA as capturas tem que durar o que dura o
#              agente (C-158).
#
# WHY:         Observado na limpeza das VMs em 2026-08-20. A chave privada do
#              agente era procurada no diretorio da chave do analista, que e
#              CONFIGURACAO, e configuracao se recria. Numa simples troca de
#              diretorio de implantacao a chave publica do agente da 161 passou
#              de 13e2eb55... para dcab6e89..., sem aviso nenhum.
#
#              O UUID sobrevivia, porque mora ao lado do banco. A chave nao.
#              Quem fosse verificar a cadeia veria o MESMO agente assinando com
#              DUAS chaves diferentes, sem nada explicando a troca, que e
#              precisamente o sinal que a parte contraria procura numa peca
#              pericial. E fomos nos que o produzimos.
#
# O QUE PROVA: os tres eixos da correcao, que sao independentes e podem regredir
#              separadamente:
#                1. a chave nasce ao lado do BANCO, e nao do arquivo de config;
#                2. quando existe chave no lugar antigo, ela e HERDADA, senao a
#                   propria correcao trocaria a chave de toda a frota;
#                3. quando ainda assim nasce chave nova, o registro de custodia
#                   DIZ isso, em vez de trocar em silencio.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os

import pytest

from src.core.crypto import ensure_agent_identity
from src.core.custody import build_for_capture

# Os nomes abaixo NASCERAM com a correcao. Importados no topo do modulo, um
# nome ausente vira ImportError e derruba a coleta do arquivo inteiro: ao
# conferir estes testes contra a versao com defeito o relatorio diria "1 erro"
# em vez de dizer quais comportamentos faltam. Como texto, eles nao impedem a
# coleta, e cada caso falha dizendo o que falta.
IDENTITY_EXISTING = "existing"
IDENTITY_MIGRATED = "migrated"
IDENTITY_CREATED = "created"


def agent_key_fingerprint(public_path):
    """Chama o auxiliar da correcao, resolvido no momento do uso."""
    from src.core.crypto import agent_key_fingerprint as impl
    return impl(public_path)


class _BancoFalso(object):
    """
    O minimo que build_for_capture usa do banco: onde ele mora e qual e o UUID.

    O caminho do banco e o que importa para este arquivo: e ele que define onde
    a identidade passa a morar.
    """

    def __init__(self, db_path, agent_id="uuid-de-teste"):
        self.db_path = db_path
        self.agent_id = agent_id

    def get_last_digest(self, _agent_uuid):
        return None


def _config(conf_dir):
    """Configuracao com a chave do ANALISTA em conf_dir, como em campo."""
    return {"security": {"private_key_path": os.path.join(conf_dir,
                                                          "private_key.pem")}}


# ==============================================================================
# 1. ONDE A IDENTIDADE MORA
# ==============================================================================

def test_a_identidade_nasce_ao_lado_do_banco_e_nao_da_configuracao(tmp_path):
    """
    REPROVA A VERSAO COM DEFEITO: antes, o par saia em `<conf>/`, derivado do
    caminho da chave do analista. O teste falha contra aquele codigo porque os
    arquivos aparecem no diretorio errado.

    O criterio nao e estetico: `<conf>` e recriado num redeploy, e `<estado>`
    nao, que e por isso que o `.agent_id` sempre morou la.
    """
    conf = tmp_path / "conf"
    estado = tmp_path / "var"
    conf.mkdir()
    estado.mkdir()
    db = _BancoFalso(str(estado / "sys_inspector.db"))

    build_for_capture(db, _config(str(conf)), {"processes": {}})

    assert (estado / "agent_private_key.pem").exists(), (
        "a identidade do agente nao nasceu ao lado do banco (C-158)")
    assert (estado / "agent_public_key.pem").exists()
    assert not (conf / "agent_private_key.pem").exists(), (
        "a identidade voltou a nascer no diretorio de configuracao (C-158)")


def test_caminho_declarado_na_configuracao_continua_mandando(tmp_path):
    """
    PERDA DE FUNCIONALIDADE que a correcao nao pode causar: quem escolheu onde
    a chave fica escolheu por algum motivo, e nao cabe a uma atualizacao mudar
    isso por conta propria.
    """
    escolhido = tmp_path / "escolhido"
    escolhido.mkdir()
    estado = tmp_path / "var"
    estado.mkdir()
    db = _BancoFalso(str(estado / "sys_inspector.db"))

    cfg = _config(str(tmp_path))
    cfg["security"]["agent_private_key_path"] = str(escolhido / "priv.pem")
    cfg["security"]["agent_public_key_path"] = str(escolhido / "pub.pem")

    build_for_capture(db, cfg, {"processes": {}})

    assert (escolhido / "priv.pem").exists()
    assert not (estado / "agent_private_key.pem").exists(), (
        "o caminho declarado na configuracao foi ignorado (C-158)")


# ==============================================================================
# 2. HERANCA: A CORRECAO NAO PODE CAUSAR O DEFEITO QUE CORRIGE
# ==============================================================================

def test_a_chave_do_lugar_antigo_e_herdada_e_nao_regerada(tmp_path):
    """
    O caso que decide se a correcao presta.

    Um agente que ja roda tem a chave no lugar ANTIGO. Se a atualizacao gerasse
    uma nova por nao encontrar nada no lugar novo, ela produziria, de uma vez e
    em toda a frota, exatamente a descontinuidade que este item existe para
    evitar. A chave depois da migracao tem que ser A MESMA.
    """
    conf = tmp_path / "conf"
    estado = tmp_path / "var"
    conf.mkdir()
    estado.mkdir()

    # Agente que ja rodava: identidade no lugar antigo.
    velha_priv = str(conf / "agent_private_key.pem")
    velha_pub = str(conf / "agent_public_key.pem")
    assert ensure_agent_identity(velha_priv, velha_pub) == IDENTITY_CREATED
    impressao_antes = agent_key_fingerprint(velha_pub)

    db = _BancoFalso(str(estado / "sys_inspector.db"))
    registro = build_for_capture(db, _config(str(conf)), {"processes": {}})

    impressao_depois = agent_key_fingerprint(str(estado / "agent_public_key.pem"))
    assert impressao_depois == impressao_antes, (
        "a atualizacao TROCOU a chave do agente em vez de herda-la (C-158)")
    assert registro["agent_key_event"] == IDENTITY_MIGRATED


def test_a_heranca_nao_apaga_a_chave_do_lugar_antigo(tmp_path):
    """
    COLISAO com um processo antigo ainda no ar: se a migracao REMOVESSE o
    original, um agente que ainda aponta para o caminho velho nao acharia nada e
    geraria outra chave, criando a descontinuidade pelo outro lado.
    """
    conf = tmp_path / "conf"
    estado = tmp_path / "var"
    conf.mkdir()
    estado.mkdir()
    velha_priv = str(conf / "agent_private_key.pem")
    velha_pub = str(conf / "agent_public_key.pem")
    ensure_agent_identity(velha_priv, velha_pub)

    db = _BancoFalso(str(estado / "sys_inspector.db"))
    build_for_capture(db, _config(str(conf)), {"processes": {}})

    assert os.path.exists(velha_priv), (
        "a migracao apagou a chave do lugar antigo (C-158)")


def test_a_segunda_captura_nao_migra_de_novo(tmp_path):
    """
    Depois de migrar, o evento passa a ser "existing". Continuar dizendo
    "migrated" a cada captura transformaria um fato pontual em ruido, e ruido
    esconde a proxima troca de verdade.
    """
    conf = tmp_path / "conf"
    estado = tmp_path / "var"
    conf.mkdir()
    estado.mkdir()
    ensure_agent_identity(str(conf / "agent_private_key.pem"),
                          str(conf / "agent_public_key.pem"))
    db = _BancoFalso(str(estado / "sys_inspector.db"))
    cfg = _config(str(conf))

    primeiro = build_for_capture(db, cfg, {"processes": {}})
    segundo = build_for_capture(db, cfg, {"processes": {}})

    assert primeiro["agent_key_event"] == IDENTITY_MIGRATED
    assert segundo["agent_key_event"] == IDENTITY_EXISTING
    assert segundo["agent_key_fingerprint"] == primeiro["agent_key_fingerprint"]


def test_heranca_ignorada_quando_o_par_antigo_esta_incompleto(tmp_path):
    """
    CENARIO ADVERSO: so a metade publica sobrou no lugar antigo. Herdar uma
    chave publica sem a privada produziria um agente que declara uma identidade
    com que nao consegue assinar.
    """
    conf = tmp_path / "conf"
    estado = tmp_path / "var"
    conf.mkdir()
    estado.mkdir()
    (conf / "agent_public_key.pem").write_text("nao importa o conteudo")

    db = _BancoFalso(str(estado / "sys_inspector.db"))
    registro = build_for_capture(db, _config(str(conf)), {"processes": {}})

    assert registro["agent_key_event"] == IDENTITY_CREATED
    assert registro["signature"], (
        "o agente ficou sem conseguir assinar depois de uma heranca parcial")


# ==============================================================================
# 3. DECLARACAO: A TROCA APARECE NA PROPRIA PECA
# ==============================================================================

def test_toda_captura_carrega_a_impressao_da_chave(tmp_path):
    """
    REPROVA A VERSAO COM DEFEITO: o registro de custodia nao dizia QUAL chave
    assinou. Sem isso, uma troca so aparece para quem comparar assinaturas de
    capturas distintas, que e o trabalho que a parte contraria faz e nos nao.

    A impressao vai em TODA captura, e nao so quando muda: um campo que so
    aparece no momento ruim e um campo que ninguem sabe ler.
    """
    estado = tmp_path / "var"
    estado.mkdir()
    db = _BancoFalso(str(estado / "sys_inspector.db"))

    registro = build_for_capture(db, _config(str(tmp_path)), {"processes": {}})

    assert registro["agent_key_fingerprint"], (
        "a captura nao diz com que chave foi assinada (C-158)")
    assert registro["agent_key_fingerprint"].startswith("sha256:")
    esperada = agent_key_fingerprint(str(estado / "agent_public_key.pem"))
    assert registro["agent_key_fingerprint"] == esperada


def test_chave_nova_e_declarada_como_nova(tmp_path):
    """
    Uma identidade nova e fato legitimo na primeira execucao de um agente. O que
    nao pode e nascer CALADA: e a diferenca entre uma descontinuidade explicada
    e uma descoberta por quem contesta o laudo.
    """
    estado = tmp_path / "var"
    estado.mkdir()
    db = _BancoFalso(str(estado / "sys_inspector.db"))

    registro = build_for_capture(db, _config(str(tmp_path)), {"processes": {}})

    assert registro["agent_key_event"] == IDENTITY_CREATED


def test_a_impressao_e_do_conteudo_da_chave_e_nao_do_arquivo(tmp_path):
    """
    A impressao tem que identificar a CHAVE, nao o arquivo. Se fosse o hash do
    PEM, uma reescrita do arquivo com o mesmo par pareceria troca de chave, e um
    alarme falso numa peca pericial custa tanto quanto um alarme ausente.
    """
    priv = str(tmp_path / "a.pem")
    pub = str(tmp_path / "b.pem")
    ensure_agent_identity(priv, pub)
    antes = agent_key_fingerprint(pub)

    # Reescreve o mesmo conteudo, mudando mtime e possivelmente o final de linha.
    conteudo = open(pub, "rb").read()
    with open(pub, "wb") as fh:
        fh.write(conteudo)

    assert agent_key_fingerprint(pub) == antes


def test_chave_ilegivel_nao_quebra_a_captura(tmp_path):
    """
    CENARIO ADVERSO: a chave publica pode estar truncada ou corrompida. A
    impressao vira campo ausente, e a coleta segue: falhar aqui custaria a
    captura inteira, que e o oposto do que se quer numa ferramenta forense.
    """
    pub = tmp_path / "quebrada.pem"
    pub.write_text("isto nao e uma chave")
    assert agent_key_fingerprint(str(pub)) is None


def test_a_assinatura_cobre_a_impressao_da_chave(tmp_path):
    """
    Os campos novos entram ANTES da assinatura, e nao depois. Um carimbo de
    identidade fora da area assinada poderia ser reescrito sem invalidar nada, e
    um campo de custodia falsificavel e pior que campo nenhum.
    """
    estado = tmp_path / "var"
    estado.mkdir()
    db = _BancoFalso(str(estado / "sys_inspector.db"))
    registro = build_for_capture(db, _config(str(tmp_path)), {"processes": {}})

    from src.core.crypto import load_public_key, verify_bytes
    from src.core.custody import canonical_bytes
    import base64

    assinatura = base64.b64decode(registro["signature"])
    sem_assinatura = dict(registro)
    sem_assinatura.pop("signature", None)
    sem_assinatura.pop("signature_algorithm", None)

    pub = load_public_key(str(estado / "agent_public_key.pem"))
    assert verify_bytes(canonical_bytes(sem_assinatura), assinatura, pub), (
        "a assinatura nao confere sobre o registro com os campos de identidade")

    # E, adulterando a impressao, a assinatura tem que REPROVAR.
    adulterado = dict(sem_assinatura)
    adulterado["agent_key_fingerprint"] = "sha256:" + "0" * 64
    assert not verify_bytes(canonical_bytes(adulterado), assinatura, pub), (
        "a impressao da chave esta fora da area assinada (C-158)")


@pytest.mark.parametrize("evento", [IDENTITY_EXISTING, IDENTITY_MIGRATED,
                                    IDENTITY_CREATED])
def test_os_tres_eventos_tem_nome_estavel(evento):
    """
    Os nomes viajam dentro da peca e serao lidos por quem verifica a cadeia
    meses depois. Renomea-los quebraria a leitura de capturas ja emitidas.
    """
    assert evento in ("existing", "migrated", "created")


# ==============================================================================
# 4. O AGENTE ENRIJECIDO, QUE NAO TEM A CHAVE DO ANALISTA
# ==============================================================================
# Achado em 2026-09-18 ao preparar o laboratorio, e nao por leitura de codigo.
# A heranca era derivada de `private_key_path`, que e a chave do ANALISTA. Um
# agente correto NAO a possui: ele recebe so a publica, porque precisa cifrar e
# nao pode decifrar. Nesses hosts o caminho virava ".", relativo ao diretorio de
# trabalho, a heranca nao achava nada e o agente gerava chave nova.
#
# Ou seja: o defeito que o C-158 existe para evitar sobreviveria DENTRO da
# correcao, e justamente nos agentes mais bem configurados. O laboratorio so nao
# denunciou de imediato porque a config de la declara a chave do analista sem
# ter o arquivo.
# ==============================================================================

def test_agente_sem_chave_do_analista_ainda_herda(tmp_path):
    """
    REPROVA A VERSAO COM O FURO: com apenas `public_key_path` na configuracao, a
    chave do lugar antigo tem que ser herdada do mesmo jeito.
    """
    conf = tmp_path / "conf"
    estado = tmp_path / "var"
    conf.mkdir()
    estado.mkdir()

    velha_priv = str(conf / "agent_private_key.pem")
    velha_pub = str(conf / "agent_public_key.pem")
    ensure_agent_identity(velha_priv, velha_pub)
    impressao_antes = agent_key_fingerprint(velha_pub)

    # Configuracao de AGENTE de verdade: so a chave publica do analista.
    cfg = {"security": {"public_key_path": str(conf / "public_key.pem")}}
    db = _BancoFalso(str(estado / "sys_inspector.db"))
    registro = build_for_capture(db, cfg, {"processes": {}})

    assert registro["agent_key_event"] == IDENTITY_MIGRATED, (
        "agente sem a chave do analista gerou identidade NOVA em vez de herdar "
        "a que ja existia (C-158)")
    assert agent_key_fingerprint(str(estado / "agent_public_key.pem")) == impressao_antes


def test_o_caminho_do_agente_tem_precedencia_sobre_o_do_analista(tmp_path):
    """
    Quem declarou onde a chave DO AGENTE fica foi explicito sobre este assunto.
    Essa declaracao vale mais que a do analista, que fala de outra coisa.
    """
    explicito = tmp_path / "explicito"
    outro = tmp_path / "outro"
    estado = tmp_path / "var"
    for d in (explicito, outro, estado):
        d.mkdir()

    velha_priv = str(explicito / "agent_private_key.pem")
    velha_pub = str(explicito / "agent_public_key.pem")
    ensure_agent_identity(velha_priv, velha_pub)
    impressao = agent_key_fingerprint(velha_pub)

    cfg = {"security": {
        "agent_private_key_path": str(explicito / "agent_private_key.pem"),
        "private_key_path": str(outro / "private_key.pem"),
    }}
    db = _BancoFalso(str(estado / "sys_inspector.db"))
    registro = build_for_capture(db, cfg, {"processes": {}})

    # O caminho explicito manda, entao a chave continua onde estava.
    assert registro["agent_key_event"] == IDENTITY_EXISTING
    assert registro["agent_key_fingerprint"] == impressao


def test_configuracao_sem_caminho_nenhum_nao_quebra(tmp_path):
    """
    CENARIO ADVERSO: configuracao minima, sem chave declarada. A captura tem que
    sair assinada do mesmo jeito, com identidade nova e o evento declarando isso.
    """
    estado = tmp_path / "var"
    estado.mkdir()
    db = _BancoFalso(str(estado / "sys_inspector.db"))
    registro = build_for_capture(db, {"security": {}}, {"processes": {}})

    assert registro["agent_key_event"] == IDENTITY_CREATED
    assert registro["signature"]
