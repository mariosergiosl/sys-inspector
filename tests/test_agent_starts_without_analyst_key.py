# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_agent_starts_without_analyst_key.py
# DESCRIPTION: A configuracao CORRETA de um agente tem que ser aceita na
#              partida, e ela nao declara a chave privada do analista.
#
# WHY:         Achado em 2026-09-18 ao subir o laboratorio, e nao por leitura de
#              codigo. O agente recusou subir com
#              "Failed to provision cryptographic keys: 'private_key_path'".
#
#              O modelo forense do produto e explicito: o agente recebe SOMENTE
#              a chave publica do analista. Ele cifra o que coleta e nao
#              consegue reabrir, e e isso que impede que quem comprometeu o host
#              leia a propria evidencia. A rotina de provisionamento ja tratava
#              isso certo, so gerando par quando falta a chave PUBLICA. Mas o
#              main.py lia o caminho da privada com acesso direto ao dicionario
#              e estourava antes de chegar la.
#
#              Resultado: a implantacao correta era recusada, e todo agente era
#              obrigado a declarar um caminho para a chave que nao pode ter. Foi
#              o que se encontrou no laboratorio, um config apontando um arquivo
#              que nunca existiu, e foi tambem o que escondeu o defeito por
#              tanto tempo.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _fonte(caminho):
    """Le um arquivo do projeto como texto, tolerando byte estranho."""
    with io.open(os.path.join(RAIZ, caminho), encoding="utf-8",
                 errors="replace") as fh:
        return fh.read()


def _bloco_de_provisionamento():
    """O trecho do main.py que provisiona as chaves na partida."""
    src = _fonte("main.py")
    inicio = src.index("AUTO-PROVISION CRYPTOGRAPHIC IDENTITY")
    fim = src.index("# Override Mode logic", inicio)
    return src[inicio:fim]


def test_a_chave_privada_do_analista_e_opcional_na_partida():
    """
    REPROVA A VERSAO COM DEFEITO: o acesso direto
    `config['security']['private_key_path']` estourava KeyError e derrubava o
    agente antes de qualquer coisa.
    """
    bloco = _bloco_de_provisionamento()
    assert "config['security']['private_key_path']" not in bloco, (
        "o main.py voltou a exigir a chave privada do analista na partida, "
        "recusando a configuracao correta de um agente")
    assert "get('private_key_path')" in bloco, (
        "o caminho da chave privada deixou de ser lido de forma opcional")


def test_a_chave_publica_continua_obrigatoria():
    """
    PERDA DE FUNCIONALIDADE que a correcao nao pode causar: sem a chave publica
    o agente nao consegue cifrar, e uma captura em claro no disco de um host
    comprometido e pior que captura nenhuma. Essa continua sendo exigida.
    """
    bloco = _bloco_de_provisionamento()
    assert "seguranca['public_key_path']" in bloco, (
        "a chave publica deixou de ser obrigatoria na partida")


def test_o_destino_da_privada_fica_ao_lado_da_publica():
    """
    O caminho so e usado quando a chave PUBLICA falta e o par precisa nascer.
    Nesse caso a privada nasce ao lado da publica, que e onde alguem iria
    procurar, e nao no diretorio de trabalho do processo.
    """
    bloco = _bloco_de_provisionamento()
    assert "os.path.dirname(caminho_publica)" in bloco, (
        "o destino da chave privada deixou de acompanhar o da publica")


def test_o_utilitario_de_decifrar_explica_a_ausencia():
    """
    Decifrar PRECISA da chave privada. Sem ela o utilitario tem que dizer isso
    em uma frase, e nao estourar KeyError: a mensagem e o que ensina que essa
    chave mora no servidor e nunca num agente.
    """
    src = _fonte("main.py")
    inicio = src.index("UTILITY: DECRYPTION CLI")
    bloco = src[inicio:inicio + 1200]
    assert "config['security']['private_key_path']" not in bloco
    assert "never on an agent" in bloco, (
        "o utilitario parou de explicar onde a chave privada deve morar")


# ==============================================================================
# A OPCAO QUE DECIDE SE A EVIDENCIA CHEGA NAO PODE VIVER SO NO CODIGO
# ==============================================================================

def test_a_verificacao_de_certificado_esta_documentada():
    """
    Tambem achado ao subir o laboratorio: contra certificado autoassinado a
    entrega falhava, o agente registrava "Delivery failed" sem motivo, e a
    unica explicacao estava no codigo-fonte. A chave que decide se a evidencia
    chega ao servidor precisa estar no arquivo de configuracao, com o que se
    ganha e o que se perde ao desliga-la.
    """
    cfg = _fonte("conf/config.yaml")
    assert "verify_tls" in cfg, (
        "a chave verify_tls sumiu do arquivo de configuracao")
    inicio = cfg.index("verify_tls")
    # A explicacao vem ANTES da chave, no comentario.
    contexto = cfg[max(0, inicio - 1200):inicio]
    assert "self-signed" in contexto, (
        "a documentacao parou de dizer quando desligar a verificacao")
    assert "secrecy" in contexto or "Encryption stays" in contexto, (
        "a documentacao parou de dizer o que se perde: identidade, nao sigilo")


def test_a_verificacao_nasce_ligada():
    """
    O padrao protege. Desligar e escolha explicita de quem opera, e o agente
    avisa no log toda vez que sobe assim.
    """
    cfg = _fonte("conf/config.yaml")
    assert "verify_tls: true" in cfg, (
        "a verificacao de certificado passou a nascer DESLIGADA")

    src = _fonte("src/core/outbox.py")
    assert 'get("verify_tls", True)' in src, (
        "o padrao da verificacao no codigo deixou de ser ligado")
