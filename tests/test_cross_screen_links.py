# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_cross_screen_links.py
# DESCRIPTION: O que liga uma tela a outra: ATT&CK, pivo para a arvore, ajuda e
#              identificacao humana do agente.
#
# WHY:         Cada uma destas ligacoes existe para o analista NAO ter de fazer
#              a correspondencia a mao entre telas. Sao exatamente o tipo de
#              coisa que se perde numa refatoracao de interface sem ninguem
#              perceber, porque a tela continua carregando e bonita: o que some
#              e o caminho. Os testes abaixo travam os caminhos.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os

import pytest

from src.core.attack import TECHNIQUES

FONTE = os.path.join("src", "controllers", "server_controller.py")
ASSETS = os.path.join("src", "exporters", "web_assets.py")


@pytest.fixture(scope="module")
def codigo():
    return io.open(FONTE, encoding="utf-8").read()


@pytest.fixture(scope="module")
def assets():
    return io.open(ASSETS, encoding="utf-8").read()


# ------------------------------------------------------------------------------
# ATT&CK EM TODA TELA QUE TEM TECNICA PARA MOSTRAR
# ------------------------------------------------------------------------------
def test_o_selo_attck_traz_nome_tatica_e_link():
    """
    "T1574.006" sozinho nao informa nada. O selo tem de carregar o nome da
    tecnica, a tatica e o link do MITRE, e funcionar em rede isolada (o
    catalogo e local).
    """
    from src.controllers.server_controller import _selo_attck

    html = _selo_attck("T1574.006")
    assert "T1574.006" in html
    assert "Dynamic Linker Hijacking" in html
    assert "Persistence" in html
    assert "attack.mitre.org/techniques/T1574/006/" in html


def test_tecnica_desconhecida_aparece_e_diz_que_falta_verbete():
    """
    Identificador sem verbete nao pode sumir da tela: some o dado e o leitor
    conclui que nao havia tecnica associada.
    """
    from src.controllers.server_controller import _selo_attck

    html = _selo_attck("T9999")
    assert "T9999" in html
    assert "sem verbete" in html


def test_sem_tecnica_nao_desenha_selo_vazio():
    from src.controllers.server_controller import _selo_attck

    assert _selo_attck("") == ""
    assert _selo_attck(None) == ""


def test_o_cenario_de_teste_declara_a_tecnica_que_exercita(codigo):
    """
    O chaos planta ld.so.preload, que e T1574.006. O registro de comandos tem de
    dizer isso: uma acao registrada sem a tecnica vira "chaos", uma palavra que
    so significa algo para quem escreveu a ferramenta.
    """
    bloco = codigo.split("ACOES = {")[1].split("}")[0]
    assert "T1574.006" in bloco
    assert "T1574.006" in TECHNIQUES


def test_a_linha_do_tempo_mostra_attck_e_risco(codigo):
    bloco = codigo.split("def _serve_timeline")[1].split("def _serve_capabilities")[0]
    assert "_selo_attck(" in bloco
    assert "_selo_risco(" in bloco
    assert "ATT&amp;CK" in bloco


def test_a_correlacao_mostra_severidade_e_tecnica(codigo):
    """A conclusao ja carrega as duas; escondê-las obriga a abrir o laudo."""
    bloco = codigo.split("if conclusoes:")[1].split("linhas = \"\"")[0]
    assert "c.severity" in bloco
    assert "c.technique" in bloco


# ------------------------------------------------------------------------------
# PIVO ENTRE A LINHA DO TEMPO E A ARVORE
# ------------------------------------------------------------------------------
def test_o_evento_leva_ao_processo_na_arvore(codigo):
    bloco = codigo.split("def _serve_timeline")[1].split("def _serve_capabilities")[0]
    assert "#pid=" in bloco


def test_o_laudo_atende_o_pivo_vindo_de_fora(assets):
    """
    O link so serve se o laudo souber recebe-lo: e preciso ler o fragmento da
    URL no carregamento e chamar o pivo que ja existe.
    """
    assert "location.hash" in assets
    assert "pivotToProcess(m[1])" in assets


def test_o_pivo_nao_falha_em_silencio(assets):
    """
    Processo ausente da captura e informacao, nao erro mudo. Sair calado faria
    a tela parecer quebrada e o analista concluir que o pivo nao funciona.
    """
    bloco = assets.split("function pivotToProcess")[1]
    assert "avisaPivo(" in bloco
    assert "function avisaPivo" in assets
    assert ".aviso-pivo" in assets


# ------------------------------------------------------------------------------
# AJUDA NO MESMO LUGAR, EM TODA TELA
# ------------------------------------------------------------------------------
def _metodo(codigo, nome):
    """Corpo de um metodo: do 'def <nome>' ate o proximo 'def ' no mesmo nivel."""
    corpo = codigo.split("def %s" % nome)[1]
    corte = corpo.find("\n    def ")
    return corpo if corte < 0 else corpo[:corte]


def test_toda_tela_auxiliar_tem_bolha_de_ajuda(codigo):
    for tela in ("_serve_timeline", "_serve_queue", "_serve_capabilities",
                 "_serve_command_log", "_serve_history"):
        bloco = _metodo(codigo, tela)
        assert ("_ajuda_risco()" in bloco or "_bolha_ajuda(" in bloco), tela


def test_a_ajuda_de_risco_e_gerada_da_tabela_de_sinais():
    """
    Legenda escrita a mao ao lado da tabela e a mesma classe de falha do tag_map
    e da lista ARTEFATOS: as duas fontes divergem no primeiro sinal novo.
    """
    from src.controllers.server_controller import _ajuda_risco
    from src.core import risk

    html = _ajuda_risco()
    for _bit, _chave, rotulo, _sev, _exp in risk.SINAIS:
        assert rotulo in html


def test_as_barras_de_controle_usam_a_mesma_classe(codigo):
    """Mesma forma em toda tela: o controle nao pode mudar de lugar a cada uma."""
    assert codigo.count("class='controles'") >= 5
    assert ".controles{" in codigo


# ------------------------------------------------------------------------------
# O REGISTRO DE COMANDOS COMO LOG DE VERDADE
# ------------------------------------------------------------------------------
def test_o_pedido_tem_data_e_utc(codigo):
    """
    "13:24:07" nao serve como rastro: nao diz o dia, e nao cruza com log de
    outro sistema, que quase sempre esta em UTC.
    """
    bloco = codigo.split("def _serve_command_log")[1].split("def _serve_dashboard")[0]
    assert "utcfromtimestamp" in bloco
    assert "%Y-%m-%d %H:%M:%S" in bloco


def test_o_resultado_leva_ao_efeito_do_comando(codigo):
    """Todo comando aponta o laudo, as capturas e a janela de eventos."""
    bloco = codigo.split("def _serve_command_log")[1].split("def _serve_dashboard")[0]
    assert "/agent/%s" in bloco
    assert "/history/%s" in bloco
    assert "/timeline?min=%d&agent=%s" in bloco


def test_cada_acao_e_explicada(codigo):
    """
    "chaos" e "collect" nao se explicam sozinhos para quem opera a ferramenta
    sem te-la escrito.
    """
    bloco = codigo.split("ACOES = {")[1].split("\n        }")[0]
    for acao in ("collect", "chaos", "restart"):
        assert '"%s"' % acao in bloco


# ------------------------------------------------------------------------------
# AGENTE IDENTIFICADO POR NOME
# ------------------------------------------------------------------------------
def test_agente_aparece_com_nome_fqdn_e_ip():
    from src.controllers.server_controller import _identifica_agente

    html = _identifica_agente({"uuid": "abc-123", "hostname": "openSUSE",
                               "fqdn": "openSUSE.lab",
                               "ip_address": "192.168.56.161"})
    assert "openSUSE" in html
    assert "openSUSE.lab" in html
    assert "192.168.56.161" in html
    assert "abc-123" in html


def test_agente_sem_identidade_diz_isso_em_vez_de_ficar_vazio():
    """Celula vazia nao distingue "nao reportou" de "a tela nao mostra"."""
    from src.controllers.server_controller import _identifica_agente

    html = _identifica_agente(None, "abc-123")
    assert "nao identificado" in html
    assert "abc-123" in html


def test_identidade_do_agente_e_escapada():
    """Hostname vem do host inspecionado, que pode estar comprometido."""
    from src.controllers.server_controller import _identifica_agente

    html = _identifica_agente({"uuid": "u", "hostname": "<script>x</script>",
                               "fqdn": "a\"b", "ip_address": "1.2.3.4"})
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
