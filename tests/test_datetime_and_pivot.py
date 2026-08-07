# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_datetime_and_pivot.py
# DESCRIPTION: Formato unico de data/hora, numero cru do risco de volta na
#              arvore, e o pivo da linha do tempo apontando a captura de origem.
#
# WHY:         Tres pedidos diretos do Mario, e cada um trava um jeito da tela
#              enganar o leitor: hora sem data nao cruza com log de outro
#              sistema; o rotulo de severidade sem o numero esconde a evidencia
#              (o campo de bits); e o pivo que abre sempre a captura mais recente
#              cai em "nao esta nesta captura" para todo processo efemero.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os
import re

import pytest

FONTE = os.path.join("src", "controllers", "server_controller.py")
CHAOS = os.path.join("tools", "agent_chaos.sh")


@pytest.fixture(scope="module")
def codigo():
    return io.open(FONTE, encoding="utf-8").read()


# ------------------------------------------------------------------------------
# FORMATO UNICO DE DATA E HORA
# ------------------------------------------------------------------------------
def test_data_e_hora_traz_data_local_e_utc():
    from src.controllers.server_controller import _fmt_datahora

    html = _fmt_datahora(1_754_000_000)
    assert "UTC" in html
    # Duas datas completas AAAA-MM-DD HH:MM:SS (local e UTC).
    assert len(re.findall(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", html)) == 2


def test_data_e_hora_invalida_nao_quebra():
    from src.controllers.server_controller import _fmt_datahora

    for v in (None, "", "abc"):
        assert _fmt_datahora(v)  # devolve um traco, nunca excecao


def test_fmt_ts_delega_ao_formato_unico():
    from src.controllers.server_controller import _fmt_ts

    html = _fmt_ts(1_754_000_000)
    assert "UTC" in html
    assert re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", html)


def test_a_frota_usa_o_formato_completo(codigo):
    """LAST SEEN deixou de mostrar so a hora curta."""
    bloco = codigo.split("def _serve_dashboard")[1]
    assert "_fmt_datahora(" in bloco


def test_a_linha_do_tempo_usa_o_formato_completo(codigo):
    bloco = codigo.split("def _serve_timeline")[1].split("def _serve_capabilities")[0]
    assert "_fmt_datahora(" in bloco


# ------------------------------------------------------------------------------
# O NUMERO CRU DO RISCO VOLTA A ARVORE
# ------------------------------------------------------------------------------
def test_badge_da_arvore_mostra_o_numero_e_o_rotulo():
    """
    O badge exibia so "High"; o numero (campo de bits) sumira. Ele e o dado
    coletado, e o rotulo e a leitura dele: exibir so o rotulo esconde a
    evidencia atras da interpretacao.
    """
    from src.exporters.html_report import _render_badges

    class _No(object):
        pid = 10
        ppid = 1
        is_new = False
        context_tags = []
        anomaly_score = 8 + 2   # binario apagado + /dev/shm -> Critical
        tree_max_score = 8 + 2
        detection_reasons = ["x"]

    html = _render_badges(_No())
    assert "Critical" in html
    assert "10" in html or ">10<" in html  # o score cru aparece
    # O tooltip decodifica os bits em sinais nomeados.
    assert "apagado" in html


def test_badge_tooltip_lista_os_sinais():
    from src.exporters.html_report import _render_badges

    class _No(object):
        pid = 5
        ppid = 1
        is_new = False
        context_tags = []
        anomaly_score = 128        # processo defunto -> Info, nao Critical
        tree_max_score = 128
        detection_reasons = []

    html = _render_badges(_No())
    assert "Info" in html
    assert "defunto" in html


# ------------------------------------------------------------------------------
# PIVO APONTA A CAPTURA DE ORIGEM
# ------------------------------------------------------------------------------
def test_o_pivo_leva_a_captura_de_origem(codigo):
    """
    O evento sai de uma captura especifica (capture_id). Abrir sempre a mais
    recente fazia o pivo cair em "nao esta nesta captura" para todo processo
    efemero. O link tem de carregar a captura de origem.
    """
    bloco = codigo.split("def _serve_timeline")[1].split("def _serve_capabilities")[0]
    assert "capture_id" in bloco
    assert "?capture=" in bloco
    assert "#pid=" in bloco


def test_o_laudo_aceita_captura_especifica(codigo):
    """O /agent tem de saber renderizar a captura pedida, nao so a ultima."""
    bloco = codigo.split("elif self.path.startswith('/agent/')")[1][:2500]
    assert "capture" in bloco
    assert "get_snapshot_details" in bloco


# ------------------------------------------------------------------------------
# CHAOS NAO CONTAMINA O HOST INTEIRO
# ------------------------------------------------------------------------------
def test_o_preload_global_nao_aponta_para_tmp():
    """
    O defeito de campo: /etc/ld.so.preload apontava para uma lib em /tmp, e como
    o preload e global, TODO processo do host era marcado como biblioteca de
    local nao confiavel. A lib do preload agora vive em caminho de sistema.
    """
    texto = io.open(CHAOS, encoding="utf-8").read()
    # A linha que escreve o preload usa a lib de sistema, nao a de /tmp nem /dev/shm.
    m = re.search(r'echo\s+"\$\{SYS_LIB\}"\s*>\s*"\$\{PRELOAD_FILE\}"', texto)
    assert m, "o preload deve apontar para a lib em caminho de sistema"
    assert 'SYS_LIB_DIR="/usr/local/lib"' in texto


def test_run_chaos_procura_o_maker_em_varios_caminhos():
    """
    O chaos_maker nao esta no mesmo lugar em todo host: deploy de fonte poe em
    /opt/sys-inspector/tools, RPM expoe /usr/bin/chaos_maker.sh, e o lab pode
    largar em /tmp. Fixar um caminho so fazia o cenario PULAR o chaos de runtime
    em silencio nos hosts que usam outro (foi o que aconteceu em 168 e 200).
    """
    texto = io.open(CHAOS, encoding="utf-8").read()
    assert "find_chaos_maker" in texto
    for caminho in ("/usr/bin/chaos_maker.sh", "/tmp/chaos_maker.sh"):
        assert caminho in texto
    # Deixa marca no log para distinguir "rodou e terminou" de "nunca rodou".
    assert "CHAOS_MAKER_START" in texto
    assert "CHAOS_MAKER_NOT_FOUND" in texto


def test_apenas_um_processo_carrega_lib_de_local_estranho():
    """
    So o processo plantado carrega a lib de /dev/shm, via seu proprio ambiente.
    Nada mais no host e tocado pelo sinal de runtime.
    """
    texto = io.open(CHAOS, encoding="utf-8").read()
    assert "LD_PRELOAD=" in texto
    assert 'SHM_LIB="/dev/shm/' in texto
    # A lib de /dev/shm NAO entra no /etc/ld.so.preload global.
    assert re.search(r'"\$\{SHM_LIB\}"\s*>\s*"\$\{PRELOAD_FILE\}"', texto) is None
