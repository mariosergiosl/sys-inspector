# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_lote3_laudo_como_peca.py
# DESCRIPTION: Trava os itens do Lote 3, que tratam o laudo como PECA e nao
#              apenas como tela: filtro que responde, pivo que existe em todo
#              achado com processo, navegacao entre capturas e o laudo como
#              arquivo anexavel.
#
# WHY:         Cada teste aqui nasceu de um defeito observado na tela, e cada um
#              foi conferido contra a versao com defeito ANTES de ser escrito.
#              Teste que so passa nao prova nada: o que prova e o teste que
#              reprova o codigo antigo.
#
#              O registro de qual defeito fez cada caso existir fica no proprio
#              teste, para que quem o vir falhar saiba se esta quebrando um
#              pedido ou corrigindo um engano.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os

from src.exporters.html_report import render_findings_panel


def _pid_nomeado_pelo_achado(finding):
    """
    Importa o auxiliar SOB DEMANDA, dentro do caso de teste.

    No topo do modulo, um auxiliar ausente vira ImportError e derruba a coleta
    do arquivo inteiro: os casos do F-244, que nao dependem dele, morreriam
    junto e o relatorio diria "1 erro" em vez de dizer quais comportamentos
    faltam. Ao conferir estes testes contra a versao com defeito foi exatamente
    isso que aconteceu, e por isso o import desceu para ca.
    """
    from src.exporters.html_report import _pid_nomeado_pelo_achado as impl
    return impl(finding)

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _fonte(caminho):
    """Le um arquivo do projeto como texto, tolerando byte estranho."""
    with io.open(os.path.join(RAIZ, caminho), encoding="utf-8",
                 errors="replace") as fh:
        return fh.read()


def _achado(**extra):
    """Finding minimo no formato que viaja no payload da captura."""
    base = {"title": "Achado de teste", "severity": "High", "source": "ebpf",
            "target": "/tmp/x", "description": "d", "rank": 1}
    base.update(extra)
    return base


# ==============================================================================
# F-244: filtro sem resultado precisa DIZER que nao ha resultado
# ==============================================================================
# Defeito: ao clicar num filtro que nao casa com processo algum, a arvore
# simplesmente ficava vazia. Da tela, "nenhum resultado" e "quebrado" sao
# indistinguiveis, e foi essa ambiguidade que levou o filtro KEXEC_LOAD a ser
# reportado como defeito quando estava correto.
# ==============================================================================

def test_f244_existe_a_caixa_de_filtro_vazio_na_marcacao():
    """
    REPROVA A VERSAO COM DEFEITO: antes do F-244 nao havia elemento nenhum onde
    escrever a resposta, e por isso a tela nao tinha como responder.
    """
    src = _fonte("src/exporters/web_assets.py")
    assert 'id="filtro-vazio"' in src, (
        "a caixa de resposta do filtro vazio sumiu da marcacao (F-244)")
    assert ".filtro-vazio {" in src, (
        "o estilo da caixa de filtro vazio sumiu (F-244)")


def test_f244_a_caixa_fica_no_fluxo_e_nao_flutua():
    """
    O aviso descreve o ESTADO ATUAL da tela, nao um evento. Como position
    fixed ele viraria recado passageiro sobre o conteudo, que e o mesmo defeito
    ja corrigido na barra de retorno do painel do gerente.
    """
    src = _fonte("src/exporters/web_assets.py")
    inicio = src.index(".filtro-vazio {")
    bloco = src[inicio:inicio + 400]
    assert "position: fixed" not in bloco, (
        "a caixa do filtro vazio voltou a flutuar sobre o conteudo (F-244)")
    assert "display: none" in bloco, (
        "a caixa precisa nascer escondida, senao aparece sem filtro algum")


def test_f244_o_filtro_conta_o_que_casou():
    """
    REPROVA A VERSAO COM DEFEITO: filterTable escondia as linhas que nao casavam
    e nunca contava quantas sobraram, entao nao tinha como saber que o resultado
    era zero.
    """
    src = _fonte("src/exporters/web_assets.py")
    inicio = src.index("function filterTable()")
    corpo = src[inicio:src.index("function setFilter(")]
    assert "casaram" in corpo, (
        "filterTable parou de contar as linhas que casam (F-244)")
    assert "avisaFiltroVazio(" in corpo, (
        "filterTable nao chama mais o aviso de filtro vazio (F-244)")


def test_f244_o_aviso_declara_quantos_processos_foram_examinados():
    """
    "Nao achei" sem dizer onde procurou nao e resposta. O numero de processos
    examinados e o que separa "nao ha o sinal nesta captura" de "a arvore esta
    vazia".
    """
    src = _fonte("src/exporters/web_assets.py")
    inicio = src.index("function avisaFiltroVazio(")
    corpo = src[inicio:inicio + 1600]
    assert "querySelectorAll('.proc-row').length" in corpo, (
        "o aviso deixou de contar o universo examinado (F-244)")


def test_f244_o_termo_filtrado_nao_e_concatenado_em_html():
    """
    O termo vem da caixa de busca, ou seja, de quem opera. Concatenado em
    innerHTML ele injeta marcacao no proprio laudo.
    """
    src = _fonte("src/exporters/web_assets.py")
    inicio = src.index("function avisaFiltroVazio(")
    corpo = src[inicio:inicio + 1600]
    assert ".textContent = termo" in corpo, (
        "o termo do filtro voltou a entrar como HTML em vez de texto (F-244)")
    assert "+ termo +" not in corpo, (
        "o termo do filtro esta sendo concatenado em HTML (F-244)")


def test_f244_o_aviso_some_quando_ha_resultado():
    """Filtro que casa alguma coisa nao pode deixar o aviso de vazio na tela."""
    src = _fonte("src/exporters/web_assets.py")
    inicio = src.index("function avisaFiltroVazio(")
    corpo = src[inicio:inicio + 1600]
    assert "casaram > 0" in corpo, (
        "o aviso nao some mais quando o filtro tem resultado (F-244)")


# ==============================================================================
# F-242: o pivo para o processo aparecia em 5 de 33 achados
# ==============================================================================
# Defeito: o pivo so nascia de related_pids, preenchido pela correlacao quando o
# CAMINHO denunciado esta sendo executado. Achados que nomeiam um PID
# diretamente (memoria gravavel-e-executavel, processo oculto, divergencia de
# threads) nao passam por ali e ficavam sem botao, justamente os mais precisos.
# ==============================================================================

def test_f242_le_o_pid_do_alvo():
    """O formato pid:NNNN e como os coletores de runtime nomeiam o objeto."""
    assert _pid_nomeado_pelo_achado({"target": "pid:4242"}) == 4242


def test_f242_le_o_pid_da_evidencia():
    """Segunda fonte, na mesma ordem usada pela correlacao."""
    assert _pid_nomeado_pelo_achado({"evidence": {"pid": 77}}) == 77


def test_f242_achado_que_nao_e_sobre_processo_nao_inventa_pid():
    """
    Achado de kernel, de arquivo ou de frota NAO tem PID, e isso nao e ausencia
    de dado: e a resposta certa para aquele achado. Inventar um aqui criaria
    atalho para processo que o achado nunca citou.
    """
    assert _pid_nomeado_pelo_achado({"target": "/etc/cron.d/backdoor"}) is None
    assert _pid_nomeado_pelo_achado({"target": "kmod:evil"}) is None
    assert _pid_nomeado_pelo_achado({}) is None


def test_f242_pid_invalido_nao_quebra_o_laudo():
    """Evidencia vem do host analisado e pode trazer qualquer coisa."""
    assert _pid_nomeado_pelo_achado({"evidence": {"pid": "abc"}}) is None
    assert _pid_nomeado_pelo_achado({"evidence": {"pid": None}}) is None


def test_f242_achado_que_nomeia_pid_ganha_pivo_sem_correlacao():
    """
    REPROVA A VERSAO COM DEFEITO: este e o caso exato que media 5 de 33. O
    achado nomeia o PID no proprio alvo e NAO tem related_pids, porque a
    correlacao nao rodou ou o processo ja saiu da arvore. Antes do F-242 o card
    saia sem atalho nenhum.
    """
    html = render_findings_panel([
        _achado(title="Memoria gravavel-e-executavel", target="pid:4242",
                evidence={"pid": 4242})])
    assert "fnd-pivot" in html, (
        "achado que nomeia o PID voltou a sair sem pivo (F-242)")
    assert "pivotToProcess('4242')" in html


def test_f242_a_correlacao_continua_tendo_precedencia():
    """
    Quando related_pids existe, ele manda: pode citar VARIOS processos
    executando o mesmo caminho, e essa resposta e mais rica que o PID unico.
    """
    html = render_findings_panel([
        _achado(target="pid:1", related_pids=[10, 20])])
    assert "pivotToProcess('10,20')" in html
    assert "Ver 2 processos" in html


def test_f242_achado_sem_processo_continua_sem_pivo():
    """
    PERDA DE FUNCIONALIDADE que o F-242 nao pode causar: a ausencia do atalho
    continua significando alguma coisa. Um achado de persistencia cujo artefato
    nao esta em execucao nao ganha botao, e e isso que informa o perito.
    """
    html = render_findings_panel([
        _achado(target="/etc/systemd/system/x.service")])
    assert "fnd-pivot" not in html, (
        "achado sem processo ganhou pivo para lugar nenhum (F-242)")


def test_f242_o_pivo_nao_promete_o_que_nao_pode_cumprir():
    """
    O texto antigo afirmava que o caminho estava sendo executado agora, o que
    deixou de ser verdade para o pivo vindo do PID nomeado: o processo pode ter
    terminado. O laudo nao pode afirmar o que nao verificou.
    """
    html = render_findings_panel([_achado(target="pid:4242")])
    assert "sendo executado agora" not in html, (
        "o pivo voltou a afirmar execucao que nao verificou (F-242)")


def test_f242_pivo_para_pid_ausente_avisa_em_vez_de_falhar_calado():
    """
    COLISAO com o pivo vindo da linha do tempo: os dois entram pela mesma
    funcao. Se o PID nao estiver na captura, a tela tem que dizer isso, senao o
    F-242 transforma um card util num botao que parece quebrado.
    """
    src = _fonte("src/exporters/web_assets.py")
    inicio = src.index("function pivotToProcess(")
    corpo = src[inicio:inicio + 1400]
    assert "avisaPivo(" in corpo, (
        "pivotToProcess voltou a sair em silencio quando o PID nao existe")
    assert "nao esta nesta captura" in corpo
