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

import pytest

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


# ==============================================================================
# F-234: navegacao entre capturas na barra do laudo
# ==============================================================================
# Decidido em 2026-08-14 e nunca implementado. Sem isso, ler a captura de ontem
# exigia sair do laudo, entrar no historico, escolher na lista, e comparar duas
# exigia refazer o caminho inteiro a cada troca.
# ==============================================================================

def _nav(escolhido_id, ids):
    """
    Chama _navegacao_de_capturas sem subir a pilha HTTP.

    O metodo so usa `self` para alcancar a si mesmo, entao um objeto qualquer
    serve de portador. Subir um BaseHTTPRequestHandler de verdade exigiria
    socket, e o que esta sob teste e a aritmetica da posicao, nao o transporte.
    """
    mod = pytest.importorskip(
        "src.controllers.server_controller",
        reason="o controlador importa process_tree, que exige pwd (Linux)")

    class _Portador(object):
        _navegacao_de_capturas = mod.ServerHTTPHandler._navegacao_de_capturas

    historico = [{"id": i} for i in ids]
    escolhido = {"id": escolhido_id}
    return _Portador()._navegacao_de_capturas("uuid-x", escolhido, historico)


def test_f234_a_rota_de_navegacao_existe():
    """
    REPROVA A VERSAO COM DEFEITO: antes do F-234 nao havia funcao nenhuma de
    navegacao, e a barra do laudo so oferecia voltar para a Manager.
    """
    src = _fonte("src/controllers/server_controller.py")
    assert "_navegacao_de_capturas" in src, (
        "a navegacao entre capturas sumiu da barra do laudo (F-234)")


def test_f234_a_barra_do_laudo_chama_a_navegacao():
    """Existir a funcao nao basta: a barra tem que usa-la."""
    src = _fonte("src/controllers/server_controller.py")
    inicio = src.index("back = (")
    bloco = src[inicio:inicio + 2500]
    assert "self._navegacao_de_capturas(" in bloco, (
        "a barra do laudo parou de montar a navegacao entre capturas (F-234)")


def test_f234_conta_capturas_do_mais_antigo_para_o_mais_recente():
    """
    O banco devolve a mais recente primeiro; a linha do tempo se le ao
    contrario. A captura mais nova de cinco e a 5 de 5, nao a 1 de 5.
    """
    html = _nav(10, [10, 9, 8, 7, 6])
    assert "captura 5 de 5" in html
    html = _nav(6, [10, 9, 8, 7, 6])
    assert "captura 1 de 5" in html


def test_f234_anterior_aponta_para_a_mais_antiga():
    """A seta para tras e cronologica, nao posicional na lista."""
    html = _nav(9, [10, 9, 8])
    assert "capture=8" in html


def test_f234_proxima_aponta_para_a_mais_nova():
    """A seta para frente leva a captura mais recente que a atual."""
    html = _nav(9, [10, 9, 8])
    assert "capture=10" in html


def test_f234_seta_sem_destino_fica_visivel_e_apagada():
    """
    Uma seta que SOME muda a largura da barra e deixa o leitor sem saber se
    chegou ao fim da colecao ou se a tela quebrou. O limite da colecao e
    informacao, e informacao se mostra.
    """
    html = _nav(10, [10, 9, 8])  # ja e a mais recente: nao ha proxima
    assert "#9654;" in html, "a seta de proxima sumiu em vez de ficar apagada"
    assert "color:#444" in html, (
        "a seta sem destino nao esta marcada como inativa")


def test_f234_captura_unica_ainda_declara_a_contagem():
    """
    D-020 aplicada a navegacao: sem setas, mas com resposta. "1 de 1" explica
    por que nao ha para onde ir.
    """
    html = _nav(1, [1])
    assert "captura 1 de 1" in html
    assert "capture=" not in html, (
        "um agente com uma captura nao tem para onde navegar")


def test_f234_captura_fora_do_historico_nao_quebra_o_laudo():
    """
    CENARIO ADVERSO: a captura pedida pode ter sido apagada pela retencao entre
    a montagem do link e o clique. O laudo abre a mais recente, e a barra nao
    pode estourar por causa disso.
    """
    html = _nav(999, [10, 9, 8])
    assert "captura 3 de 3" in html


# ==============================================================================
# C-149: o laudo como ARQUIVO
# ==============================================================================
# Antes da remocao dos modos, a captura gravava
# report/sys-inspector_<host>_<ts>.html. Depois dela nao havia rota de download
# nem Content-Disposition, e obter a peca dependia do salvar-como do navegador,
# que produz artefato sem carimbo de origem.
# ==============================================================================

def test_c149_existe_a_rota_de_download():
    """
    REPROVA A VERSAO COM DEFEITO: a string /download/ nao existia em ponto
    nenhum do codigo.
    """
    src = _fonte("src/controllers/server_controller.py")
    assert "elif self.path.startswith('/download/'):" in src, (
        "a rota de download do laudo sumiu (C-149)")


def test_c149_o_download_declara_anexo_e_nome_de_arquivo():
    """
    Sem Content-Disposition o navegador ABRE o laudo em vez de salvar, e a peca
    continua dependendo do salvar-como.
    """
    src = _fonte("src/controllers/server_controller.py")
    inicio = src.index("elif self.path.startswith('/download/'):")
    bloco = src[inicio:inicio + 3200]
    assert "Content-Disposition" in bloco
    assert "attachment; filename=" in bloco
    assert "sys-inspector_%s_%s.html" in bloco, (
        "o nome do arquivo deixou de carregar host e instante da coleta (C-149)")


def test_c149_o_nome_do_arquivo_filtra_o_que_vem_do_host():
    """
    O hostname vem do host analisado. Sem filtro ele injeta travessia de
    caminho e quebra o cabecalho Content-Disposition com aspas.
    """
    src = _fonte("src/controllers/server_controller.py")
    inicio = src.index("elif self.path.startswith('/download/'):")
    bloco = src[inicio:inicio + 3200]
    assert '[^A-Za-z0-9._-]' in bloco, (
        "o hostname voltou a entrar cru no nome do arquivo (C-149)")


def test_c149_o_download_valida_o_identificador_como_as_demais_rotas():
    """
    COLISAO com a allowlist do painel: uma rota nova nao pode nascer sem a
    guarda que todas as outras tem.
    """
    src = _fonte("src/controllers/server_controller.py")
    inicio = src.index("elif self.path.startswith('/download/'):")
    bloco = src[inicio:inicio + 3200]
    assert "id_valido(agent_uuid)" in bloco
    assert "self._recusa_id(agent_uuid)" in bloco


def test_c149_tela_e_arquivo_saem_da_mesma_montagem():
    """
    A peca que se anexa ao processo tem que ser a peca que o perito leu na
    tela. Duas montagens seriam a classe de defeito da copia silenciosa: duas
    representacoes do mesmo fato que se afastam sem nada denunciar.
    """
    src = _fonte("src/controllers/server_controller.py")
    assert src.count("self._laudo_de(") == 2, (
        "a tela e o download deixaram de compartilhar a montagem do laudo "
        "(C-149)")
    assert src.count("generate_report(") == 1, (
        "voltou a existir mais de um ponto que monta o laudo (C-149)")


def test_c149_o_historico_oferece_download_por_captura():
    """
    A tela do laudo baixa a captura aberta; a lista do historico precisa baixar
    QUALQUER uma sem obrigar a abrir antes.
    """
    src = _fonte("src/controllers/server_controller.py")
    inicio = src.index("def _serve_history(")
    bloco = src[inicio:src.index("def _serve_diff(")]
    assert "/download/%s?capture=%s" in bloco, (
        "a coluna de download por captura sumiu do historico (C-149)")
    assert "<th>Baixar</th>" in bloco, (
        "a coluna de download perdeu o cabecalho (C-149)")


def test_c149_o_arquivo_nao_leva_a_barra_de_navegacao():
    """
    PERDA DE FUNCIONALIDADE ao contrario: o arquivo NAO pode herdar a barra.
    Ela aponta para um servidor que quem le o processo nao alcanca, e uma peca
    pericial com botoes mortos e pior que uma sem botao nenhum.

    A barra e injetada depois de _laudo_de, e so na rota da tela: o download
    escreve o corpo sem passar pela ancora.
    """
    src = _fonte("src/controllers/server_controller.py")
    inicio = src.index("elif self.path.startswith('/download/'):")
    bloco = src[inicio:src.index("elif self.path.startswith('/agent/'):")]
    assert "sticky-wrapper" not in bloco, (
        "o download voltou a injetar a barra de navegacao no arquivo (C-149)")
    assert "back = (" not in bloco
