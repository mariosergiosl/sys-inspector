# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_ui_ajustes_2026_08_20.py
# DESCRIPTION: Trava os 16 ajustes de interface pedidos pelo Mario em prints de
#              2026-08-20 (itens F-219 a F-239).
#
# WHY:         Ajuste de tela nao tem teste de comportamento obvio, e por isso e
#              o que mais silenciosamente regride: alguem mexe no CSS meses
#              depois, a borda volta, e ninguem percebe ate o Mario abrir a tela
#              de novo. Estes testes olham o HTML/CSS GERADO e falham quando o
#              pedido e desfeito.
#
#              Cada teste cita o item e o que foi pedido, para que quem o vir
#              falhar saiba se esta quebrando um pedido ou corrigindo um engano.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os
import re

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _fonte(caminho):
    with io.open(os.path.join(RAIZ, caminho), encoding="utf-8",
                 errors="replace") as fh:
        return fh.read()


# ------------------------------------------------------------------------------
# TELA MANAGER
# ------------------------------------------------------------------------------

def test_f221_botoes_de_navegacao_sem_borda():
    """F-221: os cinco botoes do topo desenhavam retangulos concorrendo com a
    tabela. O realce passa a vir da cor."""
    src = _fonte("src/controllers/server_controller.py")
    assert ".navlink{" in src
    trecho = src[src.index(".navlink{"):src.index(".navlink{") + 260]
    assert "border:1px solid transparent" in trecho, (
        "a borda solida do .navlink voltou (F-221)")


def test_f222_hover_da_linha_nao_move_nada():
    """F-222: `transform:scale` deslocava a linha sob o cursor no instante do
    clique. So a cor muda."""
    src = _fonte("src/controllers/server_controller.py")
    assert "tr:hover {{ background: #2a2d2e !important; }}" in src, (
        "o hover da linha da Manager mudou de forma")
    assert "transform: scale(1.01)" not in src, (
        "a animacao de escala no hover voltou (F-222)")


def test_f224_severidades_num_bloco_unico():
    """F-224: quatro colunas largas para quatro numeros de um digito viraram
    uma celula so."""
    src = _fonte("src/controllers/server_controller.py")
    assert "class='sev-bloco'" in src
    assert ".sev-cel {{" in src
    for antigo in ('title="Achados criticos na ultima captura">Crit<',
                   '>High<', '>Med<', '>Low<'):
        assert antigo not in src, (
            "as colunas separadas de severidade voltaram (F-224): %s" % antigo)


def test_f226_status_nomeia_o_agente_e_diz_desde_quando():
    """F-226: um ponto verde nao dizia de QUEM era o estado nem desde quando."""
    src = _fonte("src/controllers/server_controller.py")
    assert "Status do agente" in src, "o cabecalho nao diz que o status e do agente"
    assert "agente ativo" in src and "agente mudo" in src
    assert "falou ha %s" in src, "a ultima conversa nao aparece na celula"


def test_f227_todos_os_nomes_e_enderecos_atravessam_ate_a_tela():
    """
    F-227: o coletor ja reunia todos os nomes, mas nada disso chegava a frota.
    O teste segue a fatia inteira, porque quebrar em qualquer ponto do caminho
    devolve o mesmo sintoma na tela: um nome so.
    """
    outbox = _fonte("src/core/outbox.py")
    assert '"hostnames": nomes' in outbox and '"ip_addresses": enderecos' in outbox, (
        "o agente parou de enviar a identidade estendida")

    db = _fonte("src/core/database.py")
    assert '("hostnames", "TEXT")' in db and '("ip_addresses", "TEXT")' in db, (
        "as colunas sumiram do ALTER guardado")
    assert "a.hostnames, a.ip_addresses" in db, (
        "a consulta da frota parou de trazer os campos")

    server = _fonte("src/controllers/server_controller.py")
    assert 'hostnames=host.get("hostnames")' in server, (
        "o servidor recebe e nao persiste")
    assert "outros_nomes" in server and "outros_ips" in server, (
        "a tela voltou a mostrar so o nome principal")


def test_f227_lista_vazia_nao_apaga_identidade_ja_guardada():
    """
    Um agente antigo, que ainda nao envia estes campos, nao pode zerar o que ja
    esta no banco a cada check-in. Por isso o teste e truthy, e nao 'is not
    None' como nos campos numericos que aceitam zero.
    """
    db = _fonte("src/core/database.py")
    trecho = db[db.index("if hostnames:"):db.index("if hostnames:") + 400]
    assert "if hostnames:" in trecho and "if ip_addresses:" in trecho


def test_f228_bloco_do_agente_tem_identificacao_propria():
    """F-228: Last Seen, Next, Uptime e Status respondem a mesma pergunta e
    liam-se como colunas independentes."""
    src = _fonte("src/controllers/server_controller.py")
    assert 'class="grp-agente"' in src
    assert "Agente: presenca e ritmo" in src
    assert src.count('class="col-agente"') >= 4, (
        "as colunas do bloco perderam a marcacao comum")


def test_f230_tabela_ocupa_a_largura_da_tela():
    """F-230: 90% de largura mais 30px de margem deixavam faixas vazias dos
    dois lados."""
    src = _fonte("src/controllers/server_controller.py")
    assert "width: 100%; margin: 12px 0 30px 0" in src, (
        "a tabela da Manager voltou a desperdicar as laterais (F-230)")


# ------------------------------------------------------------------------------
# LAUDO
# ------------------------------------------------------------------------------

def test_f231_e_f232_barra_do_laudo():
    """F-231: barra mais baixa. F-232: icones sem caixa e o botao com o nome do
    DESTINO."""
    src = _fonte("src/controllers/server_controller.py")
    assert "&larr; Manager</a>" in src, (
        "o botao voltou a se chamar Fleet (F-232)")
    assert "&larr; Fleet</a>" not in src
    assert 'padding:4px 16px; display:flex' in src, "a barra voltou a ser alta"
    assert 'border:1px solid #4ec9b0; ' not in src, (
        "a borda do botao de voltar reapareceu (F-232)")


def test_f235_laudo_identifica_o_host_como_a_manager():
    """F-235: o laudo e a peca que sai daqui; nao pode identificar o host com
    menos precisao que o painel."""
    src = _fonte("src/exporters/html_report.py")
    assert "HOSTNAME=(inventory['os'].get('fqdn')" in src, (
        "o laudo voltou a mostrar so o nome curto (F-235)")


def test_f220_inventario_tem_controle_de_recolher():
    """F-220: o bloco das tres caixas ocupa metade da altura util e quase nunca
    muda durante uma analise."""
    css = _fonte("src/exporters/web_assets.py")
    assert 'id="bloco-inventario"' in css
    assert 'onclick="alternarInventario()"' in css
    assert "function alternarInventario()" in css
    assert ".inv.oculto { display:none; }" in css
    assert "si_inv_oculto" in css, (
        "o estado deixou de ser lembrado entre laudos")


def test_f238_arvore_rola_nos_dois_eixos_com_cabecalho_junto():
    """
    F-238: sem rolagem a tabela era cortada e o dado ficava inacessivel. O
    cabecalho tem que viver DENTRO da caixa que rola, senao a rolagem
    horizontal desalinha titulo e coluna.
    """
    css = _fonte("src/exporters/web_assets.py")
    assert ".tabela-rolagem {" in css
    assert "overflow: auto" in css
    # [2026-08-20, segunda rodada] O cabecalho deixou de ser uma div flex por
    # cima da tabela e virou um <thead> DENTRO dela. Enquanto foram dois
    # elementos, cada tentativa de alinhar abria um desencontro novo: o colgroup
    # contra as divs, depois `min-width:100%` esticando so o corpo, depois
    # `table-layout:fixed` encolhendo so a tabela. Com uma fonte de geometria so,
    # cabecalho e corpo nao tem como discordar.
    assert "tbl-hdr" not in css, (
        "o cabecalho em divs voltou; ele desalinha do corpo por construcao")
    # O arquivo tem outros <thead> (legenda de badges, tooltip de score), entao
    # a busca comeca DEPOIS da caixa de rolagem, e nao no inicio do arquivo.
    i_caixa = css.index('class="tabela-rolagem"')
    i_thead = css.index("<thead>", i_caixa)
    i_tbody = css.index("{TABLE_ROWS}", i_caixa)
    assert i_caixa < i_thead < i_tbody, (
        "o <thead> saiu de dentro da caixa de rolagem, ou do corpo (F-238)")
    assert css.count('data-col="--w-') == 12, (
        "as colunas do cabecalho perderam a ligacao com as variaveis")


def test_f219_larguras_do_laudo_tem_fonte_unica():
    """
    F-219: a largura de cada coluna vivia em DOIS lugares (as divs do cabecalho
    e o colgroup). Agora as duas pontas leem a mesma variavel, entao o arraste
    move as duas por construcao.
    """
    css = _fonte("src/exporters/web_assets.py")
    assert "--w-cmd:" in css, "as variaveis de largura sumiram"
    assert '<col width=' not in css, (
        "o colgroup voltou a ter largura propria, fora da variavel (F-219)")
    # Depois de o cabecalho virar <thead>, a largura e declarada em UM lugar
    # (o colgroup) e o cabecalho apenas NOMEIA a variavel que a alca move, via
    # data-col. Antes eram dois lugares escrevendo o mesmo numero, e era isso
    # que desalinhava.
    assert css.count("var(--w-") == 12, (
        "o colgroup deixou de ser a fonte unica das larguras")
    assert css.count('data-col="--w-') == 12, (
        "o cabecalho perdeu a ligacao com as variaveis de largura")


def test_f219_f223_um_mecanismo_de_arraste_para_as_duas_telas():
    """
    O mesmo pedido feito em datas diferentes para telas diferentes. Duas
    implementacoes do mesmo comportamento sao a divergencia silenciosa que este
    projeto ja pagou caro.
    """
    css = _fonte("src/exporters/web_assets.py")
    assert "_JS_COLUNAS_CORE" in css
    assert 'JS_COLUNAS_AJUSTAVEIS = "<script>" + _JS_COLUNAS_CORE' in css
    server = _fonte("src/controllers/server_controller.py")
    assert "JS_COLUNAS_AJUSTAVEIS" in server, "a Manager perdeu o arraste"
    laudo = _fonte("src/exporters/html_report.py")
    assert "_JS_COLUNAS_CORE" in laudo, "o laudo perdeu o arraste"
    assert 'data-col="--w-cmd"' in css, (
        "o cabecalho do laudo perdeu a ligacao com a variavel")


def test_f223_manager_tem_alcas_e_largura_fixa():
    """F-223: sem `table-layout:fixed` o navegador recalcula tudo e o arraste
    nao gruda."""
    src = _fonte("src/controllers/server_controller.py")
    assert "table-layout: fixed" in src
    assert src.count('class="col-grip"') >= 8, (
        "as alcas de redimensionamento sumiram do cabecalho (F-223)")
    # Com `table-layout:fixed` quem manda e o colgroup ou a PRIMEIRA linha. Esta
    # tabela tem linha de agrupamento com colspan, entao SEM colgroup o
    # navegador derivava as larguras dela e ignorava as colunas: o arraste nao
    # pegava e a coluna Action ficava espremida.
    assert "--m-w-act:" in src, "as variaveis de largura da Manager sumiram"
    assert 'style="width:var(--m-w-host)"' in src, (
        "o colgroup da Manager sumiu, e sem ele as larguras nao valem")
    assert 'data-col="--m-w-' in src, (
        "as alcas deixaram de mover a variavel de largura")


def test_f237_e_f239_sem_espaco_desperdicado_no_laudo():
    """F-237: a faixa entre o filtro e o cabecalho valia quase uma linha de
    processo. F-239: a moldura lateral era largura tirada da arvore."""
    css = _fonte("src/exporters/web_assets.py")
    assert "margin-bottom:4px" in css, "a faixa acima da arvore voltou a crescer"
    assert ".table-container { padding: 0 0 12px 0; }" in css, (
        "a moldura lateral da tabela voltou (F-239)")
    assert re.search(r"^body \{[^}]*padding:0 8px", css, re.M), (
        "o corpo do laudo voltou a ter moldura de 20px (F-239)")
