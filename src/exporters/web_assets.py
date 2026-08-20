# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/exporters/web_assets.py
# DESCRIPTION: Contains the static HTML/CSS/JS assets for the report.
#              Serves as the Frontend Resource bundle.
#
#              UPDATED v0.70.02:
#              - FEAT: Added 'Duration' column to Table Structure (Header & Colgroup).
#              - FEAT: Added CSS class .phys-alert for Hardware Drop Alerts (CRC/Frame).
#              - FIX: Adjusted table widths to accommodate the new timing column.
#              - MAINTAINED: All features, logic, and documentation from v0.61.00.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

from src.core import risk
from src.core import badges as badges_reg

# ------------------------------------------------------------------------------
# 1. LEGEND COMPONENT
# ------------------------------------------------------------------------------
# Gerada a partir de src/core/risk.py, e nao escrita a mao.
#
# A tabela que existia aqui era uma copia mantida em paralelo e ja tinha se
# afastado da origem: anunciava "+512 EDR Latency (Process Frozen)", um bit que
# nenhum coletor atribui, e omitia o nivel de cada sinal. Um laudo que descreve
# uma regra que a ferramenta nao aplica e pior que um laudo sem legenda.


def _linhas_legenda():
    """
    Duas linhas por sinal: a compacta (bit/rotulo/severidade) e, logo
    abaixo, a explicacao por extenso, sempre VISIVEL.

    [2026-08-18] Antes a explicacao so ia no title (hover): o Mario testou
    e relatou "ainda estou tentando entender a numeracao e valores" -- um
    popup cujo unico jeito de entender cada linha e passar o mouse em cima,
    uma de cada vez, nao ensina nada de longe. A explicacao de risk.SINAIS
    ja e escrita nesse tom (o que o sinal representa para seguranca/pericia,
    nao so o nome tecnico); so precisava parar de estar escondida.
    """
    linhas = ""
    for bit, _chave, rotulo, severidade, explicacao in risk.SINAIS:
        linhas += ("<tr><td>+%d</td><td>%s</td>"
                   "<td style='color:%s'>%s</td></tr>"
                   "<tr class='leg-exp-row'><td></td>"
                   "<td colspan='2'><span class='leg-sig'>%s</span></td></tr>"
                   % (bit, _esc_legenda(rotulo),
                      risk.CORES.get(severidade, "#888"), severidade,
                      _esc_legenda(explicacao)))
    return linhas


def _esc_legenda(valor):
    """Escape minimo para texto vindo de risk.SINAIS dentro de atributo/celula."""
    return (str(valor).replace("&", "&amp;").replace('"', "&quot;")
            .replace("<", "&lt;").replace(">", "&gt;"))


def _botoes_filtro():
    """
    Um botao de filtro por chave de src.core.badges.TAG_MAP, na mesma ordem.

    Existia aqui uma lista de 11 botoes escrita a mao, que ja tinha ficado
    para tras (IMMUTABLE e DELETED tinham badge e nenhum filtro) antes mesmo
    do F-201 acrescentar 13 badges novos. Um sinal presente que ninguem
    consegue isolar numa arvore de centenas de processos esta la so
    formalmente (D-028); gerar daqui, do MESMO registro que desenha o badge,
    e o que impede a proxima divergencia.
    """
    linhas = ""
    for tag, (icone, _cls, tooltip, _sig) in badges_reg.TAG_MAP.items():
        linhas += ('<span class="filter-btn" onclick="setFilter(\'%s\', this)" '
                   'title="%s">%s</span>\n                    '
                   % (tag, tooltip, icone))
    return linhas


FILTER_BAR_HTML = _botoes_filtro()

# Badges que a barra de filtro desenha por caminho proprio (fora do
# TAG_MAP): NEW (node.is_new) e NET ERR (contadores agregados). Precisam de
# legenda tambem, senao o popup mente por omissao sobre dois botoes que
# estao bem ali do lado.
_BADGES_FORA_DO_MAPA = (
    ("NEW", "✨", "Processo novo nesta captura, ausente na anterior.",
     "Sozinho e neutro (todo host cria processos o tempo todo). O valor "
     "forense esta em CRUZAR com o resto da arvore: processo novo com "
     "caminho gravavel, ou novo direto sob PID 1 sem passar por um "
     "gerenciador de servico conhecido, pesa mais que o badge isolado."),
    ("NET ERR", "❌",
     "Falhas de rede do processo (retransmissoes TCP + pacotes descartados), somadas.",
     "Pode ser so problema de infraestrutura (link instavel, MTU errado). "
     "Tambem e a assinatura de C2 mal configurado ou de exfiltracao para "
     "um destino que bloqueia/reseta a conexao repetidamente."),
)


def _linhas_legenda_badges():
    linhas = ""
    for tag, icone, explicacao, significado in _BADGES_FORA_DO_MAPA:
        linhas += ("<tr><td>%s</td><td>%s</td><td>%s<br><span class='leg-sig'>%s</span></td></tr>"
                   % (icone, _esc_legenda(tag), _esc_legenda(explicacao),
                      _esc_legenda(significado)))
    for tag, (icone, _cls, explicacao, significado) in badges_reg.TAG_MAP.items():
        linhas += ("<tr><td>%s</td><td>%s</td><td>%s<br><span class='leg-sig'>%s</span></td></tr>"
                   % (icone, _esc_legenda(tag), _esc_legenda(explicacao),
                      _esc_legenda(significado)))
    return linhas


BADGE_LEGEND_HTML = ("""
<div class="score-legend-wrapper">
    <span class="legend-icon" title="Legenda dos badges" onclick="toggleLegend(this)">?</span>
    <div class="legend-backdrop" onclick="this.closest('.score-legend-wrapper').classList.remove('open')"></div>
    <div class="score-tooltip">
        <span class="legend-close" onclick="this.closest('.score-legend-wrapper').classList.remove('open')" title="Fechar">&times;</span>
        <h4>Badges da arvore de processos</h4>
        <div style="font-size:10px; color:#999; margin-bottom:6px;">
            Rotulo tecnico (o que a sonda observou) e, logo abaixo em cinza,
            o que isso costuma significar para seguranca e pericia.
        </div>
        <table class="badge-legend">%s</table>
        <div style="font-size:9px; color:#777; margin-top:5px;
                    border-top:1px solid #333; padding-top:2px;">
            * Clique num icone da barra de Filters para isolar so os
            processos com aquele sinal. Esta lista e a mesma fonte que
            desenha os icones (src/core/badges.py): nunca fica desatualizada
            em relacao aos botoes ao lado.
        </div>
    </div>
</div>
""" % _linhas_legenda_badges())

LEGEND_HTML = ("""
<div class="score-legend-wrapper">
    <span class="legend-icon" title="Anomaly Score Rules" onclick="toggleLegend(this)">?</span>
    <div class="legend-backdrop" onclick="this.closest('.score-legend-wrapper').classList.remove('open')"></div>
    <div class="score-tooltip">
        <span class="legend-close" onclick="this.closest('.score-legend-wrapper').classList.remove('open')" title="Fechar">&times;</span>
        <h4>Sinais do anomaly score (campo de bits)</h4>
        <table>%s</table>
        <div style="font-size:9px; color:#777; margin-top:5px;
                    border-top:1px solid #333; padding-top:2px;">
            * Cada bit e um sinal observado. O VALOR somado nao mede gravidade:
            o nivel exibido vem dos sinais presentes, e sobe um degrau quando
            dois ou mais de peso coincidem.
        </div>
    </div>
</div>
""" % _linhas_legenda())

# ------------------------------------------------------------------------------
# 2. CSS STYLES (Supports New Badges & Dark Theme)
# ------------------------------------------------------------------------------
CSS_BASE = r"""
:root { --bg:#121212; --fg:#e0e0e0; --acc:#0078d4; --red:#ff6b6b; --grn:#51cf66; --yel:#fcc419; --pur:#b180ff; --gry:#777; --drk:#252526; --border:#333; --cyn:#4ec9b0; }
/* [F-239] Antes 20px em volta do corpo inteiro. Numa tela cuja informacao e
   horizontal (a arvore de comando trunca com "..."), essa moldura era largura
   tirada do que se le. O topo e a base ficam em zero porque a barra grudada ja
   traz o proprio respiro. */
/* A pagina ocupa a janela e NAO rola: quem rola e a arvore. Ver .tabela-rolagem. */
/* `overflow:hidden` no html TAMBEM, e nao so no body: sem isso a janela
   continua rolavel por script mesmo sem barra de rolagem, e um
   `window.scrollTo` levava a viewport para 1844px de area vazia. A tela
   ficava EM BRANCO e parecia que a pagina tinha quebrado. */
html { height: 100%; overflow: hidden; }
body {
    font-family:'Segoe UI', 'Roboto', monospace; background:var(--bg);
    color:var(--fg); padding:0 8px; font-size:13px; margin:0;
    height: 100%; box-sizing: border-box;
    display: flex; flex-direction: column; overflow: hidden;
}
/* As abas que NAO sao a arvore (Findings, ATT&CK) rolam por dentro tambem, pelo
   mesmo motivo: duas barras na mesma tela e sempre uma a mais. */
.findings-container { overflow: auto; flex: 1 1 auto; min-height: 0; }
.table-container { display: flex; flex-direction: column; min-height: 0; flex: 1 1 auto; }
.table-container.panel-hidden, .findings-container.panel-hidden { display: none; }

/* [F-220] Controle de recolher o inventario. */
.inv-toggle {
    display:inline-flex; align-items:center; gap:6px; cursor:pointer;
    color:var(--gry); font-size:11px; text-transform:uppercase;
    letter-spacing:1px; padding:2px 6px; margin-bottom:6px; user-select:none;
}
.inv-toggle:hover { color:var(--cyn); }
.inv.oculto { display:none; }

/* [F-238] A arvore rola dentro da propria caixa, nos DOIS eixos. Sem isto a
   tabela era cortada e nao havia como alcancar o que passava da largura: o
   dado existia e ficava inacessivel, que e pior que nao ter o dado. */
/* UMA barra de rolagem, e ela e da arvore.
   A primeira versao deixava a pagina rolar TAMBEM, e o resultado eram duas
   barras concorrendo, sendo que a da pagina ficava enorme sem ter conteudo
   proporcional. A pagina passa a ocupar exatamente a altura da janela, a barra
   grudada e as abas tem altura propria, e a arvore recebe o que sobrar. Quem
   rola e so ela. */
.tabela-rolagem {
    overflow: auto; flex: 1 1 auto; min-height: 120px;
    border: 1px solid var(--border); border-radius: 4px;
}
/* Cabecalho fixo enquanto se rola: perder o nome da coluna depois de vinte
   linhas transforma numero em enigma.
   O cabecalho das colunas vive DENTRO desta caixa, e nao na barra grudada do
   topo. Fora dela, a rolagem horizontal moveria so o corpo e as colunas
   deixariam de bater com seus titulos, que e pior que nao rolar. */
/* UMA fonte de geometria: o cabecalho vive DENTRO da tabela, entao ele nao tem
   como discordar do corpo. Enquanto foram dois elementos (uma div flex por cima
   de uma table), cada tentativa de alinhar os dois abria um desencontro novo:
   colgroup contra as divs, depois `min-width:100%` esticando so o corpo, depois
   `table-layout:fixed` encolhendo so a tabela. O <thead> resolve por
   construcao, e nao por ajuste. */
.tabela-rolagem thead th {
    position: sticky; top: 0; background: var(--drk); z-index: 5;
    text-align: center; text-transform: uppercase; font-size: 11px;
    color: #aaa; font-weight: bold; padding: 8px 5px;
    border-bottom: 2px solid #444;
}
    position: sticky; top: 0; z-index: 6; background: var(--bg);
    width: max-content;
}
/* A tabela nunca encolhe abaixo da soma das colunas: e o que garante que o
   corpo e o cabecalho rolem juntos, em vez de o corpo se comprimir. */
/* A largura da tabela e a soma das colunas; a caixa rola quando nao cabe.
   `max-content` inflava a PAGINA em vez da caixa. */
/* Cabecalho e corpo tem que ter EXATAMENTE a mesma largura, senao as
   colunas desencontram. `min-width:100%` esticava a TABELA ate o
   container enquanto o cabecalho ficava na soma das colunas: cada
   coluna do corpo ganhava um pouco e o titulo ficava para tras.
   Os dois passam a ser exatamente a soma das variaveis. */
/* Preenche o container e cresce alem dele quando as colunas pedem mais; a
   caixa e quem rola. Com o cabecalho dentro da tabela, esticar ou
   encolher move os dois juntos, entao isto ja nao pode desalinhar. */
.tabela-rolagem table { width: 100%; min-width: max-content; }

/* [F-219] Alca de arraste na borda direita do cabecalho, mesmo mecanismo da
   tela Manager (JS_COLUNAS_AJUSTAVEIS). */
.col-grip { position:absolute; top:0; right:0; width:6px; bottom:0;
               cursor:col-resize; user-select:none; }
/* A alca precisa APARECER. Sem nada na tela, so descobre que a coluna e
   ajustavel quem passa o mouse por acaso no pixel certo. O tracinho marca a
   divisa entre colunas e o cursor de arraste confirma o que ele faz. */
.col-grip::after {
    content: ''; position: absolute; right: 2px; top: 22%; bottom: 22%;
    width: 1px; background: #4a4a4a;
}
.col-grip:hover::after { background: var(--cyn); width: 2px; }
.col-grip:hover { background:var(--cyn); opacity:0.5; }


/* [F-219] Largura das colunas da aba Processes numa FONTE SO.
   Antes o mesmo numero vivia em dois lugares (as divs do cabecalho e o
   colgroup da tabela): mexer num sem o outro desalinhava a tela, e era a
   divergencia silenciosa de sempre. Agora o arraste altera a variavel e as
   duas pontas seguem juntas por construcao. */
:root {
    --w-cmd: 540px;   /* px, e nao %: a tabela usa width:max-content */
    --w-pid: 60px;
    --w-dur: 90px;
    --w-user: 90px;
    --w-nice: 50px;
    --w-cpu: 60px;
    --w-rss: 80px;
    --w-dhot: 100px;
    --w-dhist: 100px;
    --w-ntx: 90px;
    --w-nrx: 90px;
    --w-alerts: 320px;
}
/* --- HEADER & LAYOUT --- */
/* Ja nao precisa ser "sticky": a pagina inteira nao rola mais, entao o topo
   fica onde esta por construcao. Sticky aqui, com a pagina sem rolagem,
   so criava um contexto de empilhamento a toa. */
.sticky-wrapper {
    flex: 0 0 auto; z-index: 1000;
    background-color: var(--bg);
    padding: 10px 20px 0 20px;
    border-bottom: 1px solid var(--acc);
    box-shadow: 0 5px 15px rgba(0,0,0,0.5);
}
.hdr { display:flex; justify-content:space-between; align-items:center; margin-bottom:15px; }
.title h1 { margin:0; font-weight:300; font-size:26px; color:var(--acc); letter-spacing:-0.5px; }
.title span { font-size:0.6em; color:#666; margin-left:10px; }
.subtitle { color:var(--gry); font-size:0.85em; text-transform:uppercase; letter-spacing:2px; margin-top:4px; font-weight:bold; }
.meta { text-align:right; color:#888; font-size:0.9em; }

/* --- CARDS --- */
.inv { display:grid; grid-template-columns:repeat(auto-fit,minmax(380px,1fr)); gap:15px; margin-bottom:15px; }
.card { background:var(--drk); border:1px solid #444; padding:12px; border-radius:4px; display:flex; flex-direction:column; }
.card h3 { margin:0 0 10px 0; border-bottom:1px solid #444; color:var(--acc); font-size:11px; text-transform:uppercase; display:flex; justify-content:space-between; align-items:center; }
.kv { display:grid; grid-template-columns: 140px 1fr; gap:10px; border-bottom:1px solid #2a2a2a; padding-bottom:2px; align-items:baseline; }
.kv:last-child { border-bottom: none; }
.kv-k { color:var(--gry); font-weight:normal; } .kv-v { font-weight:600; color:#ddd; word-break:break-all; }

/* --- PHYSICAL DROP ALERT (v0.70) --- */
.phys-alert {
    border: 1px solid var(--red);
    background: rgba(255, 107, 107, 0.1);
    color: var(--red);
    padding: 8px;
    margin-bottom: 15px;
    border-radius: 4px;
    font-weight: bold;
    text-align: center;
    animation: pulse 2s infinite;
    font-family: 'Consolas', monospace;
    font-size: 12px;
}
@keyframes pulse { 0% { opacity: 0.8; } 50% { opacity: 1; } 100% { opacity: 0.8; } }

/* --- SCROLLABLE LIST BOX (Files/Libs) --- */
.list-box {
    max-height: 250px;
    overflow-y: auto;
    overflow-x: hidden;
    border: 1px solid #333;
    background: #1a1a1a;
    padding: 5px;
    border-radius: 3px;
}
.list-box::-webkit-scrollbar { width: 8px; }
.list-box::-webkit-scrollbar-track { background: #222; }
.list-box::-webkit-scrollbar-thumb { background: #444; border-radius: 4px; }
.list-box::-webkit-scrollbar-thumb:hover { background: var(--acc); }

/* --- PHYSICAL DROP ALERT (v0.70) --- */
.phys-alert {
    border: 1px solid var(--red);
    background: rgba(255, 107, 107, 0.1);
    color: var(--red);
    padding: 8px;
    margin-bottom: 15px;
    border-radius: 4px;
    font-weight: bold;
    text-align: center;
    animation: pulse 2s infinite;
    font-family: 'Consolas', monospace;
    font-size: 12px;
}
@keyframes pulse { 0% { opacity: 0.8; } 50% { opacity: 1; } 100% { opacity: 0.8; } }

/* --- DISK TOPOLOGY SPECIFIC SCROLL (FIXED HEIGHT WRAPPER) --- */
.disk-topology-wrapper {
    display: block;
    position: relative;
    height: 180px;  /* FIXED HEIGHT for container */
    /* overflow: hidden; */ /* Contain overflow */
    border: 1px solid #333;
    border-radius: 3px;
    background: #1a1a1a;
}

.disk-topology-box {
    height: 100%;
    width: 100%;
    overflow-y: scroll; /* Force Scrollbar */
    padding: 5px;
    box-sizing: border-box;
}

/* High Contrast Scrollbar */
.disk-topology-box::-webkit-scrollbar { width: 12px; }
.disk-topology-box::-webkit-scrollbar-track { background: #000; border-left: 1px solid #333; }
.disk-topology-box::-webkit-scrollbar-thumb { background: #888; border-radius: 6px; border: 2px solid #000; }
.disk-topology-box::-webkit-scrollbar-thumb:hover { background: var(--acc); }

/* --- TOPOLOGY STYLES --- */
.disk-root { margin-bottom: 5px; border-bottom: 1px solid #333; padding-bottom: 5px; }
.disk-header { display: flex; align-items: center; gap: 10px; font-weight: bold; }
.disk-icon { color: var(--acc); cursor: pointer; font-family: monospace; font-size: 14px; border: 1px solid #444; width: 16px; height: 16px; display: flex; align-items: center; justify-content: center; border-radius: 3px; background: #333; }
.disk-details { display: none; margin-left: 20px; margin-top: 5px; border-left: 1px solid #444; padding-left: 10px; font-size: 0.9em; color: #bbb; }
.disk-details.show { display: block; }
.disk-part { margin-top: 3px; }
.disk-meta { font-size: 0.85em; color: #777; margin-left: 5px; }
.hctl-tag { background: #333; color: var(--cyn); padding: 1px 4px; border-radius: 2px; font-size: 0.85em; border: 1px solid #444; }
.btn-print-disk { cursor: pointer; font-size: 10px; padding: 1px 5px; border: 1px solid #555; border-radius: 3px; background: #222; color: #aaa; }
.btn-print-disk:hover { background: var(--acc); color: white; border-color: var(--acc); }

.net-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 5px; font-size: 0.95em; margin-bottom: 5px; }
.net-iface { font-weight: bold; color: var(--acc); }
.net-gw-dns { margin-top: 8px; border-top: 1px dashed #444; padding-top: 4px; font-size: 0.9em; color: #888; }

/* --- BADGES & ICONS --- */
/* [F-237] A faixa entre o campo de filtro e o cabecalho da arvore
   somava 15px de margem mais 20px de padding do container: quase
   uma linha de processo desperdicada, na tela em que altura e o
   recurso escasso. */
.controls { display:flex; flex-direction: column; gap:8px; margin-bottom:4px; width: 100%; }
.legend { display:flex; gap:15px; background:#222; padding:8px 12px; border:1px solid #444; border-radius:3px; align-items:center; flex-wrap:wrap; width: 100%; box-sizing: border-box; }
.leg-grp { display:flex; align-items:center; gap:10px; padding-right:15px; border-right:1px solid #444; }
.leg-grp:last-child { border:none; }
.leg-lbl { font-weight:bold; color:#aaa; font-size:11px; text-transform:uppercase; }

/* LEGEND BARS (Restored) */
.bar { width:60px; height:8px; border-radius:2px; display:inline-block; }
.grad-prio { background: linear-gradient(to right, var(--red), var(--grn)); }
.grad-cpu { background: linear-gradient(to right, var(--grn), var(--red)); }

/* Base Tag Style */
.tag {
    display:inline-flex; align-items:center; justify-content:center;
    padding:1px 4px; border-radius:3px;
    font-weight:bold; margin-right:1px; cursor:help;
    font-size:16px; /* Optimized for Emojis */
    border:1px solid transparent;
    vertical-align: middle;
}

/* A coluna ALERTS pode usar DUAS linhas: a altura da linha ja e ditada pela
   coluna DISK, que ocupa tres. Antes os badges eram forcados numa linha so
   (regra global `td { white-space:nowrap }`) e o excedente era cortado, com a
   altura sobrando ao lado, sem uso. Fonte um pouco menor pelo mesmo motivo:
   cabe mais sinal no mesmo espaco. */
/* COMMAND TREE tambem quebra, ate tres linhas. A linha inteira ja tem essa
   altura por causa da coluna DISK, e o comando truncado com "..." escondia
   justamente o argumento que interessa numa analise (o caminho de onde o
   binario foi lancado costuma estar no fim). Passando de tres linhas volta a
   cortar, para uma linha de comando gigante nao empurrar a tabela toda. */
td:first-child:not(.det-cell) {
    /* SEM `display:-webkit-box`: isso tira a celula do fluxo de tabela, e foi o
       que produziu o vao gigante entre o comando e a coluna PID (a celula
       ocupava a largura declarada, o texto se espremia em ~150px). Quebra
       normal de linha basta; a largura da coluna e quem limita. */
    white-space: normal; overflow-wrap: anywhere; line-height: 1.4;
}
td.alert-cell, td:last-child {
    white-space: normal; overflow: visible; text-overflow: clip;
    line-height: 1.5;
}
td:last-child .tag { margin-right: 1px; margin-bottom: 2px; }
.tag:hover { transform: scale(1.2); transition: 0.1s; background: rgba(255,255,255,0.1); }

/* Detalhe da custodia: os LIMITES da aquisicao, logo abaixo do nivel. Fonte
   menor mas cor legivel de proposito -- e ressalva, nao rodape decorativo. */
.fnd-cust-det {
    margin-top: 3px; font-size: 10.5px; color: #a0a0a0; line-height: 1.5;
    white-space: normal; word-break: break-word;
}
.fnd-cust-det code { color: var(--cyn); font-size: 10px; word-break: break-all; }

/* --- ENCAMINHAMENTO A BANCADA (C-044) --- */
/* Bloco visualmente distinto do resto do detalhe do achado de proposito: ele
   nao fala com o operador do host, fala com quem vai continuar o trabalho fora
   da frota, e essa mudanca de interlocutor precisa ser vista antes de ser lida. */
.fnd-referral {
    margin: 8px 0; padding: 8px 10px;
    border-left: 3px solid var(--cyn);
    background: rgba(78,201,176,0.06);
    border-radius: 0 3px 3px 0;
}
.fnd-ref-hdr {
    color: var(--cyn); font-weight: bold; font-size: 11px;
    text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 5px;
}
.fnd-ref-why {
    display: block; text-transform: none; letter-spacing: 0;
    font-weight: normal; color: #8a8a8a; font-size: 10px; margin-top: 1px;
}
.fnd-ref-tbl { width: 100%; border-collapse: collapse; font-size: 11.5px; }
.fnd-ref-tbl td {
    padding: 2px 6px 2px 0; vertical-align: top;
    white-space: normal; overflow: visible; text-overflow: clip;
}
.fnd-ref-k { color: #999; width: 190px; font-weight: bold; }
.fnd-ref-tbl code { color: var(--yel); word-break: break-all; }

/* Visually Hidden (But searchable/filterable) */
.visually-hidden {
    position: absolute;
    width: 1px; height: 1px; margin: -1px;
    padding: 0; overflow: hidden;
    clip: rect(0, 0, 0, 0); border: 0;
}

/* Badge Filters in Toolbar (Clickable) */
.filter-btn { cursor: pointer; opacity: 0.7; transition: 0.2s; font-size: 16px; margin: 0 4px; }
.filter-btn:hover { opacity: 1.0; transform: scale(1.2); }
/* [UI] Active indicator: outline (not border) so it never shifts neighbor icons */
.filter-btn.active { opacity: 1.0; outline: 2px solid var(--red); outline-offset: 2px; border-radius: 3px; }

/* Special Badges (Backgrounds can be minimal now, relying on Icon) */
.t-warn { border-color:var(--red); background:rgba(255, 107, 107, 0.1); }
/* [2026-08-20] Estes dois carregam numero, entao sao os mais largos e os
   que mais empurravam a altura da linha: o padding interno somado a
   margem externa fazia duas linhas onde cabia uma. */
.t-err  { background:var(--red); color:#000; padding:0 3px; margin-right:1px; }
.t-warn { padding:0 3px; margin-right:1px; }
.t-err span, .t-warn span { font-size:0.9em; }

.btn-clear { cursor:pointer; padding:2px 6px; border-radius:3px; border:1px solid #555; font-size:10px; font-weight:bold; color:#aaa; background:#333; }
/* [UI] Sort buttons styled as bare icons, symmetric with .filter-btn (no gray box) */
.btn-act { cursor:pointer; opacity:0.7; transition:0.2s; font-size:16px; margin:0 4px; display:inline-block; }
.btn-act:hover { opacity:1.0; transform: scale(1.2); }
/* [UI] Active sort indicator, identical to the active filter outline (no layout shift) */
.btn-act.sort-active { opacity:1.0; outline: 2px solid var(--red); outline-offset: 2px; border-radius: 3px; }
#search { width:100%; padding:8px; background:#252526; border:1px solid #555; color:white; border-radius:3px; font-family:monospace; box-sizing:border-box; }

/* --- TABLE STYLES --- */
/* [F-239] Sem moldura lateral: a largura vai toda para a arvore. */
.table-container { padding: 0 0 12px 0; }
table { width:100%; border-collapse:collapse; font-size:12px; table-layout:fixed; }
th { text-align:left; background:#2d2d30; padding:10px 5px; border-bottom:2px solid #444; color:#aaa; text-transform:uppercase; font-size:11px; }
td { padding:6px 5px; border-bottom:1px solid #2a2a2a; vertical-align:middle; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.row:hover { background:#2a2d2e; cursor:pointer; }
.row.warn { background:rgba(244,135,113,0.08); border-left:3px solid var(--red); }
.exp { color:var(--acc); font-weight:bold; display:inline-block; width:16px; height:16px; line-height:14px; text-align:center; background:#333; border:1px solid #555; border-radius:3px; cursor:pointer; }
.hidden { display:none; }
tr.det-row { display:none; } tr.det-row.show { display:table-row; }
/* A celula de detalhe usa colspan e atravessa a tabela inteira: ela nao
   pode herdar as regras da PRIMEIRA COLUNA, senao a largura dela passa a
   ser a da coluna Command Tree e o painel encolhe. */
.det-cell { width:auto; background:#151515; border-left:3px solid var(--acc); padding:20px; white-space:normal; }
.det-blk { margin-bottom:15px; border-bottom:1px solid #333; padding-bottom:10px; }
.det-title { color:var(--acc); font-weight:bold; margin-bottom:8px; display:block; font-size:1.1em; border-bottom:1px solid #444; padding-bottom:2px; }
.ctx-tbl { width:100%; border-spacing:0; }
.ctx-lbl { color:#666; width:150px; vertical-align:top; }
.ctx-val { color:#ccc; font-family:'Consolas',monospace; white-space: pre-wrap; word-break: break-all; }
.hctl { color:var(--cyn); font-weight:bold; background:rgba(78, 201, 176, 0.1); padding:0 3px; border-radius:2px; }
.disk-str { color:#888; font-size:0.9em; margin-left:10px; }
.d-na { opacity:0.4; font-style:italic; }
.io-r { color:var(--grn); } .io-w { color:var(--red); }
.io-agg { color:#777; font-size:10px; display:block; margin-top:2px; }
.net-agg { color:#777; font-size:9px; display:block; margin-top:2px; }
.cpu-hi { color:var(--red); font-weight:bold; }
.lib-list { max-height:150px; overflow-y:auto; background:#1a1a1a; padding:5px; border:1px solid #333; color:#bbb; }

/* Legend Tooltip */
/* [FIX] Era :hover com o popup ancorado (position:absolute) perto do icone
   "?". Em monitor pequeno, com o icone la embaixo na barra de filtros, o
   popup nascia estourando o rodape da janela; rolar ATE ele tirava o mouse
   da area de hover e ele fechava sozinho antes do analista ler a metade de
   baixo. Agora e clique (ver toggleLegend no JS) e o popup e FIXED e
   CENTRALIZADO na tela: sempre cabe inteiro no viewport, em qualquer
   resolucao, e o scroll interno (quando a lista nao cabe) fica sempre
   alcancavel porque o popup nao depende mais de onde o botao esta na
   pagina nem do mouse continuar sobre ele. */
.score-legend-wrapper { position: relative; display: inline-flex; align-items: center; justify-content: center; margin-left: 8px; vertical-align: middle; }
.legend-icon { background: var(--drk); border: 1px solid var(--acc); color: var(--acc); width: 20px; height: 20px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 12px; cursor: pointer; }
.legend-backdrop {
    display: none; position: fixed; inset: 0; z-index: 9998;
    background: rgba(0,0,0,0.6);
}
.score-legend-wrapper.open .legend-backdrop { display: block; }
.score-tooltip {
    display: none; position: fixed; top: 50%; left: 50%;
    transform: translate(-50%, -50%); z-index: 9999;
    background: #1e1e1e; border: 1px solid var(--acc); padding: 14px;
    width: 460px; max-width: 90vw; max-height: 80vh; overflow-y: auto;
    box-shadow: 0 10px 40px rgba(0,0,0,0.9); border-radius: 6px;
    text-align: left;
}
.score-legend-wrapper.open .score-tooltip { display: block; }
.legend-close {
    position: absolute; top: 8px; right: 10px; cursor: pointer;
    color: #888; font-size: 16px; font-weight: bold; line-height: 1;
}
.legend-close:hover { color: var(--red); }
.score-tooltip h4 { margin: 0 0 8px 0; color: var(--acc); border-bottom: 1px solid #333; padding-bottom: 4px; font-size: 12px; text-transform: uppercase; padding-right: 20px; }
.score-tooltip table { width: 100%; border-collapse: collapse; table-layout: fixed; }
/* [FIX] O 'td { white-space:nowrap; text-overflow:ellipsis }' global (regra da
   arvore de processos) vazava para esta tabela e cortava rotulo e severidade
   no meio da palavra ("carregou kernel via ke...", "Hig..."). Aqui o texto
   PRECISA quebrar linha: e a unica explicacao de cada sinal que o laudo
   oferece antes do analista clicar num processo de verdade. */
.score-tooltip td {
    padding: 4px 4px; border-bottom: 1px solid #333; color: #ccc; font-size: 11px;
    white-space: normal; overflow: visible; text-overflow: clip; vertical-align: top;
}
.score-tooltip td:first-child { color: var(--red); font-weight: bold; text-align: right; padding-right: 8px; width: 52px; }
.score-tooltip td:nth-child(2) { width: auto; }
.score-tooltip td:last-child { width: 60px; font-weight: bold; text-align: right; white-space: nowrap; }
/* Legenda de badges: 1a coluna e o icone (nao um numero), 2a e o nome curto
   em destaque, 3a a explicacao -- layout diferente da legenda de score. */
.score-tooltip table.badge-legend td:first-child { color: inherit; font-weight: normal; text-align: center; padding-right: 4px; width: 26px; font-size: 15px; }
.score-tooltip table.badge-legend td:nth-child(2) { color: #fff; font-weight: bold; width: 96px; white-space: normal; }
.score-tooltip table.badge-legend td:last-child { width: auto; font-weight: normal; text-align: left; white-space: normal; color: #ccc; }
/* Significado forense/seguranca: mais discreto que o rotulo tecnico acima
   dele, mas legivel -- e a resposta a "o que isso quer dizer de verdade". */
.leg-sig { color: #888; font-size: 10px; font-style: italic; display: inline-block; margin-top: 2px; }
/* Linha de explicacao do popup de score: continuacao visual da linha
   compacta acima dela, sem borda propria repetida. */
.leg-exp-row td { border-bottom: 1px solid #333 !important; padding-top: 0 !important; padding-bottom: 6px !important; }
/* Significado forense no bloco "Probe Signals" do detalhe do processo
   (mesmo texto de risk.SINAIS, ver _render_probe_signals). */
.probe-sig { color: #888; font-size: 10px; font-style: italic; white-space: normal; margin-top: 2px; }

/* --- TABS (Findings / Processes) --- */
/* A troca de aba usa esta classe, nunca o estilo inline: o cabecalho da tabela
   declara display:flex inline, e zerar o inline o faria voltar para block,
   empilhando as colunas na vertical. */
.panel-hidden { display: none !important; }
.tabbar { display: flex; gap: 4px; padding: 0 10px; border-bottom: 2px solid #444; }
.tab {
    padding: 8px 18px; cursor: pointer; font-size: 12px; font-weight: bold;
    text-transform: uppercase; letter-spacing: 0.5px; color: #888;
    border: 1px solid transparent; border-bottom: none; border-radius: 4px 4px 0 0;
    user-select: none;
}
.tab:hover { color: #ddd; background: #2a2d2e; }
.tab-active { color: var(--acc); background: #252526; border-color: #444; margin-bottom: -2px; }
.tab-count {
    display: inline-block; min-width: 16px; padding: 1px 5px; margin-left: 5px;
    background: var(--red); color: #fff; border-radius: 8px; font-size: 10px;
}

/* --- FINDINGS PANEL --- */
.findings-container { padding: 12px 16px 40px 16px; }
.fnd-empty { color: #777; font-style: italic; padding: 20px; }
.fnd-summary { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; }
.fnd-chip {
    padding: 5px 12px; border: 1px solid #555; border-radius: 14px;
    font-size: 11px; color: #ccc; cursor: pointer; user-select: none;
}
.fnd-chip:hover { background: #2a2d2e; }
.fnd-chip b { margin-right: 4px; font-size: 13px; }
.fnd-chip-zero { opacity: 0.4; }
.fnd-chip-all { border-style: dashed; }
.fnd-list { display: flex; flex-direction: column; gap: 8px; }
.fnd-item { background: #252526; border-left: 4px solid #444; border-radius: 3px; padding: 8px 12px; }
.fnd-item:hover { background: #2a2d2e; }
.fnd-head { display: flex; align-items: center; gap: 10px; cursor: pointer; }
.fnd-sev {
    color: #1e1e1e; font-weight: bold; font-size: 10px; text-transform: uppercase;
    padding: 2px 8px; border-radius: 3px; min-width: 60px; text-align: center;
}
.fnd-title { font-weight: bold; color: #eee; flex: 1; }
.fnd-tech {
    font-family: monospace; font-size: 10px; color: var(--yel);
    border: 1px solid #555; padding: 1px 6px; border-radius: 3px;
    cursor: pointer; transition: 0.15s;
}
.fnd-tech:hover { background: var(--yel); color: #1e1e1e; }
.fnd-src {
    font-size: 10px; color: #888; text-transform: uppercase;
    border: 1px dashed #555; padding: 1px 6px; border-radius: 3px;
}
.fnd-target { font-family: monospace; font-size: 11px; color: #999; margin: 4px 0 0 70px; word-break: break-all; }
.fnd-det { display: none; margin: 8px 0 4px 70px; padding-top: 8px; border-top: 1px dashed #444; }
.fnd-desc { color: #bbb; font-size: 12px; margin-bottom: 6px; }
.fnd-rec { color: var(--grn); font-size: 12px; margin-bottom: 6px; }
.fnd-refs { color: #999; font-size: 11px; margin-bottom: 6px; }
.fnd-conf {
    font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px;
    border: 1px solid #555; padding: 1px 6px; border-radius: 3px; cursor: help;
}
.fnd-custody { color: #999; font-size: 11px; margin-bottom: 6px; cursor: help; }
/* Faixa guiada "como ler" (1 Achados -> 2 Processes -> 3 ATT&CK). */
.read-guide {
    display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
    margin: 10px 0 0; padding: 6px 12px; font-size: 11px; color: #aaa;
    background: #1f1f1f; border-radius: 4px;
}
.read-guide .rg-lbl { color: #777; text-transform: uppercase; letter-spacing: 1px; font-size: 10px; }
.read-guide .rg-step { cursor: pointer; padding: 2px 6px; border-radius: 3px; transition: 0.15s; }
.read-guide .rg-step:hover { background: #2d2d2d; color: #eee; }
.read-guide .rg-step b { color: var(--acc); margin-right: 4px; }
.read-guide .rg-step em { color: #777; font-style: normal; margin-left: 4px; }
.read-guide .rg-arrow { color: #555; }
/* Tecnica citada por um achado, clicada para pivotar de volta aos achados. */
.atk-back {
    font-size: 10px; color: #7fb3d5; cursor: pointer; margin-left: 8px;
}
.atk-back:hover { text-decoration: underline; }
/* Destaque temporario da tecnica alvo, ao pivotar do achado para a aba ATT&CK. */
.atk-flash { box-shadow: 0 0 0 2px var(--yel); transition: box-shadow 0.3s; }
.fnd-ev-title { color: var(--acc); font-size: 10px; text-transform: uppercase; font-weight: bold; margin: 8px 0 4px 0; }
.fnd-ev-row { display: flex; gap: 8px; margin-bottom: 3px; align-items: flex-start; }
.fnd-ev-k { color: #888; font-size: 11px; min-width: 90px; font-family: monospace; }
.fnd-ev-v {
    margin: 0; color: #ccc; font-size: 11px; font-family: monospace;
    white-space: pre-wrap; word-break: break-all; flex: 1;
    background: #1e1e1e; padding: 4px 6px; border-radius: 3px; max-height: 220px; overflow: auto;
}
/* Pivo para o processo em execucao (so aparece quando ha correspondencia). */
.fnd-pivot {
    font-size: 10px; color: var(--grn); border: 1px solid var(--grn);
    padding: 2px 8px; border-radius: 3px; cursor: pointer; white-space: nowrap;
}
.fnd-pivot:hover { background: var(--grn); color: #1e1e1e; }

/* Destaque temporario da linha alvo apos o pivo. */
@keyframes pivotPulse {
    0%   { background: rgba(78,201,176,0.55); }
    100% { background: transparent; }
}
.pivot-target { animation: pivotPulse 2.5s ease-out; }
.aviso-pivo {
    display: none; position: fixed; top: 12px; left: 50%; transform: translateX(-50%);
    z-index: 3000; background: #2a2a1a; border: 1px solid var(--yel);
    color: var(--yel); padding: 10px 18px; border-radius: 4px; font-size: 12px;
    max-width: 70%; box-shadow: 0 8px 24px rgba(0,0,0,0.6);
}

/* --- ATT&CK REFERENCE --- */
.atk-intro { color: #bbb; font-size: 13px; margin-bottom: 14px; max-width: 1000px; line-height: 1.6; }
.atk-tac-badge { display:inline-block; background:#2a2a1a; border:1px solid var(--yel); color:var(--yel); font-size:10px; padding:1px 7px; border-radius:10px; margin-right:5px; }
.atk-list { display: flex; flex-direction: column; gap: 8px; }
.atk-item { background: #252526; border-left: 4px solid var(--yel); border-radius: 3px; padding: 10px 12px; }
.atk-head { display: flex; align-items: center; gap: 10px; }
.atk-id { font-family: monospace; font-weight: bold; color: var(--yel); font-size: 12px; }
.atk-name { color: #eee; font-weight: bold; flex: 1; }
.atk-qty {
    background: #333; color: #ccc; font-size: 10px; padding: 1px 8px;
    border-radius: 8px; border: 1px solid #555;
}
.atk-tactic { color: #999; font-size: 12px; margin-top: 6px; }
.atk-desc { color: #ccc; font-size: 13.5px; margin-top: 8px; line-height: 1.65; }
.atk-link { color: var(--acc); font-size: 10px; text-decoration: none; display: inline-block; margin-top: 6px; }
.atk-link:hover { text-decoration: underline; }
"""

# ------------------------------------------------------------------------------
# 3. JAVASCRIPT (State Preservation, AJAX, & Logic)
# ------------------------------------------------------------------------------
JS_BLOCK = r"""

// [F-220] Recolhe o inventario (System, Storage, Network) e devolve a altura
// para a arvore de processos. O estado fica no navegador: quem trabalha com a
// arvore nao quer recolher o bloco a cada laudo que abre.
function alternarInventario(){
    var bloco = document.getElementById('bloco-inventario');
    var seta = document.getElementById('inv-seta');
    var rotulo = document.getElementById('inv-rotulo');
    if (!bloco) return;
    var oculto = bloco.classList.toggle('oculto');
    if (seta) seta.innerHTML = oculto ? '&#9654;' : '&#9660;';
    if (rotulo) rotulo.textContent = oculto ? 'Mostrar inventario'
                                            : 'Ocultar inventario';
    try { localStorage.setItem('si_inv_oculto', oculto ? '1' : '0'); } catch (e) {}
}
(function(){
    function restaurar(){
        var guardado = null;
        try { guardado = localStorage.getItem('si_inv_oculto'); } catch (e) {}
        if (guardado === '1') { alternarInventario(); }
    }
    if (document.readyState === 'loading'){
        document.addEventListener('DOMContentLoaded', restaurar);
    } else { restaurar(); }
})();
    // --- STATE MANAGEMENT ---
    var state = {
        expandedPids: new Set(),
        detailsOpenPids: new Set(),
        currentFilter: "",
        // Ordem original da arvore, guardada antes da primeira reordenacao para
        // que o botao de reset devolva a hierarquia pai-filho sem recarregar.
        originalOrder: null
    };

    // --- TREE INTERACTION ---
    function toggleBranch(pid) {
        var btn = document.getElementById('b-'+pid);
        if(btn && btn.classList.contains('disabled')) return;

        var closed = btn && btn.innerText === '+';
        if(btn) btn.innerText = closed ? '-' : '+';

        // Track state
        if(closed) state.expandedPids.add(parseInt(pid));
        else state.expandedPids.delete(parseInt(pid));

        document.querySelectorAll('.c-'+pid).forEach(r => {
            if(closed) r.classList.remove('hidden');
            else {
                r.classList.add('hidden');
                var childPid = r.dataset.pid;
                // Recursive close logic
                var sub = document.getElementById('b-'+childPid);
                if(sub && sub.innerText==='-') toggleBranch(childPid);

                var det = document.getElementById('d-'+childPid);
                if(det) det.classList.remove('show');
            }
        });
    }

    function toggleDet(pid) {
        var el = document.getElementById('d-'+pid);
        if(el) {
            el.classList.toggle('show');
            if(el.classList.contains('show')) state.detailsOpenPids.add(parseInt(pid));
            else state.detailsOpenPids.delete(parseInt(pid));
        }
    }

    function restoreTreeState() {
        // Re-open branches
        state.expandedPids.forEach(pid => {
            var btn = document.getElementById('b-'+pid);
            if(btn && btn.innerText === '+') toggleBranch(pid);
        });
        // Re-apply Filter
        if(state.currentFilter) {
            document.getElementById("search").value = state.currentFilter;
            filterTable();
        }
    }

    // --- FILTERING ---
    function filterTable() {
        var v = document.getElementById("search").value.toUpperCase();
        state.currentFilter = v;

        var isFiltering = v !== "";
        document.querySelectorAll(".proc-row").forEach(r => {
            // Include hidden text (badge names) in search
            var txt = r.innerText.toUpperCase();
            // Also check data-filter attribute specifically
            var badges = r.querySelectorAll('.tag');
            badges.forEach(b => { if(b.dataset.filter) txt += b.dataset.filter.toUpperCase(); });

            var pid = r.dataset.pid;
            var btn = document.getElementById('b-'+pid);

            var match = txt.indexOf(v) > -1;

            if(isFiltering) {
                if(btn) btn.classList.add('disabled');
                if(match) { r.style.display=""; r.classList.remove('hidden'); }
                else r.style.display="none";
            } else {
                if(btn) btn.classList.remove('disabled');
                r.style.display="";
                if(r.classList.contains('root')) r.classList.remove('hidden');
                else r.classList.add('hidden');
                if(btn) btn.innerText='+';
            }
        });

        if(isFiltering) document.querySelectorAll('.det-row').forEach(d => d.classList.remove('show'));
        else restoreTreeState();
    }

    function setFilter(val, el) {
        document.getElementById("search").value = val;
        filterTable();
        // [UI] Highlight the active filter badge (single active filter at a time)
        document.querySelectorAll(".filter-btn").forEach(function(b){ b.classList.remove("active"); });
        if (el) el.classList.add("active");
    }

    // --- UTILS ---
    function toggleDisk(name) {
        // [UPDATED] Sanitize name for ID selector (match with Python logic)
        var safeName = name.replace(/[^a-zA-Z0-9_-]/g, '_');

        var el = document.getElementById('dd-'+safeName);
        var btn = document.getElementById('db-'+safeName);
        if(el && btn) {
            if(el.classList.contains('show')) { el.classList.remove('show'); btn.innerText = '+'; }
            else { el.classList.add('show'); btn.innerText = '-'; }
        }
    }

    function resetTree() {
        // Devolve a arvore ao estado inicial SEM recarregar a pagina.
        //
        // Antes isto era um location.reload(): alem de reprocessar um relatorio
        // que passa de 10MB, o recarregamento voltava para a aba padrao, de modo
        // que quem pedia "resetar a arvore" era jogado para fora dela.
        var tbody = document.querySelector(".table-container tbody");
        if (tbody && state.originalOrder) {
            state.originalOrder.forEach(function (n) { tbody.appendChild(n); });
        }

        state.expandedPids.clear();
        state.detailsOpenPids.clear();
        state.currentFilter = "";

        var busca = document.getElementById("search");
        if (busca) busca.value = "";

        document.querySelectorAll(".proc-row").forEach(function (r) {
            r.style.display = "";
            if (r.classList.contains("root")) r.classList.remove("hidden");
            else r.classList.add("hidden");
            var btn = document.getElementById("b-" + r.dataset.pid);
            if (btn) { btn.classList.remove("disabled"); btn.innerText = "+"; }
        });
        document.querySelectorAll(".det-row").forEach(function (d) {
            d.classList.remove("show");
        });

        document.querySelectorAll(".filter-btn").forEach(function (b) {
            b.classList.remove("active");
        });
        document.querySelectorAll(".btn-act").forEach(function (b) {
            b.classList.remove("sort-active");
        });
    }

    function sortView(metric, el) {
        var tbody = document.querySelector(".table-container tbody");
        if (!tbody) return;
        var rows = Array.from(tbody.querySelectorAll(".proc-row"));
        // A ordem hierarquica so existe no DOM inicial: se for perdida sem
        // copia, a unica forma de recupera-la seria recarregar a pagina.
        if (state.originalOrder === null) {
            state.originalOrder = Array.from(tbody.children);
        }
        rows.forEach(r => {
            r.classList.remove('hidden'); r.style.display="";
            var btn=document.getElementById('b-'+r.dataset.pid);
            if(btn){ btn.innerText='•'; btn.classList.add('disabled'); }
        });
        rows.sort((a, b) => {
            var va = parseFloat(a.dataset[metric] || 0);
            var vb = parseFloat(b.dataset[metric] || 0);
            return vb - va;
        });
        rows.forEach(r => { tbody.appendChild(r); var det = document.getElementById('d-'+r.dataset.pid); if(det) tbody.appendChild(det); });
        // [UI] Highlight the active sort badge (independent from the filter highlight)
        document.querySelectorAll(".btn-act").forEach(function(b){ b.classList.remove("sort-active"); });
        if (el) el.classList.add("sort-active");
    }

    // Function to Print Storage Card content (Handles 100+ disks by removing Scroll)
    function printStorage() {
        var content = document.getElementById('storage-card').innerHTML;
        var win = window.open('', '', 'height=600,width=800');
        win.document.write('<html><head><title>Storage Topology</title>');
        win.document.write('<style>');
        win.document.write('body{font-family:sans-serif; background:#fff; color:#000;}');
        // KEY FIX: Override .list-box to allow full expansion
        win.document.write('.list-box, .disk-topology-box { max-height: none !important; overflow: visible !important; border: none; }');
        win.document.write('.disk-details { display: block !important; margin-left: 20px; border-left: 1px solid #ccc; padding-left: 10px; }');
        win.document.write('.disk-icon, .btn-print-disk { display: none; }');
        win.document.write('.disk-header { font-weight: bold; margin-top: 10px; }');
        win.document.write('</style>');
        win.document.write('</head><body>');
        win.document.write(content);
        win.document.write('</body></html>');
        win.document.close();
        win.print();
    }

    // --- TABS ---
    // Alterna os paineis por data-panel. A arvore de processos e seus controles
    // sao preservados integralmente: apenas mudam de visibilidade.
    function showTab(name, el) {
        var panels = document.querySelectorAll('[data-panel]');
        for (var i = 0; i < panels.length; i++) {
            var p = panels[i];
            // Alterna pela classe: mexer em style.display apagaria o display
            // inline original (o cabecalho da tabela e flex) e quebraria o layout.
            if (p.getAttribute('data-panel') === name) {
                p.classList.remove('panel-hidden');
            } else {
                p.classList.add('panel-hidden');
            }
        }
        var tabs = document.querySelectorAll('.tab');
        for (var j = 0; j < tabs.length; j++) {
            tabs[j].classList.remove('tab-active');
        }
        if (el) { el.classList.add('tab-active'); }
    }

    // Expande/recolhe a evidencia de um achado.
    function toggleFinding(idx) {
        var d = document.getElementById('fnd-' + idx);
        if (!d) { return; }
        d.style.display = (d.style.display === 'block') ? 'none' : 'block';
    }

    // Aviso curto no topo da tela, para o pivo nunca falhar em silencio.
    function avisaPivo(texto) {
        var caixa = document.getElementById('aviso-pivo');
        if (!caixa) {
            caixa = document.createElement('div');
            caixa.id = 'aviso-pivo';
            caixa.className = 'aviso-pivo';
            document.body.appendChild(caixa);
        }
        caixa.innerText = texto;
        caixa.style.display = 'block';
        clearTimeout(window.__avisoPivoTimer);
        window.__avisoPivoTimer = setTimeout(function () {
            caixa.style.display = 'none';
        }, 9000);
    }

    // Entrada vinda de FORA do laudo: a linha do tempo do servidor aponta um
    // processo com /agent/<uuid>#pid=1234. Sem isto, cruzar o evento com a
    // arvore era copiar um PID a mao e procurar na lista.
    window.addEventListener('load', function () {
        var m = /(?:^|[#&])pid=(\d+)/.exec(window.location.hash || '');
        if (!m) { return; }
        // Espera a arvore terminar de montar antes de pivotar.
        setTimeout(function () { pivotToProcess(m[1]); }, 80);
    });

    // Pivo: leva da aba Findings ate o processo que executa o caminho
    // denunciado pelo achado, revelando toda a cadeia de ancestrais.
    function pivotToProcess(pidList) {
        var pids = String(pidList).split(',');
        var targetPid = pids[0];

        // 1. Vai para a aba Processes.
        showTab('processes', document.querySelector('.tab[data-tab="processes"]'));

        // 2. Limpa qualquer filtro ativo ANTES de expandir. Com filtro ligado a
        //    arvore desabilita os botoes de ramo e esconde o que nao casa, entao
        //    o alvo poderia ficar invisivel e os controles travados.
        setFilter('');

        var row = document.querySelector('tr[data-pid="' + targetPid + '"]');
        if (!row) {
            // O processo NAO esta nesta captura. Sair em silencio faria a tela
            // parecer quebrada, e pior: quem veio da linha do tempo concluiria
            // que o pivo nao funciona, quando a resposta correta e que aquele
            // processo ja nao existia quando esta captura foi feita, o que e
            // informacao, e nao falha.
            avisaPivo('Processo ' + targetPid + ' nao esta nesta captura. Ele '
                      + 'pode ter terminado antes dela: procure-o no historico '
                      + 'de capturas deste agente.');
            return;
        }

        // 3. Monta a cadeia de ancestrais subindo por data-ppid.
        var chain = [];
        var current = row;
        var guard = 0;
        while (current && guard < 64) {
            guard++;
            var ppid = current.getAttribute('data-ppid');
            if (!ppid || ppid === '0') { break; }
            var parent = document.querySelector('tr[data-pid="' + ppid + '"]');
            if (!parent || parent === current) { break; }
            chain.push(ppid);
            current = parent;
        }

        // 4. Expande da raiz para baixo usando a funcao da PROPRIA arvore, para
        //    o estado (botoes +/- e state.expandedPids) continuar coerente e a
        //    navegacao seguir funcionando depois do pivo.
        chain.reverse();
        for (var i = 0; i < chain.length; i++) {
            var btn = document.getElementById('b-' + chain[i]);
            if (btn && btn.innerText === '+' && !btn.classList.contains('disabled')) {
                toggleBranch(chain[i]);
            }
        }

        // 5. Rola descontando o cabecalho fixo; sem isso a linha para embaixo
        //    dele e parece que o pivo nao chegou a lugar nenhum.
        // Quem rola e a CAIXA da arvore, nao a janela: desde que a pagina passou
        // a ocupar exatamente a altura do viewport, `window.scrollTo` nao move
        // nada visivel -- e, pior, movia a viewport para dentro de area vazia,
        // deixando a tela EM BRANCO (medido: scrollY 1844). `scrollIntoView`
        // acha sozinho o ancestral rolavel, e `block:'center'` ja resolve o
        // cabecalho grudado.
        // Rola a CAIXA diretamente, com a conta feita a mao. `scrollIntoView`
        // resolve o alvo, mas rola tambem os ancestrais -- inclusive a janela,
        // que `overflow:hidden` esconde mas nao impede de mover por script.
        // Medido: a janela deslocava 166px e levava o cabecalho para fora da
        // vista. Mexendo so no scrollTop da caixa, nada mais se move.
        var caixa = row.closest('.tabela-rolagem');
        if (caixa) {
            caixa.scrollTop = Math.max(0, row.offsetTop
                                          - (caixa.clientHeight / 2));
        } else {
            row.scrollIntoView({block: 'center'});
        }

        // 6. Destaca o alvo e os demais processos correlacionados.
        document.querySelectorAll('.pivot-target').forEach(function (e) {
            e.classList.remove('pivot-target');
        });
        void row.offsetWidth;  // reinicia a animacao
        row.classList.add('pivot-target');
        for (var k = 1; k < pids.length; k++) {
            var extra = document.querySelector('tr[data-pid="' + pids[k] + '"]');
            if (extra) { extra.classList.add('pivot-target'); }
        }
    }

    // Filtra a lista de achados por severidade ('' mostra todos).
    function filterFindings(sev) {
        var items = document.querySelectorAll('.fnd-item');
        for (var i = 0; i < items.length; i++) {
            var match = (!sev || items[i].getAttribute('data-sev') === sev);
            items[i].style.display = match ? '' : 'none';
        }
        var chips = document.querySelectorAll('.fnd-chip');
        for (var k = 0; k < chips.length; k++) {
            chips[k].style.background = (sev && chips[k].getAttribute('data-sev') === sev) ? '#333' : '';
        }
    }

    // Acoplamento entre abas (contrato D-022): do achado para a tecnica na aba
    // ATT&CK, com a tecnica destacada, e da tecnica de volta para os achados que
    // a citam. Sem isto o "?" nao bastava e as abas ficavam soltas.
    function pivotToAttack(tid) {
        showTab('attack', document.querySelector('.tab[data-tab="attack"]'));
        var el = document.getElementById('atk-' + tid);
        if (!el) {
            avisaPivo('A tecnica ' + tid + ' nao esta listada nesta captura.');
            return;
        }
        el.scrollIntoView({behavior: 'smooth', block: 'center'});
        el.classList.add('atk-flash');
        setTimeout(function () { el.classList.remove('atk-flash'); }, 2000);
    }

    function filterFindingsByTechnique(tid) {
        showTab('findings', document.querySelector('.tab[data-tab="findings"]'));
        var items = document.querySelectorAll('.fnd-item');
        var achou = false;
        for (var i = 0; i < items.length; i++) {
            var t = items[i].getAttribute('data-technique') || '';
            var match = (t === tid);
            items[i].style.display = match ? '' : 'none';
            if (match) { achou = true; }
        }
        if (achou) {
            avisaPivo('Mostrando so os achados da tecnica ' + tid +
                      '. Use "Ver todos os niveis" para limpar o filtro.');
        }
    }

    // --- LEGENDAS DE AJUDA (score / badges) ---
    // [FIX] Eram :hover puro: em monitor pequeno o popup nasce perto do
    // icone "?" (que fica la embaixo, na barra de filtros ja rolada) e
    // estoura o rodape da tela. Rolar ATE o popup tira o mouse da area de
    // hover, e ele fecha antes de dar para ler o resto -- o analista nunca
    // via a segunda metade da lista. Clique fixa o popup ABERTO (nao
    // depende do mouse continuar sobre nada) e centralizado na tela (nao
    // depende de onde o botao esta na pagina), entao o scroll interno
    // sempre fica alcancavel em qualquer resolucao.
    function toggleLegend(el) {
        var wrapper = el.closest('.score-legend-wrapper');
        if (!wrapper) return;
        var estavaAberto = wrapper.classList.contains('open');
        document.querySelectorAll('.score-legend-wrapper.open').forEach(function (w) {
            w.classList.remove('open');
        });
        if (!estavaAberto) wrapper.classList.add('open');
    }

    document.addEventListener('click', function (e) {
        if (e.target.closest && e.target.closest('.score-legend-wrapper')) return;
        document.querySelectorAll('.score-legend-wrapper.open').forEach(function (w) {
            w.classList.remove('open');
        });
    });

    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            document.querySelectorAll('.score-legend-wrapper.open').forEach(function (w) {
                w.classList.remove('open');
            });
        }
    });
"""

# ------------------------------------------------------------------------------
# 4. HTML SKELETON (Standardized)
# ------------------------------------------------------------------------------
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Sys-Inspector v{VERSION}</title>
<style>
    {CSS_BLOCK}
</style>
<script>
    {JS_BLOCK}
</script>
</head>
<body>
    <div class="sticky-wrapper">
        <div class="hdr">
            <div class="logo-area">
                <div>
                    <div class="title"><h1>Sys-Inspector<span>v{VERSION}</span></h1></div>
                    <div class="subtitle">OBSERVABILITY SUITE - Enterprise Forensic Report</div>
                </div>
            </div>
            <div class="meta">{TIMESTAMP}<br>{HOSTNAME}</div>
        </div>

        <!-- [F-220] O bloco das tres caixas (System, Storage, Network) ocupa
             metade da altura util e quase nunca muda durante uma analise. O
             controle abaixo o recolhe e devolve a tela para a arvore de
             processos, que e onde o analista trabalha. Reversivel, e o estado
             fica gravado no navegador para nao ter que recolher a cada laudo. -->
        <div class="inv-toggle" onclick="alternarInventario()"
             title="Mostrar ou ocultar System, Storage e Network, para dar espaco a arvore">
            <span id="inv-seta">&#9660;</span>
            <span id="inv-rotulo">Ocultar inventario</span>
        </div>

        <div class="inv" id="bloco-inventario">
            <div class="card">
                <h3>System</h3>
                <div id="os-info">{OS_CONTENT}</div>
            </div>

            <div class="card" id="storage-card">
                <h3>Storage Topology <span class="btn-print-disk" onclick="printStorage()">Print</span></h3>
                <div class="disk-topology-wrapper"> <div class="disk-topology-box">
                        {DISK_CONTENT}
                    </div>
                </div>
            </div>

            <div class="card">
                <h3>Network Topology</h3>
                <div id="net-info">{NET_CONTENT}</div>
            </div>
        </div>

        <div class="read-guide" title="Ordem sugerida para ler este laudo">
            <span class="rg-lbl">Como ler:</span>
            <span class="rg-step" onclick="showTab('findings', document.querySelector('.tab[data-tab=findings]'))"><b>1</b> Achados <em>o que esta errado</em></span>
            <span class="rg-arrow">&rarr;</span>
            <span class="rg-step" onclick="showTab('processes', document.querySelector('.tab[data-tab=processes]'))"><b>2</b> Processes <em>quem executa</em></span>
            <span class="rg-arrow">&rarr;</span>
            <span class="rg-step" onclick="showTab('attack', document.querySelector('.tab[data-tab=attack]'))"><b>3</b> ATT&amp;CK <em>que tecnica e</em></span>
        </div>

        <div class="tabbar">
            <span class="tab tab-active" data-tab="findings" onclick="showTab('findings', this)">Findings {FINDINGS_BADGE}</span>
            <span class="tab" data-tab="processes" onclick="showTab('processes', this)">Processes</span>
            <span class="tab" data-tab="attack" onclick="showTab('attack', this)">ATT&amp;CK {ATTACK_BADGE}</span>
        </div>

        <div class="controls panel-hidden" data-panel="processes">
            <div class="legend">
                <div class="leg-grp">
                    <span class="leg-lbl">Priority</span> <div class="bar grad-prio"></div>
                </div>
                <div class="leg-grp">
                    <span class="leg-lbl">CPU %</span> <div class="bar grad-cpu"></div>
                </div>

                <div class="leg-grp">
                    <span class="leg-lbl">Process By</span>
                    <span class="btn-act" onclick="resetTree()" title="Reset Tree View">⟳</span>
                    <span class="btn-act" onclick="sortView('cpu', this)" title="Top CPU Usage">🔥</span>
                    <span class="btn-act" onclick="sortView('io', this)" title="Top Disk I/O">💾</span>
                    <span class="btn-act" onclick="sortView('mem', this)" title="Top Memory (RSS)">🧠</span>
                    <span class="btn-act" onclick="sortView('net', this)" title="Top Network Activity">🌐</span>
                    <span class="btn-act" onclick="sortView('prio', this)" title="Top Priority (Nice)">⚖️</span>
                </div>

                <div class="leg-grp" style="border:none; margin-left:auto; display:flex; align-items:center;">
                    <span class="leg-lbl">Filters</span>
                    <span class="filter-btn" onclick="setFilter('NEW', this)" title="New Processes">✨</span>
                    {FILTER_BAR_HTML}
                    <span class="filter-btn" onclick="setFilter('NET ERR', this)" title="Network Errors">❌</span>
                    {BADGE_LEGEND_HTML}

                    <span class="btn-clear" onclick="setFilter('')">🧹 CLEAR</span>
                    <span class="btn-act" onclick="window.print()" title="Save PDF">🖨️</span>

                    {LEGEND_HTML}
                </div>
            </div>
            <input type="text" id="search" placeholder="Filter processes (PID, User, Disk, Alert)..." onkeyup="filterTable()">
        </div>

    </div>

    <div class="findings-container" data-panel="findings">
        {FINDINGS_CONTENT}
    </div>

    <div class="findings-container panel-hidden" data-panel="attack">
        {ATTACK_CONTENT}
    </div>

    <div class="table-container panel-hidden" data-panel="processes">
        <div class="tabela-rolagem">
        <table>
            <colgroup>
                <col style="width:var(--w-cmd)">
                <col style="width:var(--w-pid)">
                <col style="width:var(--w-dur)">
                <col style="width:var(--w-user)">
                <col style="width:var(--w-nice)">
                <col style="width:var(--w-cpu)">
                <col style="width:var(--w-rss)">
                <col style="width:var(--w-dhot)">
                <col style="width:var(--w-dhist)">
                <col style="width:var(--w-ntx)">
                <col style="width:var(--w-nrx)">
                <col style="width:var(--w-alerts)">
            </colgroup>
            <thead>
              <tr>
                <th data-col="--w-cmd">Command Tree<span class="col-grip"></span></th>
                <th data-col="--w-pid">PID<span class="col-grip"></span></th>
                <th data-col="--w-dur">Duration<span class="col-grip"></span></th>
                <th data-col="--w-user">User<span class="col-grip"></span></th>
                <th data-col="--w-nice">Nice<span class="col-grip"></span></th>
                <th data-col="--w-cpu">CPU%<span class="col-grip"></span></th>
                <th data-col="--w-rss">RSS<span class="col-grip"></span></th>
                <th title="Current Disk I/O (Bytes/sec) - Hot Activity" data-col="--w-dhot">Disk &Delta;<br>I/O Hot<span class="col-grip"></span></th>
                <th title="Total Disk I/O during Session (Accumulated in Tree)" data-col="--w-dhist">Disk &Sigma;<br>I/O Hist<span class="col-grip"></span></th>
                <th title="Network Transmit: Current Delta / Total Session" data-col="--w-ntx">Net TX<br>&Delta; / &Sigma;<span class="col-grip"></span></th>
                <th title="Network Receive: Current Delta / Total Session" data-col="--w-nrx">Net RX<br>&Delta; / &Sigma;<span class="col-grip"></span></th>
                <th data-col="--w-alerts">Alerts<span class="col-grip"></span></th>
              </tr>
            </thead>
            <tbody style="margin-top:10px">
                {TABLE_ROWS}
            </tbody>
        </table>
        </div>
    </div>
</body>
</html>
"""


# ------------------------------------------------------------------------------
# COLUNAS AJUSTAVEIS (F-219 na aba Processes, F-223 na tela Manager)
# ------------------------------------------------------------------------------
# Escrito UMA vez e usado nas duas telas. Sao o mesmo pedido do Mario feito em
# datas diferentes ("as colunas devem ter tamanho ajustavel"), e duas
# implementacoes do mesmo comportamento e exatamente a divergencia silenciosa
# que este projeto ja pagou caro: uma seria corrigida um dia e a outra nao.
#
# Requisitos do lado do HTML, nos dois casos:
#   - a tabela precisa de `table-layout:fixed`, senao o navegador recalcula as
#     larguras e o arraste nao gruda;
#   - cada `th` redimensionavel carrega um `<span class="col-grip"></span>`.
_JS_COLUNAS_CORE = r"""
(function(){
  function ligar(grip){
    var alvo = grip.parentElement;
    // Duas telas, dois jeitos de guardar a largura, um mecanismo so:
    //  - Manager: tabela de verdade, a largura vai no proprio <th>;
    //  - laudo: cabecalho em divs e corpo em <table>, com as larguras vindas de
    //    variaveis CSS. Ali o arraste altera a VARIAVEL, e as duas pontas se
    //    movem juntas. Escrever dois arrastes diferentes recriaria a
    //    divergencia que as variaveis acabaram de eliminar.
    // O nome da variavel pode vir na propria alca (Manager, onde o <th> ja
    // carrega outros atributos) ou no elemento que a contem (laudo, onde o
    // cabecalho e uma div por coluna). Aceitar os dois evita obrigar as duas
    // telas a escrever o HTML do mesmo jeito para usar o mesmo mecanismo.
    var variavel = grip.getAttribute('data-col') || alvo.getAttribute('data-col');
    var iniX = 0, iniW = 0, arrastando = false;
    grip.addEventListener('mousedown', function(e){
      arrastando = true; iniX = e.pageX; iniW = alvo.offsetWidth;
      if (!variavel){
        // Fixa a largura ATUAL de todas as colunas antes do primeiro arraste.
        // Sem isso, mexer numa coluna faz as vizinhas se redistribuirem e a
        // tabela inteira "pula" no primeiro pixel de movimento.
        var linha = alvo.parentElement;
        for (var i = 0; i < linha.children.length; i++){
          var c = linha.children[i];
          if (!c.style.width) { c.style.width = c.offsetWidth + 'px'; }
        }
      }
      document.body.style.userSelect = 'none';
      e.preventDefault();
    });
    document.addEventListener('mousemove', function(e){
      if (!arrastando) return;
      var largura = iniW + (e.pageX - iniX);
      if (largura <= 40) return;
      if (variavel){
        document.documentElement.style.setProperty(variavel, largura + 'px');
      } else {
        alvo.style.width = largura + 'px';
      }
    });
    document.addEventListener('mouseup', function(){
      if (!arrastando) return;
      arrastando = false;
      document.body.style.userSelect = '';
    });
  }
  function iniciar(){
    var grips = document.getElementsByClassName('col-grip');
    for (var i = 0; i < grips.length; i++){ ligar(grips[i]); }
  }
  if (document.readyState === 'loading'){
    document.addEventListener('DOMContentLoaded', iniciar);
  } else { iniciar(); }
})();
"""

# A Manager injeta o bloco pronto, com as tags; o laudo injeta o NUCLEO
# dentro do <script> que ja existe la. Uma fonte, dois involucros.
JS_COLUNAS_AJUSTAVEIS = "<script>" + _JS_COLUNAS_CORE + "</script>"
