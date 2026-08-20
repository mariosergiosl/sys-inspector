# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_server_security.py
# DESCRIPTION: Seguranca do painel do SERVIDOR: allowlist de identificador e
#              autenticacao. O modulo mais exposto do produto.
#
# ORIGEM:      Este arquivo SUCEDE tests/test_web_security.py, removido em
#              2026-08-19 junto com o web_controller (C-134). Aqueles 14 testes
#              nao eram descartaveis: descreviam comportamento exigido, e a
#              remocao do controlador deixou a ferramenta com o painel que NAO
#              tinha as protecoes. Recuperados de
#              `git show 16d9d9d^:tests/test_web_security.py` e adaptados, como
#              o item C-141 pedia.
#
# O QUE MUDOU: o original exercitava Flask (`app.test_client()`). O servidor usa
#              BaseHTTPRequestHandler, entao aqui se testa a REGRA (allowlist,
#              conferencia de credencial) e a presenca das guardas no despacho,
#              em vez de subir a pilha HTTP inteira a cada caso.
#
# WHY:         O painel serve evidencia forense e faz bind em 0.0.0.0 por
#              escolha explicita. Uma falha aqui expoe a coleta inteira da
#              frota, e nao um host.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os

import pytest

FONTE = os.path.join("src", "controllers", "server_controller.py")


@pytest.fixture(scope="module")
def codigo():
    return io.open(FONTE, encoding="utf-8").read()


def _padrao():
    """
    A allowlist, sem importar o controlador.

    server_controller importa process_tree, que importa `pwd` (Linux-only).
    Compilar o padrao a partir da FONTE mantem estes testes rodando em qualquer
    plataforma, que e o que se quer de uma trava de seguranca: ela nao pode
    depender de o ambiente ser o certo para ser cobrada.
    """
    import re
    fonte = io.open(FONTE, encoding="utf-8").read()
    linha = [l for l in fonte.split("\n")
             if l.startswith("SAFE_ID_PATTERN = re.compile(")][0]
    return re.compile(eval(linha.split("re.compile(", 1)[1].rstrip(")")))


# ------------------------------------------------------------------------------
# ALLOWLIST DE IDENTIFICADOR (C-140)
# ------------------------------------------------------------------------------
def test_allowlist_aceita_identificador_normal():
    padrao = _padrao()
    for valor in ("03baa956-51c6-4af0-bb2d-e3d9850a50aa", "local", "AGENT-01"):
        assert padrao.match(valor), valor


def test_allowlist_recusa_travessia_e_injecao():
    """
    O identificador vira consulta e vai para a pagina; qualquer coisa fora de
    letras, numeros e hifen e recusada ANTES de ser usada.
    """
    padrao = _padrao()
    for valor in ("../../etc/passwd", "a/b", "a'; DROP TABLE snapshots;--",
                  "<script>alert(1)</script>", "a b", "a;b", "a\x00b",
                  "%2e%2e%2f", ""):
        assert not padrao.match(valor), valor


def test_allowlist_recusa_entrada_longa_demais():
    padrao = _padrao()
    assert not padrao.match("a" * 65)
    assert padrao.match("a" * 64)


def test_toda_rota_que_recebe_identificador_passa_pela_allowlist(codigo):
    """
    A trava que importa de verdade: nao basta a allowlist existir, ela precisa
    ser CHAMADA. Antes desta correcao o padrao nem existia no servidor, e as
    rotas pegavam o uuid com split('/')[-1] e usavam direto.
    """
    despacho = codigo[codigo.index("def do_GET(self):"):
                      codigo.index("def do_POST(self):")]
    for rota in ("/cmdclear/", "/priority/", "/history/", "/agent/", "/cmd/"):
        assert rota in despacho, rota
    # Uma chamada de validacao por rota que extrai identificador.
    assert despacho.count("id_valido(") >= 5, (
        "alguma rota que recebe identificador deixou de validar")


def test_a_recusa_nao_ecoa_o_valor_recebido(codigo):
    """
    Repetir na resposta uma entrada que ja se sabe hostil e como nasce um XSS
    refletido. A recusa responde texto fixo e registra so o TAMANHO.
    """
    bloco = codigo[codigo.index("def _recusa_id"):codigo.index("def _authorized")]
    assert 'b"Invalid identifier."' in bloco
    assert "len(str(valor" in bloco


def test_a_validacao_nao_depende_do_numero_de_segmentos_da_url(codigo):
    """
    Achado medindo contra o servidor no ar (2026-08-20). Com a guarda DENTRO do
    teste de aridade, um valor contendo barra
    (`/priority/<script>x</script>/5`) virava quatro segmentos e escapava da
    validacao inteira. Nao era exploravel, porque nada e usado quando a aridade
    nao bate; o problema e que a protecao passava a depender do FORMATO da URL,
    e o proximo ramo acrescentado ali nasceria sem validacao nenhuma.
    """
    inicio = codigo.index("elif self.path.startswith('/priority/'):")
    # A busca do FIM comeca depois do inicio: o proprio bloco comeca com
    # "elif self.path.startswith", entao procurar do zero devolveria posicao 0
    # e o recorte sairia vazio.
    fim = codigo.index("elif self.path.startswith", inicio + 10)
    bloco = codigo[inicio:fim]
    pos_validacao = bloco.index("id_valido(")
    pos_aridade = bloco.index("len(partes) == 3")
    assert pos_validacao < pos_aridade, (
        "a validacao voltou para dentro do teste de aridade")


def test_travessia_no_caminho_vira_chave_de_consulta_e_nao_arquivo(codigo):
    """
    Documenta por que `/agent/../../etc/passwd` responde 404 e nao 400, para
    ninguem "corrigir" isso achando que e furo.

    A rota usa apenas o ULTIMO segmento (`split('/')[-1]`), entao aquele
    caminho vira o identificador "passwd", que e uma chave de consulta ao banco
    e nunca um caminho de arquivo. A travessia nao alcanca o sistema de
    arquivos porque nao ha leitura de arquivo nenhuma nesse fluxo.
    """
    assert "caminho.split('/')[-1]" in codigo
    assert "id_valido(agent_uuid)" in codigo


# ------------------------------------------------------------------------------
# AUTENTICACAO DO PAINEL (C-139)
# ------------------------------------------------------------------------------
def test_a_guarda_de_auth_fica_antes_do_roteamento(codigo):
    """
    A guarda no inicio do do_GET, e nao em cada rota, faz uma rota NOVA nascer
    protegida por omissao. Rota nova que nasce aberta ate alguem lembrar de
    proteger e como esta classe de furo aparece.
    """
    despacho = codigo[codigo.index("def do_GET(self):"):]
    antes_do_roteamento = despacho[:despacho.index("if self.path == '/':")]
    assert "_painel_autorizado" in antes_do_roteamento
    assert "_pede_credencial" in antes_do_roteamento


def test_auth_ligada_sem_hash_falha_fechada(codigo):
    """
    O operador PEDIU protecao. Seguir aberto porque falta o hash o deixaria
    acreditando estar protegido -- pior que recusar.
    """
    bloco = codigo[codigo.index("def _painel_autorizado"):
                   codigo.index("def _pede_credencial")]
    assert "if not controller.auth_hash:" in bloco
    assert "return False" in bloco


def test_o_desafio_declara_basic(codigo):
    bloco = codigo[codigo.index("def _pede_credencial"):
                   codigo.index("def _recusa_id")]
    assert "WWW-Authenticate" in bloco
    assert "Basic realm=" in bloco
    assert "self.send_response(401)" in bloco


def test_o_nome_de_usuario_e_comparado_em_tempo_constante(codigo):
    """
    Acrescimo em relacao ao original. A senha ja era conferida por
    check_password_hash, que e constante no tempo; o NOME ficava num "==",
    que retorna mais cedo no primeiro caractere diferente e por isso vaza,
    pelo tempo de resposta, quantos caracteres iniciais batem.
    """
    bloco = codigo[codigo.index("def _painel_autorizado"):
                   codigo.index("def _pede_credencial")]
    assert "hmac.compare_digest" in bloco
    assert "auth.username ==" not in bloco


def test_sem_werkzeug_o_painel_recusa_em_vez_de_abrir(codigo):
    """
    Dependencia ausente nao pode virar porta aberta. Sem a biblioteca nao ha
    como conferir a senha, e a unica resposta honesta e recusar.
    """
    bloco = codigo[codigo.index("def _painel_autorizado"):
                   codigo.index("def _pede_credencial")]
    assert "except ImportError:" in bloco
    trecho = bloco[bloco.index("except ImportError:"):]
    assert "return False" in trecho


def test_painel_sem_auth_avisa_no_log(codigo):
    """
    Painel aberto continua sendo possivel (era o comportamento anterior), mas
    nao pode ser silencioso: quem alcanca a porta le a coleta inteira da frota.
    """
    assert "[AUTH] Painel SEM autenticacao" in codigo


# ------------------------------------------------------------------------------
# INGESTAO: OUTRA CONVERSA, OUTRO SEGREDO
# ------------------------------------------------------------------------------
def test_a_ingestao_continua_usando_o_token_do_agente(codigo):
    """
    Basic Auth protege o acesso HUMANO. O agente nao tem usuario e senha, ele
    tem o token de ingestao: se a guarda do painel valesse para as rotas de
    ingestao, todos os agentes parariam de entregar.
    """
    bloco = codigo[codigo.index("def do_POST(self):"):]
    assert "self._authorized(controller)" in bloco
    assert "_painel_autorizado" not in bloco


def test_a_rota_legada_de_upload_tambem_exige_token(codigo):
    """
    Achado ao migrar as protecoes: `/upload` (legada da v0.60) era a UNICA rota
    de ingestao sem conferencia de token. Quem alcancasse a porta podia injetar
    uma captura na base da frota, ou seja, PLANTAR evidencia -- numa ferramenta
    forense isso e pior do que ler sem autorizacao.
    """
    bloco = codigo[codigo.index("if self.path == '/upload':"):]
    trecho = bloco[:600]
    assert "self._authorized(controller)" in trecho
    assert "unauthorized" in trecho
