# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_referral.py
# DESCRIPTION: Guarda o encaminhamento a bancada (C-044, D-028/D-032).
#
# WHY:         Este campo e a contrapartida de uma decisao de escopo. A D-032
#              fixou que a ferramenta coleta o suficiente para IDENTIFICAR e
#              DIRECIONAR, e nao a massa que PROVA. Isso e defensavel, mas so e
#              honesto com a outra metade: dizer quem termina o servico.
#
#              Sem esse campo, "a ferramenta nao conclui isso" vira omissao. Com
#              ele, vira direcao. A diferenca aparece para quem le o laudo e
#              precisa decidir o proximo passo.
#
#              Os testes cobram tres coisas, e as tres ja falharam em produtos
#              parecidos: que o encaminhamento seja completo (analise + motivo +
#              objeto, os tres ou nenhum), que ele apareca NA TELA e nao so em
#              tooltip, e que a ausencia dele continue significando "nao precisa
#              de bancada" em vez de "esqueceram de preencher".
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import re

from src.core.findings import (Finding, make_referral, has_referral,
                               REFERRAL_CAMPOS, SEV_HIGH, SRC_HEURISTIC)
from src.exporters.html_report import render_findings_panel


def _achado(**kwargs):
    base = dict(title="achado de teste", severity=SEV_HIGH, source=SRC_HEURISTIC,
                target="pid:1234", description="descricao")
    base.update(kwargs)
    return Finding(**base)


# ------------------------------------------------------------------------------
# O MODELO: OS TRES CAMPOS, OU NENHUM
# ------------------------------------------------------------------------------
def test_encaminhamento_completo_e_aceito():
    r = make_referral("desmontagem da regiao", "W+X sem JIT que explique",
                      "pid:1234 regiao 7f00-7f01")
    assert has_referral(r)
    assert set(r) == set(REFERRAL_CAMPOS)


def test_encaminhamento_pela_metade_e_recusado():
    """
    Dizer a analise sem dizer o objeto nao encaminha nada: vira recomendacao
    generica, que e o que o campo `recommendation` ja fazia. O valor do
    encaminhamento esta em entregar um OBJETO para a proxima ferramenta.
    """
    assert make_referral("desmontagem", "porque sim", "") == {}
    assert make_referral("", "porque sim", "pid:1") == {}
    assert make_referral("desmontagem", "", "pid:1") == {}
    assert not has_referral({"analysis": "x"})
    assert not has_referral(None)


def test_achado_sem_encaminhamento_tem_campo_vazio_e_nao_none():
    """
    Campo sempre presente na serializacao, mesmo vazio (D-020). Um campo que
    aparece so as vezes faz a tela precisar adivinhar se ele nao existe ou se
    nao foi preenchido.
    """
    d = _achado().to_dict()
    assert "referral" in d
    assert d["referral"] == {}


def test_encaminhamento_viaja_na_serializacao():
    r = make_referral("analise A", "motivo B", "objeto C")
    d = _achado(referral=r).to_dict()
    assert d["referral"]["analysis"] == "analise A"
    assert d["referral"]["object"] == "objeto C"


# ------------------------------------------------------------------------------
# A TELA: DITO, NAO ESCONDIDO
# ------------------------------------------------------------------------------
def test_o_encaminhamento_aparece_como_texto_e_nao_so_em_tooltip():
    """
    D-028 pede todo encaminhamento DITO. Texto que so aparece com o mouse em
    cima nao esta dito: numa lista de dezenas de achados ninguem passa o mouse
    em cada um para descobrir se havia direcionamento ali.

    O teste confere que o conteudo esta FORA de qualquer atributo title.
    """
    r = make_referral("dump e desmontagem da regiao",
                      "a ferramenta ve a permissao, nao o conteudo",
                      "pid:1234 regiao 7f2a-7f2b")
    html = render_findings_panel([_achado(referral=r).to_dict()])

    # Remove TODO conteudo de atributo title="..." e cobra o texto no que
    # sobra. E a unica forma de distinguir "esta na tela" de "esta
    # escondido no hover".
    sem_tooltips = re.sub(r'title="[^"]*"', "", html)
    for valor in r.values():
        assert valor in html, valor
        assert valor in sem_tooltips, (
            "'%s' so aparece dentro de um title=: isso e tooltip, nao e dito"
            % valor)


def test_as_tres_perguntas_aparecem_rotuladas_na_tela():
    """
    Nao basta despejar os tres textos: o leitor precisa saber qual e a analise,
    qual e o motivo e qual e o objeto. Sem rotulo, os tres viram um paragrafo.
    """
    r = make_referral("analise X", "motivo Y", "objeto Z")
    html = render_findings_panel([_achado(referral=r).to_dict()])
    assert "Analise necessaria" in html
    assert "Por que este achado a motiva" in html
    assert "Objeto" in html


def test_achado_que_se_conclui_sozinho_nao_desenha_o_bloco():
    """
    Ausencia e resposta: quando a frota conclui, nao ha bancada a acionar, e um
    bloco vazio so faria ruido. O que nao pode e o bloco sumir por defeito
    quando o encaminhamento EXISTE -- por isso o teste anterior.
    """
    html = render_findings_panel([_achado().to_dict()])
    assert "Encaminhamento a bancada" not in html


def test_o_objeto_do_encaminhamento_e_escapado():
    """
    O objeto carrega caminho de arquivo vindo do host inspecionado, que e dado
    nao confiavel por definicao numa ferramenta forense.
    """
    r = make_referral("a", "b", '<script>alert(1)</script>')
    html = render_findings_panel([_achado(referral=r).to_dict()])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
