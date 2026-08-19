# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_acquisition.py
# DESCRIPTION: Guarda a aquisicao dirigida (C-043) e a fronteira da D-032.
#
# WHY:         Este modulo e o unico do projeto que ESCREVE no host inspecionado.
#              Duas coisas precisam ser inviolaveis, e cada uma protege contra um
#              acidente diferente:
#
#              1. Desligada por padrao. Um agente ja implantado nao pode comecar a
#                 gravar no host medido so porque a ferramenta foi atualizada.
#              2. Os tetos valem sempre. A D-032 diz que se coleta o suficiente
#                 para IDENTIFICAR e DIRECIONAR, nunca a massa. Um teto que
#                 escapa transforma o agente em coletor de massa, que e
#                 exatamente o que a decisao proibe.
#
#              E a terceira, que e de honestidade e nao de recurso: todo teto
#              atingido tem que aparecer no resultado. Recorte truncado em
#              silencio e lido como artefato inteiro, e um sha256 do recorte
#              exibido como se fosse do objeto identifica a coisa errada.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import hashlib
import io
import os

import pytest

from src.core.acquisition import (Acquirer, PADRAO, NAO_LIGADA, SEM_ORCAMENTO,
                                  ILEGIVEL)
from src.core.findings import CUSTODY_NONE, CUSTODY_HASH, CUSTODY_FULL


def _cfg(**kwargs):
    """Configuracao com aquisicao LIGADA e os tetos que o teste quiser."""
    valores = {"enabled": True}
    valores.update(kwargs)
    return {"forensics": {"acquisition": valores}}


def _arquivo(tmpdir, nome, conteudo):
    caminho = os.path.join(str(tmpdir), nome)
    with io.open(caminho, "wb") as fh:
        fh.write(conteudo)
    return caminho


# ------------------------------------------------------------------------------
# A TRAVA PRINCIPAL: DESLIGADA POR PADRAO
# ------------------------------------------------------------------------------
def test_desligada_por_padrao_sem_nenhuma_configuracao():
    """
    Sem configuracao nenhuma, nada e adquirido. Este teste existe para que
    ninguem inverta o padrao "por conveniencia": ligar a aquisicao faz o agente
    escrever no host que ele mede, e essa e uma decisao de quem opera.
    """
    assert PADRAO["enabled"] is False
    assert Acquirer(None).enabled is False
    assert Acquirer({}).enabled is False


def test_desligada_devolve_o_motivo_em_vez_de_ficar_calada(tmpdir):
    """
    D-020: "nao foi coletado" e uma resposta diferente de "nada havia", e o laudo
    precisa poder dizer qual das duas e. Devolver None faria as duas virarem a
    mesma coisa na tela.
    """
    alvo = _arquivo(tmpdir, "amostra.bin", b"conteudo")
    resultado = Acquirer({}).acquire_file(alvo)
    assert resultado["acquired"] is False
    assert resultado["reason"] == NAO_LIGADA
    assert resultado["level"] == CUSTODY_NONE


# ------------------------------------------------------------------------------
# O QUE SE PRESERVA: HASH DO INTEIRO, METADADO, RECORTE
# ------------------------------------------------------------------------------
def test_hash_cobre_o_objeto_inteiro_mesmo_com_recorte_pequeno(tmpdir):
    """
    O ponto central da D-032. O recorte e pequeno de proposito, mas o HASH e do
    objeto inteiro: e ele que identifica a amostra depois, quando o arquivo ja
    nao existir no host. Um hash so do recorte identificaria o recorte.
    """
    conteudo = b"\x7fELF" + os.urandom(50000)
    alvo = _arquivo(tmpdir, "grande.bin", conteudo)
    a = Acquirer(_cfg(dir=os.path.join(str(tmpdir), "acq"), excerpt_bytes=128))

    r = a.acquire_file(alvo)
    assert r["sha256"] == hashlib.sha256(conteudo).hexdigest()
    assert r["hash_scope"] == "full"
    assert r["excerpt_bytes"] == 128
    assert r["truncated"] is True
    assert r["size"] == len(conteudo)


def test_objeto_grande_demais_tem_hash_do_recorte_e_diz_isso(tmpdir):
    """
    Acima do teto de hash a leitura para, porque varrer um objeto enorme no host
    medido custa I/O que ninguem pediu. O que NAO pode acontecer e o resultado
    parecer igual ao caso anterior: o escopo muda, e o laudo mostra a diferenca.
    """
    conteudo = os.urandom(20000)
    alvo = _arquivo(tmpdir, "enorme.bin", conteudo)
    a = Acquirer(_cfg(dir=os.path.join(str(tmpdir), "acq"),
                      hash_max_bytes=1000, excerpt_bytes=256))

    r = a.acquire_file(alvo)
    assert r["hash_scope"] == "excerpt"
    assert r["sha256"] != hashlib.sha256(conteudo).hexdigest()
    assert r["truncated"] is True


def test_metadados_do_arquivo_acompanham_a_aquisicao(tmpdir):
    alvo = _arquivo(tmpdir, "meta.bin", b"x" * 100)
    a = Acquirer(_cfg(dir=os.path.join(str(tmpdir), "acq")))
    r = a.acquire_file(alvo)
    for campo in ("mtime", "ctime", "uid", "mode", "acquired_at"):
        assert campo in r, campo


# ------------------------------------------------------------------------------
# COPIA INTEGRAL: SO PARA ARTEFATO PEQUENO
# ------------------------------------------------------------------------------
def test_artefato_pequeno_vira_copia_integral(tmpdir):
    """
    O caso CUSTODY_FULL da D-032: cabe inteiro no teto, entao o perito recebe a
    amostra e nao precisa voltar a um host que pode ja nao existir.
    """
    alvo = _arquivo(tmpdir, "pequeno.bin", b"amostra pequena")
    destino = os.path.join(str(tmpdir), "acq")
    a = Acquirer(_cfg(dir=destino, copy_max_bytes=1024))

    r = a.acquire_file(alvo)
    assert r["level"] == CUSTODY_FULL
    assert os.path.exists(r["copy_path"])
    with io.open(r["copy_path"], "rb") as fh:
        assert fh.read() == b"amostra pequena"


def test_artefato_grande_nao_e_copiado_e_para_no_hash(tmpdir):
    """A fronteira em uma linha: acima do teto, identifica-se sem transportar."""
    alvo = _arquivo(tmpdir, "grande.bin", b"y" * 5000)
    a = Acquirer(_cfg(dir=os.path.join(str(tmpdir), "acq"), copy_max_bytes=100))

    r = a.acquire_file(alvo)
    assert r["level"] == CUSTODY_HASH
    assert "copy_path" not in r


def test_o_nome_da_copia_carrega_o_hash(tmpdir):
    """
    Dois arquivos de mesmo nome vindos de hosts ou caminhos diferentes nao podem
    se sobrescrever no diretorio de aquisicao. O prefixo de hash resolve isso e,
    de quebra, torna o nome do arquivo verificavel.
    """
    alvo = _arquivo(tmpdir, "igual.bin", b"conteudo A")
    a = Acquirer(_cfg(dir=os.path.join(str(tmpdir), "acq")))
    r = a.acquire_file(alvo)
    assert os.path.basename(r["copy_path"]).startswith(r["sha256"][:16])


# ------------------------------------------------------------------------------
# ORCAMENTO DA CAPTURA
# ------------------------------------------------------------------------------
def test_orcamento_da_captura_e_respeitado(tmpdir):
    """
    Sem teto por captura, um host com 200 achados adquire 200 vezes o teto
    individual e o teto individual deixa de significar qualquer coisa.
    """
    a = Acquirer(_cfg(dir=os.path.join(str(tmpdir), "acq"),
                      excerpt_bytes=1024, capture_max_bytes=2048,
                      copy_max_bytes=0))
    alvos = [_arquivo(tmpdir, "a%d.bin" % i, b"z" * 4000) for i in range(5)]

    resultados = [a.acquire_file(c) for c in alvos]
    adquiridos = [r for r in resultados if r.get("acquired")]
    recusados = [r for r in resultados if not r.get("acquired")]

    assert adquiridos, "o orcamento nao pode zerar antes da primeira aquisicao"
    assert recusados, "o orcamento tem que parar em algum ponto"
    assert all(r["reason"] == SEM_ORCAMENTO for r in recusados)


def test_o_orcamento_e_por_captura_e_nao_perpetuo(tmpdir):
    """
    Um Acquirer por captura. Se o objeto fosse de vida longa, o gasto se
    acumularia entre capturas e a aquisicao se desligaria sozinha depois de
    algumas horas, sem avisar -- que e a falha do agente que emudece (D-015).
    """
    cfg = _cfg(dir=os.path.join(str(tmpdir), "acq"), excerpt_bytes=1024,
               capture_max_bytes=1024, copy_max_bytes=0)
    alvo = _arquivo(tmpdir, "a.bin", b"z" * 4000)

    primeiro = Acquirer(cfg)
    primeiro.acquire_file(alvo)
    assert primeiro.acquire_file(alvo)["acquired"] is False

    # Captura seguinte: instancia nova, orcamento cheio de novo.
    assert Acquirer(cfg).acquire_file(alvo)["acquired"] is True


# ------------------------------------------------------------------------------
# O QUE NAO DA PARA LER
# ------------------------------------------------------------------------------
def test_arquivo_inexistente_diz_que_nao_conseguiu_ler(tmpdir):
    """
    Um arquivo que sumiu entre a deteccao e a aquisicao e o caso NORMAL numa
    ferramenta forense: o atacante apaga. Isso nao pode virar excecao subindo
    para o laco de coleta, nem sumir sem explicacao no laudo.
    """
    a = Acquirer(_cfg(dir=os.path.join(str(tmpdir), "acq")))
    r = a.acquire_file(os.path.join(str(tmpdir), "nunca-existiu.bin"))
    assert r["acquired"] is False
    assert r["reason"] == ILEGIVEL
    assert "error" in r


def test_regiao_de_memoria_invalida_nao_explode(tmpdir):
    a = Acquirer(_cfg(dir=os.path.join(str(tmpdir), "acq")))
    assert a.acquire_memory_region(1, "zzz", "www")["acquired"] is False
    assert a.acquire_memory_region(1, "1000", "1000")["acquired"] is False


@pytest.mark.skipif(not os.path.exists("/proc/self/mem"),
                    reason="exige /proc (Linux)")
def test_regiao_de_memoria_do_proprio_processo_e_lida():
    """
    Prova em memoria de verdade, sem depender de um processo alvo: le uma regiao
    do proprio processo de teste. O que se afere e a mecanica (seek, leitura,
    hash, recorte, tetos), que e a mesma usada sobre a regiao W+X de um
    processo suspeito.
    """
    regiao = None
    with io.open("/proc/self/maps", "r") as fh:
        for linha in fh:
            partes = linha.split()
            if len(partes) >= 2 and partes[1].startswith("r"):
                regiao = partes[0]
                break
    assert regiao, "nenhuma regiao legivel encontrada"
    inicio, fim = regiao.split("-")

    # Teto de hash baixo de proposito: o teste afere a MECANICA, e a regiao
    # sorteada pode ser grande. Varrer megabytes aqui so deixaria a suite lenta.
    a = Acquirer(_cfg(dir="/tmp/sys-inspector-test-acq", excerpt_bytes=256,
                      hash_max_bytes=65536))
    r = a.acquire_memory_region(os.getpid(), inicio, fim)
    assert r["acquired"] is True
    assert r["excerpt_bytes"] > 0
    assert r["sha256"]
    assert r["region"] == regiao
