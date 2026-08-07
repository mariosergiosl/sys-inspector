# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_packaging.py
# DESCRIPTION: Cada papel instala apenas o que o papel usa.
#
#              Medido em campo: instalar o agente no gateway trouxe doze pacotes
#              de servidor web (Flask, Jinja2, Werkzeug, Babel e cadeia) para um
#              host sob inspecao que jamais os usaria, enquanto o servidor era
#              obrigado a instalar bcc e cabecalhos de kernel que nunca carregou.
#
#              O custo real nao e disco: e superficie de ataque acrescentada
#              onde nao ha funcao que a justifique, justamente pela ferramenta
#              que existe para reduzi-la.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os
import re

import pytest

SPEC = "sys-inspector.spec"
SETUP = "setup.py"


@pytest.fixture(scope="module")
def spec():
    return io.open(SPEC, encoding="utf-8").read()


def _bloco_do_pacote(spec, nome):
    """Trecho do .spec entre a declaracao de um subpacote e a seguinte."""
    # Concatenacao, nao formatacao: "%package" comeca com %p, e o operador %
    # do Python tentaria interpreta-lo como especificador de formato.
    inicio = spec.index("%package " + nome)
    resto = spec[inicio + 1:]
    fim = resto.find("%package")
    if fim == -1:
        fim = resto.find("%prep")
    return resto[:fim]


# ------------------------------------------------------------------------------
# A DIVISAO
# ------------------------------------------------------------------------------
def test_the_three_roles_exist(spec):
    for papel in ("agent", "server", "scenarios"):
        assert "%%package %s" % papel in spec


def test_the_inspected_host_gets_no_web_server(spec):
    """
    O agente roda na maquina sob investigacao. Um servidor web ali e superficie
    de ataque sem funcao, acrescentada pela propria ferramenta de seguranca.
    """
    bloco = _bloco_do_pacote(spec, "agent")
    assert "Flask" not in bloco


def test_the_server_needs_no_kernel_probes(spec):
    """
    O modo servidor roda sem bcc, e isso ja foi validado em campo: um dos hosts
    do laboratorio operou como servidor por dias sem o modulo instalado.
    """
    bloco = _bloco_do_pacote(spec, "server")
    assert "bcc" not in bloco
    assert "kernel-devel" not in bloco


def test_the_agent_gets_what_collection_requires(spec):
    bloco = _bloco_do_pacote(spec, "agent")
    assert "python3-bcc" in bloco
    assert "kernel-devel" in bloco


def test_the_base_carries_only_what_every_role_needs(spec):
    """
    Criptografia e leitura de configuracao servem aos tres papeis; web e sondas
    de kernel, nao.
    """
    base = spec.split("%package")[0]
    assert "python3-cryptography" in base
    assert "python3-PyYAML" in base
    assert "python3-Flask" not in base
    assert "python3-bcc" not in base


def test_every_subpackage_depends_on_the_base(spec):
    """Sem isso as versoes poderiam divergir entre os pacotes instalados."""
    for papel in ("agent", "server", "scenarios"):
        bloco = _bloco_do_pacote(spec, papel)
        assert "Requires:       %{name} = %{version}-%{release}" in bloco


# ------------------------------------------------------------------------------
# O CENARIO DE TESTE
# ------------------------------------------------------------------------------
def test_the_scenarios_are_a_separate_package(spec):
    """
    Gerar comportamento de ataque nao pode vir junto com a coleta: um host em
    servico nao deve sequer ter o gerador instalado.
    """
    bloco = _bloco_do_pacote(spec, "scenarios")
    assert "chaos_maker.sh" in spec.split("%files scenarios")[1]
    assert "LABORATORY USE ONLY" in bloco


def test_the_scenario_package_states_what_it_is_not(spec):
    """
    A descricao precisa deixar claro que isto e ferramenta de VERIFICACAO, nao
    de ataque: age so no host local, sem varredura de rede, sem exploracao
    remota e sem exploit funcional. Quem le a lista de pacotes de um servidor
    precisa entender isso sem abrir a documentacao.
    """
    bloco = _bloco_do_pacote(spec, "scenarios")
    assert "no network scanning" in bloco
    assert "no remote exploitation" in bloco
    assert "no functional exploit code" in bloco


def test_the_scenario_package_promises_cleanup(spec):
    bloco = _bloco_do_pacote(spec, "scenarios")
    assert "removed afterwards" in bloco


# ------------------------------------------------------------------------------
# UMA UNICA VERSAO
# ------------------------------------------------------------------------------
def test_the_version_has_a_single_source():
    """
    A versao estava repetida no setup.py, no .spec e em cada cabecalho, e ja
    tinha divergido em cinco valores ao mesmo tempo. Num laudo forense a versao
    identifica o codigo que produziu a analise: errada, compromete a reproducao.
    """
    conteudo = io.open(os.path.join("src", "version.py"), encoding="utf-8").read()
    assert "__version__" in conteudo

    setup = io.open(SETUP, encoding="utf-8").read()
    assert "_version['__version__']" in setup
    assert not re.search(r"version\s*=\s*['\"]\d+\.\d+", setup)


def test_the_spec_matches_the_single_source(spec):
    versao = {}
    exec(io.open(os.path.join("src", "version.py"), encoding="utf-8").read(),
         versao)
    assert "Version:        %s" % versao["__version__"] in spec


def test_the_version_module_imports_nothing():
    """
    E lido pelo setup.py durante o empacotamento, quando as dependencias ainda
    nao existem. Um import aqui quebraria a construcao do pacote.
    """
    conteudo = io.open(os.path.join("src", "version.py"), encoding="utf-8").read()
    for linha in conteudo.split("\n"):
        assert not linha.startswith("import ")
        assert not linha.startswith("from ")


# ------------------------------------------------------------------------------
# PYPI SEGUE A MESMA DIVISAO
# ------------------------------------------------------------------------------
def test_pypi_offers_the_same_roles():
    setup = io.open(SETUP, encoding="utf-8").read()
    assert "extras_require" in setup
    assert "'server': ['flask']" in setup


def test_pypi_core_does_not_pull_the_web_server():
    setup = io.open(SETUP, encoding="utf-8").read()
    bloco = setup.split("install_requires=[")[1].split("]")[0]
    assert "flask" not in bloco.lower()
