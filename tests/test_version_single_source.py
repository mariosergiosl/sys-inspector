# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_version_single_source.py
# DESCRIPTION: Guarda a versao como FONTE UNICA (src/version.py, D-018).
#
#              A versao ja divergiu em varias telas: o modo Live mostrava
#              "0.90", o laudo do snapshot "0.90 (Snapshot)", o live "0.61.00" e
#              a custodia carimbava "0.91.0", tudo hardcoded, enquanto o produto
#              era 0.92.0. Cada um desses e a mesma classe de bug (copia
#              silenciosa). Este teste impede que voltem: quem mostra ou carimba
#              versao tem de ler __version__, nunca um literal.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import inspect

from src.version import __version__


def _src(path):
    return io.open(path, encoding="utf-8").read()


def test_single_source_matches_spec():
    """A versao do pacote e do spec RPM sai da mesma fonte."""
    setup = _src("setup.py")
    spec = _src("sys-inspector.spec")
    # setup.py le __version__ dinamicamente; o spec declara o mesmo numero.
    assert "_version['__version__']" in setup
    assert ("Version:        %s" % __version__) in spec


def test_live_web_ui_reads_version_from_source():
    """O modo Live nao pode hardcodar a versao (era '0.90 (Live)')."""
    s = _src("src/controllers/web_controller.py")
    assert "from src.version import __version__" in s
    assert '"0.90 (Live)"' not in s
    assert "__version__" in s


def test_live_report_reads_version_from_source():
    """O laudo do modo live nao pode ficar preso em '0.61.00'."""
    s = _src("src/controllers/live_controller.py")
    assert "from src.version import __version__" in s
    assert '"0.61.00"' not in s


def test_snapshot_report_reads_version_from_source():
    """O laudo do snapshot nao pode hardcodar '0.90 (Snapshot)'."""
    s = _src("src/controllers/snapshot_controller.py")
    assert "from src.version import __version__" in s
    assert '"0.90 (Snapshot)"' not in s


def test_custody_stamps_version_from_source():
    """A custodia carimba a versao real, nao um literal ('0.91.0')."""
    s = _src("src/core/custody.py")
    assert "from src.version import __version__" in s
    assert 'collector_version="0' not in s
    # o default da assinatura e None (resolvido para __version__ no corpo).
    from src.core.custody import build_for_capture
    sig = inspect.signature(build_for_capture)
    assert sig.parameters["collector_version"].default is None


def test_obs_service_pins_the_current_release_tag():
    """
    O _service versionado no repo fixa a tag da versao ATUAL (vX.Y.Z), nao uma
    antiga. Era a fonte de drift silencioso: ficou preso em v0.91.0 por releases
    seguidos porque nada o cobria, enquanto o produto ja era outro.
    """
    s = _src("_service")
    assert ('<param name="revision">v%s</param>' % __version__) in s, \
        "_service nao aponta para a tag v%s" % __version__


def test_shell_scripts_share_the_product_version():
    """Os scripts do lote de cenario/instalacao espelham a versao do produto."""
    for path in ("tools/chaos_maker.sh", "tools/agent_chaos.sh",
                 "tools/install_deps.sh", "tools/setup_env.sh"):
        s = _src(path)
        assert __version__ in s, path
        # nenhuma das versoes antigas conhecidas sobra num cabecalho.
        for velho in ("v0.90.15", "v0.70.07", 'VERSION="2.0"'):
            assert velho not in s, "%s ainda tem %s" % (path, velho)
