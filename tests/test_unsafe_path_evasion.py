# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_unsafe_path_evasion.py
# DESCRIPTION: Deteccao de execucao a partir de diretorio inseguro, inclusive
#              quando o payload roda por um interpretador.
#
#              Regressao real, vista no teste distribuido: oito processos
#              "/bin/bash /dev/shm/miner.sh" rodavam ao mesmo tempo e apenas um
#              foi marcado como UNSAFE. As verificacoes olhavam o inicio da
#              linha de comando ou /proc/PID/exe, e nos dois casos o que aparece
#              e o interpretador (/bin/bash), nao o payload em /dev/shm. Chamar
#              o codigo por um interpretador e a evasao mais simples que existe.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

from src.collectors.process_tree import unsafe_path_in_cmdline


def test_detects_payload_run_by_an_interpreter():
    """O caso que escapava: o payload esta num argumento, nao no executavel."""
    assert unsafe_path_in_cmdline("/bin/bash /dev/shm/miner.sh") == "/dev/shm/miner.sh"
    assert unsafe_path_in_cmdline("python3 /tmp/implant.py") == "/tmp/implant.py"
    assert unsafe_path_in_cmdline("/usr/bin/perl /var/tmp/x.pl") == "/var/tmp/x.pl"


def test_detects_direct_execution():
    """O caso simples continua detectado."""
    assert unsafe_path_in_cmdline("/tmp/evil.sh --daemon") == "/tmp/evil.sh"


def test_detects_payload_in_a_later_argument():
    """O caminho pode estar em qualquer posicao da linha."""
    assert unsafe_path_in_cmdline("bash -c -x /dev/shm/p.sh") == "/dev/shm/p.sh"


def test_ignores_legitimate_command_lines():
    """Comandos normais de sistema nao viram alerta."""
    for cmd in ("/usr/lib/systemd/systemd --switched-root --system",
                "/usr/sbin/sshd -D", "/usr/bin/python3 /usr/bin/app.py",
                "nginx: worker process"):
        assert unsafe_path_in_cmdline(cmd) is None, cmd


def test_does_not_match_similar_directory_names():
    """"/tmpfs" ou "/var/tmpdata" nao sao os diretorios inseguros."""
    assert unsafe_path_in_cmdline("/opt/tmpdata/app") is None
    assert unsafe_path_in_cmdline("/tmpfs/x") is None


def test_handles_quotes_and_missing_input():
    """Argumento entre aspas e entrada vazia nao quebram a deteccao."""
    assert unsafe_path_in_cmdline('bash "/tmp/x.sh"') == "/tmp/x.sh"
    assert unsafe_path_in_cmdline("") is None
    assert unsafe_path_in_cmdline(None) is None
