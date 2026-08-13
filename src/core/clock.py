# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/core/clock.py
# DESCRIPTION: Mede o desvio do relogio do host contra o tempo de referencia.
#
# WHY:         A linha do tempo ENTRE HOSTS e o artefato que responde a pergunta
#              central de uma pericia distribuida: o que aconteceu primeiro? Se
#              os relogios nao forem comparaveis, a ordenacao produz uma sequencia
#              plausivel e ERRADA, o que e pior que nao ter timeline, porque
#              parece resposta (D-019). Doze segundos de defasagem bastam para
#              inverter a relacao entre um shell reverso abrindo num host e uma
#              persistencia sendo plantada em outro.
#
#              O evento ja carrega um `clock_offset` e o `corrected_ts` ja o usa
#              (corrected = ts - offset). O que faltava era MEDIR: o agente
#              gravava 0.0 fixo, e 0.0 ASSUMIDO e chute, nao fato. Mesmo com NTP,
#              o desvio medido tem que viajar junto para a ordenacao ser
#              verificavel, e nao confiada.
#
# MEASURED:    A medicao distingue tres estados, no espirito do D-020: medido com
#              valor, medido e zero, e NAO medido (chrony ausente). Um 0.0 medido
#              afirma "os relogios batem"; um 0.0 nao medido nao afirma nada, e a
#              timeline precisa saber a diferenca para nao dar como comparavel o
#              que nunca foi conferido.
#
# SIGN:        offset > 0  => relogio do host ADIANTADO (fast) em relacao a
#              referencia; o carimbo esta alto, e corrected_ts subtrai o offset.
#              offset < 0  => relogio ATRASADO (slow).
#
# NOTES:       Compativel com Python 3.6. Sem dependencia externa; le a saida do
#              chronyc, que e o servico de tempo dos hosts do lab.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import re
import shutil
import logging
import subprocess

LOG = logging.getLogger("Clock")

# "System time     : 0.000049565 seconds fast of NTP time"
# "System time     : 0.012 seconds slow of NTP time"
_RE_SYSTIME = re.compile(
    r"System time\s*:\s*([0-9]+\.?[0-9]*)\s+seconds\s+(fast|slow)", re.I)


def _from_chrony():
    """
    Le o desvio que o chrony ja calcula contra a fonte de tempo.

    Devolve (offset_segundos, fonte) ou None se o chrony nao estiver presente ou
    a saida nao trouxer a linha esperada. 'fast' e desvio positivo (adiantado),
    'slow' e negativo (atrasado).
    """
    if not shutil.which("chronyc"):
        return None
    proc = None
    try:
        proc = subprocess.Popen(["chronyc", "tracking"],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL,
                                universal_newlines=True)
        out, _ = proc.communicate(timeout=3)
    except Exception:
        if proc:
            try: proc.kill()
            except Exception: pass
        return None

    m = _RE_SYSTIME.search(out or "")
    if not m:
        return None
    valor = float(m.group(1))
    if m.group(2).lower() == "slow":
        valor = -valor
    return (valor, "chrony")


def measure_offset():
    """
    Desvio conhecido do relogio deste host, para viajar junto da captura.

    Devolve um dict:
      offset:   segundos (float); positivo = adiantado.
      measured: True se foi realmente medido; False se assumido por falta de
                fonte (chrony ausente). Um 0.0 medido afirma sincronia; um 0.0
                NAO medido nao afirma nada.
      source:   de onde veio ("chrony" ou "unavailable").

    Nunca levanta: uma falha de medicao vira 'nao medido', e a captura segue.
    """
    try:
        via_chrony = _from_chrony()
    except Exception as exc:  # defesa extra; _from_chrony ja engole o esperado
        LOG.debug("Clock offset via chrony failed: %s", exc)
        via_chrony = None

    if via_chrony is not None:
        offset, source = via_chrony
        return {"offset": float(offset), "measured": True, "source": source}

    return {"offset": 0.0, "measured": False, "source": "unavailable"}
