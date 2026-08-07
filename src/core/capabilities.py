# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/core/capabilities.py
# DESCRIPTION: O que ESTE host consegue medir, e o que consegue exercitar.
#
# WHY:         Sem esta resposta, "o agente X nao acusou o cenario Y" e ambiguo
#              entre duas coisas opostas: a deteccao falhou, ou o host nunca
#              teve como gerar aquele cenario. As duas produzem exatamente o
#              mesmo resultado visivel, que e a ausencia, e foi essa ambiguidade
#              que consumiu um diagnostico inteiro no laboratorio antes de se
#              descobrir que uma das maquinas simplesmente nao tinha compilador.
#
# TWO SIDES:   Capacidade de DETECTAR (o que a ferramenta enxerga aqui: sondas
#              carregadas, versao do kernel, BTF, cgroup) e capacidade de GERAR
#              (o que o cenario de teste consegue produzir aqui: compilador,
#              runtime de conteiner, controle de trafego, firewall).
#
#              As duas importam por motivos diferentes. A primeira diz quanto
#              vale um laudo produzido neste host; a segunda diz o que a
#              afericao pode cobrar dele.
#
# HONESTY:     Um laudo que nao declara o que NAO foi olhado induz a conclusao
#              errada, porque silencio se le como ausencia de achado. Por isso
#              esta informacao viaja em claro junto da identidade do host: e
#              metadado operacional, e o analista precisa dela antes de concluir
#              qualquer coisa.
#
# NOTES:       Somente leitura, sem alterar estado. Compativel com Python 3.6.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import logging
import subprocess

LOG = logging.getLogger("Capabilities")

# Ferramentas que o cenario de teste usa. A ausencia de qualquer uma delas faz
# um modulo inteiro ser pulado, e o servidor precisa saber disso para nao cobrar
# do host algo que ele nunca teve como produzir.
FERRAMENTAS_DE_CENARIO = ("gcc", "podman", "docker", "tc", "iptables",
                          "chattr", "sudo", "python3")

# Caminho que o kernel expoe quando traz o proprio BTF. E o que distingue um
# host onde o motor CO-RE pode rodar de outro onde so o BCC funciona.
BTF_PATH = "/sys/kernel/btf/vmlinux"

TIMEOUT = 5


def _tem(comando):
    """Se o comando existe e pode ser executado neste host."""
    try:
        subprocess.check_output(["sh", "-c", "command -v %s" % comando],
                                stderr=subprocess.DEVNULL, timeout=TIMEOUT)
        return True
    except Exception:
        return False


def generation_capabilities():
    """
    O que o cenario de teste consegue exercitar aqui.

    Um host sem compilador nao produz o modulo de biblioteca insegura nem o
    falso agente de seguranca; sem runtime de conteiner nao produz o modulo de
    conteiner. Nos dois casos a ausencia do artefato e legitima e NAO deve
    contar como falha de deteccao.
    """
    return dict((nome, _tem(nome)) for nome in FERRAMENTAS_DE_CENARIO)


def detection_capabilities():
    """
    O que a ferramenta consegue enxergar aqui.

    Determina quanto vale um laudo produzido neste host: sem eBPF disponivel, a
    captura se reduz ao que /proc mostra, e isso precisa estar dito e nao
    suposto.
    """
    caps = {"ebpf": False, "btf": os.path.exists(BTF_PATH),
            "kernel": "", "cgroup_v2": False, "root": os.geteuid() == 0}

    try:
        caps["kernel"] = os.uname().release
    except Exception:
        pass

    # A presenca do modulo bcc e o que separa um agente capaz de instrumentar o
    # kernel de um que so consegue ler /proc.
    try:
        import bcc            # noqa: F401
        caps["ebpf"] = True
    except Exception:
        caps["ebpf"] = False

    # cgroup v2 muda como se identifica conteiner e limite de recurso.
    try:
        with open("/proc/mounts", "r") as fh:
            caps["cgroup_v2"] = any(l.split()[2] == "cgroup2"
                                    for l in fh if len(l.split()) > 2)
    except Exception:
        pass

    # Sem privilegio nao ha como carregar sonda nem ler o que interessa; um
    # agente sem root produz laudo incompleto sem qualquer erro aparente, que e
    # o modo de falha que este projeto mais evita.
    return caps


def describe_host():
    """
    Retrato completo, para viajar no check-in.

    Estruturado em dois blocos porque respondem a perguntas diferentes, e
    junta-los faria perder a distincao entre "nao vi" e "nao havia como ver".
    """
    return {"detect": detection_capabilities(),
            "generate": generation_capabilities()}


def missing_for_scenarios(capacidades):
    """
    Ferramentas ausentes que limitam o cenario de teste neste host.

    Serve a interface: em vez de o analista deduzir por que um agente acusa
    menos que outro, a tela diz o que falta e o que isso impede.
    """
    gerar = (capacidades or {}).get("generate") or {}
    return sorted(nome for nome, presente in gerar.items() if not presente)


def summarize(capacidades):
    """Frase curta para a linha do agente na frota."""
    if not capacidades:
        return "capacidades desconhecidas (agente antigo)"

    detectar = capacidades.get("detect") or {}
    partes = []
    partes.append("eBPF" if detectar.get("ebpf") else "SEM eBPF")
    if detectar.get("btf"):
        partes.append("BTF")
    if not detectar.get("root", True):
        partes.append("SEM root")

    faltando = missing_for_scenarios(capacidades)
    if faltando:
        partes.append("cenario limitado: falta %s" % ", ".join(faltando))
    return " | ".join(partes)
