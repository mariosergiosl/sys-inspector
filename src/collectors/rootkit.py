# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/collectors/rootkit.py
# DESCRIPTION: Indicios de rootkit, do kernel e do espaco de usuario (C-037).
#
# WHY:         O detector de processo oculto que ja existe compara /proc com a
#              resposta do kernel a um sinal. Isso pega o rootkit que esconde
#              PROCESSO, e por desenho nao pega o que se esconde a si MESMO
#              dentro do kernel: quando o codigo hostil e um modulo, ele nao
#              aparece como processo em lugar nenhum.
#
# METHOD:      Nao ha aqui nenhuma tentativa de "detectar rootkit" por assinatura,
#              que e corrida perdida. O metodo e outro, e e o mesmo que este
#              projeto ja usa como principio: CRUZAR FONTES INDEPENDENTES DO
#              MESMO FATO e denunciar a divergencia. Um rootkit de kernel precisa
#              mentir para alguem; ele raramente mente para todos ao mesmo tempo,
#              e a mentira aparece como desacordo entre listas que deveriam
#              concordar.
#
# FIVE LAYERS: Nao sao cinco assinaturas, sao cinco perguntas independentes:
#              S1. Algum modulo foi carregado FORA do boot?
#              S2. Algum modulo carregado nao pertence a pacote nenhum?
#              S3. Ha sequestro por biblioteca no espaco de usuario
#                  (/etc/ld.so.preload)?
#              S4. O kernel esta TINGIDO por modulo fora da arvore ou nao
#                  assinado?
#              S5. As tres listas de modulos DIVERGEM entre si?
#
# THE LIMIT:   S5 e a unica camada que aponta um modulo ATIVAMENTE ESCONDIDO, e
#              e tambem a unica que nao se prova com artefato de espaco de
#              usuario: esconder um modulo da lista exige codigo rodando dentro
#              do kernel. Ver tools/rootkit_demo/ para o modulo didatico que o
#              cenario de teste usa, e a ressalva que ele carrega.
#
# FALSE POS:   Dito de frente, porque cada camada tem o seu:
#              - S1: modulo carregado por automontagem (usb, sistema de arquivo
#                    novo) e rotina, nao ataque. Por isso e LOW e traz o nome.
#              - S2: DKMS, VirtualBox, nvidia e drivers compilados no host nao
#                    pertencem a pacote e sao legitimos.
#              - S4: o bit "proprietary" sobe com qualquer driver fechado.
#              - S5-a: /proc/kallsyms anota trampolim de ftrace e programa eBPF
#                    com a MESMA notacao "[nome]" dos modulos. Sem filtrar, o
#                    proprio agente desta ferramenta faria o detector acusar
#                    rootkit em toda captura (medido em host real, 2026-08-19).
#              - S5-c: uma corrida entre carga e leitura pode produzir
#                    divergencia momentanea.
#
# TESTABLE:    Toda funcao recebe `raiz`, um prefixo de caminho. Em producao e
#              vazio (le /proc e /sys de verdade); no teste aponta para uma
#              arvore sintetica. E assim que o caminho POSITIVO de cada camada e
#              provado sem precisar de um rootkit real na maquina de quem roda os
#              testes (D-025, caminho sintetico).
#
# NOTES:       Compativel com Python 3.6. So leitura, nada e modificado.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import re
import time
import logging
import subprocess

from src.core.findings import (Finding, SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM,
                               SEV_LOW, SEV_INFO, SRC_HEURISTIC,
                               CONF_CONFIRMED, CONF_PROBABLE, CONF_HEURISTIC,
                               CUSTODY_NONE, CUSTODY_METADATA, make_referral)

LOG = logging.getLogger("Rootkit")

# Folga apos o instante de boot dentro da qual uma carga de modulo ainda conta
# como "do boot". A inicializacao de um host nao termina no segundo zero: udev,
# systemd e automontagem continuam carregando modulo por um bom tempo depois.
FOLGA_DE_BOOT_S = 300

# Bits de taint do kernel que interessam a esta analise, com o que cada um
# significa aqui. Referencia: Documentation/admin-guide/tainted-kernels.rst.
TAINT_BITS = {
    0: ("P", "modulo proprietario carregado", SEV_INFO,
        "Sobe com qualquer driver de codigo fechado (nvidia, VirtualBox). "
        "Sozinho nao e indicio de nada."),
    1: ("F", "modulo carregado a forca", SEV_HIGH,
        "Alguem usou insmod --force para carregar um modulo que o kernel "
        "recusaria. E o contorno explicito de uma verificacao de seguranca."),
    3: ("R", "modulo descarregado a forca", SEV_HIGH,
        "Descarga forcada de modulo. Fora de desenvolvimento de driver, e "
        "manobra de quem esta mexendo no kernel em execucao."),
    12: ("O", "modulo fora da arvore do kernel", SEV_MEDIUM,
         "Modulo que nao veio com o kernel da distribuicao. Legitimo em host "
         "com DKMS ou driver de terceiro; e tambem o estado que TODO rootkit "
         "de modulo deixa para tras."),
    13: ("E", "modulo NAO ASSINADO", SEV_HIGH,
         "Modulo sem assinatura valida entrou no kernel. Num host com Secure "
         "Boot isso nao deveria ser possivel; nos demais, e o rastro mais "
         "direto de codigo de kernel de procedencia desconhecida."),
}


def _ler(caminho):
    """Conteudo de um arquivo, ou None. Ausencia nao e erro nesta analise."""
    try:
        with open(caminho, "r") as fh:
            return fh.read()
    except (IOError, OSError):
        return None


# ------------------------------------------------------------------------------
# AS TRES FONTES DA MESMA LISTA
# ------------------------------------------------------------------------------
def modulos_em_proc(raiz=""):
    """
    Modulos segundo /proc/modules: a lista que lsmod mostra.

    E a PRIMEIRA lista que um rootkit de modulo apaga, porque e a que o
    administrador consulta.
    """
    texto = _ler(os.path.join(raiz, "proc/modules") if raiz else "/proc/modules")
    if not texto:
        return {}
    achados = {}
    for linha in texto.splitlines():
        partes = linha.split()
        if len(partes) >= 3:
            try:
                achados[partes[0]] = {"size": int(partes[1]),
                                      "refcount": int(partes[2])}
            except ValueError:
                achados[partes[0]] = {"size": 0, "refcount": 0}
    return achados


def modulos_em_sysfs(raiz=""):
    """
    Modulos segundo /sys/module: a arvore de objetos do kernel.

    So conta o que tem `initstate`. Sem esse filtro a lista incluiria os modulos
    COMPILADOS DENTRO do kernel (que aparecem aqui so para expor parametros) e
    toda comparacao com /proc/modules acusaria dezenas de divergencias em
    qualquer host saudavel -- o classico detector que grita sempre e por isso
    deixa de ser lido.
    """
    base = os.path.join(raiz, "sys/module") if raiz else "/sys/module"
    achados = {}
    try:
        nomes = os.listdir(base)
    except (IOError, OSError):
        return {}
    for nome in nomes:
        caminho = os.path.join(base, nome)
        estado = _ler(os.path.join(caminho, "initstate"))
        if estado is None:
            continue                      # embutido no kernel, nao carregado
        try:
            carga = int(os.stat(caminho).st_mtime)
        except OSError:
            carga = 0
        achados[nome] = {"initstate": estado.strip(), "loaded_at": carga}
    return achados


# Nomes que aparecem entre colchetes em /proc/kallsyms e NAO sao modulos.
#
# Achado medindo em host real (2026-08-19), e o achado mais importante deste
# coletor: o kernel usa a mesma notacao "[nome]" para anotar simbolos que nao
# pertencem a modulo nenhum -- trampolins de ftrace e programas eBPF compilados
# em tempo de execucao. Sem esta lista, os dois viravam achado CRITICAL de
# "modulo escondido" em qualquer host com eBPF ativo, o que inclui **o proprio
# agente desta ferramenta**: ela acusaria rootkit por causa de si mesma, em toda
# captura, em todo host.
#
# Um detector que acusa sempre nao e um detector sensivel, e um detector morto:
# depois do terceiro alarme falso ninguem mais le o quarto, e o achado
# verdadeiro passa junto com o resto.
PSEUDO_MODULOS_KALLSYMS = frozenset(("bpf", "ftrace", "kprobes", "ftrace_mod"))
PREFIXO_PSEUDO = "__builtin__"


def modulos_em_kallsyms(raiz=""):
    """
    Modulos citados em /proc/kallsyms, pelo sufixo "[nome]" dos simbolos.

    E a terceira fonte, e a mais interessante: um rootkit que se remove da lista
    de modulos frequentemente DEIXA os simbolos dele na tabela, porque apaga-los
    quebraria o proprio codigo. Divergencia aqui e o indicio mais forte que este
    coletor produz.
    """
    caminho = os.path.join(raiz, "proc/kallsyms") if raiz else "/proc/kallsyms"
    texto = _ler(caminho)
    if not texto:
        return set()
    achados = set(re.findall(r"\[([\w\-]+)\]\s*$", texto, re.MULTILINE))
    return {nome for nome in achados
            if nome not in PSEUDO_MODULOS_KALLSYMS
            and not nome.startswith(PREFIXO_PSEUDO)}


def _boot_time(raiz=""):
    """Instante do boot, de /proc/stat (btime). Zero quando indisponivel."""
    texto = _ler(os.path.join(raiz, "proc/stat") if raiz else "/proc/stat")
    if not texto:
        return 0
    for linha in texto.splitlines():
        if linha.startswith("btime "):
            try:
                return int(linha.split()[1])
            except (IndexError, ValueError):
                return 0
    return 0


def taint_flags(raiz=""):
    """Bits de taint ligados no kernel, dos que esta analise sabe interpretar."""
    caminho = (os.path.join(raiz, "proc/sys/kernel/tainted") if raiz
               else "/proc/sys/kernel/tainted")
    texto = _ler(caminho)
    if not texto:
        return []
    try:
        valor = int(texto.strip())
    except ValueError:
        return []
    return [(bit,) + TAINT_BITS[bit] for bit in sorted(TAINT_BITS)
            if valor & (1 << bit)]


def _tem_pacote(caminho):
    """
    Se um arquivo pertence a algum pacote instalado.

    Devolve None quando nao da para saber (host sem rpm, tempo esgotado). None e
    diferente de False, e o laudo precisa dessa diferenca: "nao pertence a
    pacote" e um indicio, "nao consegui perguntar" nao e.
    """
    if not caminho or not os.path.exists(caminho):
        return None
    try:
        r = subprocess.call(["rpm", "-qf", caminho],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
        return r == 0
    except (OSError, subprocess.SubprocessError):
        return None


# ------------------------------------------------------------------------------
# COMPOSICAO
# ------------------------------------------------------------------------------
def _finding_modulo_escondido(nome, onde_aparece, onde_falta, confianca):
    """Achado de divergencia entre as listas de modulos (camada S5)."""
    return Finding(
        title="Modulo de kernel ausente da lista de modulos: %s" % nome,
        severity=SEV_CRITICAL,
        source=SRC_HEURISTIC,
        category="rootkit",
        target="kmod:%s" % nome,
        description=(
            "O modulo aparece em %s e NAO aparece em %s. Estas fontes descrevem "
            "o mesmo fato e deveriam concordar. Um modulo que se remove da lista "
            "que o administrador consulta, mantendo o codigo carregado, e a "
            "definicao operacional de um rootkit de kernel: nao ha uso legitimo "
            "conhecido para essa combinacao."
            % (onde_aparece, onde_falta)),
        evidence={"module": nome, "seen_in": onde_aparece,
                  "missing_from": onde_falta},
        technique="T1014",
        confidence=confianca,
        custody={"level": CUSTODY_NONE},
        recommendation=(
            "Nao descarregar o modulo nem reiniciar o host antes de preservar "
            "evidencia: os dois apagam o estado que sustenta este achado. "
            "Isolar o host na rede e tratar como comprometido no nivel do "
            "kernel, o que significa que NENHUMA resposta deste host e "
            "confiavel, inclusive as desta ferramenta."),
        referral=make_referral(
            analysis=(
                "Aquisicao de memoria do kernel e analise do modulo carregado "
                "(extracao do codigo a partir da imagem, comparacao com o .ko "
                "em disco se ele existir). Analise em host de bancada, nunca "
                "no proprio host suspeito."),
            reason=(
                "A ferramenta prova a DIVERGENCIA entre fontes, que e o "
                "indicio. Ela nao consegue ler o codigo do modulo escondido: "
                "no nivel do kernel, quem esconde o modulo tambem controla as "
                "respostas que este agente recebe."),
            obj="modulo de kernel '%s' no host inspecionado" % nome))


def collect_rootkit(raiz="", agora=None, acquirer=None):
    """
    Roda as cinco camadas e devolve os Findings.

    PARAMETER raiz: prefixo de caminho, vazio em producao. Existe para os testes
              montarem uma arvore /proc + /sys sintetica e exercitarem o caminho
              POSITIVO de cada camada sem um rootkit real na maquina.
    PARAMETER agora: instante de referencia, para o teste nao depender do relogio.
    PARAMETER acquirer: core.acquisition.Acquirer (C-043), ou None. Serve a
              camada S3: a biblioteca pre-carregada E a amostra, e ate aqui o
              achado mandava preserva-la sem preservar nada.
    """
    achados = []
    agora = int(agora if agora is not None else time.time())

    proc = modulos_em_proc(raiz)
    sysfs = modulos_em_sysfs(raiz)
    kallsyms = modulos_em_kallsyms(raiz)
    btime = _boot_time(raiz)

    # --- S5: divergencia entre as fontes (o indicio mais forte) ---------------
    if proc or sysfs:
        for nome in sorted(kallsyms - set(proc)):
            # Simbolos de um modulo que a lista de modulos nao conhece. Filtra
            # contra o sysfs para nao acusar um modulo que acabou de descarregar
            # e ainda tem simbolo residual.
            if nome in sysfs or not kallsyms:
                continue
            achados.append(_finding_modulo_escondido(
                nome, "/proc/kallsyms (simbolos do modulo)",
                "/proc/modules e /sys/module", CONF_PROBABLE))

        for nome in sorted(set(sysfs) - set(proc)):
            achados.append(_finding_modulo_escondido(
                nome, "/sys/module (com initstate=%s)"
                      % sysfs[nome].get("initstate", "?"),
                "/proc/modules", CONF_CONFIRMED))

        for nome in sorted(set(proc) - set(sysfs)):
            achados.append(Finding(
                title="Modulo em /proc/modules sem objeto em /sys/module: %s" % nome,
                severity=SEV_HIGH,
                source=SRC_HEURISTIC,
                category="rootkit",
                target="kmod:%s" % nome,
                description=(
                    "O modulo consta da lista de modulos mas nao tem entrada "
                    "correspondente na arvore de objetos do kernel. O caso "
                    "benigno existe (leitura feita no exato instante de uma "
                    "carga ou descarga), e por isso este achado nasce como "
                    "indicio e nao como fato: se ele persistir entre capturas, "
                    "deixa de ser corrida e passa a ser divergencia."),
                evidence={"module": nome, "proc_modules": proc.get(nome, {})},
                technique="T1014",
                confidence=CONF_HEURISTIC,
                custody={"level": CUSTODY_NONE},
                recommendation=(
                    "Conferir se o achado se repete na proxima captura. "
                    "Divergencia persistente entre as duas fontes pede o mesmo "
                    "tratamento de um modulo escondido.")))

    # --- S1 e S2: carga fora do boot, e procedencia de pacote -----------------
    for nome, dados in sorted(sysfs.items()):
        carga = dados.get("loaded_at") or 0
        if not (btime and carga and carga > btime + FOLGA_DE_BOOT_S):
            continue
        pertence = None
        if not raiz:
            # So consulta o gerenciador de pacote em execucao real: dentro de uma
            # arvore sintetica de teste a pergunta nao faz sentido.
            caminho_ko = _caminho_do_ko(nome)
            pertence = _tem_pacote(caminho_ko) if caminho_ko else None

        grave = SEV_MEDIUM if pertence is False else SEV_LOW
        achados.append(Finding(
            title="Modulo de kernel carregado fora do boot: %s" % nome,
            severity=grave,
            source=SRC_HEURISTIC,
            category="rootkit",
            target="kmod:%s" % nome,
            description=(
                "O modulo entrou no kernel %d segundos apos o boot. Carga fora "
                "do boot e rotina em muitos casos (automontagem de midia, "
                "sistema de arquivos usado pela primeira vez, DKMS), e por isso "
                "sozinha nao acusa nada. Ela importa por ser o PRIMEIRO passo "
                "obrigatorio de todo rootkit de modulo: nao existe rootkit de "
                "kernel que nao tenha sido carregado em algum momento.%s"
                % (carga - btime,
                   " Este nao pertence a pacote nenhum instalado, o que estreita "
                   "bastante o conjunto de explicacoes legitimas."
                   if pertence is False else
                   "" if pertence is None else
                   " Pertence a um pacote instalado, o que e a explicacao "
                   "legitima mais comum.")),
            evidence={"module": nome, "loaded_at": carga, "boot_time": btime,
                      "seconds_after_boot": carga - btime,
                      "owned_by_package": pertence,
                      "initstate": dados.get("initstate")},
            technique="T1547.006",
            confidence=CONF_CONFIRMED,
            custody={"level": CUSTODY_METADATA},
            recommendation=(
                "Cruzar o horario da carga com o log de autenticacao e com o "
                "historico de comandos: quem estava no host naquele minuto.")))

    # --- S3: sequestro por biblioteca no espaco de usuario --------------------
    achados.extend(_camada_preload(raiz, acquirer))

    # --- S4: taint do kernel --------------------------------------------------
    achados.extend(_camada_taint(raiz))

    return achados


def _caminho_do_ko(nome):
    """Caminho do arquivo .ko de um modulo carregado, quando descobrivel."""
    try:
        release = os.uname()[2]
    except AttributeError:
        return None
    base = "/lib/modules/%s" % release
    for raiz_dir, _dirs, arquivos in os.walk(base):
        for arq in arquivos:
            if arq.split(".")[0] == nome:
                return os.path.join(raiz_dir, arq)
    return None


def _camada_preload(raiz="", acquirer=None):
    """
    S3: rootkit de espaco de usuario via /etc/ld.so.preload.

    Este arquivo faz TODO processo iniciado depois carregar a biblioteca listada,
    antes de qualquer outra. E o mecanismo de toda uma familia de rootkits de
    usuario, que interceptam as funcoes de listagem para esconder arquivo,
    processo e conexao sem tocar no kernel.

    A enumeracao de persistencia ja registra a EXISTENCIA do arquivo (T1574.006).
    O que se faz aqui e diferente e complementar: julgar o CONTEUDO dele, item a
    item, pela procedencia de pacote de cada biblioteca listada.
    """
    caminho = (os.path.join(raiz, "etc/ld.so.preload") if raiz
               else "/etc/ld.so.preload")
    texto = _ler(caminho)
    if not texto or not texto.strip():
        return []

    achados = []
    for linha in texto.splitlines():
        lib = linha.strip()
        if not lib or lib.startswith("#"):
            continue
        pertence = _tem_pacote(lib) if not raiz else None
        existe = os.path.exists(lib if not raiz
                                else os.path.join(raiz, lib.lstrip("/")))
        # [C-043] A biblioteca E a amostra: e ela que o perito precisa ler para
        # dizer o que o rootkit esconde. A recomendacao abaixo ja mandava
        # preserva-la; sem isto, mandava e nao fazia.
        custodia = {"level": CUSTODY_METADATA}
        if acquirer is not None and existe and not raiz:
            try:
                custodia = acquirer.acquire_file(lib)
            except Exception as exc:
                LOG.error("[RK] Aquisicao de %s falhou: %s", lib, exc)

        achados.append(Finding(
            title="Biblioteca pre-carregada em todo processo do host: %s" % lib,
            severity=SEV_HIGH if pertence is False else SEV_MEDIUM,
            source=SRC_HEURISTIC,
            category="rootkit",
            target=lib,
            description=(
                "O arquivo /etc/ld.so.preload faz esta biblioteca ser carregada "
                "em TODO processo iniciado no host, antes de qualquer outra. "
                "Quem controla esse arquivo controla o que cada programa do host "
                "enxerga: e assim que um rootkit de espaco de usuario esconde "
                "arquivo, processo e conexao sem precisar entrar no kernel. Uso "
                "legitimo existe e e raro (instrumentacao, malloc alternativo).%s"
                % (" A biblioteca listada nao pertence a pacote nenhum."
                   if pertence is False else
                   " O arquivo listado nem sequer existe, o que costuma ser "
                   "resto de uma tentativa mal feita ou de uma limpeza parcial."
                   if not existe else "")),
            evidence={"preload_file": caminho, "library": lib,
                      "library_exists": existe, "owned_by_package": pertence},
            technique="T1574.006",
            confidence=CONF_CONFIRMED if not existe else CONF_PROBABLE,
            custody=custodia,
            recommendation=(
                "Nao remover o arquivo antes de preservar a biblioteca: ela e a "
                "amostra. Remover /etc/ld.so.preload tambem NAO desmapeia a "
                "biblioteca dos processos que ja estao rodando, que continuam "
                "com ela em memoria ate reiniciarem."),
            referral=make_referral(
                analysis=(
                    "Analise da biblioteca: quais simbolos da libc ela "
                    "substitui (readdir, open, stat, e as funcoes de listagem "
                    "de rede sao as classicas), e o que ela filtra."),
                reason=(
                    "A ferramenta prova que a biblioteca e carregada em todo "
                    "processo e diz de onde ela veio. O que ela esconde so se "
                    "descobre lendo o codigo dela."),
                obj="arquivo %s, listado em %s" % (lib, caminho))))
    return achados


def _camada_taint(raiz=""):
    """
    S4: o proprio kernel declarando que aceitou codigo de fora.

    Leitura de custo zero e frequentemente esquecida. Um bit de taint nao acusa
    ninguem, mas responde uma pergunta que nenhuma outra fonte responde: se algum
    modulo NAO ASSINADO ou fora da arvore ja entrou neste kernel desde o boot,
    inclusive um que ja tenha sido descarregado e nao apareca em lista nenhuma.
    """
    bits = taint_flags(raiz)
    if not bits:
        return []

    relevantes = [b for b in bits if b[3] != SEV_INFO]
    if not relevantes:
        return []

    pior = max(relevantes, key=lambda b: {"Critical": 4, "High": 3, "Medium": 2,
                                          "Low": 1, "Info": 0}.get(b[3], 0))
    detalhe = "; ".join("%s (%s): %s" % (b[1], b[2], b[4]) for b in relevantes)
    return [Finding(
        title="Kernel tingido por modulo de procedencia irregular",
        severity=pior[3],
        source=SRC_HEURISTIC,
        category="rootkit",
        target="kernel",
        description=(
            "O kernel registra, desde o boot, que aceitou codigo nestas "
            "condicoes: %s. Este registro e CUMULATIVO e nao volta atras: ele "
            "vale mesmo que o modulo responsavel ja tenha sido descarregado e "
            "nao apareca em nenhuma lista de modulos. E, por isso, a unica "
            "fonte que enxerga um modulo que passou por aqui e saiu." % detalhe),
        evidence={"taint_bits": [{"bit": b[0], "flag": b[1], "meaning": b[2]}
                                 for b in bits]},
        technique="T1014",
        confidence=CONF_CONFIRMED,
        custody={"level": CUSTODY_METADATA},
        recommendation=(
            "Levantar quais modulos fora da arvore ou nao assinados o host "
            "usa legitimamente (DKMS, drivers de terceiro) e comparar com a "
            "lista de modulos carregada agora. O que sobrar precisa de "
            "explicacao."))]
