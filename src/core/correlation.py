# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/core/correlation.py
# DESCRIPTION: Varios sinais fracos viram uma conclusao que nenhum sustenta.
#
# WHY:         A ferramenta ja produz achados individuais, e cada um deles,
#              sozinho, e fraco demais para justificar acao. Um processo em
#              /tmp acontece; uma conexao de saida acontece; um processo que
#              reaparece acontece. Nenhum dos tres, isolado, faz alguem agir.
#
#              Os tres JUNTOS, no mesmo processo, nao sao tres observacoes: sao
#              uma so, e ela tem nome. E essa a diferenca entre uma lista de
#              alertas e uma conclusao, e e a unica coisa que transforma ATT&CK
#              de etiqueta em encadeamento.
#
# CONFIDENCE:  Nenhuma regra afirma comprometimento. Cada uma diz o que foi
#              observado, quais sinais a sustentam e o que verificar em seguida.
#              A decisao continua sendo do analista, e a regra existe para
#              levar ate ele um caso montado, nao um veredito.
#
# ORDER:       As regras que dependem de SEQUENCIA usam o instante corrigido
#              pelo desvio de relogio. Sem isso, "A aconteceu antes de B" entre
#              hosts diferentes e chute com aparencia de fato.
#
# NOTES:       Compativel com Python 3.6.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import logging

from src.core.findings import (Finding, SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM,
                               SRC_HEURISTIC)
from src.core.events import (EV_PROCESS_START, EV_CONNECTION, EV_PERSISTENCE,
                             EV_FINDING, corrected_ts)
from src.core.attack import describe

LOG = logging.getLogger("Correlation")

# Ordem canonica do kill chain, das primeiras taticas as ultimas. Serve para
# apresentar as taticas observadas na sequencia em que um ataque as percorre, e
# nao na ordem em que os achados chegaram. A fonte da tatica de cada tecnica e o
# catalogo local (src/core/attack.py); nao ha uma segunda copia aqui, para as
# duas nao divergirem.
ORDEM_TATICAS = (
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
)

# A partir de quantas taticas distintas no mesmo host a leitura deixa de ser um
# conjunto de achados e passa a descrever uma progressao de ataque.
MIN_TATICAS_CADEIA = 3

# Janela em que dois eventos sao considerados relacionados. Curta de proposito:
# quanto maior, mais coincidencia entra como se fosse causa, e uma correlacao
# que aceita qualquer coisa deixa de informar.
JANELA_RELACAO = 300

# Quantas capturas um artefato precisa atravessar para deixar de ser acao
# pontual e passar a caracterizar persistencia ativa.
MIN_RECORRENCIA = 3


# Interpretadores: quando o executavel e um deles, o risco esta no ARGUMENTO,
# porque e ele que carrega o codigo.
INTERPRETADORES = ("bash", "sh", "dash", "zsh", "python", "python3", "perl",
                   "ruby", "node", "php", "lua", "awk")

DIRETORIOS_GRAVAVEIS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/")


def _em_diretorio_gravavel(token):
    return any((token or "").lower().startswith(d) for d in DIRETORIOS_GRAVAVEIS)


def _e_caminho_gravavel(texto):
    """
    Se a linha de comando EXECUTA algo de um diretorio gravavel.

    A distincao aqui foi aprendida em campo, e nos dois sentidos.

    Procurar o diretorio em qualquer parte do texto produz falso positivo: o
    servico legitimo `/usr/lib/gvfs/gvfsd-fuse /run/user/0/gvfs -f` foi acusado
    em quatro hosts de uma vez, porque o caminho gravavel aparecia como
    argumento de DIRETORIO de trabalho, nao como codigo. Falso positivo nessa
    regra e caro de um jeito especifico: ela afirma "campanha", e uma campanha
    inventada manda o analista procurar vetor comum que nao existe.

    Olhar apenas o executavel produz falso NEGATIVO, e ja produziu: rodar por
    interpretador (`/bin/bash /dev/shm/miner.sh`) e evasao trivial, porque o
    binario e legitimo e o codigo esta no argumento.

    A regra que cobre os dois: o executavel esta em diretorio gravavel, OU o
    executavel e um interpretador e algum argumento esta.
    """
    partes = (texto or "").split()
    if not partes:
        return False

    executavel = partes[0]
    if _em_diretorio_gravavel(executavel):
        return True

    nome = executavel.rsplit("/", 1)[-1].lower()
    if any(nome.startswith(i) for i in INTERPRETADORES):
        return any(_em_diretorio_gravavel(a) for a in partes[1:])

    return False


# ------------------------------------------------------------------------------
# REGRA 1: PERSISTENCIA COM CANAL ATIVO
# ------------------------------------------------------------------------------
def rule_active_c2(eventos):
    """
    Processo de caminho gravavel, com conexao de saida, que reaparece.

    Sozinhos os tres sinais sao banais. Somados descrevem um artefato que se
    mantem vivo no host e fala com fora, que e a forma corrente de um canal de
    comando: matar o processo nao resolve, porque ele volta.
    """
    por_comando = {}
    for ev in eventos:
        if ev.get("type") not in (EV_PROCESS_START, EV_CONNECTION):
            continue
        chave = (ev.get("detail") or {}).get("cmd") or ev.get("subject") or ""
        if not chave:
            continue
        registro = por_comando.setdefault(chave, {
            "cmd": chave, "inicios": [], "conexoes": [], "agentes": set()})
        registro["agentes"].add(ev.get("agent_uuid"))
        if ev.get("type") == EV_PROCESS_START:
            registro["inicios"].append(ev)
        else:
            registro["conexoes"].append(ev)

    achados = []
    for chave, r in por_comando.items():
        if not _e_caminho_gravavel(chave):
            continue
        if not r["conexoes"]:
            continue
        if len(r["inicios"]) < MIN_RECORRENCIA:
            continue

        destinos = sorted(set(c.get("subject") for c in r["conexoes"]))[:5]
        achados.append(Finding(
            title="Persistencia com canal de saida ativo",
            severity=SEV_CRITICAL,
            source=SRC_HEURISTIC,
            category="correlation",
            target=chave[:200],
            description=(
                "Tres sinais que isolados nao justificariam acao aparecem no "
                "MESMO processo: ele executa de diretorio gravavel por qualquer "
                "usuario, mantem conexao de saida, e reapareceu em %d execucoes. "
                "Juntos deixam de ser tres observacoes e passam a ser uma: um "
                "artefato que se mantem vivo e fala com fora. Encerrar o "
                "processo nao encerra o problema, porque ele retorna."
                % len(r["inicios"])),
            evidence={"cmd": chave[:300], "execucoes": len(r["inicios"]),
                      "destinos": destinos,
                      "hosts": sorted(a for a in r["agentes"] if a)},
            technique="T1071",
            recommendation=(
                "Preservar memoria e o binario ANTES de encerrar. Localizar o "
                "mecanismo que o traz de volta (unit, cron, ld.so.preload) em "
                "vez de matar o processo. Bloquear os destinos observados e "
                "verificar se outros hosts falam com os mesmos.")))
    return achados


# ------------------------------------------------------------------------------
# REGRA 2: PERSISTENCIA PLANTADA LOGO APOS ATIVIDADE SUSPEITA
# ------------------------------------------------------------------------------
def rule_persistence_after_activity(eventos):
    """
    Mecanismo de persistencia criado logo depois de um processo suspeito.

    E a regra que so o modelo de eventos torna possivel, porque depende de
    ORDEM. "O cron surgiu quatro segundos depois do shell abrir" e uma frase
    que nenhuma captura isolada produz, e e exatamente o tipo de encadeamento
    que sustenta a conclusao de um laudo.
    """
    suspeitos = sorted(
        (e for e in eventos
         if e.get("type") == EV_PROCESS_START
         and (_e_caminho_gravavel(e.get("subject"))
              or (e.get("detail") or {}).get("score", 0) >= 70)),
        key=corrected_ts)
    persistencias = sorted(
        (e for e in eventos if e.get("type") == EV_PERSISTENCE),
        key=corrected_ts)

    achados = []
    for p in persistencias:
        t_p = corrected_ts(p)
        anteriores = [s for s in suspeitos
                      if 0 <= (t_p - corrected_ts(s)) <= JANELA_RELACAO]
        if not anteriores:
            continue
        gatilho = anteriores[-1]
        intervalo = int(t_p - corrected_ts(gatilho))
        achados.append(Finding(
            title="Persistencia criada logo apos atividade suspeita",
            severity=SEV_CRITICAL,
            source=SRC_HEURISTIC,
            category="correlation",
            target=(p.get("subject") or "")[:200],
            description=(
                "O mecanismo de persistencia foi criado %d segundo(s) depois de "
                "um processo suspeito iniciar. A proximidade nao prova causa, "
                "mas a ordem inverte o onus: nesse intervalo, coincidencia e "
                "explicacao menos economica que a sequencia. Nenhuma captura "
                "isolada mostraria isso, porque ordem nao e propriedade de um "
                "retrato." % intervalo),
            evidence={"persistencia": (p.get("subject") or "")[:300],
                      "processo": (gatilho.get("subject") or "")[:300],
                      "intervalo_s": intervalo,
                      "host": p.get("agent_uuid")},
            technique="T1053",
            recommendation=(
                "Reconstituir a janela completa em torno do intervalo. Conferir "
                "se o processo gatilho criou o arquivo, comparando horario de "
                "modificacao com o inicio dele.")))
    return achados


# ------------------------------------------------------------------------------
# REGRA 3: O MESMO ARTEFATO EM VARIOS HOSTS
# ------------------------------------------------------------------------------
def rule_fleet_campaign(eventos):
    """
    O mesmo artefato observado em maquinas diferentes.

    Um host comprometido e um incidente. O mesmo artefato em varios e uma
    campanha, e a resposta muda inteiramente: deixa de ser limpar uma maquina e
    passa a ser encontrar o vetor comum. E a leitura que so existe olhando a
    frota, e por isso nenhuma analise por host a alcanca.
    """
    por_alvo = {}
    for ev in eventos:
        if ev.get("type") not in (EV_PROCESS_START, EV_FINDING):
            continue
        alvo = (ev.get("subject") or "").strip()
        if not alvo or not _e_caminho_gravavel(alvo):
            continue
        por_alvo.setdefault(alvo, set()).add(ev.get("agent_uuid"))

    achados = []
    for alvo, hosts in por_alvo.items():
        hosts = set(h for h in hosts if h)
        if len(hosts) < 2:
            continue
        achados.append(Finding(
            title="Mesmo artefato observado em %d hosts" % len(hosts),
            severity=SEV_HIGH,
            source=SRC_HEURISTIC,
            category="correlation",
            target=alvo[:200],
            description=(
                "O mesmo artefato aparece em maquinas diferentes. Um host "
                "comprometido e um incidente; varios com o mesmo artefato sao "
                "uma campanha, e a resposta e outra: limpar as maquinas nao "
                "encerra nada enquanto o vetor comum continuar de pe."),
            evidence={"artefato": alvo[:300], "hosts": sorted(hosts),
                      "quantidade": len(hosts)},
            technique="T1078",
            recommendation=(
                "Procurar o que os hosts afetados tem em comum: imagem de "
                "origem, credencial compartilhada, rede, janela de manutencao. "
                "Verificar a frota inteira antes de limpar qualquer um.")))
    return achados


# ------------------------------------------------------------------------------
# REGRA 4: ENCADEAMENTO DE TECNICAS ATT&CK
# ------------------------------------------------------------------------------
def _taticas_de(tecnica):
    """
    Taticas de uma tecnica, lidas do catalogo local (fonte unica).

    Uma tecnica pode pertencer a mais de uma tatica; o catalogo guarda a lista
    separada por virgula. Tecnica sem verbete devolve vazio: nao inventa tatica.
    """
    dados = describe(tecnica)
    if not dados:
        return []
    _nome, taticas, _resumo = dados
    return [t.strip() for t in (taticas or "").split(",") if t.strip()]


def rule_attack_chain(eventos):
    """
    Varias taticas do ATT&CK observadas no MESMO host.

    Oito achados, todos de persistencia, sao oito observacoes da mesma coisa.
    Oito achados que atravessam execucao, persistencia, evasao e canal de
    comando sao uma progressao: descrevem um ataque avancando pelo kill chain, e
    a resposta a uma progressao e diferente da resposta a um alerta isolado.

    A regra nao afirma comprometimento. Diz quais estagios do ataque tem sinal
    presente naquele host, apresentados na ordem canonica do kill chain, e deixa
    a leitura da amplitude com o analista: quanto mais estagios cobertos, menos
    provavel que sejam achados independentes e sem relacao.

    A tatica de cada tecnica vem do catalogo local, entao a regra herda tudo que
    ele souber sem manter uma segunda lista.
    """
    # Tecnica observada por host, com o instante mais recente de cada uma.
    por_host = {}
    for ev in eventos:
        if ev.get("type") != EV_FINDING:
            continue
        tecnica = (ev.get("detail") or {}).get("technique")
        if not tecnica:
            continue
        host = ev.get("agent_uuid")
        registro = por_host.setdefault(host, {})
        # Guarda o evento mais recente daquela tecnica, para datar a etapa.
        anterior = registro.get(tecnica)
        if anterior is None or corrected_ts(ev) > corrected_ts(anterior):
            registro[tecnica] = ev

    achados = []
    for host, tecnicas in por_host.items():
        # Uma cadeia e uma PROGRESSAO, entao exige mais de uma acao. Uma unica
        # tecnica que por si so pertence a varias taticas (T1053.003 cobre tres)
        # nao e progressao: e um artefato so. Sem esta guarda, um unico achado
        # viraria "cadeia", que e o oposto do que a regra quer dizer.
        if len(tecnicas) < 2:
            continue

        # Mapeia tatica -> as tecnicas observadas que a exercitam.
        por_tatica = {}
        for tecnica in tecnicas:
            for tatica in _taticas_de(tecnica):
                por_tatica.setdefault(tatica, set()).add(tecnica)

        if len(por_tatica) < MIN_TATICAS_CADEIA:
            continue

        # Apresenta as taticas na ordem do kill chain; as que o catalogo trouxer
        # e que nao estejam na ordem canonica vao ao final, preservadas.
        ordenadas = [t for t in ORDEM_TATICAS if t in por_tatica]
        ordenadas += [t for t in por_tatica if t not in ORDEM_TATICAS]

        etapas = []
        for t in ordenadas:
            tecs = sorted(por_tatica[t])
            etapas.append("%s (%s)" % (t, ", ".join(tecs)))
        sequencia = "  ->  ".join(etapas)

        # A severidade acompanha a amplitude: quanto mais estagios, mais forte a
        # leitura de que ha um so ataque por tras.
        severidade = SEV_CRITICAL if len(ordenadas) >= 4 else SEV_HIGH

        achados.append(Finding(
            title="Cadeia ATT&CK: %d taticas no mesmo host" % len(ordenadas),
            severity=severidade,
            source=SRC_HEURISTIC,
            category="correlation",
            target=(host or "")[:200],
            description=(
                "Sinais de %d taticas distintas do ATT&CK aparecem no mesmo "
                "host, na ordem do kill chain: %s. Cada achado, isolado, e uma "
                "observacao; atravessando varios estagios, eles descrevem uma "
                "progressao. Quanto mais estagios cobertos, menos economica fica "
                "a hipotese de que sao achados independentes."
                % (len(ordenadas), sequencia)),
            evidence={"host": host,
                      "taticas": ordenadas,
                      "tecnicas": sorted(tecnicas.keys())},
            # A tecnica do achado e a da etapa mais avancada observada, que e a
            # que melhor resume ate onde a progressao chegou.
            technique=sorted(
                tecnicas.keys(),
                key=lambda tc: max(
                    [ORDEM_TATICAS.index(t) for t in _taticas_de(tc)
                     if t in ORDEM_TATICAS] or [-1]))[-1],
            recommendation=(
                "Tratar como um incidente unico, e nao como achados avulsos. "
                "Reconstituir a ordem dos estagios na linha do tempo deste host "
                "e conter a etapa mais avancada primeiro (canal de comando ou "
                "exfiltracao, se presentes).")))
    return achados


# ------------------------------------------------------------------------------
# COMPOSICAO
# ------------------------------------------------------------------------------
REGRAS = (rule_active_c2, rule_persistence_after_activity, rule_fleet_campaign,
          rule_attack_chain)


def correlate(eventos):
    """
    Aplica todas as regras sobre a linha do tempo.

    Uma regra que falha nao pode calar as outras: sao leituras independentes do
    mesmo material, e perder todas por causa de uma seria trocar analise parcial
    por nenhuma.
    """
    achados = []
    for regra in REGRAS:
        try:
            achados.extend(regra(eventos or []))
        except Exception as exc:
            LOG.error("Correlation rule %s failed: %s",
                      getattr(regra, "__name__", "?"), exc)
    return achados
