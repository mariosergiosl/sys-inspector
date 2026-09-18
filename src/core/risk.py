# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/core/risk.py
# DESCRIPTION: Leitura unica do anomaly_score: quais sinais ele carrega, e o que
#              esse conjunto vale na escala de severidade do produto.
#
# WHY:         `anomaly_score` nunca foi um numero. E um CAMPO DE BITS: cada bit
#              declara um sinal distinto que o coletor observou (ver os SCORE_*
#              em src/collectors/process_tree.py). Somar bits produz um inteiro
#              cujo VALOR nao tem significado; so o conjunto de bits tem.
#
#              Tres partes da ferramenta liam esse inteiro como se fosse
#              magnitude, cada uma com um limiar proprio: o laudo cortava em
#              128/32/8, o diff e a linha do tempo cortavam em 70, e a tela de
#              historico exibia o numero cru. As tres leituras discordavam entre
#              si e as tres estavam erradas pelo mesmo motivo.
#
#              O efeito e inversao de gravidade, nao imprecisao. Um processo
#              defunto marca 128 (ZOMBIE) e era classificado como o pior caso
#              possivel; um binario apagado do disco executando de /dev/shm marca
#              8+2=10 e ficava abaixo do limiar, exibido como brando. O primeiro
#              e rotina de sistema, o segundo e a assinatura que motiva resposta
#              a incidente. A tela dizia o contrario.
#
# READING:     Um score vira: (1) a lista dos sinais presentes, cada um com nome,
#              severidade e explicacao; (2) um nivel unico, que e o MAIOR entre os
#              sinais presentes, elevado um degrau quando dois ou mais sinais de
#              peso coincidem. Coincidencia importa: caminho gravavel sozinho e
#              comum, caminho gravavel MAIS binario apagado descreve uma so coisa.
#
# NEVER HIDE:  O numero cru continua disponivel e continua sendo exibido junto do
#              rotulo. Ele e o dado coletado; o rotulo e a leitura dele. Trocar um
#              pelo outro esconderia evidencia atras de interpretacao.
#
# NOTES:       Sem dependencia de coletor (process_tree importa pwd/grp e so
#              carrega em Linux). Os bits sao declarados aqui e conferidos contra
#              a origem por teste, para as duas listas nao divergirem em silencio,
#              que e a classe de falha mais cara deste projeto.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

from src.core.findings import (SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH,
                               SEV_CRITICAL, SEVERITY_ORDER)


# ------------------------------------------------------------------------------
# OS SINAIS
# ------------------------------------------------------------------------------
# Espelho dos SCORE_* de src/collectors/process_tree.py. A severidade de cada um
# responde a uma pergunta so: se este fosse o UNICO sinal presente no host,
# quanto ele justificaria de atencao?
#
# (bit, chave, rotulo curto, severidade, o que foi observado)
SINAIS = (
    (2, "unsafe_exec", "executa de diretorio gravavel", SEV_HIGH,
     "A linha de comando aponta para /tmp, /dev/shm ou /var/tmp. Software "
     "instalado nao roda de la; e o local escolhido justamente por ser "
     "gravavel por qualquer um."),
    (8, "deleted_exe", "binario apagado em execucao", SEV_HIGH,
     "O executavel sumiu do disco com o processo vivo. Apagar a amostra apos "
     "executar e tecnica corrente para impedir analise (ATT&CK T1070.004)."),
    (256, "immutable", "atributo imutavel", SEV_MEDIUM,
     "Arquivo marcado como imutavel, o que impede remocao pelos meios comuns e "
     "e usado tanto por endurecimento legitimo quanto por persistencia."),
    (32, "gpu_miner", "assinatura de mineracao / uso de GPU", SEV_MEDIUM,
     "Nome ou acesso a dispositivo compativel com mineracao. Legitimo em host "
     "de computacao grafica, anomalo em servidor."),
    (1, "unsafe_lib", "biblioteca de local nao confiavel", SEV_MEDIUM,
     "Carregou biblioteca fora dos diretorios do sistema, caminho usado para "
     "injetar codigo em processo legitimo."),
    (4, "net_tool", "ferramenta de rede", SEV_LOW,
     "Utilitario de transferencia ou tunel (netcat e similares). Comum em "
     "administracao, e tambem o primeiro passo de exfiltracao."),
    (64, "net_error", "falha de rede", SEV_LOW,
     "Retransmissoes ou descartes TCP no processo. Indica problema de rede ou "
     "destino que nao responde; sozinho nao e indicio de seguranca."),
    (16, "inspector", "EDR/AV", SEV_INFO,
     "A propria ferramenta de seguranca do host. Aparece para explicar o que "
     "esta observando o sistema, nao como suspeita."),
    (128, "zombie", "processo defunto", SEV_INFO,
     "Terminou e aguarda o pai recolher o status. E rotina de sistema; so "
     "informa quando acumula ou quando o pai desapareceu."),

    # [F-201] Sinais das 18 sondas eBPF de 2026-08-17. tcp_v6_connect e
    # sched_process_exit ficam fora desta tabela de proposito: nao sao
    # indicio de nada por si so e ja tem seu proprio lugar no laudo (lista de
    # conexoes, status de saida do processo).
    (1048576, "kexec_load", "carregou kernel via kexec", SEV_CRITICAL,
     "Troca do kernel em execucao por outro, sem reboot completo. Uso "
     "legitimo existe (kdump, atualizacao ao vivo), mas e raro fora de boot "
     "e e o unico ponto que da a um atacante controle total do kernel sem "
     "derrubar a maquina."),
    (8192, "mem_access", "acessou memoria de outro processo", SEV_HIGH,
     "ptrace ou process_vm_readv contra outro PID. Tecnica corrente de dump "
     "de credencial em memoria e de injecao de codigo em processo alheio."),
    (32768, "exec_mem_grant", "concedeu execucao a regiao de memoria", SEV_HIGH,
     "mprotect trocou uma pagina de memoria para executavel. Assinatura "
     "classica de shellcode desempacotado em runtime ou de JIT abusado."),
    (65536, "bpf_use", "uso de eBPF por terceiro", SEV_HIGH,
     "Chamada a bpf() por um processo que nao e o proprio coletor. E a mesma "
     "capacidade usada por rootkits modernos de eBPF; raro em processo comum."),
    (524288, "ns_change", "mudou de namespace", SEV_HIGH,
     "setns ou unshare. E o movimento central de uma fuga de conteiner: sair "
     "do isolamento para o namespace do host ou de outro conteiner."),
    (1024, "kmod_load", "carregou modulo de kernel", SEV_HIGH,
     "init_module ou finit_module fora do boot. Vetor classico de rootkit de "
     "kernel; administracao legitima normalmente passa por modprobe no boot."),
    (512, "cred_change", "mudanca de credencial (uid)", SEV_INFO,
     "commit_creds trocou o uid do processo. Dispara em TODO sudo, su, "
     "binario setuid e servico que larga privilegio ao subir; e o caso mais "
     "comum do host, nao a excecao. O discriminante que separa rotina de "
     "escalada e a AUSENCIA de mediador legitimo (sudo/su/PAM) na arvore de "
     "ancestrais, e essa e a regra AM-001-L1, nao este bit. Em MEDIUM ele "
     "entrava na contagem de coincidencia (NIVEL_MINIMO_PARA_ESCALAR) e "
     "promovia a HIGH qualquer processo com sudo mais qualquer outro sinal "
     "MEDIUM do host (ex.: ld.so.preload marcado imutavel), inundando a tela."),
    (16384, "memfd_create", "criou memoria de arquivo anonima", SEV_LOW,
     "memfd_create monta a base da execucao fileless, mas tambem e uso "
     "corrente de software legitimo (systemd, navegadores, IPC via "
     "shared-memory). So vira execucao de fato quando o processo roda a "
     "partir dai; esse caso mais forte ja tem sinal proprio (binario "
     "apagado/memfd em execucao)."),
    (2048, "new_listener", "abriu porta de escuta", SEV_LOW,
     "bind() passou o socket a escutar. Rotina de qualquer servico, e "
     "tambem o primeiro passo de um shell reverso ou backdoor com porta "
     "propria."),
    (4096, "accepted_conn", "aceitou conexao de entrada", SEV_LOW,
     "inet_csk_accept: alguem do lado de fora se conectou a este processo. "
     "Rotina de servidor; util para saber quem entrou em processo que nao "
     "deveria aceitar conexao nenhuma."),
    (131072, "file_deleted", "apagou arquivo", SEV_LOW,
     "vfs_unlink. Volume normal e alto (rm, gerenciador de pacote); o "
     "julgamento fino sobre padrao anti-forense fica para a regra que cruza "
     "com o restante do comportamento do processo."),
    (262144, "file_renamed", "renomeou arquivo", SEV_LOW,
     "vfs_rename. Tao comum quanto apagar (rotacao de log, mv); mesma "
     "ressalva do sinal anterior."),
    (2097152, "dns_query", "consulta DNS observada", SEV_INFO,
     "Dominio resolvido pelo processo, capturado no proprio pacote. Puro "
     "registro por enquanto; e o insumo da analise de periodicidade de "
     "beaconing (regra futura, ainda nao implementada)."),

    # [Lote 2, 2026-08-19] Sinais das sondas de SNI (C-022) e de arvore de
    # montagem (C-023). A ordem dentro da tabela segue a severidade, como o
    # resto: pivot_root em HIGH sobe, mount e SNI descem.
    (16777216, "pivot_root", "trocou a raiz do sistema de arquivos", SEV_HIGH,
     "pivot_root substitui a raiz que o processo enxerga. Fora de um runtime "
     "de conteiner iniciando um conteiner, e o passo que transforma uma troca "
     "de namespace em acesso efetivo a outra arvore de arquivos, e e a segunda "
     "metade de uma fuga de conteiner: a primeira (setns/unshare) ja tem "
     "sinal proprio, e as duas no mesmo processo descrevem a fuga inteira."),
    (8388608, "mount_op", "montou sistema de arquivos", SEV_LOW,
     "mount() executado por este processo. Volume normal e alto (systemd, "
     "autofs, runtime de conteiner, automontagem de midia). O que muda a "
     "leitura e a companhia: montagem com MS_BIND logo depois de uma troca de "
     "namespace e a forma corrente de trazer um caminho do host para dentro "
     "de um conteiner."),
    (4194304, "tls_sni", "nome do destino em conexao TLS (SNI)", SEV_INFO,
     "Nome do servidor declarado em claro pelo proprio ClientHello, no socket "
     "da conexao. Alcanca o que o DNS nao alcanca: destino resolvido por "
     "cache, endereco fixo sem consulta, ou resolucao por DoH. Puro registro, "
     "como o DNS: o valor esta em cruzar o nome com listas de ameaca e em "
     "amarrar o nome ao fluxo que de fato aconteceu, e nao a uma consulta "
     "feita ao lado dele."),
)

# Ordem de exibicao ja e a ordem da tupla: do que mais pesa para o que menos.

# A partir deste nivel o processo entra na frente da fila do analista.
NIVEL_ATENCAO = SEV_HIGH

# Coincidencia de sinais de peso eleva um degrau (ver ESCALADA no cabecalho).
NIVEL_MINIMO_PARA_ESCALAR = SEV_MEDIUM

CORES = {
    SEV_CRITICAL: "#ff4d4d",
    SEV_HIGH: "#ff8c42",
    SEV_MEDIUM: "#ffd166",
    SEV_LOW: "#6bcB77",
    SEV_INFO: "#7fb3d5",
}

_ESCALA = (SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL)


def _inteiro(score):
    """
    O score como inteiro nao negativo.

    Negativo vira zero de proposito: em complemento de dois, -5 tem quase todos
    os bits ligados, e a leitura ingenua acusaria oito sinais simultaneos a
    partir de um valor que so pode ter vindo de dado corrompido.
    """
    try:
        valor = int(score or 0)
    except (TypeError, ValueError):
        return 0
    return valor if valor > 0 else 0


def decode(score):
    """
    Os sinais presentes num score, do que mais pesa para o que menos.

    Devolve lista de dicts com bit, chave, rotulo, severidade e explicacao. Lista
    vazia significa que nenhum sinal foi levantado, e nao que nao se olhou.
    """
    valor = _inteiro(score)
    presentes = []
    for bit, chave, rotulo, severidade, explicacao in SINAIS:
        if valor & bit:
            presentes.append({"bit": bit, "key": chave, "label": rotulo,
                              "severity": severidade,
                              "explanation": explicacao})
    return presentes


def level(score):
    """
    Nivel unico de um score, na escala de severidade do produto.

    E o maior nivel entre os sinais presentes, elevado um degrau quando dois ou
    mais sinais de nivel Medium ou acima coincidem no mesmo processo: sinais que
    isoladamente sao comuns, juntos deixam de descrever coincidencia.

    Devolve None quando nenhum sinal esta presente, para o chamador distinguir
    "olhou e nada havia" de "nao olhou" (D-020).
    """
    sinais = decode(score)
    if not sinais:
        return None

    ranks = [SEVERITY_ORDER.get(s["severity"], 0) for s in sinais]
    maior = max(ranks)

    piso = SEVERITY_ORDER[NIVEL_MINIMO_PARA_ESCALAR]
    if len([r for r in ranks if r >= piso]) >= 2:
        maior = min(maior + 1, len(_ESCALA) - 1)

    return _ESCALA[maior]


def rank(score):
    """Peso numerico do nivel, para ordenar. Sem sinal algum vale -1."""
    nivel = level(score)
    return SEVERITY_ORDER[nivel] if nivel else -1


def color(score):
    """Cor do nivel, unica em toda a interface."""
    nivel = level(score)
    return CORES.get(nivel, "#6bcB77") if nivel else "#555"


def needs_attention(score):
    """
    Se este score coloca o processo na frente da fila.

    Substitui a comparacao `score >= 70`, que media a soma dos bits e por isso
    promovia um processo defunto e rebaixava um binario apagado.
    """
    return rank(score) >= SEVERITY_ORDER[NIVEL_ATENCAO]


def summary(score):
    """
    Frase curta com os sinais presentes, para tooltip e coluna estreita.

    Ex.: "executa de diretorio gravavel + binario apagado em execucao".
    """
    sinais = decode(score)
    if not sinais:
        return ""
    return " + ".join(s["label"] for s in sinais)


def unknown_bits(score):
    """
    Bits ligados que esta tabela nao sabe nomear.

    Existe para o mesmo fim do rotulo desconhecido na arvore: um sinal novo no
    coletor aparece como sinal desconhecido em vez de ser descartado sem rastro.
    """
    valor = _inteiro(score)
    conhecidos = 0
    for bit, _chave, _rotulo, _sev, _exp in SINAIS:
        conhecidos |= bit
    return valor & ~conhecidos
