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
