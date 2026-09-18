# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/core/badges.py
# DESCRIPTION: Registro UNICO dos rotulos de context_tags que viram badge na
#              arvore de processos: icone, classe CSS, rotulo curto e o
#              significado forense/seguranca de cada um.
#
# WHY:         Existia uma copia deste mapa em src/exporters/html_report.py
#              (para desenhar o badge) e outra, escrita a mao e incompleta, em
#              src/exporters/web_assets.py (a barra de filtro do topo, so 11
#              botoes). As duas listas do mesmo fato ja tinham divergido antes
#              do F-201 (IMMUTABLE e DELETED tinham badge mas nenhum filtro) e
#              o F-201 ia repetir o erro, acrescentando 13 badges novos sem
#              filtro correspondente. A D-028 pede que cada indicador presente
#              venha com encaminhamento dito; um badge que ninguem consegue
#              isolar numa arvore de centenas de processos esta presente so
#              formalmente. A correcao e ter UMA lista: badge e filtro nascem
#              dela, e um sinal novo que entra aqui ganha os dois de graca.
#
# [2026-08-18] SIGNIFICADO: o Mario testou o popup de legenda dos badges e
#              perguntou o que cada um representa em termos de seguranca e
#              pericia, nao so o rotulo tecnico. Para os 13 badges que tem bit
#              correspondente em risk.SINAIS, o texto vem de LA (mesma fonte
#              que ja explica o sinal no popup do anomaly score, D-021):
#              escrever um SEGUNDO texto aqui, em paralelo, seria a mesma
#              classe de divergencia silenciosa que motivou este arquivo
#              existir. Os badges sem bit (SSH, SUDO, CONTAINER, EDR-WAIT) tem
#              texto proprio, escrito aqui, porque nao tem de onde puxar.
#
# NOTA:        "INSPECTOR" nao entra aqui: e um sinonimo de "EDR/AV" tratado
#              por substituicao de string antes do lookup (ver
#              html_report._render_badges), nunca uma chave own.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

from src.core import risk

# chave de risk.SINAIS -> explicacao (a MESMA que alimenta o popup do
# anomaly score). Fonte unica para os badges que tem bit correspondente.
_EXPLICACAO_POR_CHAVE_DE_RISCO = {
    chave: explicacao for _bit, chave, _rotulo, _sev, explicacao in risk.SINAIS
}


def _sig(chave_risco):
    """Significado forense de um badge que tem bit em risk.SINAIS."""
    return _EXPLICACAO_POR_CHAVE_DE_RISCO[chave_risco]


# chave (o valor em context_tags) -> (icone, classe css, rotulo curto,
# significado forense/seguranca).
TAG_MAP = {
    "SSH": ("🔌", "t-ssh", "Active SSH Connection",
            "Sessao SSH ativa. Rotina de administracao remota; o valor "
            "forense esta em cruzar QUEM entrou (loginuid) e QUANDO com o "
            "log de autenticacao do host, nao no badge isolado."),
    "SUDO": ("🛡️", "t-sudo", "Running via Sudo",
             "Rodando via sudo. Rotina de elevacao administrativa por si "
             "so; o insumo forense fica no PAR sudo+mudanca de credencial "
             "(badge CRED_CHANGE): sudo sem troca de uid registrada, ou "
             "troca de uid sem sudo/su na arvore de ancestrais, e o padrao "
             "que pede atencao (regra AM-001-L1, ainda nao implementada)."),
    "MINER": ("⛏️", "t-miner", "Crypto Mining Signature", _sig("gpu_miner")),
    "UNSAFE": ("☢️", "t-unsafe", "Unsafe Path (/tmp, /dev/shm)",
               _sig("unsafe_exec") + " Cobre tambem biblioteca carregada de "
               "diretorio nao confiavel (mesmo badge, dois caminhos de "
               "deteccao: linha de comando e mapas de memoria)."),
    "EDR/AV": ("💊", "t-edr", "Security Inspectors - EDR/AV", _sig("inspector")),
    "EDR-WAIT": ("🧊", "t-edr", "Process Frozen by EDR/AV (Wchan Wait)",
                 "Processo congelado aguardando decisao de um EDR/AV via "
                 "fanotify (o kernel PAUSA o processo ate o inspector "
                 "responder). Congelamento prolongado pode ser o proprio "
                 "EDR travado, ou um ataque de negacao de servico contra "
                 "ele: o incidente pode estar no inspector, nao no alvo."),
    "GPU": ("🕹️", "t-gpu", "Accessing GPU Resources", _sig("gpu_miner")),
    "CONTAINER": ("📦", "t-cont", "Containerized Process",
                  "Processo dentro de um contêiner (identificado pelo "
                  "cgroup). Isola do host, mas tambem e o ponto de partida "
                  "de toda fuga de contêiner: o proximo passo a checar e o "
                  "badge NS_CHANGE (setns/unshare) no mesmo processo ou "
                  "nos descendentes dele."),
    "ZOMBIE": ("🧟", "t-zombie", "Zombie Process", _sig("zombie")),
    "IMMUTABLE": ("🔒", "t-immutable", "Immutable File Attribute", _sig("immutable")),
    # O binario sumiu do disco enquanto o processo continua rodando. E um dos
    # sinais mais fortes que a arvore carrega: apagar o executavel apos a
    # execucao e tecnica corrente para nao deixar amostra para analise
    # (ATT&CK T1070.004).
    "DELETED": ("👻", "t-deleted",
                "Binario apagado do disco com o processo em execucao",
                _sig("deleted_exe")),
    # [F-201] Badges das 18 sondas eBPF de 2026-08-17. tcp_v6_connect e
    # sched_process_exit ficam fora deste mapa de proposito: nao entram em
    # anomaly_score/context_tags, sao dado puro exibido em outro lugar do
    # laudo (lista de conexoes, status de saida do processo).
    "CRED_CHANGE": ("🔑", "t-cred", "Mudanca de credencial (uid) via commit_creds",
                    _sig("cred_change")),
    "KMOD_LOAD": ("🧩", "t-kmod", "Carregou modulo de kernel (init_module/finit_module)",
                  _sig("kmod_load")),
    "NEW_LISTENER": ("👂", "t-listen", "Abriu porta de escuta (bind)",
                     _sig("new_listener")),
    "ACCEPTED_CONN": ("📥", "t-accept", "Aceitou conexao de entrada (inet_csk_accept)",
                      _sig("accepted_conn")),
    "MEM_ACCESS": ("🧠", "t-memacc", "Acessou memoria de outro processo (ptrace/process_vm_readv)",
                   _sig("mem_access")),
    "MEMFD_CREATE": ("🫥", "t-memfd", "Criou memoria de arquivo anonima (memfd_create)",
                     _sig("memfd_create")),
    "EXEC_MEM_GRANT": ("💣", "t-execmem", "Concedeu execucao a regiao de memoria (mprotect)",
                       _sig("exec_mem_grant")),
    "BPF_USE": ("🐝", "t-bpfuse", "Uso de eBPF por terceiro (bpf syscall)",
                _sig("bpf_use")),
    "FILE_DELETED": ("🗑️", "t-filedel", "Apagou arquivo (vfs_unlink)",
                     _sig("file_deleted")),
    "FILE_RENAMED": ("✏️", "t-filerename", "Renomeou arquivo (vfs_rename)",
                     _sig("file_renamed")),
    "NS_CHANGE": ("🚪", "t-nschange", "Mudou de namespace (setns/unshare)",
                  _sig("ns_change")),
    # [2026-08-20] Icone PROPRIO. Antes dividia o radioativo com UNSAFE, e o
    # Mario reportou o filtro KEXEC_LOAD como quebrado ao ver o mesmo simbolo
    # numa linha que nao tinha kexec nenhum. Dois sinais com o mesmo desenho
    # sao um sinal so aos olhos de quem le a tela.
    "KEXEC_LOAD": ("🐧", "t-kexec", "Carregou kernel via kexec_load", _sig("kexec_load")),
    "DNS_QUERY": ("🌐", "t-dns", "Consulta DNS observada", _sig("dns_query")),
    # [Lote 2] Sondas de 2026-08-19. SNI e o par do DNS (o mesmo "com quem",
    # por outro caminho); MOUNT_OP e PIVOT_ROOT sao o par de NS_CHANGE (a
    # segunda metade da fuga de conteiner). Icone proximo do parente de
    # proposito: quem ja aprendeu um reconhece o outro.
    "TLS_SNI": ("🔐", "t-sni", "Nome do destino em conexao TLS (SNI)",
                _sig("tls_sni")),
    "MOUNT_OP": ("🗄️", "t-mount", "Montou sistema de arquivos (mount)",
                 _sig("mount_op")),
    "PIVOT_ROOT": ("🌀", "t-pivot", "Trocou a raiz do sistema de arquivos (pivot_root)",
                   _sig("pivot_root")),
}

# Badges desenhados por caminho proprio em _render_badges (nao vem de uma
# unica chave em context_tags: NEW olha node.is_new, NET ERR soma
# tree_tcp_drops+tree_tcp_retrans). Ainda assim precisam de filtro, entao a
# barra os inclui MANUALMENTE em web_assets.py; aqui so documentamos a
# exclusao para quem for mexer nos dois lugares nao duplicar o botao.
TAGS_FORA_DO_MAPA = ("NEW", "NET ERR", "WARN", "ZOMBIE_PARENT")
