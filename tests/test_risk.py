# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_risk.py
# DESCRIPTION: A leitura do anomaly_score como campo de bits.
#
# WHY:         O teste que importa aqui nao e o de formatacao, e o de INVERSAO:
#              enquanto o score era lido como magnitude, um processo defunto
#              valia mais que um binario apagado executando de /dev/shm. Os casos
#              abaixo travam essa relacao.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import pytest

from src.core import risk
from src.core.findings import (SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH,
                               SEV_CRITICAL)


# ------------------------------------------------------------------------------
# A TABELA NAO PODE DIVERGIR DA ORIGEM
# ------------------------------------------------------------------------------
def test_bits_batem_com_o_coletor():
    """
    Os bits declarados aqui sao os mesmos que o coletor atribui.

    Duas listas do mesmo fato divergindo em silencio ja custou caro neste
    projeto mais de uma vez. Este teste e a trava: mexer no coletor sem mexer na
    leitura quebra aqui, e nao no laudo de alguem.
    """
    pt = pytest.importorskip("src.collectors.process_tree")

    origem = {
        "unsafe_lib": pt.SCORE_UNSAFE_LIB,
        "unsafe_exec": pt.SCORE_MALWARE,
        "net_tool": pt.SCORE_NET_TOOL,
        "deleted_exe": pt.SCORE_DELETED,
        "inspector": pt.SCORE_INSPECTOR,
        "gpu_miner": pt.SCORE_GPU,
        "net_error": pt.SCORE_NET_ISSUE,
        "zombie": pt.SCORE_ZOMBIE,
        "immutable": pt.SCORE_IMMUTABLE,
        # [F-201] Sinais das 18 sondas eBPF de 2026-08-17.
        "cred_change": pt.SCORE_CRED_CHANGE,
        "kmod_load": pt.SCORE_KMOD_LOAD,
        "new_listener": pt.SCORE_NEW_LISTENER,
        "accepted_conn": pt.SCORE_ACCEPTED_CONN,
        "mem_access": pt.SCORE_MEM_ACCESS,
        "memfd_create": pt.SCORE_MEMFD_CREATE,
        "exec_mem_grant": pt.SCORE_EXEC_MEM_GRANT,
        "bpf_use": pt.SCORE_BPF_USE,
        "file_deleted": pt.SCORE_FILE_DELETED,
        "file_renamed": pt.SCORE_FILE_RENAMED,
        "ns_change": pt.SCORE_NS_CHANGE,
        "kexec_load": pt.SCORE_KEXEC_LOAD,
        "dns_query": pt.SCORE_DNS_QUERY,
        # [Lote 2] Sondas de 2026-08-19.
        "tls_sni": pt.SCORE_TLS_SNI,
        "mount_op": pt.SCORE_MOUNT_OP,
        "pivot_root": pt.SCORE_PIVOT_ROOT,
    }

    aqui = dict((chave, bit) for bit, chave, _r, _s, _e in risk.SINAIS)
    assert aqui == origem


# ------------------------------------------------------------------------------
# DECODIFICACAO
# ------------------------------------------------------------------------------
def test_score_zero_nao_produz_sinal_nem_nivel():
    assert risk.decode(0) == []
    assert risk.level(0) is None
    assert risk.summary(0) == ""


def test_score_invalido_nao_derruba_a_leitura():
    for valor in (None, "", "abc", [], {}):
        assert risk.decode(valor) == []
        assert risk.level(valor) is None


def test_decode_devolve_cada_bit_ligado():
    chaves = [s["key"] for s in risk.decode(2 + 8)]
    assert set(chaves) == {"unsafe_exec", "deleted_exe"}


def test_decode_ordena_do_que_mais_pesa_para_o_que_menos():
    sinais = risk.decode(2 + 128)   # caminho gravavel + defunto
    assert sinais[0]["key"] == "unsafe_exec"
    assert sinais[-1]["key"] == "zombie"


# ------------------------------------------------------------------------------
# A INVERSAO QUE MOTIVOU O MODULO
# ------------------------------------------------------------------------------
def test_defunto_sozinho_e_informativo_e_nao_critico():
    """128 era o maior numero da tabela, e por isso virava o pior caso."""
    assert risk.level(128) == SEV_INFO
    assert risk.needs_attention(128) is False


def test_binario_apagado_em_diretorio_gravavel_pede_atencao():
    """
    2 + 8 = 10 ficava abaixo do limiar 70 e era exibido como brando, embora
    descreva a assinatura que motiva resposta a incidente.
    """
    assert risk.needs_attention(2 + 8) is True
    assert risk.rank(2 + 8) > risk.rank(128)


def test_dois_sinais_de_peso_elevam_um_degrau():
    assert risk.level(2) == SEV_HIGH
    assert risk.level(8) == SEV_HIGH
    assert risk.level(2 + 8) == SEV_CRITICAL


def test_sinal_fraco_nao_eleva_sinal_forte():
    """Falha de rede e defunto sao ruido; nao promovem nada."""
    assert risk.level(2 + 64 + 128) == SEV_HIGH


def test_dois_sinais_fracos_nao_escalam():
    assert risk.level(4 + 64) == SEV_LOW


def test_edr_sozinho_nao_e_suspeita():
    assert risk.level(16) == SEV_INFO
    assert risk.needs_attention(16) is False


def test_dois_medios_viram_alto():
    assert risk.level(32) == SEV_MEDIUM
    assert risk.level(256) == SEV_MEDIUM
    assert risk.level(32 + 256) == SEV_HIGH


# ------------------------------------------------------------------------------
# APRESENTACAO
# ------------------------------------------------------------------------------
def test_summary_nomeia_todos_os_sinais():
    texto = risk.summary(2 + 8)
    assert "gravavel" in texto
    assert "apagado" in texto
    assert "+" in texto


def test_cor_de_score_sem_sinal_e_neutra():
    assert risk.color(0) == "#555"
    assert risk.color(2) == risk.CORES[SEV_HIGH]


def test_toda_severidade_tem_cor():
    for _bit, _chave, _rotulo, severidade, _exp in risk.SINAIS:
        assert severidade in risk.CORES


def test_toda_explicacao_esta_preenchida():
    """Rotulo sem explicacao obriga o leitor a deduzir, que e o que D-020 veda."""
    for _bit, chave, rotulo, _sev, explicacao in risk.SINAIS:
        assert rotulo and explicacao, chave
        assert len(explicacao) > 40, chave


# ------------------------------------------------------------------------------
# SINAL NOVO NAO PODE SUMIR
# ------------------------------------------------------------------------------
def test_bit_desconhecido_e_denunciado():
    """
    Um bit novo no coletor tem que aparecer como desconhecido, e nao ser
    descartado em silencio: sinal perdido sem rastro leva o analista a concluir
    que nao havia nada.
    """
    # O bit e CALCULADO a partir da propria tabela, e nao escrito a mao.
    # A versao anterior fixava 4194304 ("acima de todos os conhecidos hoje") e
    # quebrou no primeiro sinal novo que ocupou esse bit, no Lote 2. Um teste
    # que envelhece assim ensina a errada: o proximo mantenedor troca o numero
    # e segue, quando a pergunta que o teste faz ("um bit que ninguem conhece e
    # denunciado?") nao depende de numero nenhum.
    livre = max(bit for bit, _c, _r, _s, _e in risk.SINAIS) << 1
    assert risk.unknown_bits(livre) == livre
    assert risk.unknown_bits(2 + 8) == 0


# ------------------------------------------------------------------------------
# F-201: SINAIS DAS 18 SONDAS DE 2026-08-17
# ------------------------------------------------------------------------------
def test_kexec_sozinho_e_critico():
    """
    kexec_load troca o kernel em execucao. E o unico sinal desta tabela que,
    sozinho, ja justifica o nivel mais alto da escala.
    """
    assert risk.level(1048576) == SEV_CRITICAL
    assert risk.needs_attention(1048576) is True


def test_dns_query_sozinho_e_informativo():
    """Consulta DNS e insumo (C-038, ainda nao implementado), nao suspeita."""
    assert risk.level(2097152) == SEV_INFO
    assert risk.needs_attention(2097152) is False


def test_mem_access_e_ns_change_sao_altos_e_escalam_juntos():
    """
    ptrace/process_vm_readv em outro pid + fuga de namespace no mesmo
    processo descreve mais que a soma das partes.
    """
    assert risk.level(8192) == SEV_HIGH
    assert risk.level(524288) == SEV_HIGH
    assert risk.level(8192 + 524288) == SEV_CRITICAL


def test_delete_e_rename_de_arquivo_sao_baixos_sozinhos():
    """
    Alto volume normal (rm, mv, gerenciador de pacote); o julgamento fino
    fica para a regra do Lote 3, nao para F-201.
    """
    assert risk.level(131072) == SEV_LOW
    assert risk.level(262144) == SEV_LOW


def test_cred_change_sozinho_e_apenas_informativo():
    """
    commit_creds dispara em todo sudo/su/binario setuid/servico que larga
    privilegio ao subir -- e o caso mais comum do host, nao a excecao. O
    discriminante que separa rotina de escalada e a AUSENCIA de mediador
    legitimo na arvore de ancestrais (AM-001-L1), nao este bit.
    """
    assert risk.level(512) == SEV_INFO
    assert risk.needs_attention(512) is False


def test_sudo_com_ld_preload_imutavel_nao_escala_por_causa_do_cred_change():
    """
    Regressao (achado do Mario): com cred_change em MEDIUM, todo sudo (512)
    combinado com QUALQUER outro sinal MEDIUM do host -- por exemplo
    ld.so.preload marcado imutavel (256, "immutable") -- escalava sozinho
    para HIGH pela regra de coincidencia, mesmo sem indicio nenhum de
    escalada de privilegio de fato. cred_change em INFO tira o sudo de
    dentro dessa contagem: o nivel deve continuar sendo o do sinal real
    (immutable, MEDIUM), sem o degrau extra.
    """
    so_immutable = risk.level(256)
    com_sudo = risk.level(256 + 512)
    assert so_immutable == SEV_MEDIUM
    assert com_sudo == SEV_MEDIUM
    assert com_sudo == so_immutable


def test_memfd_create_sozinho_e_baixo():
    """
    memfd_create e uso corrente de software legitimo (systemd, navegadores,
    IPC via shared-memory); so a EXECUCAO a partir dai (sinal proprio,
    ja existente) e que pesa.
    """
    assert risk.level(16384) == SEV_LOW


def test_conexao_v6_e_fim_de_processo_nao_tem_sinal_proprio():
    """
    tcp_v6_connect e sched_process_exit sao dado renderizado em outro lugar
    do laudo (lista de conexoes, status de saida), nunca bit de anomaly_score.
    """
    chaves = {chave for _bit, chave, _r, _s, _e in risk.SINAIS}
    assert "tcp_v6_connect" not in chaves
    assert "process_exit" not in chaves
    assert "sched_process_exit" not in chaves
