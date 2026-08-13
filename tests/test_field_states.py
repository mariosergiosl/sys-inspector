# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_field_states.py
# DESCRIPTION: D-020 -- todo campo do laudo sempre visivel, e os tres estados
#              nunca se confundem.
#
# WHY:         Ausencia e conclusao. Um laudo que omite o campo obriga o leitor
#              a deduzir, e as duas deducoes possiveis levam a lugares opostos:
#              "o host nao tinha" versus "a ferramenta nao olhou". A segunda
#              invalida qualquer conclusao tirada da ausencia.
#
#              O caso real: o FQDN sumia do bloco SYSTEM quando o host nao
#              tinha, e comparar dois laudos deu a leitura de que a coleta havia
#              regredido, quando o comportamento estava correto.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

from src.exporters.html_report import render_os_block, render_net_block


COMPLETO = {"hostname": "openSUSE", "fqdn": "openSUSE.lab",
            "hostnames": ["openSUSE", "openSUSE.lab", "leap"],
            "kernel": "6.4.0", "uptime": "6h", "os_pretty_name": "Leap 15.6"}
HW = {"cpu": "i9", "mem_mb": 7943}


# ------------------------------------------------------------------------------
# OS TRES ESTADOS
# ------------------------------------------------------------------------------
def test_valor_presente_aparece_normalmente():
    html = render_os_block(COMPLETO, HW, agent_uuid="abc-123")
    assert "openSUSE.lab" in html
    assert "abc-123" in html
    assert "7943 MB" in html


def test_campo_coletado_e_vazio_nao_some_da_tela():
    """O host nao tem FQDN: a linha continua, dizendo que nao havia."""
    dados = dict(COMPLETO, fqdn="")
    html = render_os_block(dados, HW)

    assert "FQDN" in html
    assert "nao havia valor" in html


def test_campo_nao_coletado_diz_que_nao_foi_coletado():
    """
    Laudo de agente antigo: o campo nem existe no dado. Isso e diferente de
    vazio, e a tela precisa dizer qual dos dois e.
    """
    dados = dict(COMPLETO)
    del dados["fqdn"]
    html = render_os_block(dados, HW)

    assert "FQDN" in html
    assert "nao coletado" in html


def test_os_dois_estados_de_ausencia_nao_se_confundem():
    """
    O mesmo campo, nos dois estados de ausencia, precisa produzir textos
    diferentes. Se produzissem o mesmo, a distincao existiria so no codigo.
    """
    vazio = render_os_block(dict(COMPLETO, fqdn=""), HW, agent_uuid="u")
    sem_chave = dict(COMPLETO)
    del sem_chave["fqdn"]
    ausente = render_os_block(sem_chave, HW, agent_uuid="u")

    assert "nao coletado" not in vazio
    assert "nao havia valor" in vazio
    assert "nao coletado" in ausente


def test_todo_campo_do_bloco_system_aparece_sempre():
    """Nem um dado sequer: o bloco continua com todas as linhas."""
    html = render_os_block({}, {})
    for rotulo in ("Hostname", "FQDN", "Other names", "Agent UUID", "Kernel",
                   "Uptime", "OS", "CPU", "Memory"):
        assert rotulo in html, rotulo


def test_uuid_ausente_nao_apaga_a_linha():
    html = render_os_block(COMPLETO, HW, agent_uuid=None)
    assert "Agent UUID" in html
    assert "nao coletado" in html


# ------------------------------------------------------------------------------
# TOPOLOGIA DE REDE
# ------------------------------------------------------------------------------
def test_host_sem_interfaces_diz_que_procurou():
    """
    Zero interfaces e observacao, nao falha. Comparando dois hosts, um tinha
    podman0 e o outro nao, e a leitura foi de topologia perdida.
    """
    html = render_net_block({"interfaces": [], "gateway": "10.0.0.1",
                             "dns": ["10.0.0.1"]})
    assert "nenhuma alem de loopback" in html


def test_interfaces_nao_coletadas_sao_declaradas():
    html = render_net_block({"gateway": "10.0.0.1"})
    assert "nao coletado" in html


def test_gateway_e_dns_vazios_nao_somem():
    html = render_net_block({"interfaces": [{"name": "eth0", "ip": "1.2.3.4"}]})
    assert "GW:" in html
    assert "DNS:" in html
    assert "nao havia valor" in html


def test_interface_sem_endereco_e_declarada():
    html = render_net_block({"interfaces": [{"name": "veth0", "ip": ""}]})
    assert "veth0" in html
    assert "sem endereco" in html


def test_bloco_de_rede_vazio_nao_quebra():
    assert render_net_block({})
    assert render_net_block(None)


# ------------------------------------------------------------------------------
# SEGURANCA
# ------------------------------------------------------------------------------
def test_os_valores_continuam_escapados():
    """O hostname vem do host inspecionado, que pode estar comprometido."""
    html = render_os_block({"hostname": "<script>x</script>"}, {})
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_nome_de_interface_e_escapado():
    html = render_net_block({"interfaces": [{"name": "<b>eth0", "ip": "1"}]})
    assert "<b>eth0" not in html
