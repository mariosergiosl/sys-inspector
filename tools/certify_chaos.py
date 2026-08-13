# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tools/certify_chaos.py
# DESCRIPTION: Le a captura decifrada de um agente numa janela de tempo e imprime,
#              em JSON, os SINAIS DETECTADOS: rotulos de processo, tecnicas ATT&CK,
#              fontes de achado, o maior anomaly score e o total de processos.
#
# WHY:         A certificacao do chaos precisa cruzar duas coisas: o que o cenario
#              RODOU (lido do chaos.log no agente) e o que a captura DETECTOU. Este
#              script produz o segundo lado, de forma auditavel: roda no servidor,
#              que e onde a chave privada decifra o bundle, e nao inventa nada -- so
#              relata o que a captura de fato contem.
#
# USAGE:       python3 certify_chaos.py <agent_uuid_prefix> <since_epoch>
#              Imprime uma linha JSON com os sinais detectados na captura mais
#              recente daquele agente dentro da janela.
#
# NOTES:       Compativel com Python 3.6. Sem dependencia alem do que o servidor
#              ja tem instalado (o pacote src).
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import sys
import json
import sqlite3

sys.path.insert(0, "/usr/lib/python3.6/site-packages")

from src.core.crypto import load_private_key, decrypt_data  # noqa: E402

DB = "/var/lib/sys-inspector/sys_inspector.db"
KEY = "/etc/sys-inspector/private_key.pem"


def _snapshots_in_window(conn, uuid_prefix, since):
    """Todas as capturas de um agente dentro da janela, da mais antiga."""
    return conn.execute(
        "SELECT id, agent_uuid, timestamp, json_blob FROM snapshots "
        "WHERE agent_uuid LIKE ? AND timestamp >= ? "
        "ORDER BY timestamp ASC",
        (uuid_prefix + "%", float(since))).fetchall()


def detected_signals(uuid_prefix, since):
    """
    Une os sinais detectados em TODAS as capturas da janela.

    A pergunta da certificacao e "esta capacidade foi detectada em algum momento
    da rodada?", nao "esta na ultima captura?". Uma so captura herda a
    fragilidade de timing: o artefato pode ter sido plantado depois dela ou
    limpo antes. Unir a janela responde a pergunta certa e nao depende de qual
    captura caiu por ultimo.

    Tudo e lido do dado decifrado, sem suposicao.
    """
    key = load_private_key(KEY)
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row

    rows = _snapshots_in_window(conn, uuid_prefix, since)
    if not rows:
        return {"found": False, "reason": "sem captura na janela"}

    tags = set()
    tecnicas = set()
    fontes = set()
    titulos = set()
    max_score = 0
    unsafe_cmds = 0
    lidas = 0
    max_procs = 0

    for row in rows:
        blob = json.loads(row["json_blob"]) if row["json_blob"] else None
        data = decrypt_data(blob, key) if blob else None
        if not data:
            continue
        lidas += 1
        procs = data.get("processes") or {}
        max_procs = max(max_procs, len(procs))
        for p in procs.values():
            if not isinstance(p, dict):
                continue
            for t in (p.get("context_tags") or []):
                tags.add(t)
            try:
                max_score = max(max_score, int(p.get("anomaly_score") or 0))
            except (TypeError, ValueError):
                pass
            cmd = (p.get("cmd") or "")
            if any(d in cmd for d in ("/tmp/", "/dev/shm/", "/var/tmp/")):
                unsafe_cmds += 1
        for f in (data.get("findings") or []):
            if f.get("technique"):
                tecnicas.add(f.get("technique"))
            if f.get("source"):
                fontes.add(f.get("source"))
            titulos.add((f.get("title") or "")[:60])

    return {
        "found": lidas > 0,
        "snapshots_in_window": len(rows),
        "snapshots_read": lidas,
        "processes_max": max_procs,
        "tags": sorted(tags),
        "max_score": max_score,
        "unsafe_cmdlines": unsafe_cmds,
        "techniques": sorted(tecnicas),
        "finding_sources": sorted(fontes),
        "finding_titles": sorted(t for t in titulos if t),
    }


def main():
    if len(sys.argv) < 3:
        print(json.dumps({"error": "uso: certify_chaos.py <uuid> <since>"}))
        return
    uuid_prefix = sys.argv[1]
    since = float(sys.argv[2])
    try:
        print(json.dumps(detected_signals(uuid_prefix, since)))
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"found": False, "error": str(exc)}))


if __name__ == "__main__":
    main()
