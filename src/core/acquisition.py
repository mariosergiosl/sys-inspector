# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/core/acquisition.py
# DESCRIPTION: Aquisicao DIRIGIDA de evidencia (C-043): o minimo que impede a
#              evidencia de evaporar entre o instante em que a frota aponta o
#              host e o instante em que o perito chega nele.
#
# WHY:         Hoje a ferramenta escreve, no achado de memoria gravavel-e-
#              executavel: "capturar a memoria do processo ANTES de qualquer
#              acao: encerra-lo apaga exatamente o conteudo que provaria a
#              injecao". E nao faz nada. O achado sai com custodia "nada
#              preservado". Quando o perito chega, o processo morreu, o binario
#              sumiu, e sobra o laudo AFIRMANDO que havia algo ali.
#
# BOUNDARY:    A D-032 fixa o que este modulo pode e nao pode fazer, e a regra
#              nao e "quanto couber": coleta de massa nao e trabalho desta
#              ferramenta. Nem gigabytes de memoria, nem gigabytes de trafego,
#              nem copia integral de artefato grande. Coleta-se o maximo
#              necessario para DUAS finalidades, e nada alem delas:
#
#                1. IDENTIFICAR: reconhecer que existe um padrao, e qual;
#                2. DIRECIONAR: dizer qual e o objeto e que analise o conclui.
#
#              A prova e atividade de bancada (coleta massiva, decifragem,
#              analise manual ou assistida), e para isso ja existem ferramentas
#              excelentes. Disputar esse espaco tiraria esta ferramenta do
#              trabalho que so ela faz, que e olhar a frota inteira.
#
# THREE PARTS: Para todo objeto adquirido, nesta ordem de prioridade:
#              - HASH do objeto inteiro: identidade sem transportar conteudo;
#              - METADADOS: onde estava, de quem era, desde quando;
#              - RECORTE pequeno, com teto: sustenta a leitura do PADRAO (e um
#                ELF? e shellcode? tem string de comando e controle?).
#
# NEVER LIE:   Todo teto atingido vira campo declarado, nunca truncagem muda.
#              Recorte cortado sem aviso e pior que recorte ausente: o leitor
#              supoe que viu o artefato inteiro (D-020). Por isso todo retorno
#              carrega o que foi feito E o que deixou de ser feito.
#
# OFF BY DEF:  Desligada por padrao. Ligar muda o comportamento de um agente em
#              campo (passa a escrever no host medido), e essa e uma decisao de
#              quem opera, nao um efeito colateral de atualizar a ferramenta.
#
# NOTES:       Compativel com Python 3.6. Sem dependencia de coletor: entra
#              caminho ou par (pid, regiao) e sai dict de custodia.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import stat
import time
import base64
import hashlib
import logging

from src.core.findings import (CUSTODY_NONE, CUSTODY_HASH, CUSTODY_FULL)

LOG = logging.getLogger("Acquisition")

# Tetos padrao. Escolhidos para caber no store-and-forward sem negociacao: uma
# captura inteira com varios achados continua sendo um payload de rede comum.
PADRAO = {
    "enabled": False,
    # Recorte por artefato. 4 KB pegam com folga o cabecalho ELF, o inicio de um
    # shellcode e as primeiras strings, que e o que responde "que padrao e este".
    "excerpt_bytes": 4096,
    # Acima disto, o hash passa a ser do RECORTE e nao do objeto inteiro. Existe
    # porque hash e barato em espaco mas nao em LEITURA: varrer um objeto enorme
    # no host medido custa I/O que ninguem pediu.
    "hash_max_bytes": 16 * 1024 * 1024,
    # Copia integral so para artefato pequeno (o caso CUSTODY_FULL da D-032).
    "copy_max_bytes": 262144,
    # Orcamento da CAPTURA inteira. Sem ele, um host com 200 achados adquire 200
    # vezes o teto individual, e o teto individual perde a funcao.
    "capture_max_bytes": 4 * 1024 * 1024,
    "dir": "/var/lib/sys-inspector/acquired",
}

# Motivos de nao ter adquirido. Sao dados do laudo, nao mensagens de erro: cada
# um deles responde "por que nao ha evidencia preservada aqui".
NAO_LIGADA = "aquisicao desligada na configuracao deste agente"
SEM_ORCAMENTO = "orcamento de aquisicao da captura esgotado"
ILEGIVEL = "objeto nao pode ser lido pelo agente"
# Motivo PROPRIO, e nao ILEGIVEL: "o alvo nao e um arquivo comum" e uma resposta
# diferente de "nao consegui ler". A primeira diz que nao havia amostra a
# preservar; a segunda diz que havia e a leitura falhou. O laudo precisa
# distinguir as duas (D-020).
NAO_E_ARQUIVO_COMUM = "o alvo existe mas nao e um arquivo comum"

# O_NONBLOCK nao existe no Windows. Ausente, vale zero e a guarda de tipo
# continua valendo -- ela e a defesa principal; o sinalizador e a segunda.
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


class ObjetoNaoRegular(OSError):
    """O alvo existe, foi aberto, e nao e um arquivo comum."""


def _abre_regular(caminho):
    """
    Abre um arquivo COMUM para leitura, sem risco de pendurar o agente.

    Duas guardas, necessarias por motivos diferentes:

    - S_ISREG: FIFO, socket e dispositivo nao sao amostra de coisa alguma, e
      abrir um FIFO sem escritor BLOQUEIA INDEFINIDAMENTE. O caminho chega aqui,
      em todos os chamadores, de conteudo escrito pelo ATACANTE: o coletor de
      rootkit le /etc/ld.so.preload (cujo conteudo hostil e a premissa do
      proprio achado) e a forense de memoria le caminhos de /proc/PID/maps.
      Sem esta guarda, um `mkfifo /tmp/x` mais uma linha no ld.so.preload
      desligam o agente: ele trava no meio da captura, para de coletar e para de
      entregar. E o agente que emudece da D-015, causado pelo proprio detector,
      que e o pior desfecho possivel -- a ferramenta vira o vetor.

    - O_NONBLOCK: fecha a corrida entre conferir e abrir. Entre o stat e o open
      o atacante pode trocar o arquivo comum por um FIFO; com o sinalizador a
      abertura retorna na hora em vez de pendurar.

    A conferencia de tipo e refeita no DESCRITOR ja aberto (fstat), e nao apenas
    no caminho, porque e o descritor que sera lido -- conferir o caminho e ler
    outra coisa e exatamente a brecha que a corrida acima explora.
    """
    fd = os.open(caminho, os.O_RDONLY | _O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ObjetoNaoRegular(caminho)
    except Exception:
        os.close(fd)
        raise
    return os.fdopen(fd, "rb"), st


def _config_de(config):
    """Le a secao forensics.acquisition da configuracao, com os padroes."""
    valores = dict(PADRAO)
    try:
        secao = (config or {}).get("forensics", {}).get("acquisition", {}) or {}
    except AttributeError:
        secao = {}
    for chave in PADRAO:
        if chave in secao and secao[chave] is not None:
            valores[chave] = secao[chave]
    return valores


class Acquirer(object):
    """
    Executa a aquisicao dirigida dentro dos tetos declarados.

    Uma instancia por CAPTURA: o orcamento total e por captura, e um objeto de
    vida longa acumularia gasto entre capturas e desligaria a aquisicao sozinho
    depois de algumas horas, silenciosamente. Esse e exatamente o tipo de falha
    que este projeto ja pagou uma vez (o agente que emudece, D-015).
    """

    def __init__(self, config=None):
        self.cfg = _config_de(config)
        self.enabled = bool(self.cfg.get("enabled"))
        self.gasto = 0
        self._dir_pronto = False

    # --------------------------------------------------------------------------
    # ESTADO
    # --------------------------------------------------------------------------
    def _sem_aquisicao(self, motivo, extra=None):
        """
        Custodia de um objeto que NAO foi adquirido, com o motivo declarado.

        Devolve dict em vez de None de proposito: o laudo precisa poder dizer
        "nao foi coletado" com a razao, que e diferente de "nada havia" (D-020).
        """
        base = {"level": CUSTODY_NONE, "acquired": False, "reason": motivo}
        if extra:
            base.update(extra)
        return base

    def _orcamento_disponivel(self):
        return max(0, int(self.cfg["capture_max_bytes"]) - self.gasto)

    def _garante_dir(self):
        if self._dir_pronto:
            return True
        try:
            if not os.path.isdir(self.cfg["dir"]):
                os.makedirs(self.cfg["dir"], 0o700)
            self._dir_pronto = True
        except OSError as exc:
            LOG.error("[ACQ] Diretorio de aquisicao indisponivel (%s): %s",
                      self.cfg["dir"], exc)
            self._dir_pronto = False
        return self._dir_pronto

    # --------------------------------------------------------------------------
    # NUCLEO: HASH DO INTEIRO + RECORTE
    # --------------------------------------------------------------------------
    def _digere(self, leitor, tamanho):
        """
        Hash do objeto e recorte do inicio, numa passada so.

        PARAMETER leitor: funcao(n) -> bytes, ja posicionada no inicio do objeto.
        PARAMETER tamanho: tamanho conhecido do objeto, ou 0 quando desconhecido.

        Devolve (sha256, escopo_do_hash, recorte, lidos). Escopo "full" significa
        que o hash cobre o objeto inteiro e portanto identifica; "excerpt"
        significa que ele cobre apenas o recorte, e o laudo TEM que dizer isso,
        senao um hash parcial e lido como se identificasse o objeto todo.
        """
        teto_hash = int(self.cfg["hash_max_bytes"])
        teto_recorte = int(self.cfg["excerpt_bytes"])
        escopo = "full"
        if tamanho and tamanho > teto_hash:
            escopo = "excerpt"

        h = hashlib.sha256()
        recorte = b""
        lidos = 0
        limite = teto_recorte if escopo == "excerpt" else teto_hash
        while lidos < limite:
            pedaco = leitor(min(65536, limite - lidos))
            if not pedaco:
                break
            h.update(pedaco)
            if len(recorte) < teto_recorte:
                recorte += pedaco[:teto_recorte - len(recorte)]
            lidos += len(pedaco)
        return h.hexdigest(), escopo, recorte, lidos

    # --------------------------------------------------------------------------
    # ARQUIVO
    # --------------------------------------------------------------------------
    def acquire_file(self, caminho, copiar=True):
        """
        Adquire um arquivo suspeito: hash do inteiro, metadados e recorte.

        A copia integral so acontece quando o arquivo cabe no teto de copia. Um
        binario pequeno cabe e vira CUSTODY_FULL, que e o caso em que o perito
        recebe a amostra e nao precisa voltar ao host (que pode ja nao existir).
        """
        if not self.enabled:
            return self._sem_aquisicao(NAO_LIGADA)
        try:
            st = os.stat(caminho)
        except OSError as exc:
            return self._sem_aquisicao(ILEGIVEL, {"error": str(exc),
                                                  "path": caminho})

        # Guarda de TIPO antes de qualquer abertura. Ver _abre_regular: o
        # caminho vem de conteudo escrito pelo atacante, e um FIFO aqui pendura
        # o agente para sempre. Recusar cedo evita ate o custo de abrir.
        if not stat.S_ISREG(st.st_mode):
            return self._sem_aquisicao(NAO_E_ARQUIVO_COMUM,
                                       {"path": caminho,
                                        "mode": oct(st.st_mode & 0o170000)})

        disponivel = self._orcamento_disponivel()
        if disponivel <= 0:
            return self._sem_aquisicao(SEM_ORCAMENTO, {"path": caminho})

        try:
            fh, st = _abre_regular(caminho)
            try:
                sha, escopo, recorte, lidos = self._digere(fh.read, st.st_size)
            finally:
                fh.close()
        except ObjetoNaoRegular:
            # O alvo trocou de tipo entre o stat e a abertura: a corrida existe,
            # e o descritor ja aberto foi quem disse a verdade.
            return self._sem_aquisicao(NAO_E_ARQUIVO_COMUM, {"path": caminho})
        except (IOError, OSError) as exc:
            return self._sem_aquisicao(ILEGIVEL, {"error": str(exc),
                                                  "path": caminho})

        self.gasto += len(recorte)
        custodia = {
            "level": CUSTODY_HASH,
            "acquired": True,
            "path": caminho,
            "size": st.st_size,
            "sha256": sha,
            "hash_scope": escopo,
            "hash_bytes": lidos,
            "mtime": int(st.st_mtime),
            "ctime": int(st.st_ctime),
            "uid": st.st_uid,
            "mode": oct(st.st_mode & 0o7777),
            "excerpt_b64": base64.b64encode(recorte).decode("ascii"),
            "excerpt_bytes": len(recorte),
            "truncated": bool(st.st_size > len(recorte)),
            "acquired_at": int(time.time()),
        }

        cabe_na_copia = (copiar
                         and st.st_size <= int(self.cfg["copy_max_bytes"])
                         and st.st_size <= disponivel)
        if cabe_na_copia and self._garante_dir():
            destino = os.path.join(
                self.cfg["dir"], "%s-%s" % (sha[:16],
                                            os.path.basename(caminho) or "obj"))
            try:
                # A copia reabre o alvo, entao repete a guarda: entre a leitura
                # do hash e esta linha o atacante teve outra janela para trocar
                # o arquivo por um FIFO.
                origem, _st_copia = _abre_regular(caminho)
                try:
                    with open(destino, "wb") as saida:
                        saida.write(origem.read(int(self.cfg["copy_max_bytes"])))
                finally:
                    origem.close()
                os.chmod(destino, 0o400)
                custodia["level"] = CUSTODY_FULL
                custodia["copy_path"] = destino
                self.gasto += st.st_size
            except (IOError, OSError) as exc:
                # ObjetoNaoRegular herda de OSError e cai aqui de proposito: a
                # copia falhar NAO invalida a aquisicao, porque o hash e o
                # recorte ja estao em maos. Mas nao pode passar em silencio,
                # senao o laudo promete uma copia que nao existe.
                LOG.error("[ACQ] Copia de %s falhou: %s", caminho, exc)
                custodia["copy_error"] = str(exc)

        return custodia

    # --------------------------------------------------------------------------
    # REGIAO DE MEMORIA
    # --------------------------------------------------------------------------
    def acquire_memory_region(self, pid, inicio, fim):
        """
        Adquire a regiao de memoria que a ferramenta JA sinalizou.

        Este e o ponto exato em que a D-027 trocou LiME por aquisicao dirigida:
        nao se adquire "a memoria do processo", se adquire A REGIAO que um
        detector apontou (hoje, a regiao gravavel-e-executavel). Sem modulo de
        kernel, sem gcc, sem parar o processo: so leitura de /proc/PID/mem, o
        mesmo principio de nao interferir no objeto sob analise que o modulo de
        forense de memoria ja segue.

        PARAMETER inicio, fim: em hexadecimal, como aparecem em /proc/PID/maps.
        """
        if not self.enabled:
            return self._sem_aquisicao(NAO_LIGADA)
        regiao = "%s-%s" % (inicio, fim)
        try:
            ini = int(str(inicio), 16)
            f = int(str(fim), 16)
        except (TypeError, ValueError):
            return self._sem_aquisicao(ILEGIVEL, {"region": regiao})
        tamanho = max(0, f - ini)
        if not tamanho:
            return self._sem_aquisicao(ILEGIVEL, {"region": regiao})

        if self._orcamento_disponivel() <= 0:
            return self._sem_aquisicao(SEM_ORCAMENTO, {"region": regiao})

        try:
            with open("/proc/%d/mem" % int(pid), "rb", 0) as fh:
                fh.seek(ini)
                sha, escopo, recorte, lidos = self._digere(fh.read, tamanho)
        except (IOError, OSError, ValueError) as exc:
            # Processo que terminou, regiao desmapeada, ou permissao negada.
            # Nenhum dos tres e evidencia de coisa alguma, mas todos precisam
            # aparecer no laudo: "nao consegui ler" nao e "nao havia nada".
            return self._sem_aquisicao(ILEGIVEL,
                                       {"error": str(exc), "pid": int(pid),
                                        "region": regiao})

        self.gasto += len(recorte)
        return {
            "level": CUSTODY_HASH,
            "acquired": True,
            "pid": int(pid),
            "region": regiao,
            "size": tamanho,
            "sha256": sha,
            "hash_scope": escopo,
            "hash_bytes": lidos,
            "excerpt_b64": base64.b64encode(recorte).decode("ascii"),
            "excerpt_bytes": len(recorte),
            "truncated": bool(tamanho > len(recorte)),
            "acquired_at": int(time.time()),
        }
