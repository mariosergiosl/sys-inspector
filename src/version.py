# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/version.py
# DESCRIPTION: A versao do produto, em um unico lugar.
#
# WHY:         A versao estava repetida no setup.py, no arquivo .spec e no
#              cabecalho de cada modulo, e ja tinha divergido em cinco valores
#              diferentes ao mesmo tempo. E a mesma classe de defeito que fez um
#              sinal detectado desaparecer na renderizacao: duas representacoes
#              do mesmo fato, mantidas em lugares distintos, que se afastam sem
#              nada denunciar.
#
#              Numa ferramenta forense a versao nao e detalhe de vitrine. O
#              laudo a carrega, e quem for reproduzir uma analise meses depois
#              precisa saber exatamente qual codigo a produziu. Uma versao
#              errada no laudo compromete a reproducao da pericia.
#
# NOTES:       Deliberadamente sem imports. E lido pelo setup.py durante o
#              empacotamento, quando as dependencias do projeto ainda nao estao
#              disponiveis, e qualquer import aqui quebraria a construcao do
#              pacote.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

__version__ = "1.0.1"

# Papeis de instalacao. O mesmo codigo-fonte serve aos tres; o que muda e o que
# cada maquina precisa ter instalado junto.
ROLE_AGENT = "agent"      # coleta no host inspecionado: precisa de eBPF
ROLE_SERVER = "server"    # recebe e apresenta: precisa de web, nunca de eBPF
ROLE_COMMON = "common"    # modelo de dados, criptografia, custodia
