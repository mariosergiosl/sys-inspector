# =======================================================================
# FILE:         tools/rootkit_demo/Makefile
# DESCRIPTION:  Compila o artefato de teste do coletor de rootkit (C-037).
#               Exige headers do kernel em execucao (kernel-devel) e gcc.
#               NAO e compilado nem instalado por nenhum pacote do projeto:
#               a compilacao e um passo manual e deliberado, porque o
#               resultado tinge o kernel do host que o carregar.
# AUTHOR:       Mario Luz
# VERSION:      1.0
# CREATED:      2026-08-19
# =======================================================================

obj-m += sysinspector_demo_hide.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
