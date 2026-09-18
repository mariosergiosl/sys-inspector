/*
 * ========================================================================================
 * FILE: tools/rootkit_demo/sysinspector_demo_hide.c
 * DESCRIPTION: Modulo de kernel DIDATICO que exercita a camada S5 do coletor de
 *              rootkit (C-037): um modulo que se retira da lista de modulos e
 *              continua carregado.
 *
 * PARA QUE EXISTE:
 *   O coletor src/collectors/rootkit.py cruza tres fontes da mesma lista de
 *   modulos e denuncia a divergencia. Quatro das cinco camadas dele tem artefato
 *   de espaco de usuario no chaos_maker. A camada S5 -- modulo ATIVAMENTE
 *   escondido -- nao tem, e nao pode ter: esconder um modulo da lista do kernel
 *   exige codigo rodando DENTRO do kernel. Nao existe script capaz de produzir
 *   essa divergencia de fora.
 *
 *   A regra do projeto (D-025) e que o cenario de teste prova o que o detector
 *   foi programado para pegar. Para esta camada, o unico jeito de cumprir a
 *   regra e este arquivo.
 *
 * O QUE ELE FAZ, E SO ISSO:
 *   Remove a PROPRIA entrada da lista encadeada de modulos do kernel, espera N
 *   segundos, e se recoloca. Nada mais.
 *
 * O QUE ELE NAO FAZ (deliberado, e o que o separa de um rootkit de verdade):
 *   - nao intercepta nenhuma syscall, nao altera nenhuma tabela do kernel;
 *   - nao esconde processo, arquivo, porta, conexao nem usuario;
 *   - nao concede privilegio a ninguem, nao tem porta de entrada, nao tem
 *     gatilho, nao escuta rede;
 *   - nao persiste: nao se instala em lugar nenhum, nao sobrevive ao reboot;
 *   - nao esconde o proprio objeto em /sys/module, DE PROPOSITO -- e justamente
 *     por manter esse rastro que ele e detectavel, e que consegue voltar.
 *
 *   Ele e um alvo de tiro, nao uma arma: reproduz UM sintoma, o suficiente para
 *   provar que o detector acende, e nada do que faria dele util para outra
 *   coisa.
 *
 * REVERSIBILIDADE:
 *   Enquanto escondido, `rmmod` NAO o encontra (rmmod procura na mesma lista da
 *   qual ele saiu). Por isso ele se recoloca sozinho, por temporizador, depois
 *   de `hide_seconds`. Sem esse temporizador o modulo ficaria carregado ate o
 *   reboot, o que transformaria um teste em sujeira permanente na VM.
 *
 * CUSTO QUE ELE DEIXA (e que precisa ser dito antes de carregar):
 *   O kernel fica TINGIDO ate o proximo boot, com os bits O (fora da arvore) e
 *   E (nao assinado). Isso e irreversivel sem reiniciar, e vai fazer a propria
 *   camada S4 do coletor acusar o host pelo resto da sessao. Em VM de teste isso
 *   e aceitavel e ate util; em qualquer outro host, nao.
 *
 * RISCO TECNICO, DITO DE FRENTE:
 *   A manipulacao da lista de modulos e feita sem tomar `module_mutex`, que o
 *   kernel nao exporta para modulos. Se outro modulo for carregado ou
 *   descarregado no MESMO instante, a lista pode corromper e derrubar o kernel.
 *   Numa VM de teste ociosa a chance e remota; num host com carga, nao se carrega
 *   isto. Esta e a razao de o chaos_maker exigir uma opcao propria e nunca
 *   incluir este artefato em --all.
 *
 * USO:
 *   make
 *   sudo insmod sysinspector_demo_hide.ko hide_seconds=60
 *   # o modulo some de lsmod; /sys/module/sysinspector_demo_hide continua la
 *   # ... rodar a captura aqui ...
 *   # apos hide_seconds ele reaparece:
 *   sudo rmmod sysinspector_demo_hide
 *
 * AUTHOR: Mario Luz (Sys-Inspector Project)
 * VERSION: 1.0
 * CREATED: 2026-08-19
 * ========================================================================================
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/timer.h>
#include <linux/jiffies.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mario Luz (Sys-Inspector Project)");
MODULE_DESCRIPTION("Artefato de TESTE do sys-inspector: esconde a si mesmo da "
                   "lista de modulos por N segundos, para provar a deteccao. "
                   "Nao intercepta nada, nao esconde mais nada, nao persiste.");
MODULE_VERSION("1.0");

static int hide_seconds = 60;
module_param(hide_seconds, int, 0444);
MODULE_PARM_DESC(hide_seconds,
                 "Segundos escondido antes de reaparecer sozinho. Enquanto "
                 "escondido o modulo nao pode ser removido, porque rmmod o "
                 "procura na mesma lista da qual ele saiu.");

/* Vizinho anterior na lista, guardado para saber onde voltar. */
static struct list_head *vizinho_anterior;
static bool escondido;
static struct timer_list temporizador;

static void esconde(void)
{
    if (escondido)
        return;
    vizinho_anterior = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    escondido = true;
    pr_info("sysinspector_demo_hide: escondido da lista de modulos por %ds. "
            "O objeto em /sys/module continua visivel de proposito.\n",
            hide_seconds);
}

static void reaparece(void)
{
    if (!escondido)
        return;
    list_add(&THIS_MODULE->list, vizinho_anterior);
    escondido = false;
    pr_info("sysinspector_demo_hide: de volta a lista de modulos. "
            "Ja pode remover com rmmod.\n");
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
static void ao_expirar(struct timer_list *t)
#else
static void ao_expirar(unsigned long dado)
#endif
{
    reaparece();
}

static int __init demo_init(void)
{
    if (hide_seconds < 1)
        hide_seconds = 1;
    if (hide_seconds > 600)
        hide_seconds = 600;   /* teto: isto e um teste, nao uma instalacao */

    pr_warn("sysinspector_demo_hide: ARTEFATO DE TESTE carregado. O kernel fica "
            "tingido (O+E) ate o proximo boot.\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
    timer_setup(&temporizador, ao_expirar, 0);
#else
    setup_timer(&temporizador, ao_expirar, 0);
#endif
    mod_timer(&temporizador, jiffies + msecs_to_jiffies(hide_seconds * 1000));

    esconde();
    return 0;
}

static void __exit demo_exit(void)
{
    del_timer_sync(&temporizador);
    reaparece();
    pr_info("sysinspector_demo_hide: descarregado.\n");
}

module_init(demo_init);
module_exit(demo_exit);
