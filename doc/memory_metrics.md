# Entendendo Métricas de Memória no Linux (VSZ vs RSS)

Ao analisar processos como o `libuv-worker` (VSCode Server) ou Java, é comum observar discrepâncias enormes entre a memória "alocada" e a memória "usada". O sys-inspector diferencia ambas:

## 1. VSZ (Virtual Memory Size)
* **Definição:** É o total de memória virtual que o processo pode acessar. Inclui:
    * Código do programa.
    * Bibliotecas compartilhadas (libc, etc).
    * Memória alocada mas não usada (mallocs preventivos).
    * Arquivos mapeados em memória.
* **Cenário VSCode:** O VSCode reserva uma área enorme de endereçamento virtual (ex: 32GB) para operações futuras, mas não consome isso de RAM física.
* **Interpretação:** Um VSZ alto **não** indica necessariamente um vazamento de memória ou problema.

## 2. Peak RSS (Resident Set Size - Pico)
* **Definição:** É a quantidade máxima de RAM física que o processo ocupou durante sua vida.
* **Composição:** Apenas as páginas de memória que estão atualmente nos pentes de RAM.
* **Importância:** Este é o valor real que impacta a capacidade do servidor. Se o RSS atingir o limite da máquina, ocorre swap ou OOM Kill.

**No sys-inspector:**
A coluna `VSZ` mostra a "promessa" de uso.
A coluna `PK_RSS` mostra o "consumo real" físico.