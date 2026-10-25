#include <stdlib.h>

typedef int (*Callback)(void);

__attribute__((noinline)) int offset_alpha(void) { return 7; }
__attribute__((noinline)) int offset_beta(void) { return 9; }

/* Repeated arithmetic from a nonzero offset must widen and terminate. */
__attribute__((noinline)) int loop_fields(void) {
    Callback *table = malloc(3 * sizeof(*table));
    if (!table) return -1;
    table[0] = offset_alpha;
    table[1] = offset_beta;
    table[2] = offset_alpha;
    Callback *cursor = table;
    int sum = 0;
    for (int i = 0; i < 3; ++i) {
        sum += (*cursor)();
        ++cursor;
    }
    free(table);
    return sum;
}

int main(void) { return loop_fields() != 23; }
