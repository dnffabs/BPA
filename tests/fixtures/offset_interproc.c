#include <stdlib.h>

typedef int (*Callback)(void);
struct Pair { Callback first; Callback second; };

__attribute__((noinline)) int offset_alpha(void) { return 7; }
__attribute__((noinline)) int offset_beta(void) { return 9; }

__attribute__((noinline)) Callback *second_slot(struct Pair *pair) {
    return &pair->second;
}

__attribute__((noinline)) int invoke_slot(Callback *slot) {
    return (*slot)();
}

/* Preserve H[sizeof(Callback)] through return, store, load and argument flow. */
__attribute__((noinline)) int interior_driver(void) {
    struct Pair *pair = malloc(sizeof(*pair));
    Callback **holder = malloc(sizeof(*holder));
    if (!pair || !holder) {
        free(pair);
        free(holder);
        return -1;
    }
    pair->first = offset_alpha;
    pair->second = offset_beta;
    *holder = second_slot(pair);
    int result = invoke_slot(*holder);
    free(holder);
    free(pair);
    return result;
}

int main(void) { return interior_driver() != 9; }
