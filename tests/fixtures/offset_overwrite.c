#include <stdlib.h>

typedef int (*Callback)(void);
struct Pair { Callback first; Callback second; };

__attribute__((noinline)) int offset_alpha(void) { return 7; }
__attribute__((noinline)) int offset_beta(void) { return 9; }

/* Offsets cannot remove an earlier write to the very same location. */
__attribute__((noinline)) int overwrite_field(void) {
    struct Pair *pair = malloc(sizeof(*pair));
    if (!pair) return -1;
    pair->first = offset_alpha;
    pair->first = offset_beta;
    int result = pair->first();
    free(pair);
    return result;
}

int main(void) { return overwrite_field() != 9; }
