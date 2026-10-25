#include <stdlib.h>

typedef int (*Callback)(void);
struct Pair { Callback first; Callback second; };

__attribute__((noinline)) int offset_alpha(void) { return 7; }
__attribute__((noinline)) int offset_beta(void) { return 9; }

/* Isolate heap precision without a caller frame pointer stored in this frame. */
int main(void) {
    struct Pair *pair = malloc(sizeof(*pair));
    if (!pair) return 2;
    pair->first = offset_alpha;
    pair->second = offset_beta;
    int result = pair->first();
    free(pair);
    return result != 7;
}
