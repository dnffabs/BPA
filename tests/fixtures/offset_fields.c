#include <stdlib.h>

typedef int (*Callback)(void);
struct Pair { Callback first; Callback second; };

__attribute__((noinline)) int offset_alpha(void) { return 7; }
__attribute__((noinline)) int offset_beta(void) { return 9; }
struct Pair global_pair = { offset_alpha, offset_beta };

__attribute__((noinline)) int heap_fields(void) {
    struct Pair *pair = malloc(sizeof(*pair));
    if (!pair) return -1;
    pair->first = offset_alpha;
    pair->second = offset_beta;
    int result = pair->first();
    free(pair);
    return result;
}

__attribute__((noinline)) int stack_fields(void) {
    struct Pair pair;
    pair.first = offset_alpha;
    pair.second = offset_beta;
    return pair.first();
}

__attribute__((noinline)) int global_fields(void) {
    return global_pair.first();
}

int main(void) {
    return !(heap_fields() == 7 && stack_fields() == 7 && global_fields() == 7);
}
