/* Experimental diagnostic: scalar writes versus explicit 128-bit writes.
 * The expected ordinary indirect call in invoke_callback is offset_alpha.
 * No analysis semantics are changed for this experiment.
 */
#include <stdint.h>
typedef int (*Callback)(void);
struct Pair { Callback first; Callback second; };

__attribute__((noinline, noclone)) int offset_alpha(void) { return 7; }
__attribute__((noinline, noclone)) int offset_beta(void) { return 9; }

__attribute__((noinline, noclone))
void initialize_callbacks(struct Pair *pair, Callback first) {
#ifdef VECTOR_WRITES
    typedef uintptr_t VectorPair __attribute__((vector_size(16)));
    VectorPair values = { (uintptr_t)first, (uintptr_t)offset_beta };
    __builtin_memcpy(pair, &values, sizeof(values));
#else
    pair->first = first;
    pair->second = offset_beta;
#endif
}

__attribute__((noinline, noclone))
int invoke_callback(struct Pair *pair) {
    return pair->first() + 1;
}

int main(void) {
    struct Pair pair;
    initialize_callbacks(&pair, offset_alpha);
    return invoke_callback(&pair) != 8;
}
