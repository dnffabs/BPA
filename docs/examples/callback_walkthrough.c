#include <stdlib.h>

typedef int (*Callback)(void);

__attribute__((noinline)) int hello(void) {
    return 7;
}

#ifdef OVERWRITE
__attribute__((noinline)) int bye(void) {
    return 9;
}
#endif

__attribute__((noinline)) int invoke(Callback *slot) {
    Callback cb = *slot;
    return cb();
}

int main(void) {
    Callback *slot = malloc(sizeof(*slot));
    if (!slot) return 2;

    *slot = hello;
#ifdef OVERWRITE
    *slot = bye;
#endif

    int result = invoke(slot);
    free(slot);
#ifdef OVERWRITE
    return result != 9;
#else
    return result != 7;
#endif
}
