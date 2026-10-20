#include <stdlib.h>
typedef int (*Callback)(void);
int alpha(void) { return 11; }
__attribute__((noinline)) int dispatch(Callback *p) { return (*p)(); }
int main(void) {
    Callback *first = calloc(3, sizeof(Callback));
    if (!first) return 2;
    *first = alpha;
    Callback *second = realloc(first, 8 * sizeof(Callback));
    if (!second) { free(first); return 2; }
    int result = dispatch(second);
    free(second);
    return result != 11;
}
