#include <stdlib.h>
typedef int (*Callback)(void);
int alpha(void) { return 11; }
int beta(void) { return 22; }
Callback global_callback = alpha;
Callback const callback_table[2] = { beta, alpha };
volatile int choice;
struct Box { long marker; Callback callback; };
__attribute__((noinline)) int from_global(void) { return global_callback(); }
__attribute__((noinline)) int from_table(void) { return callback_table[choice](); }
__attribute__((noinline)) int from_stack(void) {
    Callback cb = alpha;
    return cb();
}
__attribute__((noinline)) void install(struct Box *box, Callback cb) { box->callback = cb; }
__attribute__((noinline)) int from_heap(struct Box *box) { return box->callback(); }
int main(void) {
    struct Box *box = malloc(sizeof(*box));
    if (!box) return 2;
    install(box, beta);
    int h = from_heap(box);
    int ok = from_global() == 11 && from_table() == 22 && from_stack() == 11 && h == 22;
    free(box);
    return !ok;
}
