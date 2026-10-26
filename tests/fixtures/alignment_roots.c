typedef int (*Callback)(void);
__attribute__((noinline)) int alpha(void) { return 7; }
__attribute__((noinline)) int only_direct(void) { return 3; }
__attribute__((noinline)) int unused_dispatch(void) {
    Callback cb = alpha;
    return cb();
}
Callback global_callback = unused_dispatch;
int main(void) { return only_direct() != 3; }
