typedef int (*Callback)(void);
int alpha(void) { return 11; }
int beta(void) { return 22; }
__attribute__((noinline)) int choose(int flag) {
    Callback cb;
    if (flag) cb = alpha;
    else cb = beta;
    for (int i = 0; i < 3; ++i) __asm__ volatile ("" : : "r" (cb));
    return cb();
}
int main(void) { return choose(0) != 22 || choose(1) != 11; }
