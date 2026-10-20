typedef int (*Callback)(void);
int alpha(void) { return 11; }
int beta(void) { return 22; }
int main(void) {
#ifdef __x86_64__
    register Callback cb __asm__("r12") = alpha;
#else
    register Callback cb __asm__("ebx") = alpha;
#endif
    __asm__ volatile ("" : "+r" (cb));
    int first = cb();
    cb = beta;
    __asm__ volatile ("" : "+r" (cb));
    int second = cb();
    return first != 11 || second != 22;
}
