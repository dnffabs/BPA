typedef int (*Callback)(void);

__attribute__((noinline)) int offset_alpha(void) { return 7; }
__attribute__((noinline)) int offset_beta(void) { return 9; }

__attribute__((noinline)) int select_first(Callback first, Callback second) {
    (void)second;
    return first();
}

__attribute__((noinline)) int select_second(Callback first, Callback second) {
    (void)first;
    return second();
}

/* On AMD64 these callbacks are arguments 7 and 8, both passed on the stack. */
__attribute__((noinline)) int many_first(int a, int b, int c, int d, int e, int f,
                                       Callback first, Callback second) {
    (void)second;
    return first() + a+b+c+d+e+f;
}

__attribute__((noinline)) int many_second(int a, int b, int c, int d, int e, int f,
                                        Callback first, Callback second) {
    (void)first;
    return second() + a+b+c+d+e+f;
}

__attribute__((noinline)) int stack_argument_driver(void) {
    int one = select_first(offset_alpha, offset_beta);
    int two = select_second(offset_alpha, offset_beta);
    int seven = many_first(1,2,3,4,5,6,offset_alpha,offset_beta);
    int eight = many_second(1,2,3,4,5,6,offset_alpha,offset_beta);
    return one == 7 && two == 9 && seven == 28 && eight == 30;
}

int main(void) { return !stack_argument_driver(); }
