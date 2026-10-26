#include <stdlib.h>
typedef int (*Callback)(void);
typedef int (*Runner)(Callback);
typedef Callback (*Factory)(Callback);
#define KEEP __attribute__((noinline, noclone))

KEEP int alpha(void) { return 7; }
KEEP int beta(void) { return 9; }
KEEP int leaf(Callback cb) { return cb() + 1; }
KEEP int tail_direct(Callback cb) { return leaf(cb); }
KEEP int tail_chain(Callback cb) { return tail_direct(cb); }
KEEP int tail_indirect(Runner run, Callback cb) { return run(cb); }
KEEP Callback factory(Callback cb) { return cb; }
KEEP Callback tail_factory(Callback cb) { return factory(cb); }
KEEP Callback tail_factory_indirect(Factory make, Callback cb) { return make(cb); }
KEEP void *tail_allocate(size_t size) { return malloc(size); }

/* The last two callbacks are incoming stack parameters on AMD64 as well. */
KEEP int many_leaf(int a, int b, int c, int d, int e, int f, Callback first, Callback second) {
    (void)second;
    return first() + a+b+c+d+e+f;
}
KEEP int many_tail(int a, int b, int c, int d, int e, int f, Callback first, Callback second) {
    return many_leaf(a,b,c,d,e,f,first,second);
}

KEEP int consume_factory(void) {
    Callback cb = tail_factory(alpha);
    Callback other = tail_factory_indirect(factory,alpha);
    return cb()+other();
}
KEEP int driver(void) {
    int one = tail_chain(alpha);
    int two = tail_indirect(leaf,alpha);
    int three = consume_factory();
    int four = many_tail(1,2,3,4,5,6,alpha,beta);
    void *p = tail_allocate(8);
    if (!p) return 1;
    free(p);
    return !(one==8 && two==8 && three==14 && four==28);
}
int main(void) { return driver(); }
