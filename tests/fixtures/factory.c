typedef int (*Callback)(void);
typedef Callback (*Factory)(Callback);
int alpha(void) { return 11; }
__attribute__((noinline)) Callback identity(Callback cb) { return cb; }
__attribute__((noinline)) int invoke_factory(void) {
    Factory make = identity;
    Callback cb = make(alpha);
    return cb();
}
int main(void) { return invoke_factory() != 11; }
