typedef int (*Callback)(void);
int alpha(void) { return 11; }
__attribute__((noinline)) int many(int a, int b, int c, int d, int e, int f, Callback cb) {
    return cb() + a+b+c+d+e+f;
}
int main(void) { return many(1,2,3,4,5,6,alpha) != 32; }
