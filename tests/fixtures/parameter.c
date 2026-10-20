typedef int (*Callback)(void);
int target_true(void) { return 7; }
int target_other(void) { return 9; }
__attribute__((noinline)) int invoke(Callback cb) { return cb(); }
int main(void) { return invoke(target_true) != 7; }
