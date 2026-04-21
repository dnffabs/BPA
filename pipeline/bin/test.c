/**
 * simple_test.c
 * 简易二进制指针分析测试程序
 * 
 * 编译：gcc -O0 -g -o simple_test simple_test.c
 * 运行：./simple_test
 */

#include <stdio.h>
#include <stdlib.h>

// ========== 全局变量 ==========
int global_var = 100;
int global_array[5] = {1, 2, 3, 4, 5};

// ========== 结构体定义 ==========
struct Point {
    int x;
    int y;
};

struct Point global_point = {10, 20};

// ========== 函数指针 ==========
int add(int a, int b) {
    return a + b;
}

int sub(int a, int b) {
    return a - b;
}

// ========== 主函数 ==========
int main() {
    // 1. 局部变量（栈）
    int local_a = 10;
    int local_b = 20;
    int local_array[3] = {100, 200, 300};
    
    // 2. 指针指向局部变量
    int *ptr = &local_a;
    *ptr = 999;  // 通过指针写栈变量
    
    ptr = &local_b;
    *ptr = 888;
    
    // 3. 指针算术（数组遍历）
    int *arr_ptr = local_array;
    for (int i = 0; i < 3; i++) {
        arr_ptr[i] = arr_ptr[i] + 1;
    }
    
    // 4. 非0基地址指针算术（测试精度退化）
    int *mid_ptr = local_array + 1;
    *mid_ptr = 9999;
    
    // 5. 全局变量访问
    global_var = 200;
    int *gptr = &global_var;
    *gptr = 300;
    
    // 6. 全局数组访问
    global_array[2] = 99;
    int *garr_ptr = global_array;
    garr_ptr[4] = 88;
    
    // 7. 结构体访问
    struct Point p = {1, 2};
    p.x = 5;
    p.y = 6;
    
    struct Point *pptr = &p;
    pptr->x = 7;
    pptr->y = 8;
    
    global_point.x = 30;
    global_point.y = 40;
    
    // 8. 堆内存分配
    int *heap_ptr = (int*)malloc(10 * sizeof(int));
    heap_ptr[0] = 123;
    heap_ptr[5] = 456;
    
    int *heap_walk = heap_ptr + 5;
    *heap_walk = 789;
    
    // 9. 函数指针（间接调用）
    int (*func_ptr)(int, int);
    func_ptr = add;
    int result1 = func_ptr(5, 3);
    
    func_ptr = sub;
    int result2 = func_ptr(10, 4);
    
    // 10. 打印结果（方便验证）
    printf("=== Test Results ===\n");
    printf("local_a=%d, local_b=%d\n", local_a, local_b);
    printf("local_array: %d, %d, %d\n", local_array[0], local_array[1], local_array[2]);
    printf("global_var=%d\n", global_var);
    printf("global_array[2]=%d, global_array[4]=%d\n", global_array[2], global_array[4]);
    printf("struct p: (%d,%d)\n", p.x, p.y);
    printf("global_point: (%d,%d)\n", global_point.x, global_point.y);
    printf("heap_ptr[0]=%d, heap_ptr[5]=%d\n", heap_ptr[0], heap_ptr[5]);
    printf("func results: add=%d, sub=%d\n", result1, result2);
    
    free(heap_ptr);
    return 0;
}