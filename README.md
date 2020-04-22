# Binary Ninja Division Deoptimizer Plugin

This plugin uses z3 and a binary search to deoptimize divisions in binary ninja. It operates on MLIL, so it should be architecture agnostic. Because z3 is used and instructions are followed, the division deoptimization is also pattern agnostic, so different compiler optimizations should still work.

It works by following the operands of a SSA MLIL instruction. After following the operands, the z3 value representing the final MLIL variable will be a function of an unconstrained input variable. We can use a binary search with different arguments to that function to determine what the actual divisor is.

# Installation
Clone or symlink this repository into your plugin folder. (https://docs.binary.ninja/guide/plugins.html#using-plugins)

# Known Failures
These failures are caused by the incomplete impletation of the MLIL.

 - 64 bit dividing by very large numbers.
 - 32 bit, when large enough numbers are used that `__divdi3` and similar methods are called.
```c
    int b;
    unsigned long e;
    scanf("%d", &b);
    printf("b / 435939234853 = %d", x / 435939234853); // Doesn't work
    scanf("%ld", &e);
    printf("UNSIGNED LONG b / 435939234853 = %ld", x / 435939234853); // Also doesn't work
```
