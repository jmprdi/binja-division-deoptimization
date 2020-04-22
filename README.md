# Binary Ninja Division Deoptimizer Plugin
Clone or symlink this repository into your plugin folder. (https://docs.binary.ninja/guide/plugins.html#using-plugins)

# Known Failures
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
