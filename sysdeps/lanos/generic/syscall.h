#pragma once
#include <stddef.h>
#include <stdint.h>

static long syscall(uint64_t num, uint64_t p1 = 0, uint64_t p2 = 0, uint64_t p3 = 0, uint64_t p4 = 0, uint64_t p5 = 0, uint64_t p6 = 0) {
    volatile long ret;

    register uint64_t r4 asm("r10") = p4;
    register uint64_t r5 asm("r8") = p5;
    register uint64_t r6 asm("r9") = p6;

    asm volatile("syscall"
        : "=a"(ret)
        : "a"(num), "D"(p1), "S"(p2), "d"(p3), "r"(r4),
        "r"(r5), "r"(r6)
        : "memory", "rcx", "r11");
    return ret;
}
