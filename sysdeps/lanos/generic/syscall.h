#pragma once
#include <stddef.h>

size_t __syscall0(size_t rax) {
    size_t ret;
    __asm__ volatile (
        "movq %1, %%rax\n"
        "int $0x80"
        : "=a"(ret)
        : "r"(rax)
    );
    return ret;
}

size_t __syscall1(size_t rax, size_t rdi) {
    size_t ret;
    __asm__ volatile (
        "movq %1, %%rax\n"
        "movq %2, %%rdi\n"
        "int $0x80"
        : "=a"(ret)
        : "r"(rax), "r"(rdi)
        : "rdi"
    );
    return ret;
}

size_t __syscall2(size_t rax, size_t rdi, size_t rsi) {
    size_t ret;
    __asm__ volatile (
        "movq %1, %%rax\n"
        "movq %2, %%rdi\n"
        "movq %3, %%rsi\n"
        "int $0x80"
        : "=a"(ret)
        : "r"(rax), "r"(rdi), "r"(rsi)
        : "rdi", "rsi"
    );
    return ret;
}

size_t __syscall3(size_t rax, size_t rdi, size_t rsi, size_t rdx) {
    size_t ret;
    __asm__ volatile (
        "movq %1, %%rax\n"
        "movq %2, %%rdi\n"
        "movq %3, %%rsi\n"
        "movq %4, %%rdx\n"
        "int $0x80"
        : "=a"(ret)
        : "r"(rax), "r"(rdi), "r"(rsi), "r"(rdx)
        : "rdi", "rsi", "rdx"
    );
    return ret;
}

size_t __syscall4(size_t rax, size_t rdi, size_t rsi, size_t rdx, size_t r10) {
    size_t ret;
    __asm__ volatile (
        "movq %1, %%rax\n"
        "movq %2, %%rdi\n"
        "movq %3, %%rsi\n"
        "movq %4, %%rdx\n"
        "movq %5, %%r10\n"
        "int $0x80"
        : "=a"(ret)
        : "r"(rax), "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10)
        : "rdi", "rsi", "rdx"
    );
    return ret;
}

size_t __syscall5(size_t rax, size_t rdi, size_t rsi, size_t rdx, size_t r10, size_t r8) {
    size_t ret;
    __asm__ volatile (
        "movq %1, %%rax\n"
        "movq %2, %%rdi\n"
        "movq %3, %%rsi\n"
        "movq %4, %%rdx\n"
        "movq %5, %%r10\n"
        "movq %6, %%r8\n"
        "int $0x80"
        : "=a"(ret)
        : "r"(rax), "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8)
        : "rdi", "rsi", "rdx"
    );
    return ret;
}

size_t __syscall6(size_t rax, size_t rdi, size_t rsi, size_t rdx, size_t r10, size_t r8, size_t r9) {
    size_t ret;
    __asm__ volatile (
        "movq %1, %%rax\n"
        "movq %2, %%rdi\n"
        "movq %3, %%rsi\n"
        "movq %4, %%rdx\n"
        "movq %5, %%r10\n"
        "movq %6, %%r8\n"
        "movq %7, %%r9\n"
        "int $0x80"
        : "=a"(ret)
        : "r"(rax), "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8), "r"(r9)
        : "rdi", "rsi", "rdx"
    );
    return ret;
}