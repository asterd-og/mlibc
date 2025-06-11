#include <stddef.h>

#include <errno.h>
#include <abi-bits/signal.h>
#include <abi-bits/seek-whence.h>
#include <abi-bits/vm-flags.h>
#include <bits/off_t.h>
#include <bits/ssize_t.h>
#include <abi-bits/stat.h>
#include <mlibc/fsfd_target.hpp>
#include "syscall.h"
#include <string.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

namespace [[gnu::visibility("hidden")]] mlibc {

[[noreturn]] void sys_exit(int status) {
    __syscall1(60, status);
    __builtin_unreachable();
}

void sys_libc_log(const char *message) {
    __syscall3(1 /* write() */, 3, (size_t)message, strlen(message));
    __syscall3(1 /* write() */, 3, (size_t)"\n", 1);
}
[[noreturn]] void sys_libc_panic() {
    sys_libc_log("\n[MLIBC]: Panic!");
    __syscall1(60 /* exit() */, 1);
}

int sys_tcb_set(void *pointer) {
    auto ret = __syscall2(158, 0x1002, (size_t)pointer);
    if (ret < 0)
        return -ret;
    return 0;
}

[[gnu::weak]] int sys_futex_tid() {
    return __syscall0(186);
}
int sys_futex_wait(int *pointer, int expected, const struct timespec *time) {
    sys_libc_log("[MLIBC]: sys_futex_wait stub!");
    return ENOSYS;
}
int sys_futex_wake(int *pointer) {
    sys_libc_log("[MLIBC]: sys_futex_wake stub!");
    return ENOSYS;
}

int sys_getpid() {
    return __syscall0(39);
}

int sys_getppid() {
    // FIXME
    return sys_getpid();
}

int sys_open(const char *pathname, int flags, mode_t mode, int *fd) {
    auto ret = __syscall3(2, (size_t)pathname, flags, mode);
    if (ret < 0)
        return -ret;
    *fd = ret;
    return 0;
}

int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read) {
    ssize_t read = (ssize_t)__syscall3(0, fd, (size_t)buf, count);
    if (read < 0)
        return -read;
    *bytes_read = read;
    return 0;
}

int sys_write(int fd, const void *buf, size_t count, ssize_t *bytes_written) {
    ssize_t written = (ssize_t)__syscall3(1, fd, (size_t)buf, count);
    if (written < 0)
        return -written;
    *bytes_written = written;
    return 0;
}

int sys_clock_get(int clock, time_t *secs, long *nanos) {
    sys_libc_log("[MLIBC]: sys_clock_get stub!");
    return 0;
}

int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
    auto ret = __syscall3(8, fd, offset, whence);
    if (ret < 0)
        return -ret;
    *new_offset = ret;
    return 0;
}
int sys_close(int fd) {
    sys_libc_log("[MLIBC]: sys_close stub!");
    return 0;
}

int sys_tcgetpgrp(int fd, pid_t *pgid) {
    sys_libc_log("[MLIBC]: sys_tcgetpgrp stub!");
    return 0;
}

int sys_tcsetpgrp(int fd, pid_t pgid) {
    sys_libc_log("[MLIBC]: sys_tcsetpgrp stub!");
    return 0;
}

[[gnu::weak]] int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf) {
    switch (fsfdt) {
        case fsfd_target::fd:
            __syscall2(5, fd, (size_t)statbuf);
            break;
        case fsfd_target::path:
            __syscall2(4, (size_t)path, (size_t)statbuf);
            break;
        case fsfd_target::fd_path:
            sys_libc_log("[MLIBC]: sys_stat fsfd_target::fd_path not implemented!");
            return ENOSYS;
            break;
    }
    return 0;
}
// mlibc assumes that anonymous memory returned by sys_vm_map() is zeroed by the kernel / whatever is behind the sysdeps
int sys_vm_map(void *addr, size_t length, int prot, int flags, int fd, off_t offset, void **window) {
    *window = (void*)__syscall6(9, (size_t)addr, length, prot, flags, fd, offset);
    return 0;
}
int sys_vm_unmap(void *pointer, size_t size) {
    sys_libc_log("[MLIBC]: sys_vm_unmap stub!");
    return 0;
}
[[gnu::weak]] int sys_vm_protect(void *pointer, size_t size, int prot) {
    sys_libc_log("[MLIBC]: sys_vm_protect stub!");
    return ENOSYS;
}

int sys_anon_allocate(size_t size, void **pointer) {
    return sys_vm_map(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0, pointer);
}
int sys_anon_free(void *pointer, size_t size) {
    sys_libc_log("[MLIBC]: sys_anon_free stub!");
    return 0;
}

uid_t sys_getuid() {
    sys_libc_log("[MLIBC]: sys_getuid stub (returns root for now)!");
    return 0;
}

gid_t sys_getgid() {
    sys_libc_log("[MLIBC]: sys_getgid stub (returns root for now)!");
    return 0;
}

gid_t sys_geteuid() {
    sys_libc_log("[MLIBC]: sys_geteuid stub (returns root for now)!");
    return 0;
}

gid_t sys_getegid() {
    sys_libc_log("[MLIBC]: sys_getegid stub (returns root for now)!");
    return 0;
}

int sys_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
    sys_libc_log("[MLIBC]: sys_sigaction stub!");
    return 0;
}

int sys_sigprocmask(int how, const sigset_t *set, sigset_t *old) {
    sys_libc_log("[MLIBC]: sys_sigprocmask stub!");
    return 0;
}

int sys_gethostname(char *name, size_t len) {
    // Stub, TODO: Actually read from hostname
    const char *hostname = "LanOS";
    size_t hostlen = strlen(hostname) + 1;  

    if (!name)
        return EFAULT;
    if (!len)
        return EINVAL;

    if (len < hostlen) {
        memcpy(name, hostname, len - 1);
        name[len - 1] = '\0';
    } else
        memcpy(name, hostname, hostlen);
    return 0;
}

int sys_isatty(int fd) {
    sys_libc_log("[MLIBC]: sys_isatty stub!");
    return 0;
}

int sys_getcwd(char *buf, size_t size) {
    int ret = __syscall2(79, (size_t)buf, size);
    if (ret < 0)
        return -ret;
    return 0;
}

int sys_chdir(const char *path) {
    int ret = __syscall1(80, (size_t)path);
    if (ret < 0)
        return -ret;
    return 0;
}

} //namespace mlibc

extern "C" {
    void *__dso_handle __attribute__((visibility("hidden"))) = nullptr;
}