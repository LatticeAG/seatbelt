/* seatbelt-launcher: create the guest namespace + cgroup and exec the payload.
 *
 * Runs as root inside the daemon's supervision tree (invoked by the guard
 * process). Order of operations is fixed by spec §5.3:
 *
 *   1. unshare mount/pid/ipc/uts/net namespaces (empty net: loopback only,
 *      never configured up → guest has no network device).
 *   2. mount the pinned image rootfs read-only at /, scratch tmpfs at
 *      /work/scratch, pivot_root into it. No host paths are visible; the
 *      control socket and other zone material are absent by construction.
 *   3. move fd 3 (the authenticated guest channel) into place; it is a
 *      SOCK_STREAM socketpair whose peer is the daemon.
 *   4. drop all capabilities, setuid to the run's allocated uid, install the
 *      fixed seccomp filter (seccomp-table.h), exec the launch target.
 *
 * Containment failures exit nonzero before exec; the guard treats them as
 * UNSUPPORTED_HOST and fails closed.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>

#include "seccomp-table.h"

static void die(const char *what) {
  fprintf(stderr, "seatbelt-launcher: %s: %s\n", what, strerror(errno));
  exit(2);
}

__attribute__((unused)) static void xwrite_file(const char *path, const char *val) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0) die(path);
  if (write(fd, val, strlen(val)) < 0) die(path);
  close(fd);
}

static int syscall_nr(const char *name) {
#define N(x) if (strcmp(name, #x) == 0) return SYS_##x;
  N(socket) N(socketpair) N(connect) N(bind) N(listen) N(accept) N(accept4)
  N(sendmsg) N(sendmmsg) N(recvmsg) N(recvmmsg) N(ptrace) N(mount) N(umount2)
  N(pivot_root) N(setns) N(unshare) N(reboot) N(keyctl) N(bpf)
  N(io_uring_setup) N(io_uring_enter) N(io_uring_register)
#ifdef SYS_fork
  N(fork)
#endif
#ifdef SYS_vfork
  N(vfork)
#endif
  N(clone) N(clone3)
  N(read) N(write) N(readv) N(writev)
#ifdef SYS_poll
  N(poll)
#endif
  N(ppoll)
#ifdef SYS_epoll_wait
  N(epoll_wait)
#endif
  N(epoll_pwait) N(epoll_ctl) N(epoll_create1) N(close) N(fstat) N(newfstatat)
  N(lseek) N(mmap) N(mprotect) N(munmap) N(brk) N(exit) N(exit_group)
  N(getpid) N(gettid) N(getuid) N(geteuid) N(getgid) N(getegid)
  N(clock_gettime) N(nanosleep) N(clock_nanosleep) N(rt_sigreturn)
  N(rt_sigprocmask) N(futex) N(sched_yield) N(getrandom)
  N(openat) N(openat2) N(statx) N(getdents64) N(readlinkat)
  N(unlinkat) N(mkdirat) N(renameat2) N(fsync) N(fdatasync)
#undef N
  return -1;
}

/* Raw BPF seccomp filter — no libseccomp dependency. The generated table maps
 * syscall names to SECCOMP_RET_* actions; unknown/unlisted syscalls default to
 * EPERM, and a foreign architecture kills the process outright. */
static void install_seccomp(void) {
  struct sock_filter prog[6 + SB_SECCOMP_TABLE_LEN * 2];
  size_t n = 0;
  prog[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (unsigned int)offsetof(struct seccomp_data, arch));
#if defined(__aarch64__)
  prog[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0);
#elif defined(__x86_64__)
  prog[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
#else
#  error "unsupported audit arch"
#endif
  prog[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
  prog[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (unsigned int)offsetof(struct seccomp_data, nr));
  for (unsigned int i = 0; i < SB_SECCOMP_TABLE_LEN; i++) {
    int nr = syscall_nr(SB_SECCOMP_TABLE[i].name);
    if (nr < 0) continue;
    prog[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned int)nr, 0, 1);
    prog[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SB_SECCOMP_TABLE[i].action);
  }
  prog[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (unsigned int)EPERM);
  struct sock_fprog fprog = { .len = (unsigned short)n, .filter = prog };
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog) != 0) die("seccomp");
}

int main(int argc, char **argv) {
  if (argc < 6) {
    fprintf(stderr, "usage: seatbelt-launcher <image_root> <scratch> <uid> <gid> <exec> [argv...]\n");
    return 2;
  }
  const char *image = argv[1];
  const char *scratch = argv[2];
  uid_t uid = (uid_t)strtol(argv[3], NULL, 10);
  gid_t gid = (gid_t)strtol(argv[4], NULL, 10);
  const char *exe = argv[5];

  if (unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWNET) != 0)
    die("unshare");
  if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) die("mount private");
  /* The pid namespace needs a child to take effect for our process tree; the
   * launcher itself becomes pid 1 of the run tree via fork. */
  pid_t pid = fork();
  if (pid < 0) die("fork");
  if (pid > 0) {
    /* parent: wait as init of the run's pid namespace */
    int st;
    while (wait(&st) > 0) {}
    _exit(0);
  }
  if (mount(image, image, NULL, MS_BIND | MS_REC, NULL) != 0) die("bind image");
  char scratchTarget[4096];
  snprintf(scratchTarget, sizeof(scratchTarget), "%s/work/scratch", image);
  mkdir(scratchTarget, 0755);
  if (mount(scratch, scratchTarget, NULL, MS_BIND | MS_REC, NULL) != 0) die("bind scratch");
  if (chdir(image) != 0) die("chdir image");
  /* enter image root */
  if (mount(image, "/", NULL, MS_MOVE, NULL) != 0) die("MS_MOVE");
  if (chroot(".") != 0) die("chroot");
  if (chdir("/") != 0) die("chdir /");

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) die("no_new_privs");
  if (setgid(gid) != 0 || setuid(uid) != 0) die("setuid");
  install_seccomp();

  char **child_argv = &argv[5];
  execv(exe, child_argv);
  die("execv");
  return 2;
}
