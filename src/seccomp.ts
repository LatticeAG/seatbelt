// Guest syscall policy (spec §5.3): the fixed containment profile restricts the
// guest to process-local syscalls. This table is the single source of truth;
// scripts/gen-seccomp-h.mjs renders it into native/seccomp-table.h for the
// launcher, and tests assert the classifications.

export type SeccompAction = "ALLOW" | "EPERM" | "ENOSYS" | "KILL_PROCESS";

export interface SeccompRule {
  syscall: string;
  action: SeccompAction;
  /** non-empty when only specific argument forms are allowed */
  note?: string;
}

/**
 * Decisions for syscalls the spec names explicitly. Anything not listed is
 * denied by the launcher's default-EPERM profile.
 */
export const SECCOMP_RULES: SeccompRule[] = [
  // guest can never reach the network or pass file descriptors over fd 3
  { syscall: "socket", action: "EPERM" },
  { syscall: "socketpair", action: "EPERM" },
  { syscall: "connect", action: "EPERM" },
  { syscall: "bind", action: "EPERM" },
  { syscall: "listen", action: "EPERM" },
  { syscall: "accept", action: "EPERM" },
  { syscall: "accept4", action: "EPERM" },
  { syscall: "sendmsg", action: "EPERM", note: "blocks SCM_RIGHTS over the fd3 channel" },
  { syscall: "sendmmsg", action: "EPERM" },
  { syscall: "recvmsg", action: "EPERM" },
  { syscall: "recvmmsg", action: "EPERM" },
  { syscall: "ptrace", action: "EPERM" },
  { syscall: "mount", action: "EPERM" },
  { syscall: "umount2", action: "EPERM" },
  { syscall: "pivot_root", action: "EPERM" },
  { syscall: "setns", action: "EPERM" },
  { syscall: "unshare", action: "EPERM" },
  { syscall: "reboot", action: "EPERM" },
  { syscall: "keyctl", action: "EPERM" },
  { syscall: "bpf", action: "EPERM" },
  { syscall: "io_uring_setup", action: "EPERM" },
  { syscall: "io_uring_enter", action: "EPERM" },
  { syscall: "io_uring_register", action: "EPERM" },
  // thread/fork containment is enforced via pids.max, not the filter; the
  // spec requires fork-family calls to fail with distinct codes under the
  // fixed profile: fork/vfork/clone → EPERM, clone3 → ENOSYS.
  { syscall: "fork", action: "EPERM" },
  { syscall: "vfork", action: "EPERM" },
  { syscall: "clone", action: "EPERM", note: "guests are single-threaded; pids.max=1 guards the run tree" },
  { syscall: "clone3", action: "ENOSYS", note: "struct clone_args forms the filter cannot inspect → ENOSYS" },
  // the channel itself: read/write/poll on fd 3 plus scratch fd are allowed
  { syscall: "read", action: "ALLOW" },
  { syscall: "write", action: "ALLOW" },
  { syscall: "readv", action: "ALLOW" },
  { syscall: "writev", action: "ALLOW" },
  { syscall: "poll", action: "ALLOW" },
  { syscall: "ppoll", action: "ALLOW" },
  { syscall: "epoll_wait", action: "ALLOW" },
  { syscall: "epoll_pwait", action: "ALLOW" },
  { syscall: "epoll_ctl", action: "ALLOW" },
  { syscall: "epoll_create1", action: "ALLOW" },
  { syscall: "close", action: "ALLOW" },
  { syscall: "fstat", action: "ALLOW" },
  { syscall: "newfstatat", action: "ALLOW" },
  { syscall: "lseek", action: "ALLOW" },
  { syscall: "mmap", action: "ALLOW", note: "PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON only" },
  { syscall: "mprotect", action: "ALLOW" },
  { syscall: "munmap", action: "ALLOW" },
  { syscall: "brk", action: "ALLOW" },
  { syscall: "exit", action: "ALLOW" },
  { syscall: "exit_group", action: "ALLOW" },
  { syscall: "getpid", action: "ALLOW" },
  { syscall: "gettid", action: "ALLOW" },
  { syscall: "getuid", action: "ALLOW" },
  { syscall: "geteuid", action: "ALLOW" },
  { syscall: "getgid", action: "ALLOW" },
  { syscall: "getegid", action: "ALLOW" },
  { syscall: "clock_gettime", action: "ALLOW" },
  { syscall: "nanosleep", action: "ALLOW" },
  { syscall: "clock_nanosleep", action: "ALLOW" },
  { syscall: "rt_sigreturn", action: "ALLOW" },
  { syscall: "rt_sigprocmask", action: "ALLOW" },
  { syscall: "futex", action: "ALLOW" },
  { syscall: "sched_yield", action: "ALLOW" },
  { syscall: "getrandom", action: "ALLOW" },
  { syscall: "openat", action: "ALLOW", note: "scratch dir + image rootfs only; enforced by mount ns" },
  { syscall: "openat2", action: "ALLOW" },
  { syscall: "statx", action: "ALLOW" },
  { syscall: "getdents64", action: "ALLOW" },
  { syscall: "readlinkat", action: "ALLOW" },
  { syscall: "unlinkat", action: "ALLOW", note: "scratch only" },
  { syscall: "mkdirat", action: "ALLOW", note: "scratch only" },
  { syscall: "renameat2", action: "ALLOW", note: "scratch only" },
  { syscall: "fsync", action: "ALLOW" },
  { syscall: "fdatasync", action: "ALLOW" },
];

export function seccompDecision(syscall: string): SeccompAction {
  const r = SECCOMP_RULES.find((x) => x.syscall === syscall);
  return r ? r.action : "EPERM";
}

/** The mounts a guest sees: image rootfs (ro), scratch (rw). No host paths. */
export interface GuestMount { source: string; target: string; readonly: boolean }
export function guestMounts(imageRoot: string, scratchDir: string): GuestMount[] {
  return [
    { source: imageRoot, target: "/", readonly: true },
    { source: scratchDir, target: "/work/scratch", readonly: false },
  ];
}
