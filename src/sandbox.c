#define _GNU_SOURCE  // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
// bcachefs inode numbers overflow the 32-bit `stat` and `readdir`
#define _FILE_OFFSET_BITS 64

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

// newer than the build's kernel headers:
// https://github.com/torvalds/linux/blob/8d3ae59288f1e7d58d76558a6ee96d533bc5019f/include/uapi/linux/landlock.h#L196-L199
#define LANDLOCK_RESTRICT_SELF_TSYNC (1U << 3)
// https://github.com/torvalds/linux/blob/8d3ae59288f1e7d58d76558a6ee96d533bc5019f/include/uapi/linux/landlock.h#L402-L418
#define LANDLOCK_ACCESS_FS_RESOLVE_UNIX (1ULL << 16)

enum {
  kHandledFsAccess = (LANDLOCK_ACCESS_FS_RESOLVE_UNIX << 1) - 1,

  kFileAccess = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
                LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_TRUNCATE |
                LANDLOCK_ACCESS_FS_IOCTL_DEV | LANDLOCK_ACCESS_FS_RESOLVE_UNIX,

  kRead = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,

  kWrite = kRead | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE |
           LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_DIR |
           LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |
           LANDLOCK_ACCESS_FS_REFER,

  kDevice = kRead | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_IOCTL_DEV,

  // chromium keeps its singleton lock as a symlink and talks over unix sockets
  kBrowser = kWrite | LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_MAKE_SOCK |
             LANDLOCK_ACCESS_FS_RESOLVE_UNIX,

  kNamespaceFlags = CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWPID |
                    CLONE_NEWUSER | CLONE_NEWUTS,
};

static const char* const kExcludedRootEntries[] = {"dev",  "home", "media", "mnt",
                                                   "root", "run",  "tmp",   NULL};
static const char* const kExcludedRunEntries[] = {"credentials", "keys", "secrets", "user", NULL};
static const char* const kExcludedSteamEntries[] = {"config", "local.vdf", "userdata", NULL};

static const int kDeniedSyscalls[] = {
    // keep-sorted start
    __NR_add_key,
    __NR_bpf,
    __NR_delete_module,
    __NR_finit_module,
    __NR_fsconfig,
    __NR_fsmount,
    __NR_fsopen,
    __NR_fspick,
    __NR_init_module,
    __NR_io_uring_enter,
    __NR_io_uring_register,
    __NR_io_uring_setup,
    __NR_kexec_load,
    __NR_keyctl,
    __NR_modify_ldt,
    __NR_mount,
    __NR_mount_setattr,
    __NR_move_mount,
    __NR_open_by_handle_at,
    __NR_open_tree,
    __NR_perf_event_open,
    __NR_pidfd_send_signal,
    __NR_pivot_root,
    __NR_process_vm_readv,
    __NR_process_vm_writev,
    __NR_ptrace,
    __NR_request_key,
    __NR_setns,
    __NR_tkill,
    __NR_umount2,
    __NR_unshare,
    __NR_userfaultfd,
    __NR_vm86,
    __NR_vm86old,
    // keep-sorted end
};

static void AllowPath(int ruleset, const char* path, __u64 access) {
  int fd = open(path, O_PATH | O_CLOEXEC);
  // fonts, icon themes, shader caches and gpu devices differ between hosts
  if (fd < 0 && errno == ENOENT)
    return;

  if (fd < 0)
    __builtin_trap();

  struct stat status;
  if (fstat(fd, &status) != 0)
    __builtin_trap();

  // landlock rejects directory rights on a file
  struct landlock_path_beneath_attr rule = {
      .allowed_access = S_ISDIR(status.st_mode) ? access : access & kFileAccess,
      .parent_fd = fd,
  };
  if (syscall(__NR_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH, &rule, 0) != 0)
    __builtin_trap();

  close(fd);
}

static void AllowEntries(int ruleset, const char* directory, __u64 access,
                         const char* const* excluded) {
  DIR* entries = opendir(directory);
  if (!entries)
    __builtin_trap();

  for (struct dirent* entry; (entry = readdir(entries));) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;

    // prefixes, so `secrets` covers `secrets.d` and `secrets-for-users` too
    const char* const* exclusion = excluded;
    while (*exclusion && strncmp(entry->d_name, *exclusion, strlen(*exclusion)) != 0)
      exclusion++;

    if (*exclusion)
      continue;

    char path[PATH_MAX];
    (void)snprintf(path, sizeof(path), "%s/%s", strcmp(directory, "/") == 0 ? "" : directory,
                   entry->d_name);
    AllowPath(ruleset, path, access);
  }

  closedir(entries);
}

static void AllowHomePath(int ruleset, const char* home, const char* path, __u64 access) {
  char fullPath[PATH_MAX];
  (void)snprintf(fullPath, sizeof(fullPath), "%s/%s", home, path);
  AllowPath(ruleset, fullPath, access);
}

static void AllowGameDirectory(int ruleset, const char* game) {
  // the game's root holds `hl.sh` and the libraries steam starts before the sandbox exists
  AllowPath(ruleset, game, kRead);

  DIR* entries = opendir(game);
  if (!entries)
    __builtin_trap();

  for (struct dirent* entry; (entry = readdir(entries));) {
    if (entry->d_type != DT_DIR || strcmp(entry->d_name, ".") == 0 ||
        strcmp(entry->d_name, "..") == 0)
      continue;

    char path[PATH_MAX];
    (void)snprintf(path, sizeof(path), "%s/%s", game, entry->d_name);
    AllowPath(ruleset, path, kBrowser);
  }

  closedir(entries);

  static const char* const kWrittenFiles[] = {"hl.conf", "qconsole.log"};
  for (size_t i = 0; i < sizeof(kWrittenFiles) / sizeof(kWrittenFiles[0]); i++) {
    char path[PATH_MAX];
    (void)snprintf(path, sizeof(path), "%s/%s", game, kWrittenFiles[i]);
    AllowPath(ruleset, path, kRead | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE);
  }

  char shaderCache[PATH_MAX];
  (void)snprintf(shaderCache, sizeof(shaderCache), "%s/../../shadercache/10", game);
  AllowPath(ruleset, shaderCache, kWrite);
}

static void AllowDevices(int ruleset) {
  static const char* const kStreams[] = {"/dev/full", "/dev/null", "/dev/random", "/dev/urandom",
                                         "/dev/zero"};
  for (size_t i = 0; i < sizeof(kStreams) / sizeof(kStreams[0]); i++)
    AllowPath(ruleset, kStreams[i], kRead | LANDLOCK_ACCESS_FS_WRITE_FILE);

  AllowPath(ruleset, "/dev/shm", kWrite);
  AllowPath(ruleset, "/dev/dri", kDevice);

  DIR* entries = opendir("/dev");
  if (!entries)
    __builtin_trap();

  for (struct dirent* entry; (entry = readdir(entries));) {
    if (strncmp(entry->d_name, "nvidia", strlen("nvidia")) != 0)
      continue;

    char path[PATH_MAX];
    (void)snprintf(path, sizeof(path), "/dev/%s", entry->d_name);
    AllowPath(ruleset, path, kDevice);
  }

  closedir(entries);
}

// the name lookups of glibc's `nss` modules; both services only answer queries
static void AllowNameResolution(int ruleset) {
  AllowPath(ruleset, "/run/nscd/socket", LANDLOCK_ACCESS_FS_RESOLVE_UNIX);
  AllowPath(ruleset, "/run/systemd/resolve/io.systemd.Resolve", LANDLOCK_ACCESS_FS_RESOLVE_UNIX);
}

// only the audio sockets of the session: its bus can start any program outside the sandbox through
// systemd
static void AllowSession(int ruleset) {
  const char* runtime = getenv("XDG_RUNTIME_DIR");

  char path[PATH_MAX];
  (void)snprintf(path, sizeof(path), "%s/pulse/native", runtime);
  AllowPath(ruleset, path, LANDLOCK_ACCESS_FS_RESOLVE_UNIX);

  (void)snprintf(path, sizeof(path), "%s/pipewire-0", runtime);
  AllowPath(ruleset, path, LANDLOCK_ACCESS_FS_RESOLVE_UNIX);

  AllowPath(ruleset, getenv("XAUTHORITY"), kRead);

  // the steam overlay and x11 sockets; steam's runtime gives the game a `/tmp` of its own
  AllowPath(ruleset, "/tmp", kBrowser);
}

static void AllowHome(int ruleset) {
  const char* home = getenv("HOME");

  // keep-sorted start
  AllowHomePath(ruleset, home, ".cache/fontconfig", kWrite);
  AllowHomePath(ruleset, home, ".cache/mesa_shader_cache", kWrite);
  AllowHomePath(ruleset, home, ".cache/nvidia", kWrite);
  AllowHomePath(ruleset, home, ".config/MangoHud", kRead);
  AllowHomePath(ruleset, home, ".config/fontconfig", kRead);
  AllowHomePath(ruleset, home, ".icons", kRead);
  AllowHomePath(ruleset, home, ".local/share/fonts", kRead);
  AllowHomePath(ruleset, home, ".local/share/icons", kRead);
  AllowHomePath(ruleset, home, ".nv", kWrite);
  // keep-sorted end

  // `registry.vdf` and the ipc pipe of the steam client
  AllowHomePath(ruleset, home, ".steam", kWrite);

  char steamLink[PATH_MAX];
  (void)snprintf(steamLink, sizeof(steamLink), "%s/.steam/steam", home);

  char steam[PATH_MAX];
  if (!realpath(steamLink, steam))
    __builtin_trap();

  // the login tokens and the account data of the steam client
  AllowEntries(ruleset, steam, kRead, kExcludedSteamEntries);
}

static void RestrictFilesystem(const char* game) {
  struct landlock_ruleset_attr attributes = {
      .handled_access_fs = kHandledFsAccess,
      // nothing in the game listens on tcp
      .handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP,
  };
  int ruleset = (int)syscall(__NR_landlock_create_ruleset, &attributes, sizeof(attributes), 0);
  if (ruleset < 0)
    __builtin_trap();

  AllowEntries(ruleset, "/", kRead, kExcludedRootEntries);
  AllowEntries(ruleset, "/run", kRead, kExcludedRunEntries);
  AllowDevices(ruleset);
  AllowNameResolution(ruleset);
  AllowSession(ruleset);
  AllowHome(ruleset);
  AllowGameDirectory(ruleset, game);

  // log denials in the processes chromium starts as well
  if (syscall(__NR_landlock_restrict_self, ruleset,
              LANDLOCK_RESTRICT_SELF_TSYNC | LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON) != 0)
    __builtin_trap();

  close(ruleset);
}

static void RestrictSyscalls(void) {
  enum {
    kHeaderLength = 22,
    kFilterLength = kHeaderLength + 2 * sizeof(kDeniedSyscalls) / sizeof(kDeniedSyscalls[0]) + 1,
  };

  struct sock_filter filter[kFilterLength] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
      // x86-64 syscalls from a far jump into a 64-bit code segment would skip every check below
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_I386, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
      // `clone3` passes its flags in memory, which seccomp can't read; glibc falls back to `clone`
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 4),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
      BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, kNamespaceFlags, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      // steam's api checks that the steam client is alive with `kill(pid, 0)`, so only real signals
      // stay within the game
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_kill, 0, 2),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 6, 4),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_tgkill, 3, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigqueueinfo, 2, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_tgsigqueueinfo, 1, 0),
      BPF_JUMP(BPF_JMP | BPF_JA | BPF_K, 4, 0, 0),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (__u32)getpid(), 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
  };

  size_t length = kHeaderLength;
  for (size_t i = 0; i < sizeof(kDeniedSyscalls) / sizeof(kDeniedSyscalls[0]); i++) {
    filter[length++] =
        (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kDeniedSyscalls[i], 0, 1);
    // the core dump of a violation reaches the desktop's crash reporter
    filter[length++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
  }

  filter[length++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

  struct sock_fprog program = {.len = length, .filter = filter};
  if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
              SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_LOG, &program) != 0)
    __builtin_trap();
}

// runs after the other preloaded libraries, gamemode's registration included, and before the
// game loads anything it could have downloaded
__attribute__((constructor)) static void Sandbox_Initialize(void) {
  char executable[PATH_MAX];
  if (!realpath("/proc/self/exe", executable))
    __builtin_trap();

  // steam's `reaper` is 32-bit too and preloads the library before it starts the game
  char* name = strrchr(executable, '/') + 1;
  if (strcmp(name, "hl_linux") != 0)
    return;

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
    __builtin_trap();

  RestrictFilesystem(dirname(executable));
  RestrictSyscalls();
}
