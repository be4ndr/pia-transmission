#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <linux/capability.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

static void fail(const char *operation)
{
    perror(operation);
    exit(EXIT_FAILURE);
}

static unsigned int parse_id(const char *value)
{
    char *end;
    unsigned long id;
    if (*value < '0' || *value > '9')
        goto invalid;
    errno = 0;
    id = strtoul(value, &end, 10);
    /* Reject root and the kernel's reserved (uid_t)-1 value. */
    if (errno || *end || id == 0 || id >= UINT_MAX)
        goto invalid;
    return (unsigned int)id;
invalid:
    fputs("PUID and PGID must be nonzero decimal IDs below 4294967295\n", stderr);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    struct __user_cap_header_struct header = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct caps[2] = { {0}, {0} };
    struct rlimit core_limit = {0, 0};
    unsigned int uid, gid;
    int cap;

    if (argc == 4 && !strcmp(argv[1], "--check-ids")) {
        parse_id(argv[2]);
        parse_id(argv[3]);
        return EXIT_SUCCESS;
    }
    if (argc < 4) {
        fputs("usage: drop-privileges PUID PGID /absolute/command [args...]\n", stderr);
        return EXIT_FAILURE;
    }
    uid = parse_id(argv[1]);
    gid = parse_id(argv[2]);
    if (geteuid() != 0 || argv[3][0] != '/') {
        fputs("launcher requires root and an absolute command path\n", stderr);
        return EXIT_FAILURE;
    }
    if (setrlimit(RLIMIT_CORE, &core_limit) == -1)
        fail("disable core dumps");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
        fail("set no_new_privs");
    if (prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) == -1)
        fail("disable keepcaps");
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) == -1)
        fail("clear ambient capabilities");
    /* Drop every capability supported by the running kernel, including ones
     * newer than the build headers. Do this while CAP_SETPCAP is available. */
    for (cap = 0; ; cap++) {
        if (prctl(PR_CAPBSET_READ, cap, 0, 0, 0) == -1) {
            if (errno == EINVAL)
                break;
            fail("read capability bounding set");
        }
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) == -1)
            fail("drop capability bounding set");
    }
    if (setgroups(0, NULL) == -1)
        fail("clear supplementary groups");
    if (setresgid(gid, gid, gid) == -1)
        fail("set GIDs");
    if (setresuid(uid, uid, uid) == -1)
        fail("set UIDs");
    if (syscall(SYS_capset, &header, caps) == -1)
        fail("clear capability sets");
    if (syscall(SYS_capget, &header, caps) == -1)
        fail("read capability sets");
    for (int i = 0; i < 2; i++) {
        if (caps[i].effective || caps[i].permitted || caps[i].inheritable) {
            fputs("capabilities remain after privilege drop\n", stderr);
            return EXIT_FAILURE;
        }
    }
    /* Never inherit controller file descriptors (including secret handles). */
    if (syscall(SYS_close_range, 3U, ~0U, 0) == -1) {
        long max_fd = sysconf(_SC_OPEN_MAX);
        if (max_fd < 0)
            fail("get file descriptor limit");
        for (long fd = 3; fd < max_fd; fd++)
            close((int)fd);
    }
    execv(argv[3], &argv[3]);
    fail("exec unprivileged process");
}
