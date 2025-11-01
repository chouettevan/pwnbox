#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <unistd.h>
#define error(arg)                                                             \
  if (arg < 0) {                                                               \
    perror("seccomp error");                                                   \
    return -1;                                                                 \
  }

int main(int argc, char *argv[]) {
  if (argc < 2) {
    puts("usage: ./isolate bin");
    return 1;
  }
  scmp_filter_ctx context = seccomp_init(SCMP_ACT_ERRNO(EPERM));
  error(seccomp_rule_add(context, SCMP_ACT_ALLOW, SCMP_SYS(write), 0));
  error(seccomp_rule_add(context, SCMP_ACT_ALLOW, SCMP_SYS(read), 0));
  error(seccomp_rule_add(context, SCMP_ACT_ALLOW, SCMP_SYS(execve), 1,
                         SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)(argv[1]))));
  error(seccomp_rule_add(context, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0));
  error(seccomp_rule_add(context, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0));
  seccomp_load(context);
  execl(argv[1], argv[1], NULL);
  return 0;
}
