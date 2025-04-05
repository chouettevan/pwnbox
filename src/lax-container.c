#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <linux/filter.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <sched.h>
#include <sys/syscall.h>

int main(int argc,char *argv[]) {
	if (argc < 2) {
		puts("usage: ./isolate bin");
		return 1;
	}
	scmp_filter_ctx context = seccomp_init(SCMP_ACT_LOG);	
	seccomp_rule_add(context,SCMP_ACT_KILL_PROCESS,SCMP_SYS(mount),0);
	seccomp_rule_add(context,SCMP_ACT_ALLOW,SCMP_SYS(write),1,SCMP_A0(SCMP_CMP_EQ,1));
	seccomp_rule_add(context,SCMP_ACT_ALLOW,SCMP_SYS(mmap),0);
	seccomp_rule_add(context,SCMP_ACT_LOG,SCMP_SYS(mmap),1,SCMP_A2(SCMP_CMP_MASKED_EQ,PROT_EXEC,1));
	seccomp_load(context);
	execl(argv[1],argv[1],NULL);
}
