#pragma once




int syscall_handle(struct user_regs_struct* regs);
int put_syscalls_bps();
int patch_syscalls_to_bps(long start,long end);