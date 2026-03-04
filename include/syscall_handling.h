#pragma once



int check_for_syscall(long current_rip);
int syscall_handle(struct user_regs_struct* regs);
int patch_syscalls_to_bps(long start,long end);