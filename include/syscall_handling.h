#pragma once


#include <sys/user.h>





typedef struct user_regs_struct regs_t;
typedef void (*syscall_handler_t)(regs_t* regs);



typedef struct {
    const char* name;
    long number;
    syscall_handler_t handler;
} syscall_entry;



extern char hooked_syscalls[1000];
extern syscall_entry syscalls[];




int syscall_handle(struct user_regs_struct* regs);
int put_syscalls_bps();
int patch_syscalls_to_bps(long start,long end);