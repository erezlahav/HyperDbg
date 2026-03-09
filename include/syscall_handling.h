#pragma once


#include <sys/user.h>





typedef struct user_regs_struct regs_t;
typedef int (*syscall_handler_t)(char* syscall_name, long syscall_number, struct user_regs_struct* regs);



typedef struct {
    const char* name;
    long number;
    syscall_handler_t handler;
} syscall_entry;


typedef struct {
    const char* name;
    unsigned long long* reg;
} syscall_param;



extern char hooked_syscalls[1000];
extern syscall_entry syscalls[];



syscall_entry* get_syscall_entry_by_number(int syscall_number);
int syscall_handle(struct user_regs_struct* regs);
int put_syscalls_bps();
int patch_syscalls_to_bps(long start,long end);
int default_handler(char* syscall_name, long syscall_number, struct user_regs_struct* regs);
int write_handler(char* syscall_name, long syscall_number, struct user_regs_struct* regs);
int read_handler(char* syscall_name, long syscall_number, struct user_regs_struct* regs);
int open_handler(char* syscall_name, long syscall_number, struct user_regs_struct* regs);
int openat_handler(char* syscall_name, long syscall_number, struct user_regs_struct* regs);
void change_params(const char* syscall_name, syscall_param* params);
char* read_remote_str(long remote_addr);