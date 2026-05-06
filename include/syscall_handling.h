#pragma once


#include <sys/user.h>

#define MAX_SYSCALLS_PARAMS 7 //6+1 for the dummy end position



typedef struct user_regs_struct regs_t;


typedef enum{
    STRING,
    ADDRESS,
    INTEGER
}param_type;

typedef struct {
    const char* name;
    unsigned long long* reg;
    param_type type;
} syscall_param;

typedef struct {
    const char* name;
    long number;
    syscall_param params[MAX_SYSCALLS_PARAMS]; 
} syscall_entry;

extern char hooked_syscalls[1000];
extern syscall_entry syscalls[];



syscall_entry* get_syscall_entry_by_number(int syscall_number);
int syscall_handle(struct user_regs_struct* regs);
int put_syscalls_bps();
int patch_syscalls_to_bps(long start,long end);
int hooked_syscall_handler(syscall_entry* entry, struct user_regs_struct* regs);
void change_params(const char* syscall_name, syscall_param* params);
char* read_remote_str(long remote_addr,int count);
void print_escaped_string(const char* str);