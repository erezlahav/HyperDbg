#include <sys/types.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <stddef.h>
#include <stdio.h>

#include "syscall_injection.h"
#include "info_commands.h"
#include "debug.h"

#define SYSCALL_OPCODE 0x050f




/* test
        struct user_regs_struct regs;
        get_registers(process_to_debug.pid, &regs);
        ptrace(PTRACE_POKEDATA, process_to_debug.pid, regs.rsp-0x100, 0x000a6161);
        remote_syscall(process_to_debug.pid,1,1,regs.rsp-0x100,4,0,0,0);
*/

long remote_syscall( //still in maitnence
    pid_t tid,
    long syscall_number,
    long arg1,
    long arg2,
    long arg3,
    long arg4,
    long arg5,
    long arg6)
{
    struct user_regs_struct saved_regs;
    printf("in syscall injection\n");
    get_registers(tid,&saved_regs);

    struct user_regs_struct syscall_regs = saved_regs;

    long original_adress = saved_regs.rip;
    syscall_regs.rax = syscall_number;
    syscall_regs.rdi = arg1;
    syscall_regs.rsi = arg2;
    syscall_regs.rdx = arg3;
    syscall_regs.r10 = arg4;
    syscall_regs.r8  = arg5;
    syscall_regs.r9  = arg6;
    ptrace(PTRACE_SETREGS,tid,NULL,&syscall_regs);

    long original_opcode = ptrace(PTRACE_PEEKDATA,tid,original_adress,0);

    ptrace(PTRACE_POKEDATA,tid,original_adress,SYSCALL_OPCODE);
    ptrace(PTRACE_SINGLESTEP,tid,NULL,0);

    
    int status;
    waitpid(tid, &status, 0);


    ptrace(PTRACE_POKEDATA,tid,original_adress,original_opcode);
    ptrace(PTRACE_SETREGS,tid,NULL,&saved_regs);

    


}
