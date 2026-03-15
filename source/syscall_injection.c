#include <sys/types.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/wait.h>

#include "syscall_injection.h"
#include "info_commands.h"
#include "debug.h"

#define SYSCALL_OPCODE 0x050f
#define MPROTECT_SYSCALL_NUMBER 10
#define MUNMAP_SYSCALL_NUMBER 11
#define MMAP_SYSCALL_NUMBER 9


extern debugee_process process_to_debug;



/* test
        struct user_regs_struct regs;
        get_registers(process_to_debug.pid, &regs);
        ptrace(PTRACE_POKEDATA, process_to_debug.pid, regs.rsp-0x100, 0x000a6161);
        remote_syscall(process_to_debug.pid,1,1,regs.rsp-0x100,4,0,0,0);
*/ 

long remote_syscall(
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

    struct user_regs_struct return_registers;
    ptrace(PTRACE_GETREGS,tid,NULL,&return_registers);


    ptrace(PTRACE_POKEDATA,tid,original_adress,original_opcode);
    ptrace(PTRACE_SETREGS,tid,NULL,&saved_regs);



    long ret = return_registers.rax;

    return ret;

}


long inject_mprotect(long adress,size_t size,int permissions){
    return remote_syscall(process_to_debug.pid,MPROTECT_SYSCALL_NUMBER,adress,size,permissions,0,0,0);
}

long inject_mmap(long adress,size_t size,int prot, int flags, int fd,size_t offset){
    return remote_syscall(process_to_debug.pid, MMAP_SYSCALL_NUMBER, adress, size, prot, flags, fd, offset);
}

long inject_munmap(long adress,size_t size){
    return remote_syscall(process_to_debug.pid,MUNMAP_SYSCALL_NUMBER,adress,size,0,0,0,0); //zeros doesnt matter 
}


