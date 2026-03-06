
#include <sys/ptrace.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "debug.h"
#include "syscall_handling.h"
#include "info_commands.h"
#include "rewind.h"
#include "disassembly.h"
#include "breakpoint.h"
#include "commands.h"




extern debugee_process process_to_debug;

#define SYSCALL_OPCODE 0x050f
#define MAX_SYSCALLS 1000

//system call in 64 bit linux systems
//rax - syscall number
//rdi - first argument
//rsi - second argument
//rdx - third argument
//r10 - fourth argument
//r8 - fifth argument
//r9 - sixth argument


char hooked_syscalls[1000] = {0};

syscall_entry syscalls[] = {
    {"read",__NR_read,NULL},
    {"write",__NR_write,NULL},
    {"open",__NR_open,NULL},
    {"close",__NR_close,NULL},
    {"mmap",__NR_mmap,NULL},
    {"socket",__NR_socket,NULL},
    {"connect",__NR_connect,NULL},
    {"accept",__NR_accept,NULL},
    {NULL,-1,NULL}
};







int syscall_handle(struct user_regs_struct* regs){
    long syscall_number = regs->rax;
    long first_arg = regs->rdi;
    long second_arg = regs->rsi;
    long third_arg = regs->rdx;
    long fourth_arg = regs->r10;
    long fifth_arg = regs->r8;
    long sixth_arg = regs->r9;



    if(syscall_number == __NR_read){
        //printf("read accured, params : \n");
        //printf("fd : %d, buffer adress : 0x%lx, count : %d\n",first_arg,second_arg,third_arg);
    }
    if(syscall_number == __NR_write){
        //printf("write accured\n");
    }
    if(syscall_number == __NR_exit || syscall_number == __NR_exit_group){
        printf("process exit code : %ld\n", first_arg);
        printf("process exited\n");
        process_to_debug.proc_state = EXITED;
        return 0;
    }   
    






    step_over_bp(process_to_debug.pid);
    process_to_debug.proc_state = STOPPED;
    struct user_regs_struct return_regs;
    get_registers(process_to_debug.pid , &return_regs);



    long return_val = return_regs.rax;

    continue_proc(0,NULL);

    return 1;
    
}


int put_syscalls_bps(){
    if(process_to_debug.proc_state == LOADED || process_to_debug.proc_state == NOT_LOADED){
        printf("process is not running yet\n");
        return 0;
    }
    int regions_count = process_to_debug.array_of_regions.regions_count;
    if(regions_count == 0){
        printf("no regions loaded yet\n");
        return 0;
    }


    for(int i = 0; i < regions_count;i++){
        if(((process_to_debug.array_of_regions.arr[i].permissions) & EXECUTE) != 0){
            int res = patch_syscalls_to_bps(process_to_debug.array_of_regions.arr[i].start , process_to_debug.array_of_regions.arr[i].end);
        }
    }
}


int patch_syscalls_to_bps(long start,long end){
    if(end <= start) return 0;
    long size = end-start;
    unsigned char* code_buffer = malloc(size);
    long syscall_opcode = SYSCALL_OPCODE;

    remote_copy(code_buffer,(void*)start,size);


    for(long i = 0; i < size-1; i++){
        if(memcmp(code_buffer + i,&syscall_opcode,2) == 0){ //check 2 lsb of opcode for syscall
            unsigned char type = SYSCALL | INTERNAL | PERM | SOFTWARE;
            create_breakpoint(NULL,0,(long)(start + i),type);
            
        }
    }
    free(code_buffer);

    

}