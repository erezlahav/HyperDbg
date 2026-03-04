
#include <sys/ptrace.h>
#include <string.h>


#include "debug.h"
#include "syscall_handling.h"
#include "info_commands.h"
#include "rewind.h"
#include "disassembly.h"
#include "breakpoint.h"
#include "commands.h"

#define SYSCALL_OPCODE 0x050f
extern debugee_process process_to_debug;

int check_for_syscall(long current_rip){
    long syscall_rip = current_rip-2;
    long res = ptrace(PTRACE_PEEKDATA,process_to_debug.pid,syscall_rip,0);
    long two_LSB = res & 0xffff;
    return two_LSB == SYSCALL_OPCODE;
}






int syscall_handle(struct user_regs_struct* regs){
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
    long size = end-start;
    unsigned char* code_buffer = malloc(size);

    long syscall_opcode = SYSCALL_OPCODE;

    remote_copy(code_buffer,(void*)start,size);

    for(int i = 0; i < size-1; i++){
        if(memcmp(code_buffer + i,&syscall_opcode,2) == 0){ //check 2 lsb of opcode for syscall
            unsigned char type = SYSCALL | INTERNAL | PERM | SOFTWARE;
            create_breakpoint(NULL,0,(long)(start + i),type);
        }
    }

    

}