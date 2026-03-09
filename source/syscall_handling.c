
#include <sys/ptrace.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/types.h>

#include "debug.h"
#include "syscall_handling.h"
#include "info_commands.h"
#include "rewind.h"
#include "disassembly.h"
#include "breakpoint.h"
#include "commands.h"
#include "colors.h"



extern debugee_process process_to_debug;

#define SYSCALL_OPCODE 0x050f
#define MAX_SYSCALLS 1000
#define MAX_FILENAME_SIZE 50

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
    {"read",__NR_read,read_handler},
    {"write",__NR_write,write_handler},
    {"open",__NR_open,open_handler},
    {"close",__NR_close,NULL},
    {"mmap",__NR_mmap,NULL},
    {"socket",__NR_socket,NULL},
    {"connect",__NR_connect,NULL},
    {"accept",__NR_accept,NULL},

    {"openat",__NR_openat,openat_handler},
    {NULL,-1,NULL}
};



syscall_entry* get_syscall_entry_by_number(int syscall_number){
    for(int i = 0; syscalls[i].name != NULL && syscalls[i].number != -1; i++){
        if(syscalls[i].number == syscall_number) return &syscalls[i];
    }
    return NULL;
}


int syscall_handle(struct user_regs_struct* regs){

    int hooked = 0;

    //check if this syscall is supposed to be hooked
    syscall_entry* entry = get_syscall_entry_by_number(regs->rax);
    
    if(entry != NULL && hooked_syscalls[entry->number]){
        hooked = 1;
        if(entry->handler != NULL){
            entry->handler(entry->name,entry->number,regs);
        }
        else {
            default_handler(entry->name,entry->number,regs);
        }
    }


    struct user_regs_struct* final_syscall_regs = regs;
    long syscall_number = final_syscall_regs->rax;
    long first_arg = final_syscall_regs->rdi;
    long second_arg = final_syscall_regs->rsi;
    long third_arg = final_syscall_regs->rdx;
    long fourth_arg = final_syscall_regs->r10;
    long fifth_arg = final_syscall_regs->r8;
    long sixth_arg = final_syscall_regs->r9;



    if(syscall_number == __NR_write && first_arg == 1){ 
        printf(GREEN "\n(PROC) " RESET);
        fflush(stdout);
    }
    step_over_bp(process_to_debug.pid); 
    fflush(stdout);
    // after syscall




    process_to_debug.proc_state = STOPPED;
    struct user_regs_struct return_regs;
    get_registers(process_to_debug.pid , &return_regs);
    long return_val = return_regs.rax;

    if(syscall_number == __NR_exit || syscall_number == __NR_exit_group){ //hook to exit
        printf("process exit code : %ld\n", first_arg);
        printf("process exited\n");
        process_to_debug.proc_state = EXITED;
        return 0;
    } 
 
    else if(syscall_number == __NR_ptrace){ //hook to ptrace
        if(first_arg == PTRACE_TRACEME){
            printf("anti debug dectected!\n");
            return_regs.rax = 0;
            printf("overriding return value to 0\n");
            ptrace(PTRACE_SETREGS,process_to_debug.pid,NULL,&return_regs);
        }
    }

    else if(syscall_number == __NR_mmap && return_val != MAP_FAILED){ //hook to mmap
        void* address = (void*)return_val;
        if(process_to_debug.current_snapshot != NULL){ //during record
            add_live_mmap(&process_to_debug.current_snapshot->current_mmaps_head, MMAP,address, second_arg,third_arg,fourth_arg,fifth_arg,sixth_arg);
        }
        else{ //not during record
            add_live_mmap(&process_to_debug.live_mmaps, MMAP, address, second_arg,third_arg,fourth_arg,fifth_arg,sixth_arg);
        }
    }
    
    else if(syscall_number == __NR_munmap && return_val != -1){ //hook to munmap
        void* address = (void*)first_arg;
        if(process_to_debug.current_snapshot != NULL){ //during record
            
            add_live_mmap(&process_to_debug.current_snapshot->current_mmaps_head, MUNMAP,address, second_arg,0,0,0,0);
        }
        else{ //not during record
            live_mmap_node* live_mmap = get_live_mmap_by_addr(& process_to_debug.live_mmaps, address, MMAP);
            if(live_mmap ){
                int res = remove_live_mmap(&process_to_debug.live_mmaps, address,MMAP);
            }
        }
    }  



    if(hooked){
        printf("%s returned : %ld\n",entry->name,return_val);
    }
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






int default_handler(char* syscall_name, long syscall_number, struct user_regs_struct* regs){
    printf(YELLOW "[HOOK]" RESET " %s(arg1=%lld, arg2=%lld, arg3=%lld, arg4=%lld)\n",syscall_name,regs->rdi, regs->rsi, regs->rdx, regs->r10);
    return 1;
}

int write_handler(char* syscall_name, long syscall_number, struct user_regs_struct* regs){
    printf(YELLOW "[HOOK]" RESET " %s(fd=%lld, buf=" BLUE "0x%016llx" RESET ", count=%lld)\n",syscall_name,regs->rdi, regs->rsi, regs->rdx);

    syscall_param params[] = {
        {"fd",&regs->rdi},
        {"buf",&regs->rsi},
        {"count",&regs->rdx},
        {NULL,NULL}
    };
    
    change_params(syscall_name, params);
    ptrace(PTRACE_SETREGS, process_to_debug.pid, 0, regs);
    return 1;
}

int read_handler(char* syscall_name, long syscall_number, struct user_regs_struct* regs){
    printf(YELLOW "[HOOK]" RESET " %s(fd=%lld, buf=" BLUE "0x%016llx" RESET ", count=%lld)\n",syscall_name,regs->rdi, regs->rsi, regs->rdx);

    syscall_param params[] = {
        {"fd",&regs->rdi},
        {"buf",&regs->rsi},
        {"count",&regs->rdx},
        {NULL,NULL}
    };
    
    change_params(syscall_name, params);
    ptrace(PTRACE_SETREGS, process_to_debug.pid, 0, regs);
    return 1;
}

int open_handler(char* syscall_name, long syscall_number, struct user_regs_struct* regs){
    long filename_addr = regs->rdi;
    char* filename = read_remote_str(filename_addr);

    printf(YELLOW "[HOOK]" RESET " %s(filename=%s, flags=%lld, mode=%lld)\n",syscall_name,filename, regs->rsi, regs->rdx);

    syscall_param params[] = {
        {"filename",&regs->rdi},
        {"flags",&regs->rsi},
        {"mode",&regs->rdx},
        {NULL,NULL}
    };
    
    change_params(syscall_name, params);
    ptrace(PTRACE_SETREGS, process_to_debug.pid, 0, regs);
    return 1;
}

int openat_handler(char* syscall_name, long syscall_number, struct user_regs_struct* regs){

    long filename_addr = regs->rsi;
    char* filename = read_remote_str(filename_addr);
    printf(YELLOW "[HOOK]" RESET " %s(dfd=%lld, filename=\"%s\", flags=%lld, mode=%lld)\n",syscall_name,regs->rdi, filename, regs->rdx,regs->r10);

    syscall_param params[] = {
        {"dfd",&regs->rdi},
        {"filename",&regs->rsi},
        {"flags",&regs->rdx},
        {"mode",&regs->r10},
        {NULL,NULL}
    };
    
    change_params(syscall_name, params);
    ptrace(PTRACE_SETREGS, process_to_debug.pid, 0, regs);
    return 1;
}







void change_params(const char* syscall_name, syscall_param* params){
    printf("You can modify the parameters. Type 'continue' or 'c' to run the syscall.\n");
    char cmd[256];

    while(1)
    {
        printf(DARK_PURPLE "hyperdbg> " RESET);
        fgets(cmd,sizeof(cmd),stdin);

        if(strncmp(cmd,"continue",8)==0 || strncmp(cmd,"c",1)==0)
            break;

        char param[64];
        long val;

        if(sscanf(cmd,"set %s %ld",param,&val)==2)
        {
            for(int i=0; params[i].name!=NULL; i++)
            {
                if(strcmp(param,params[i].name)==0)
                {
                    *params[i].reg = val; //change the register value
                    printf("%s updated\n",param);
                    break;
                }
            }
        }
    }
}








char* read_remote_str(long remote_addr){
    char* filename = malloc(MAX_FILENAME_SIZE);
    remote_read_string(process_to_debug.pid, remote_addr, filename, MAX_FILENAME_SIZE);
    return filename;
}