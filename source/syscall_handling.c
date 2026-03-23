
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
#include "syscall_injection.h"


extern debugee_process process_to_debug;

#define SCRATCH_BUFFER_SIZE 4096 * 2
#define SYSCALL_OPCODE 0x050f
#define MAX_SYSCALLS 1000
#define MAX_STR_READ 50

//system call in 64 bit linux systems
//rax - syscall number
//rdi - first argument
//rsi - second argument
//rdx - third argument
//r10 - fourth argument
//r8 - fifth argument
//r9 - sixth argument


char hooked_syscalls[1000] = {0};


#define P(...) { __VA_ARGS__, {0} }
#define NO_PARAMS { {0} }

syscall_entry syscalls[] = {
    // ===== FILE I/O =====
    { "read",     __NR_read,     P({"fd",NULL,INTEGER}, {"buf",NULL,ADDRESS}, {"count",NULL,INTEGER}) },
    { "write",    __NR_write,    P({"fd",NULL,INTEGER}, {"buf",NULL,STRING},  {"count",NULL,INTEGER}) },
    { "open",     __NR_open,     P({"filename",NULL,STRING}, {"flags",NULL,INTEGER}, {"mode",NULL,INTEGER}) },
    { "openat",   __NR_openat,   P({"dfd",NULL,INTEGER}, {"filename",NULL,STRING}, {"flags",NULL,INTEGER}, {"mode",NULL,INTEGER}) },
    { "close",    __NR_close,    P({"fd",NULL,INTEGER}) },
    { "lseek",    __NR_lseek,    P({"fd",NULL,INTEGER}, {"offset",NULL,INTEGER}, {"whence",NULL,INTEGER}) },

    // ===== MEMORY =====
    { "mmap",     __NR_mmap,     P({"addr",NULL,ADDRESS}, {"length",NULL,INTEGER}, {"prot",NULL,INTEGER}, {"flags",NULL,INTEGER}, {"fd",NULL,INTEGER}, {"offset",NULL,INTEGER}) },
    { "munmap",   __NR_munmap,   P({"addr",NULL,ADDRESS}, {"length",NULL,INTEGER}) },
    { "mprotect", __NR_mprotect, P({"addr",NULL,ADDRESS}, {"len",NULL,INTEGER}, {"prot",NULL,INTEGER}) },
    { "brk",      __NR_brk,      P({"addr",NULL,ADDRESS}) },

    // ===== PROCESS =====
    { "fork",     __NR_fork,     NO_PARAMS },
    { "vfork",    __NR_vfork,    NO_PARAMS },
    { "clone",    __NR_clone,    P({"flags",NULL,INTEGER}, {"stack",NULL,ADDRESS}, {"ptid",NULL,ADDRESS}, {"ctid",NULL,ADDRESS}, {"tls",NULL,ADDRESS}) },
    { "execve",   __NR_execve,   P({"filename",NULL,STRING}, {"argv",NULL,ADDRESS}, {"envp",NULL,ADDRESS}) },
    { "exit",     __NR_exit,     P({"status",NULL,INTEGER}) },
    { "wait4",    __NR_wait4,    P({"pid",NULL,INTEGER}, {"status",NULL,ADDRESS}, {"options",NULL,INTEGER}, {"rusage",NULL,ADDRESS}) },
    { "getpid",   __NR_getpid,   NO_PARAMS },

    // ===== FD / IOCTL =====
    { "dup",      __NR_dup,      P({"oldfd",NULL,INTEGER}) },
    { "dup2",     __NR_dup2,     P({"oldfd",NULL,INTEGER}, {"newfd",NULL,INTEGER}) },
    { "fcntl",    __NR_fcntl,    P({"fd",NULL,INTEGER}, {"cmd",NULL,INTEGER}, {"arg",NULL,INTEGER}) },
    { "ioctl",    __NR_ioctl,    P({"fd",NULL,INTEGER}, {"request",NULL,INTEGER}, {"argp",NULL,ADDRESS}) },

    // ===== NETWORK =====
    { "socket",   __NR_socket,   P({"domain",NULL,INTEGER}, {"type",NULL,INTEGER}, {"protocol",NULL,INTEGER}) },
    { "connect",  __NR_connect,  P({"sockfd",NULL,INTEGER}, {"addr",NULL,ADDRESS}, {"addrlen",NULL,INTEGER}) },
    { "accept",   __NR_accept,   P({"sockfd",NULL,INTEGER}, {"addr",NULL,ADDRESS}, {"addrlen",NULL,ADDRESS}) },
    { "bind",     __NR_bind,     P({"sockfd",NULL,INTEGER}, {"addr",NULL,ADDRESS}, {"addrlen",NULL,INTEGER}) },
    { "listen",   __NR_listen,   P({"sockfd",NULL,INTEGER}, {"backlog",NULL,INTEGER}) },
    { "recvfrom", __NR_recvfrom, P({"fd",NULL,INTEGER}, {"buf",NULL,ADDRESS}, {"len",NULL,INTEGER}, {"flags",NULL,INTEGER}, {"src_addr",NULL,ADDRESS}, {"addrlen",NULL,ADDRESS}) },
    { "sendto",   __NR_sendto,   P({"fd",NULL,INTEGER}, {"buf",NULL,STRING}, {"count",NULL,INTEGER}, {"flags",NULL,INTEGER}, {"dest_addr",NULL,ADDRESS}, {"addrlen",NULL,INTEGER}) },

    // ===== TIME =====
    { "nanosleep", __NR_nanosleep, P({"req",NULL,ADDRESS}, {"rem",NULL,ADDRESS}) },

    // ===== SIGNALS =====
    { "kill",     __NR_kill,     P({"pid",NULL,INTEGER}, {"sig",NULL,INTEGER}) },

    // ===== END =====
    { NULL, -1, NO_PARAMS }
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
        hooked_syscall_handler(entry,regs);
        hooked = 1;
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
    return 1;
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
    return 1;
}




int hooked_syscall_handler(syscall_entry* entry, struct user_regs_struct* regs){
    printf(YELLOW "[HOOK] " RESET "%s(",entry->name);

    unsigned long* regs_array[6] = {
        &regs->rdi,
        &regs->rsi,
        &regs->rdx,
        &regs->r10,
        &regs->r8,
        &regs->r9
    };

    for(int i = 0; entry->params[i].name != NULL;i++){
        entry->params[i].reg = regs_array[i];
        if(i != 0) printf(", ");

        printf("%s=",entry->params[i].name);
        switch(entry->params[i].type){
            case INTEGER:
                printf("%lld",*entry->params[i].reg);
                break;
            case STRING:
                char* buffer;
                long buffer_addr = *entry->params[i].reg;
                if( (strcmp(entry->name,"write")   == 0 ||
                    strcmp(entry->name,"sendto")  == 0 ||
                    strcmp(entry->name,"read")    == 0 ||
                    strcmp(entry->name,"recvfrom")== 0 ||
                    strcmp(entry->name,"readv")   == 0 ||
                    strcmp(entry->name,"writev")  == 0) 
                    && i+1 < 6) 
                {
                    buffer = read_remote_str(buffer_addr, *regs_array[i+1]);
                }

                else buffer = read_remote_str(buffer_addr,-1);

                printf("\"%s\"",buffer);
                break;
            case ADDRESS:
                printf(BLUE "0x%016llx" RESET,*entry->params[i].reg);
                break;
            
        }
    }
    printf(")\n");
    change_params(entry->name, entry->params);
    ptrace(PTRACE_SETREGS, process_to_debug.pid, 0, regs);
    return 1;
}



void change_params(const char* syscall_name, syscall_param* params){
    printf("You can modify the parameters. Type 'continue' or 'c' to run the syscall.\n");
    char cmd[256];



    if(process_to_debug.scratch_buffer == NULL){
        process_to_debug.scratch_buffer = (void*)inject_mmap(0, SCRATCH_BUFFER_SIZE ,PROT_READ | PROT_WRITE,MAP_PRIVATE | MAP_ANONYMOUS , 0,0);
    }


    while(1){
        printf(DARK_PURPLE "hyperdbg> " RESET);
        fgets(cmd,sizeof(cmd),stdin);

        if(strncmp(cmd,"continue",8)==0 || strncmp(cmd,"c",1)==0)
            break;


        long val;

        char param[64];
        char val_str[1024]; 

        if(sscanf(cmd,"set %63s %1023[^\n]",param,val_str) == 2)
        {
            for(int i=0; params[i].name!=NULL; i++)
            {
                if(strcmp(param, params[i].name) == 0)
                {
                    if(params[i].type == STRING)
                    {
                        size_t len = strlen(val_str) + 1;
                        if(len > SCRATCH_BUFFER_SIZE) len = SCRATCH_BUFFER_SIZE;
                        
                        
                        remote_write(val_str,process_to_debug.scratch_buffer,len);



                        *params[i].reg = (unsigned long)process_to_debug.scratch_buffer;

                        printf("%s updated to : %s\n",param, val_str);
                    }
                    else
                    {
                        long val = strtol(val_str, NULL, 0); 
                        *params[i].reg = val;
                        printf("%s updated to : %ld\n", param, val);
                    }
                    break;
                }
            }
        }
    }
}








char* read_remote_str(long remote_addr,int count){
    char* str;
    if(count == -1){
        str = malloc(MAX_STR_READ);
        remote_read_string(process_to_debug.pid, remote_addr, str, MAX_STR_READ);
    }
    else{
        str = malloc(count+1);
        remote_copy(str,remote_addr,count);
        str[count] = '\x00';
    }
    return str;
}



