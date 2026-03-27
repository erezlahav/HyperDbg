#include <stdio.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <sys/mman.h>


#include "debug.h"
#include "utils.h"
#include "info_commands.h"
#include "commands.h"
#include "breakpoint.h"
#include "hw_breakpoints.h"
#include "syscall_injection.h"
#include "rewind.h"
#include "syscall_handling.h"
#include "colors.h"


extern debugee_process process_to_debug;

const command_table table_commands[] = {
    {"info",info,"help displaying data like functions/registers and more..."},
    {"disass",disassemble_function,"print disassembly representation of the function"},
    {"disassemble",disassemble_function,"print disassembly representation of the function"},
    {"break",cmd_software_breakpoint,"set breakpoint in adress you choose"},
    {"hbreak",cmd_hardware_breakpoint,"set breakpoint in adress you choose"},
    {"delete",cmd_delete,"deletes a breakpoint"},
    {"exit",exit_debugger,"exit from debugger"},
    {"c",continue_proc,"continue the execution of the process"},
    {"continue",continue_proc,"continue the execution of the process"},
    {"r",run_process,"run the current process after breaking on stop signal before main"},
    {"run",run_process,"run the current process after breaking on stop signal before main"},
    {"si",step_into,"step into instruction(executes one instruction)"},
    {"ni",next_instruction,"step over instruction(going over functions and not into)"},
    {"bt",print_backtrace,"printing backtrace of the function"},
    {"set",set,"set value of register"},
    {"record",record,"record and save snapshot for later rewind"},
    {"rewind",rewind_snapshot,"rewind to the last snapshot saved by record"},
    {"hook",hook,"hook to system call"},
    {"unhook",unhook,"remove hook to system call"},
    {NULL,NULL,NULL}
};



int get_registers(pid_t pid, struct user_regs_struct* regs){
    if(ptrace(PTRACE_GETREGS,pid,NULL,regs) == -1){
        return 0;
    }
    return 1;
}

int set_registers(pid_t pid, struct user_regs_struct* regs){
    if(ptrace(PTRACE_SETREGS,pid,NULL,regs) == -1){
        return 0;
    }
    return 1;
}




int handle_command(char* command){
    int* argc = malloc(sizeof(int));
    char** commands = parse_command(command,argc);
    if(commands == NULL || commands[0] == NULL){
        return 0;
    }
    if(commands[0][0] == 'x'){  //syntax like x/10i $rip
        exemine(*argc,commands);
        return 1;
    }

    for(int i =0; table_commands[i].command!= NULL;i++){
        if(commands[0] == NULL){break;}
        if(strcmp(commands[0],table_commands[i].command) == 0){
            table_commands[i].func_handler(*argc,commands);
            return 1;
        }
    }
    return 0;
}

int handle_stopped_process(pid_t pid, int status){
    process_to_debug.proc_state = STOPPED;
    siginfo_t si;
    ptrace(PTRACE_GETSIGINFO, process_to_debug.pid, NULL, &si);
    int signal = WSTOPSIG(status);
    struct user_regs_struct regs;
    get_registers(pid, &regs);
    long bp_rip = regs.rip-1;

    int cont = 0;
    if(signal == SIGSEGV){
        int handled = sigsegv_handler(signal,si);
        if(handled) continue_proc(0,NULL);
    }


    else if(signal == SIGTRAP){
        breakpoint* bp = get_breakpoint_by_addr(bp_rip); //null if no breakpoint match
        if(bp != NULL){
            symbol* bp_symbol = get_symbol_by_adress(bp_rip);
            if(((bp->type & SYSCALL)) != 0){
                syscall_handle(&regs);
            }
            else if((bp->type & INTERNAL) == 0){ //not an internal bp

                printf("Breakpoint %d, " BLUE "0x%016lx " RESET ,bp->index, bp_rip);
                if(bp_symbol) printf("in " YELLOW "%s ()" RESET,bp_symbol->name);
                else  printf(YELLOW "in ?? ()" RESET);
                printf("\n");
            }
            else if ((bp->type & NI) ) {  // TF = bit 8
                printf(BLUE "0x%016lx " RESET,bp_rip);
                if(bp_symbol) printf("in " YELLOW "%s ()" RESET,bp_symbol->name);
                else  printf(YELLOW "in ?? ()" RESET);
                printf("\n");
            }
        }
        else{ //TF from si/ni
            symbol* bp_symbol = get_symbol_by_adress(regs.rip);
            printf(BLUE "0x%016lx " RESET,bp_rip);
            if(bp_symbol) printf("in " YELLOW "%s ()" RESET,bp_symbol->name);
            else{
                char* name = get_region_name_by_address(regs.rip);
                if(name) printf("in " YELLOW "%s ()" RESET,name);
                else printf("in " YELLOW "?? ()" RESET);
            }
            printf("\n");
        }
    }
    return cont;
}



int sigsegv_handler(int signal,siginfo_t si){
    long segfault_addr = (long)si.si_addr;
    page* curr_page = get_page_from_addr(segfault_addr);
    if(curr_page == NULL){
        printf("\nProgram received signal SIGSEGV, Segmentation fault.\n");
        printf("adress of segfault : 0x%016lx\n",segfault_addr);
        return 0;
    }
    else{
        if(curr_page->dirty_bit == 0){
            curr_page->data = malloc(PAGE_SIZE);
            remote_copy(curr_page->data,(void*)curr_page->start,curr_page->size);
            inject_mprotect(curr_page->start,curr_page->size,PROT_READ | PROT_WRITE);
            curr_page->dirty_bit = 1;
        }
        return 1;
    }
    

}



int debug_process(char* elf_path){
    char* input_command = malloc(sizeof(char)*INPUT_SIZE);
    int status;
    while(1){
        if(process_to_debug.proc_state == NOT_LOADED || process_to_debug.proc_state == STOPPED){
            printf(DARK_PURPLE "hyperdbg> " RESET);
            fgets(input_command,INPUT_SIZE,stdin);
            int res = handle_command(input_command);
            if(!res) printf("command is not avalieble\n");
        }
        else if(process_to_debug.proc_state == RUNNING){
            waitpid(process_to_debug.pid,&status,0);
            if(WIFEXITED(status)){
                process_to_debug.proc_state == EXITED;
                printf("process exited\n");
                break;
            }
            if(WIFSTOPPED(status)){
                int sig = WSTOPSIG(status);
                handle_stopped_process(process_to_debug.pid, status);
            }
        }
        else if(process_to_debug.proc_state == EXITED){
            break;
        }
    }
}


