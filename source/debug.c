#include <stdio.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/user.h>

#include "debug.h"
#include "utils.h"
#include "info_commands.h"
#include "commands.h"
#include "breakpoint.h"
#include "hw_breakpoints.h"
#include "syscall_injection.h"


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
    {"record",record,"record and save snapshot for later rewind"},
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
    if(commands == NULL){
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
    step_over_bp(process_to_debug.pid);
    struct user_regs_struct regs;
    get_registers(pid, &regs);


    printf("process stopped in adress : %llx",regs.rip);
    siginfo_t si;
    ptrace(PTRACE_GETSIGINFO, process_to_debug.pid, NULL, &si);
    int signal = WSTOPSIG(status);
    if(signal == SIGTRAP){
        breakpoint* bp = get_breakpoint_by_addr(regs.rip-1); //null if no breakpoint match
        if(bp != NULL){
            if((bp->type & INTERNAL) == 0){ //not an internal bp
                printf(", hit bp number : %d",bp->index);
            }
        }
    }
    else if(signal == SIGSEGV){
        sigsegv_handler(signal,si);
    }
    printf("\n");
}



int sigsegv_handler(int signal,siginfo_t si){
    printf("\nProgram received signal SIGSEGV, Segmentation fault.\n");
}



int debug_process(char* elf_path){
    char* input_command = malloc(sizeof(char)*INPUT_SIZE);
    int status;
    while(1){
        if(process_to_debug.proc_state == NOT_LOADED || process_to_debug.proc_state == STOPPED){
            printf(">");
            fgets(input_command,INPUT_SIZE,stdin);
            int res = handle_command(input_command);
            if(!res) printf("command is not avalieble\n");
        }
        else if(process_to_debug.proc_state == RUNNING){
            waitpid(process_to_debug.pid,&status,0);
            if(WIFSTOPPED(status)){
                handle_stopped_process(process_to_debug.pid, status);
            }
            else if(WIFEXITED(status)){
                printf("child exited!\n");
                break;
            }
        }
    }
}


