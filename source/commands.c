#include <stdio.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/types.h>


#include "commands.h"
#include "debug.h"
#include "breakpoint.h"
#include "maps_parsing.h"
#include "elf_parser.h"
#include "disassembly.h"
#include "utils.h"


extern debugee_process process_to_debug;
int run_process(int argc,char** argv){
    if(process_to_debug.proc_state != NOT_LOADED){
        printf("process is already loaded\n");
        return 0;
    }
    process_to_debug.pid = fork();
    if(process_to_debug.pid == 0){
        ptrace(PTRACE_TRACEME,process_to_debug.pid,NULL,NULL);
        int res = execlp(process_to_debug.elf_path,process_to_debug.elf_path,NULL);
        if(res == -1){
            printf("execlp failed\n");
        }


    }

    else{
        int status;
        waitpid(process_to_debug.pid,&status,0);
        if(WIFSTOPPED(status)){
            process_to_debug.proc_state = STOPPED;
        }
        load_proc_info(process_to_debug.pid);
        update_adressing_of_symtab_symbols(process_to_debug.array_of_symbols, process_to_debug.array_of_regions.arr[0].start);
        resolve_breakpoints();
        ptrace(PTRACE_CONT, process_to_debug.pid, NULL, NULL);
        process_to_debug.proc_state = RUNNING;
    }
    
}

int continue_proc(int argc,char** argv){
    if(process_to_debug.proc_state == LOADED || process_to_debug.proc_state == NOT_LOADED){
        printf("process is not running yet\n");
        return 0;
    }
    if(process_to_debug.pid != -1){
        step_over_bp(process_to_debug.pid);
        ptrace(PTRACE_CONT,process_to_debug.pid,NULL,0);
        process_to_debug.proc_state = RUNNING;
        return 1;
    }
    return 0;
}

int disassemble_function(int argc,char** argv){
    symbol* input_symbol = find_symbol_by_name(process_to_debug.array_of_symbols,argv[1]);
    if(input_symbol == NULL){
        printf("symbol not exist\n");
        return 0;
    }
    if(process_to_debug.proc_state == NOT_LOADED){
        static_disassemble_symbol(input_symbol);
    }
    else{
        live_disassemble_symbol(input_symbol);
   }

}

int step_into(int argc,char** argv){
    if(process_to_debug.proc_state == LOADED || process_to_debug.proc_state == NOT_LOADED){
        printf("process is not running yet\n");
        return 0;
    }
    step_over_bp(process_to_debug.pid);
    process_to_debug.proc_state = RUNNING;
    ptrace(PTRACE_SINGLESTEP,process_to_debug.pid,NULL,0);
}


int next_instruction(int argc,char** argv){
    if(process_to_debug.proc_state == LOADED || process_to_debug.proc_state == NOT_LOADED){
        printf("process is not running yet\n");
        return 0;
    }
    struct user_regs_struct regs;
    get_registers(process_to_debug.pid, &regs);
    unsigned char next_opcodes[16];

    for(int i = 0; i < sizeof(next_opcodes); i += sizeof(long)) {
        long tmp = ptrace(PTRACE_PEEKDATA, process_to_debug.pid, regs.rip + i, NULL);
        int copy_size = sizeof(long);
        if(i + copy_size > sizeof(next_opcodes)){
            copy_size = sizeof(next_opcodes) - i;
        }
        memcpy(next_opcodes + i, &tmp, copy_size);
    }
    //get 16 or less bytes from rip(16 bytes is the max instruction length in 0x86 64)

    if( !is_call_instruction(*(long*)next_opcodes) ){
        step_into(argc,argv);
    }
    else{ //call instruction in next opcode so put software bp in after call instruction
        int call_instruction_len = get_length_of_instruction(next_opcodes,sizeof(next_opcodes),regs.rip);
        unsigned char type_of_bp = SOFTWARE | TEMP | INTERNAL;
        create_breakpoint(NULL,0,regs.rip + call_instruction_len,type_of_bp);
        continue_proc(0,NULL);
    }
}


int cmd_delete(int argc,char** argv){
    if(argc == 2){
        int bp_index = atoi(argv[1]);
        if(bp_index == 0){
            if(strlen(argv[1]) == 1 && argv[1][0] == '0'){ //that means user did delete 0
                if(!delete_breakpoint(bp_index)){
                    printf("no breakpoint number 0\n");
                }
            }            
        }
        else{
            if(!delete_breakpoint(bp_index)){
                printf("no breakpoint number %d\n",bp_index);
            }
        }
    }
}



int print_backtrace(int argc,char** argv){
    struct user_regs_struct regs;
    get_registers(process_to_debug.pid, &regs);
    unsigned long current_rbp = regs.rbp;
    unsigned long current_rip = regs.rip;
    symbol* current_symbol = get_symbol_by_adress(current_rip);
    int current_function_index = 0;
    printf("#%d   %s\n",current_function_index,current_symbol->name);
    while(current_rbp != 0){
        long return_adress = ptrace(PTRACE_PEEKDATA,process_to_debug.pid,(void*)(current_rbp+8),NULL);
        current_rbp = ptrace(PTRACE_PEEKDATA,process_to_debug.pid,(void*)(current_rbp),NULL);
        current_symbol = get_symbol_by_adress(return_adress);
        if(current_symbol == NULL) break;
        current_function_index++;
        printf("#%d   %s\n",current_function_index,current_symbol->name);
    }
}







int exit_debugger(int argc,char** argv){
    printf("in exit\n");
    exit(0);
}