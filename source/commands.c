#include <stdio.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>

#include "commands.h"
#include "debug.h"
#include "breakpoint.h"
#include "maps_parsing.h"
#include "elf_parser.h"
#include "disassembly.h"
#include "utils.h"
#include "rewind.h"


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
        parse_maps(process_to_debug.pid,&process_to_debug.array_of_regions);
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
            else if(strcmp(argv[1],"record") == 0){
                delete_record();
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
    if(current_symbol == NULL){
        printf("unknown symbol\n");
        return 0;
    }
    int current_function_index = 0;
    printf("#%d   %s\n",current_function_index,current_symbol->name);
    int max_depth = 64;
    
    while(current_rbp != 0 && current_function_index < max_depth){
        long return_adress = ptrace(PTRACE_PEEKDATA,process_to_debug.pid,(void*)(current_rbp+8),NULL);
        current_rbp = ptrace(PTRACE_PEEKDATA,process_to_debug.pid,(void*)(current_rbp),NULL);
        current_symbol = get_symbol_by_adress(return_adress);
        if(current_symbol == NULL) break;
        current_function_index++;
        printf("#%d   %s\n",current_function_index,current_symbol->name);
    }
}



int set(int argc,char** argv){
    
    if(process_to_debug.proc_state == NOT_LOADED || process_to_debug.proc_state == LOADED){
        printf("program is not running yet\n");
        return 0;
    }
    

    if(argv[1] == NULL){
        printf("Argument required\n");
        return 0;
    }
    long set_val;
    if(argv[1][0] == '$'){ //register
        char register_name[5];
        char* reg_start = argv[1] + 1;
        int register_name_index = 0;
        while(reg_start != NULL && (*reg_start != ' ' &&  *reg_start != '=') && register_name_index < sizeof(register_name)){
            register_name[register_name_index] = *reg_start;
            register_name_index++;
            reg_start++;
        }
        register_name[register_name_index] = '\x00';
        if(*reg_start != '=' && strcmp(argv[2],"=") != 0){
            printf("Expression is not an assignment\n");
            return 0;
        }
        reg_start++;
        if(*reg_start != '\x00'){ //no spaces
            errno = 0;
            if(strncmp(reg_start,"0x",2) == 0) set_val = strtol(reg_start+2,NULL,16);
            else set_val = strtol(reg_start,NULL,16);
        }


        else if(argv[2] != NULL){
            char* str_num;
            errno = 0;
            if(strcmp(argv[2],"=") == 0) str_num = argv[3];
            else{str_num = argv[2];}

            if(strncmp(str_num,"0x",2) == 0) set_val = strtol(str_num+2,NULL,16);
            else set_val = strtol(str_num,NULL,16);
        }


        if(errno != 0){
            printf("error in value\n");
            return 0;
        }

        struct user_regs_struct regs;
        get_registers(process_to_debug.pid, &regs);   
        unsigned long* reg_ptr = get_register(&regs,register_name);
        if(reg_ptr == NULL){
            printf("invalid register\n");
            return 0;
        }
        *reg_ptr = set_val;
        set_registers(process_to_debug.pid, &regs);


    }
}


int record(int argc,char** argv){
    if(process_to_debug.proc_state == NOT_LOADED || process_to_debug.proc_state == LOADED){
        printf("program is not running yet\n");
        return 0;
    }
    if(process_to_debug.current_snapshot != NULL){
        printf("The process is already being recorded.  Use delete record to stop delete the recording first.\n");
        return 0;
    }
    save_snapshot();
    snapshot* snapshot = process_to_debug.current_snapshot;
    regions_array* arr_regions = snapshot->arr_of_regions;
    for(int i = 0; i < arr_regions->regions_count;i++){
        if(((arr_regions->arr[i].permissions) & WRITE) != 0){
            inject_mprotect(arr_regions->arr[i].start,arr_regions->arr[i].end-arr_regions->arr[i].start,PROT_READ);
        }
    }
}



int rewind_snapshot(int argc,char** argv){
    if(process_to_debug.proc_state == NOT_LOADED || process_to_debug.proc_state == LOADED){
        printf("program is not running yet\n");
        return 0;
    }
    snapshot* snapshot = process_to_debug.current_snapshot;
    if(snapshot == NULL){
        printf("no snapshots saved yet\n");
        return 0;
    }
    struct user_regs_struct former_regs = snapshot->regs;
    ptrace(PTRACE_SETREGS,process_to_debug.pid,0,&former_regs);
    arr_pages* pages_arr = snapshot->pages_array;
    restore_pages(pages_arr);
    delete_record();
}






int exit_debugger(int argc,char** argv){
    exit(0);
}