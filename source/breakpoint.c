#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <sys/user.h>
#include "breakpoint.h"
#include "elf_parser.h"
#include "debug.h"
#include "hw_breakpoints.h"
extern debugee_process process_to_debug;





int ptrace_breakpoint(breakpoint* bp){
    if(process_to_debug.proc_state == NOT_LOADED){
        return 0;
    }
    if(bp->state != RESOLVED){
        return 0;
    }
    if((bp->type & HARDWARE) ==  HARDWARE){
        set_hardware_breakpoint(bp->abs_adress);
    }
    else if((bp->type & SOFTWARE) == SOFTWARE){
        errno = 0;
        long res = ptrace(PTRACE_PEEKDATA,process_to_debug.pid,bp->abs_adress,NULL);
        if (res == -1 && errno != 0) {
            printf("ptrace failed: %s\n", strerror(errno));
        } 
        bp->orig_data = res;
        long new_instruction_with_cc = (res & 0xffffffffffffff00) | 0xcc;
        ptrace(PTRACE_POKEDATA,process_to_debug.pid,bp->abs_adress,new_instruction_with_cc);
    }
}


int create_pending_breakpoint(symbol* bp_symbol,long offset_from_symbol,long abs_adress,unsigned char type){
    process_to_debug.array_of_breakpoints.arr_breakpoints[process_to_debug.array_of_breakpoints.number_of_breakpoints].index = process_to_debug.array_of_breakpoints.number_of_breakpoints;
    process_to_debug.array_of_breakpoints.arr_breakpoints[process_to_debug.array_of_breakpoints.number_of_breakpoints].type = type;
    process_to_debug.array_of_breakpoints.arr_breakpoints[process_to_debug.array_of_breakpoints.number_of_breakpoints].index = process_to_debug.array_of_breakpoints.number_of_breakpoints;
    process_to_debug.array_of_breakpoints.arr_breakpoints[process_to_debug.array_of_breakpoints.number_of_breakpoints].bp_symbol = bp_symbol;
    process_to_debug.array_of_breakpoints.arr_breakpoints[process_to_debug.array_of_breakpoints.number_of_breakpoints].offset_from_symbol = offset_from_symbol;
    process_to_debug.array_of_breakpoints.arr_breakpoints[process_to_debug.array_of_breakpoints.number_of_breakpoints].abs_adress = abs_adress;
    process_to_debug.array_of_breakpoints.arr_breakpoints[process_to_debug.array_of_breakpoints.number_of_breakpoints].state = PENDING;
    process_to_debug.array_of_breakpoints.number_of_breakpoints++;
}

int create_resolved_breakpoint(symbol* bp_symbol,long offset_from_symbol,long abs_adress,unsigned char type){
    if(process_to_debug.proc_state == NOT_LOADED){
        return 0;
    }
    process_to_debug.array_of_breakpoints.arr_breakpoints[process_to_debug.array_of_breakpoints.number_of_breakpoints].index = process_to_debug.array_of_breakpoints.number_of_breakpoints;
    process_to_debug.array_of_breakpoints.arr_breakpoints[process_to_debug.array_of_breakpoints.number_of_breakpoints].type = type;
    process_to_debug.array_of_breakpoints.arr_breakpoints[process_to_debug.array_of_breakpoints.number_of_breakpoints].index = process_to_debug.array_of_breakpoints.number_of_breakpoints;
    process_to_debug.array_of_breakpoints.arr_breakpoints[process_to_debug.array_of_breakpoints.number_of_breakpoints].abs_adress = abs_adress;
    process_to_debug.array_of_breakpoints.arr_breakpoints[process_to_debug.array_of_breakpoints.number_of_breakpoints].offset_from_symbol = offset_from_symbol;
    process_to_debug.array_of_breakpoints.arr_breakpoints[process_to_debug.array_of_breakpoints.number_of_breakpoints].bp_symbol = bp_symbol;
    if(bp_symbol != NULL){
        long symbol_adress = bp_symbol->adress;
        process_to_debug.array_of_breakpoints.arr_breakpoints[process_to_debug.array_of_breakpoints.number_of_breakpoints].abs_adress = symbol_adress + offset_from_symbol;
    }
    process_to_debug.array_of_breakpoints.arr_breakpoints[process_to_debug.array_of_breakpoints.number_of_breakpoints].state = RESOLVED;
    
    ptrace_breakpoint(&process_to_debug.array_of_breakpoints.arr_breakpoints[process_to_debug.array_of_breakpoints.number_of_breakpoints]);
    process_to_debug.array_of_breakpoints.number_of_breakpoints++;
}



breakpoint* get_breakpoint_by_addr(long adress){
    breakpoints_array arr_of_breakpoints = process_to_debug.array_of_breakpoints;
    for(int i = 0; i < arr_of_breakpoints.number_of_breakpoints;i++){
        if(arr_of_breakpoints.arr_breakpoints[i].abs_adress == adress){
            return &arr_of_breakpoints.arr_breakpoints[i];
        }
    }
    return NULL; //if breakpoint not exists
}

int create_breakpoint(symbol* bp_symbol,long offset_from_symbol,long abs_adress,unsigned char type){
    if(process_to_debug.proc_state == NOT_LOADED){
        create_pending_breakpoint(bp_symbol, offset_from_symbol, abs_adress,type);
    }
    else{
        create_resolved_breakpoint(bp_symbol, offset_from_symbol, abs_adress,type);
    }
}

int resolve_breakpoints(){
    if(process_to_debug.proc_state == NOT_LOADED){return 0;}
    for(int i = 0; i < process_to_debug.array_of_breakpoints.number_of_breakpoints;i++){
        if(process_to_debug.array_of_breakpoints.arr_breakpoints[i].state == PENDING){
            if(process_to_debug.array_of_breakpoints.arr_breakpoints[i].bp_symbol != NULL){
                long symbol_adress = process_to_debug.array_of_breakpoints.arr_breakpoints[i].bp_symbol->adress;
                long offset_from_symbol = process_to_debug.array_of_breakpoints.arr_breakpoints[i].offset_from_symbol;
                process_to_debug.array_of_breakpoints.arr_breakpoints[i].abs_adress = symbol_adress + offset_from_symbol;
            }
            process_to_debug.array_of_breakpoints.arr_breakpoints[i].state = RESOLVED;
            ptrace_breakpoint(&process_to_debug.array_of_breakpoints.arr_breakpoints[i]);
        }
        
    }
}

void print_breakpoint(breakpoint* bp){
    printf("breakpoint %d : adress : %lx, state : %d\n",bp->index,bp->abs_adress,bp->state);
}

void print_breakpoints(){
    for(int i = 0; i < process_to_debug.array_of_breakpoints.number_of_breakpoints;i++){
        breakpoint current_breakpoint = process_to_debug.array_of_breakpoints.arr_breakpoints[i];
        if((current_breakpoint.type & INTERNAL) == 0){
            print_breakpoint(&current_breakpoint);
        }
    }
}


int cmd_software_breakpoint(int argc,char** argv){
    if(argc != 2){
        printf("breakpoint syntax incorrect\n");
        return 0;
    }

    if(argv[1][0] != '*'){ //no * in argv[1]
        break_symbol(argv[1],SOFTWARE | PERM);
    }
    else{ //* in argv, means its raw adrress or relitive symbol
        handle_star_breakpoint(argv,SOFTWARE | PERM);
    }
    
}



int break_symbol(char* symbol_name,unsigned char type){
    symbol* target_symbol = find_symbol_by_name(process_to_debug.array_of_symbols,symbol_name);
    if(target_symbol == NULL){
        printf("symbol not found\n");
        return 0;
    }
    else{
        long adress_of_symbol = target_symbol->adress;
        create_breakpoint(target_symbol,0,adress_of_symbol, type); //0 in offset becuase this is a condition of only symbol no offset
    }
}




int handle_star_breakpoint(char** argv,unsigned char type){
    char* break_arg = argv[1];
    if(break_arg[0] != '*'){return 0;};

    break_arg++;
    printf("%s\n",break_arg);
    if(strncmp(break_arg,"0x",2) == 0 || strncmp(break_arg,"0X",2) == 0){ //break adress case like b *0x007fffc120
        set_break_raw_adress(break_arg,type);
    }

    else{
        set_break_in_star_symbol(break_arg,type);
    }
}

int set_break_raw_adress(char* addr_to_break,unsigned char type){
    long break_adress = string_addr_to_long(addr_to_break);
    create_breakpoint(NULL,0,break_adress,type); //NULL and 0 becuase this is a condition of only raw adress
}


int break_in_relitive_symbol(char* symbol_name,long offset_from_symbol,unsigned char type){
    symbol* target_symbol = find_symbol_by_name(process_to_debug.array_of_symbols,symbol_name);
    if(target_symbol == NULL){
        printf("symbol not found!\n");
    }
    else{
        long adress_of_relitive_symbol = target_symbol->adress;
        create_breakpoint(target_symbol,offset_from_symbol,adress_of_relitive_symbol+offset_from_symbol,type); //absolute adress still unknown due to PIE and will be calculated after
    }
    return 0;
}


int set_break_in_star_symbol(char* break_argument,unsigned char type){
    int plus_index;
    char* symbol_name = get_relitive_symbol_name_and_plus_index(break_argument,&plus_index);
    long relitive_symbol_offset = 0;
    char* chars_after_plus;
    if(plus_index != -1){ //have offset after symbol
        chars_after_plus = break_argument + plus_index + 1;
        if(strncmp(chars_after_plus,"0x",2) == 0 || strncmp(chars_after_plus,"0X",2) == 0){ //offset in hexadecimal
            relitive_symbol_offset = string_addr_to_long(chars_after_plus);
        }
        else{
            relitive_symbol_offset = atoi(chars_after_plus); //offset in decimal
        }

        break_in_relitive_symbol(symbol_name,relitive_symbol_offset,type);

    }
    else{
        break_symbol(symbol_name,type); //only symbol
    }
    
}

char* get_relitive_symbol_name_and_plus_index(char* break_argument,int* plus_index){
    int length = strlen(break_argument);
    char* symbol_name = malloc(length+1);
    *plus_index = -1;
    for(int i = 0;break_argument[i] != '\x00';i++){
        if(break_argument[i] == '+'){
            *plus_index = i;
            break;
        }   
    }
    if(*plus_index != -1){
        strncpy(symbol_name,break_argument,*plus_index);
        symbol_name[*plus_index] = '\x00';
    }
    else{
        strncpy(symbol_name,break_argument,length);
        symbol_name[length] = '\x00';
    }
    return symbol_name;
}

long string_addr_to_long(char* string_adrr){
    return strtol(string_adrr,NULL,16);
}

static int remove_breakpoint_from_bp_arr(int index){
    int next_aval_index = process_to_debug.array_of_breakpoints.number_of_breakpoints;
    for(int i = index; i < next_aval_index-1;i++){
        process_to_debug.array_of_breakpoints.arr_breakpoints[i] = process_to_debug.array_of_breakpoints.arr_breakpoints[i+1];
        process_to_debug.array_of_breakpoints.arr_breakpoints[i].index--;
    }
    process_to_debug.array_of_breakpoints.number_of_breakpoints--;
    return 1;
}


int delete_breakpoint(int index){
    int next_aval_index = process_to_debug.array_of_breakpoints.number_of_breakpoints;
    if(index < 0 || index >= next_aval_index || next_aval_index == 0){
        return 0; 
    }
    breakpoint target_bp = process_to_debug.array_of_breakpoints.arr_breakpoints[index];
    if(!remove_breakpoint_from_bp_arr(index)){
        return 0;
    }
    if(process_to_debug.proc_state != NOT_LOADED){
        int res = ptrace(PTRACE_POKEDATA,process_to_debug.pid,target_bp.abs_adress,target_bp.orig_data);
        if(res == -1){
            return 0;
        }
    }
    return 1;
}

int step_over_bp(pid_t pid){
    struct user_regs_struct regs;
    get_registers(process_to_debug.pid, &regs);
    breakpoint* bp = get_breakpoint_by_addr(regs.rip-1);
    if(bp != NULL){
        if(regs.rip-1 != bp->abs_adress){
            return 0;
        }
        long current_opcodes = ptrace(PTRACE_PEEKDATA,process_to_debug.pid,regs.rip-1,NULL); //read the former instruction to check if there is a 0xCC byte
        ptrace(PTRACE_POKEDATA,process_to_debug.pid,regs.rip-1,bp->orig_data);
        regs.rip -= 1;
        set_registers(process_to_debug.pid,&regs);
        if((bp->type & TEMP) == TEMP){ //not perm breakpoint
            ptrace(PTRACE_SINGLESTEP,process_to_debug.pid,NULL,0);
            int status;
            waitpid(process_to_debug.pid, &status,0);
            if(WIFSTOPPED(status)){
                delete_breakpoint(bp->index);
            }
        }
        return 1;
    }
    return 0;
}
