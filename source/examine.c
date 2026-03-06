#include <sys/user.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <errno.h>

#include "examine.h"
#include "utils.h"
#include "debug.h"
#include "disassembly.h"
#include "breakpoint.h"
#include "colors.h"

extern debugee_process process_to_debug;


static enum format{
        HEXADECIMAL,
        DECIMAL,
        INSTRUCTION,
};


static int get_size(char str_size){
    int size_to_ret; 

    switch (str_size) //deciding size
    {
    case 'g':
        size_to_ret = sizeof(long);
        break;
    case 'w':
        size_to_ret = 4;
        break;
    case 'h':
        size_to_ret = 2;
        break;
    case 'b':
        size_to_ret = 1;
        break;
    default:
        size_to_ret=4;
        break;
    }
    return size_to_ret;
}





data_read* get_data_array(size_t count, size_t size,long adress){
    data_read* data_struct_ptr = malloc(sizeof(data_read));
    data_struct_ptr->data = malloc(size * count);
    data_struct_ptr->bytes_read = 0;
    breakpoint* bp = NULL;
    size_t total_size = count * size;
    while(data_struct_ptr->bytes_read < total_size){
        bp = get_breakpoint_by_addr(adress+data_struct_ptr->bytes_read);
        if(bp != NULL){
            unsigned char original_data = (unsigned char)(bp->orig_data & 0xFF);
            memcpy(data_struct_ptr->data + data_struct_ptr->bytes_read,&original_data,1);
            data_struct_ptr->bytes_read++;
        }
        long res = ptrace(PTRACE_PEEKDATA,process_to_debug.pid,(void*)(adress+data_struct_ptr->bytes_read),NULL);
        if(res != -1 && errno == 0){
            if(data_struct_ptr->bytes_read + size >= total_size){
                memcpy(data_struct_ptr->data + data_struct_ptr->bytes_read,&res,total_size - data_struct_ptr->bytes_read);
                data_struct_ptr->bytes_read += total_size - data_struct_ptr->bytes_read;
            }
            else{
                memcpy(data_struct_ptr->data + data_struct_ptr->bytes_read,&res,size);
                data_struct_ptr->bytes_read += size;
            }     
        }
        else{
            break;
        }
    }
    return data_struct_ptr;
}


static __uint64_t get_mask_by_size(int size){
    if(size >= 8) return ~0ULL;
    
    return (1ULL << (size*8))-1;
}


void print_data_array(long adress, data_read* data_read_ptr,int size,const char* format_string){
    int data_index = 0;
    __uint64_t mask = get_mask_by_size(size);
    while(data_index < data_read_ptr->bytes_read){
        printf(BLUE "0x%016lx: " RESET,adress + data_index);
        printf(format_string,*((long*)(data_read_ptr->data+data_index)) & mask); 
        printf("\n");
        data_index += size;
    }
}



static const char* get_format_string(enum format FORMAT, int size)
{
    switch (FORMAT)
    {
    case HEXADECIMAL:
        switch (size)
        {
        case 1: return "0x%02x";
        case 2: return "0x%04x";
        case 4: return "0x%08x";
        case 8: return "0x%016lx";
        }
        break;

    case DECIMAL:
        switch (size)
        {
        case 1: return "%d";
        case 2: return "%d";
        case 4: return "%d";
        case 8: return "%ld";
        }
        break;
    }

    return NULL; 
}

int exemine(int argc,char** argv){ // x/[COUNT][SIZE][FORMAT] ADDRESS/REGISTER 
    if(process_to_debug.proc_state == LOADED || process_to_debug.proc_state == NOT_LOADED){
        printf("process is not running yet\n");
        return 0;
    }
    if(argv[1] == NULL){
        printf("no adress/register specified\n");
        return 0;
    }

    int argv_len = strlen(argv[0]);
    char* first_str = malloc(argv_len+1);

    
    unsigned long adress = 0x0; //default no adress
    struct user_regs_struct regs;
    char register_name[5];
    strncpy(first_str,argv[0],argv_len+1);
    

    const char* format_string;

    int COUNT = 1; //default
    enum format FORMAT = HEXADECIMAL; //default

    int SIZE = sizeof(long); //default

    if(strcmp(first_str,"x") == 0){ //x ADDRESS case 
        if(argv[1][0] == '$'){ //register case
            ptrace(PTRACE_GETREGS,process_to_debug.pid,NULL,&regs);
            strncpy(register_name,argv[1]+1,sizeof(register_name));
            register_name[sizeof(register_name)] = '\x00';
            unsigned long* register_value = get_register(&regs,register_name);
            if(!register_value){ //error in get registers
                return 0;
            }
            adress = *register_value;
        }
        else{ //adress case
            if(strncmp(argv[1],"0x",2) == 0) adress = strtol(argv[1]+2,NULL,16);
            else adress = strtol(argv[1],NULL,16);
        }


        data_read* data_read_ptr = get_data_array(COUNT,SIZE,adress); //get data from adress
        if(data_read_ptr->bytes_read == 0){
            printf("could not read bytes from adress : " BLUE "0x%016lx" RESET,adress);
            return 0;
        }
        format_string = get_format_string(FORMAT,SIZE);
        print_data_array(adress,data_read_ptr,SIZE,format_string);
        free(data_read_ptr->data);
        free(data_read_ptr);
    }





    else{  //    x/[COUNT][SIZE][FORMAT] ADDRESS/REGISTER expected
        if(first_str[1] != '/'){
            printf("invalid format command\n");
            return 0;
        }
        char* after_slash = first_str + 2;
        errno = 0;
        COUNT = strtol(after_slash,NULL,10);
        if(errno == ERANGE){
            printf("long overflow\n");
            return 0;
        }
        while(*after_slash >= '0' && *after_slash <= '9'){
            after_slash++;
        }
        if(COUNT == 0) COUNT = 1;

        if(*after_slash != 'i'){
            SIZE = get_size(*after_slash);
            after_slash++;
        }
        else{ //x/i adress/register format
            SIZE = 1;
            FORMAT = INSTRUCTION;
        }
        
        if(argv[1][0] == '$'){ //register case
            ptrace(PTRACE_GETREGS,process_to_debug.pid,NULL,&regs);
            char* reg_start = argv[1] + 1;
            int register_name_index = 0;
            while(reg_start != NULL && (*reg_start != '+' &&  *reg_start != '-') && register_name_index < sizeof(register_name)){
                register_name[register_name_index] = *reg_start;
                register_name_index++;
                reg_start++;
            }
            register_name[sizeof(register_name)] = '\x00';
            int offset = 0;
            if(*reg_start == '+' || *reg_start == '-'){
                offset = strtol(reg_start+1,NULL,10);
                if(errno == ERANGE) offset = 0;
            }
            unsigned long* register_value = get_register(&regs,register_name);
            if(!register_value){ //error in get registers
                return 0;
            }
            adress = *register_value + offset;
        }
        else { //adress case
            if(strncmp(argv[1],"0x",2) == 0) adress = strtol(argv[1]+2,NULL,16);
            else adress = strtol(argv[1],NULL,16);
        }
        if(get_breakpoint_by_addr(adress-1)) adress--; //not null



        data_read* data_read_ptr = NULL;
        if(FORMAT == INSTRUCTION){
            data_read_ptr = get_data_array(COUNT*15,SIZE,adress);
        }
        else{
            data_read_ptr = get_data_array(COUNT,SIZE,adress);
        } 


        if(data_read_ptr->bytes_read == 0){
            printf("Cannot access memory at address : " BLUE "0x%016lx\n",adress);
            return 0;
        }
        if(FORMAT == INSTRUCTION){
            print_disassemble_bytes((unsigned char*)data_read_ptr->data,SIZE * COUNT * 15,adress,COUNT);
        }
        else{
            switch (*after_slash) //deciding format
            {
            case 'd':
                FORMAT = DECIMAL;
                break;
            case 'x':
                FORMAT = HEXADECIMAL;
                break;
            default:
                FORMAT = HEXADECIMAL;
                break;
            }
        }
        if(FORMAT != INSTRUCTION){
            format_string = get_format_string(FORMAT,SIZE);
            print_data_array(adress,data_read_ptr,SIZE,format_string);
        }

        free(data_read_ptr->data);
        free(data_read_ptr);

    }
    free(first_str);
}









