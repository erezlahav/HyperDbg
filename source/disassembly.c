
#include <capstone/capstone.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <string.h>

#include "debug.h"
#include "elf_parser.h"
#include "breakpoint.h"
#include "utils.h"
#include "examine.h"
#include "colors.h"
extern debugee_process process_to_debug;

int live_disassemble_symbol(symbol* symbol){
    size_t symbol_size = symbol->size;
    long symbol_adress = symbol->adress;
    data_read* data_read_ptr = get_data_array(symbol_size,1,symbol_adress);
    print_disassemble_bytes(data_read_ptr->data,data_read_ptr->bytes_read,symbol_adress,0);
    free(data_read_ptr->data);
    free(data_read_ptr);
}




int static_disassemble_symbol(symbol* symbol){
    FILE* elf_target_ptr = fopen(process_to_debug.elf_path,"rb");
    if(elf_target_ptr == NULL){
        printf("fopen failed!\n");
        return 0;
    }
    unsigned char* bytes_array = get_bytes_array_code_from_symbol(symbol,elf_target_ptr);
    print_disassemble_bytes(bytes_array,symbol->size,symbol->adress,0);
}




void print_disassemble_bytes(unsigned char* bytes_array,size_t size,long start_addr,int user_count){
    csh handle;
    cs_insn *insn;
    size_t count;
    cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    
    count = cs_disasm(handle, bytes_array, size, start_addr, 0, &insn);
    if(user_count == 0) 
        user_count = count;


    struct user_regs_struct regs;
    long rip = 0;
    if(!(process_to_debug.proc_state == NOT_LOADED || process_to_debug.proc_state == LOADED) ){
        get_registers(process_to_debug.pid, &regs); 
        rip = regs.rip;
        if(get_breakpoint_by_addr(regs.rip-1)) rip--;
    }

    if (count > 0) {
        for (size_t i = 0; i < count && i < user_count; i++) {
            if(insn[i].address == rip) printf("=> " BLUE "0x%016lx" GREEN "\t%s" RESET "\t",insn[i].address,insn[i].mnemonic);
            else printf(BLUE "   0x%016lx" GREEN "\t%s" RESET "\t",insn[i].address,insn[i].mnemonic);

            if(strncmp(insn[i].mnemonic, "call", 4) == 0 || strncmp(insn[i].mnemonic, "jmp", 3) == 0){
                uint64_t target = 0;
                if(insn[i].op_str[0]=='0' && insn[i].op_str[1]=='x'){
                    sscanf(insn[i].op_str, "%lx", &target);
                    symbol* symbol = get_symbol_by_adress(target);
                    printf(BLUE "0x%016lx" RESET,target);

                    if(symbol){
                        printf(" <" YELLOW "%s" RESET ">\n", symbol->name);
                    }
                    else printf("\n");
                }
            }
            else{
                printf("%s\n",insn[i].op_str);
            }


        }
        cs_free(insn, count);
    }
     else {
        printf("Disassembly failed\n");
    }

    cs_close(&handle);
}



int is_call_instruction(long opcode){
    unsigned char lsb = (opcode & 0xFF);
    unsigned char second_lsb = (opcode >> 8) & 0xFF;
    if(lsb == 0xE8){ //relitive call 
        return 1;
    }
    if(lsb == 0xFF && ( ((second_lsb >> 3) & 7) == 2)){//first check if the LSB is 0xFF and then get the 3-5 bits and check if they are 010b then we know its unrelitive call instruction
        return 1;
    }
    return 0;
}


int get_length_of_instruction(unsigned char* bytes_array,size_t size,long start_addr){
    csh handle;
    cs_insn *insn;
    size_t count;

    cs_open(CS_ARCH_X86, CS_MODE_64, &handle);

    count = cs_disasm(handle,bytes_array,size,start_addr,1,&insn);
    if (count > 0) {
        cs_free(insn, count);
        return insn[0].size;
    }
    else{
        return 0;
    }

}





