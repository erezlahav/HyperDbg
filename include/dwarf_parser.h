#pragma once


#include <stdint.h>
#include <stdio.h>


typedef struct{
    uint64_t unit_length;
    uint16_t version;
    uint64_t abbrev_offset;
    uint8_t  address_size;
}CUHeader64;

typedef struct{
    char* name;
    uint64_t rbp_offset;
    size_t size;
}local;



typedef struct{
    char* name;
    long start_addr;
    long end_addr;
    local* local_variebles;
}function;



typedef struct compile_unit {
    char* file_name;  
    uint64_t low_pc;
    uint64_t high_pc;
    function* functions;  
    int functions_count;
} compile_unit;


function* get_functions(FILE* elf_file_ptr);