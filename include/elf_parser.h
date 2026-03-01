#pragma once
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>

typedef enum{
    symtab,
    dynsym
}symbol_table_type;

typedef enum{
    GLOBAL_VAR,
    FUNC
}symbol_type;

typedef struct{
    long adress;
    char* name;
    size_t size;
    symbol_type type;
    symbol_table_type table_type;
}symbol;

typedef struct{
    symbol* symbols;
    uint16_t number_of_symbols;
}symbols_array;



Elf64_Ehdr* get_elf_header(FILE* elf_file_ptr);
int is_elf64(FILE* elf_ptr);
Elf64_Addr get_entry_point(Elf64_Ehdr* elf_header);
bool get_pie_status(FILE* elf_file_ptr);
Elf64_Phdr* get_program_headers(Elf64_Ehdr* elf_header,FILE* elf_file_ptr);
Elf64_Phdr* get_text_segment_ph(Elf64_Phdr* program_headers_array,int num_of_program_headers);
Elf64_Shdr* get_section_header_by_name(Elf64_Shdr* section_headers_arr,uint16_t number_of_section_headers, char* section_headers_names,char* sh_name);
unsigned char* get_bytes_array_code_from_symbol(symbol* symbol,FILE* elf_file_ptr);
long get_virtual_addr_from_text_segment_ph(Elf64_Phdr* text_segment_ph);
long get_loading_vaddr_of_text_segment(FILE* elf_file_ptr);
Elf64_Shdr* get_section_headers(Elf64_Ehdr* elf_header,FILE* elf_file_ptr);
Elf64_Shdr* find_shstrtab_in_section_headers(Elf64_Shdr* section_headers,Elf64_Ehdr* elf_header);
uint16_t get_number_of_section_headers(Elf64_Ehdr* elf_header);
char* get_section_headers_names(Elf64_Shdr* shstrtab_section_header,FILE* elf_file_ptr);
void print_section_headers(Elf64_Shdr* section_headers,char* section_header_names,uint16_t number_of_section_headers);
Elf64_Shdr* get_section_header_by_type(Elf64_Shdr* section_headers, uint32_t type, uint16_t number_of_section_headers);
Elf64_Sym* get_symbols_from_symbol_section_header(Elf64_Shdr* symbol_section_header,FILE* elf_file_ptr);
uint16_t get_number_of_symbols_from_symbol_sh(Elf64_Shdr* symbol_section_header);
uint32_t get_string_table_index_for_symbol_sh(Elf64_Shdr* symbol_section_header);
Elf64_Shdr* get_section_header_from_offset(Elf64_Shdr* first_section_header,uint32_t index_number);
char* get_string_table_values_from_string_table_sh(Elf64_Shdr* strtab_sh,FILE* elf_file_ptr);
symbol* get_symbols_from_section_header_symbol(Elf64_Shdr* symbol_section_header,Elf64_Shdr* string_table_sh, FILE* elf_file_ptr);
symbols_array* get_symbols_from_file(FILE* elf_file_ptr);
symbol* find_symbol_by_name(symbols_array* array_of_symbols,char* name);
void update_adressing_of_symtab_symbols(symbols_array* array_of_symbols,long base_binary);