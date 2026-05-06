#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>

#include "debug.h"
#include "elf_parser.h"

extern debugee_process process_to_debug;


Elf64_Ehdr* get_elf_header(FILE* elf_file_ptr){
    Elf64_Ehdr* elf_header = malloc(sizeof(Elf64_Ehdr));
    fseek(elf_file_ptr,0,SEEK_SET);
    size_t bytes_read = fread(elf_header,sizeof(Elf64_Ehdr), 1, elf_file_ptr);
    fseek(elf_file_ptr,0,SEEK_SET);
    return elf_header;
}



int is_elf64(FILE* elf_ptr) {


    Elf64_Ehdr* header = get_elf_header(elf_ptr);


    if (header->e_ident[EI_MAG0] != ELFMAG0 ||
        header->e_ident[EI_MAG1] != ELFMAG1 ||
        header->e_ident[EI_MAG2] != ELFMAG2 ||
        header->e_ident[EI_MAG3] != ELFMAG3)
        return 0;


    if (header->e_ident[EI_CLASS] != ELFCLASS64)
        return 0;


    if (header->e_type != ET_EXEC && header->e_type != ET_DYN)
        return 0;

    return 1; 
}




Elf64_Addr get_entry_point(Elf64_Ehdr* elf_header){
    return elf_header->e_entry;
}

bool get_pie_status(FILE* elf_file_ptr){
    Elf64_Ehdr* elf_header = get_elf_header(elf_file_ptr);
    bool is_pie = elf_header->e_type == ET_DYN;
    free(elf_header);
    return is_pie;
}


Elf64_Phdr* get_program_headers(Elf64_Ehdr* elf_header,FILE* elf_file_ptr){
    Elf64_Off offset_of_program_headers = elf_header->e_phoff;
    Elf64_Phdr* program_headers_array = malloc(sizeof(Elf64_Phdr) * elf_header->e_phnum);
    fseek(elf_file_ptr,offset_of_program_headers,SEEK_SET);
    fread(program_headers_array,sizeof(Elf64_Phdr),elf_header->e_phnum,elf_file_ptr);
    fseek(elf_file_ptr,0,SEEK_SET);
    return program_headers_array;
}


Elf64_Phdr* get_text_segment_ph(Elf64_Phdr* program_headers_array,int num_of_program_headers){
    for(int i = 0; i < num_of_program_headers;i++){
        if(program_headers_array[i].p_type == PT_LOAD && ((program_headers_array[i].p_flags & PF_X) == 1)){
            return &program_headers_array[i];
        }
    }
    return NULL;
}




Elf64_Shdr* get_section_header_by_name(Elf64_Shdr* section_headers_arr,uint16_t number_of_section_headers, char* section_headers_names,char* sh_name){
    for(int i = 0; i < number_of_section_headers;i++){
        if(strcmp((char*)(section_headers_names + section_headers_arr[i].sh_name),sh_name) == 0){
            return &section_headers_arr[i];
        }
    }
    return NULL;
}


unsigned char* get_bytes_array_code_from_symbol(symbol* symbol,FILE* elf_file_ptr){
    Elf64_Ehdr* elf_header = get_elf_header(elf_file_ptr);
    Elf64_Shdr* section_headers_arr = get_section_headers(elf_header,elf_file_ptr);
    Elf64_Shdr* shstrtab_section_header = find_shstrtab_in_section_headers(section_headers_arr,elf_header);
    char* section_headers_names = get_section_headers_names(shstrtab_section_header,elf_file_ptr);
    Elf64_Shdr* text_section_header = get_section_header_by_name(section_headers_arr,elf_header->e_shnum,section_headers_names,".text");
    if(text_section_header == NULL){return NULL;}

    Elf64_Off text_section_offset = text_section_header->sh_offset;
    long symbol_adress = symbol->adress;
    long text_section_rel_sym_adress = symbol_adress - text_section_header->sh_addr;
    long full_offset_in_elf_file = text_section_offset + text_section_rel_sym_adress;
    size_t size_of_symbol = symbol->size;

    unsigned char* bytes_array = malloc(size_of_symbol);
    fseek(elf_file_ptr,full_offset_in_elf_file,SEEK_SET);
    fread(bytes_array,1,size_of_symbol,elf_file_ptr);
    return bytes_array;
}




long get_virtual_addr_from_text_segment_ph(Elf64_Phdr* text_segment_ph){
    return (long)text_segment_ph->p_vaddr;
}

long get_loading_vaddr_of_text_segment(FILE* elf_file_ptr){
    Elf64_Ehdr* elf_header = get_elf_header(elf_file_ptr);
    Elf64_Phdr* program_headers_array = get_program_headers(elf_header,elf_file_ptr);
    Elf64_Phdr* text_segment_ph = get_text_segment_ph(program_headers_array,elf_header->e_phnum);
    long virtual_loading_adress = get_virtual_addr_from_text_segment_ph(text_segment_ph);
    return virtual_loading_adress;
}


Elf64_Shdr* get_section_headers(Elf64_Ehdr* elf_header,FILE* elf_file_ptr){
    Elf64_Off section_headers_offset = elf_header->e_shoff;
    Elf64_Half section_header_size = elf_header->e_shentsize;
    Elf64_Half number_of_section_headers = elf_header->e_shnum;

    Elf64_Shdr* section_headers_array = malloc(sizeof(Elf64_Shdr) * number_of_section_headers);

    fseek(elf_file_ptr,section_headers_offset,SEEK_SET);
    for(int i = 0; i < number_of_section_headers;i++){
        fread(&section_headers_array[i],sizeof(Elf64_Shdr),1,elf_file_ptr);
    }

    fseek(elf_file_ptr,0,SEEK_SET);
    return section_headers_array;
}

Elf64_Shdr* find_shstrtab_in_section_headers(Elf64_Shdr* section_headers,Elf64_Ehdr* elf_header){
    Elf64_Shdr* shstrtab =  &section_headers[elf_header->e_shstrndx];
    return shstrtab;
}

uint16_t get_number_of_section_headers(Elf64_Ehdr* elf_header){
    return elf_header->e_shnum;
}

char* get_section_headers_names(Elf64_Shdr* shstrtab_section_header,FILE* elf_file_ptr){
    char* section_header_names = malloc(shstrtab_section_header->sh_size);
    fseek(elf_file_ptr,shstrtab_section_header->sh_offset,SEEK_SET);
    fread(section_header_names, 1, shstrtab_section_header->sh_size, elf_file_ptr);
    return section_header_names;
}

void print_section_headers(Elf64_Shdr* section_headers,char* section_header_names,uint16_t number_of_section_headers){
    for(int i = 0;i < number_of_section_headers;i++){
        printf("%s\n",(section_header_names + section_headers[i].sh_name));
    }
}

Elf64_Shdr* get_section_header_by_type(Elf64_Shdr* section_headers, uint32_t type, uint16_t number_of_section_headers){
    for(int i = 0 ; i < number_of_section_headers;i++){
        if(section_headers[i].sh_type == type){
            return &section_headers[i];
        }
    }
    return NULL;
}




Elf64_Sym* get_symbols_from_symbol_section_header(Elf64_Shdr* symbol_section_header,FILE* elf_file_ptr){

    Elf64_Sym* symbols = malloc(symbol_section_header->sh_size);
    fseek(elf_file_ptr,symbol_section_header->sh_offset,SEEK_SET);
    fread(symbols,1,symbol_section_header->sh_size,elf_file_ptr);
    return symbols;
}


uint16_t get_number_of_symbols_from_symbol_sh(Elf64_Shdr* symbol_section_header){
    return (uint16_t)(symbol_section_header->sh_size / symbol_section_header->sh_entsize);
}

uint32_t get_string_table_index_for_symbol_sh(Elf64_Shdr* symbol_section_header){
    return symbol_section_header->sh_link;
}


Elf64_Shdr* get_section_header_from_offset(Elf64_Shdr* first_section_header,uint32_t index_number){
    return first_section_header+index_number;
}

char* get_string_table_values_from_string_table_sh(Elf64_Shdr* strtab_sh,FILE* elf_file_ptr){
    char* strtab_values = malloc(strtab_sh->sh_size);

    fseek(elf_file_ptr,strtab_sh->sh_offset,SEEK_SET);
    fread(strtab_values,strtab_sh->sh_size,1,elf_file_ptr);

    return strtab_values;
}


symbol* get_symbols_from_section_header_symbol(Elf64_Shdr* symbol_section_header,Elf64_Shdr* string_table_sh, FILE* elf_file_ptr){
    Elf64_Sym* symbols = get_symbols_from_symbol_section_header(symbol_section_header,elf_file_ptr);
    char* strtab_values = get_string_table_values_from_string_table_sh(string_table_sh,elf_file_ptr);
    uint16_t number_of_symbols = get_number_of_symbols_from_symbol_sh(symbol_section_header);
    symbol_table_type table_type;
    if(symbol_section_header->sh_type == SHT_SYMTAB){
        table_type = symtab;
    }
    else if(symbol_section_header->sh_type == SHT_DYNSYM){
        table_type = dynsym;
    }
    symbol* symbols_to_return = malloc(sizeof(symbol) * number_of_symbols);
    for(int i = 0; i < number_of_symbols;i++){
        if (ELF64_ST_TYPE(symbols[i].st_info) == STT_FUNC) {
            symbols_to_return[i].type = FUNC;
        }
        char* symbol_name = strtab_values + symbols[i].st_name;
        symbols_to_return[i].name = malloc(strlen(symbol_name)+1);
        strncpy(symbols_to_return[i].name,symbol_name, strlen(symbol_name)+1);
        symbols_to_return[i].adress = symbols[i].st_value;
        symbols_to_return[i].size = symbols[i].st_size;
        symbols_to_return[i].table_type = table_type;
    }
    return symbols_to_return;
}

symbols_array* get_symbols_from_file(FILE* elf_file_ptr) {
    Elf64_Ehdr* elf_header = get_elf_header(elf_file_ptr);
    Elf64_Shdr* section_headers = get_section_headers(elf_header, elf_file_ptr);
    uint16_t num_sections = get_number_of_section_headers(elf_header);

    Elf64_Shdr* shstrtab_sh = find_shstrtab_in_section_headers(section_headers, elf_header);
    char* shstrtab = get_section_headers_names(shstrtab_sh, elf_file_ptr);

    Elf64_Shdr* symtab_sh   = get_section_header_by_type(section_headers, SHT_SYMTAB, num_sections);
    Elf64_Shdr* dynsym_sh   = get_section_header_by_type(section_headers, SHT_DYNSYM, num_sections);
    Elf64_Shdr* rela_plt_sh = get_section_header_by_name(section_headers, elf_header->e_shnum, shstrtab, ".rela.plt");
    Elf64_Shdr* got_plt_sh  = get_section_header_by_name(section_headers, elf_header->e_shnum, shstrtab, ".got.plt");

    Elf64_Shdr* plt_sec_sh  = get_section_header_by_name(section_headers, elf_header->e_shnum, shstrtab, ".plt.sec");
    Elf64_Shdr* plt_sh      = get_section_header_by_name(section_headers, elf_header->e_shnum, shstrtab, ".plt");
    Elf64_Shdr* active_plt  = plt_sec_sh ? plt_sec_sh : plt_sh;

    // SYMTAB part
    symbol* symtab_symbols = NULL;
    uint16_t num_symtab = 0;
    if (symtab_sh) {
        Elf64_Shdr* strtab_sh = get_section_header_from_offset(section_headers, get_string_table_index_for_symbol_sh(symtab_sh));
        symtab_symbols = get_symbols_from_section_header_symbol(symtab_sh, strtab_sh, elf_file_ptr);
        num_symtab = get_number_of_symbols_from_symbol_sh(symtab_sh);
    }



    // DYNSYM part
    symbol* dynsym_symbols = NULL;
    uint16_t num_dynsym = 0;
    if (dynsym_sh) {
        Elf64_Shdr* dynstr_sh = get_section_header_from_offset(section_headers, get_string_table_index_for_symbol_sh(dynsym_sh));
        dynsym_symbols = get_symbols_from_section_header_symbol(dynsym_sh, dynstr_sh, elf_file_ptr);
        num_dynsym = get_number_of_symbols_from_symbol_sh(dynsym_sh);

        // PLT addresses calculate
        if (active_plt && rela_plt_sh) {
            int rela_count = rela_plt_sh->sh_size / sizeof(Elf64_Rela);
            Elf64_Rela* rela_entries = malloc(rela_plt_sh->sh_size);
            fseek(elf_file_ptr, rela_plt_sh->sh_offset, SEEK_SET);
            fread(rela_entries, 1, rela_plt_sh->sh_size, elf_file_ptr);

            uint64_t plt_entry_size = active_plt->sh_entsize ? active_plt->sh_entsize : 16;

            for (int i = 0; i < rela_count; i++) {
                uint32_t sym_idx = ELF64_R_SYM(rela_entries[i].r_info);
                if (sym_idx >= num_dynsym) continue;

                if (plt_sec_sh) {
                    dynsym_symbols[sym_idx].adress = active_plt->sh_addr + i * plt_entry_size;
                } else if (got_plt_sh) {
                    uint64_t got_index  = (rela_entries[i].r_offset - got_plt_sh->sh_addr) / sizeof(Elf64_Addr);
                    uint64_t stub_index = got_index - 3;
                    dynsym_symbols[sym_idx].adress = active_plt->sh_addr + (stub_index + 1) * plt_entry_size;
                } else {
                    dynsym_symbols[sym_idx].adress = active_plt->sh_addr + (i + 1) * plt_entry_size;
                }

                dynsym_symbols[sym_idx].size = plt_entry_size; 
            }

            free(rela_entries);
        }
    }

    // merge dynsym and symtab
    symbol* all_symbols = malloc(sizeof(symbol) * (num_symtab + num_dynsym));
    if (symtab_symbols) memcpy(all_symbols, symtab_symbols, num_symtab * sizeof(symbol));
    if (dynsym_symbols) memcpy(all_symbols + num_symtab, dynsym_symbols, num_dynsym * sizeof(symbol));

    symbols_array* array_of_symbols = malloc(sizeof(symbols_array));
    array_of_symbols->symbols = all_symbols;
    array_of_symbols->number_of_symbols = num_symtab + num_dynsym;

    free(symtab_symbols);
    free(dynsym_symbols);
    free(shstrtab);
    free(section_headers);
    free(elf_header);

    return array_of_symbols;
}

symbol* find_symbol_by_name(symbols_array* array_of_symbols, char* name) {
    for (int i = 0; i < array_of_symbols->number_of_symbols; i++) {
        if (strcmp(array_of_symbols->symbols[i].name, name) == 0) {
            return &array_of_symbols->symbols[i];
        }
    }
    return NULL;
}




void update_adressing_of_symtab_symbols(symbols_array* array_of_symbols,long base_binary){
    for(int i = 0; i < array_of_symbols->number_of_symbols;i++){
        if(array_of_symbols->symbols[i].table_type == symtab || array_of_symbols->symbols[i].table_type == dynsym){
            array_of_symbols->symbols[i].adress -= process_to_debug.text_segment_offset_va;
            array_of_symbols->symbols[i].adress += base_binary;
        }
    }
}

