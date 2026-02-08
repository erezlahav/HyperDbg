







#include "dwarf_parser.h"
#include "elf_parser.h"

function* get_functions(FILE* elf_file_ptr){

    Elf64_Ehdr* elf_header = get_elf_header(elf_file_ptr);
    Elf64_Shdr* section_headers = get_section_headers(elf_header,elf_file_ptr);
    uint16_t number_of_section_headers = get_number_of_section_headers(elf_header);
    Elf64_Shdr* shstrtab_section_header = find_shstrtab_in_section_headers(section_headers,elf_header);
    char* section_header_names = get_section_headers_names(shstrtab_section_header,elf_file_ptr);
    
    Elf64_Shdr* debug_info_sh = get_section_header_by_name(section_headers, number_of_section_headers ,section_header_names,".debug_info");
    Elf64_Shdr* debug_abbrev_sh = get_section_header_by_name(section_headers, number_of_section_headers ,section_header_names,".debug_abbrev");
    Elf64_Shdr* debug_str_sh = get_section_header_by_name(section_headers, number_of_section_headers ,section_header_names,".debug_str");
    


    char* debug_info_data = malloc(debug_info_sh->sh_size);
    fseek(elf_file_ptr, debug_info_sh->sh_offset, SEEK_SET);
    fread(debug_info_data, 1, debug_info_sh->sh_size, elf_file_ptr);
    char* p = debug_info_data;


    uint64_t unit_length   = *(uint64_t*)p; p += 8;
    uint16_t version       = *(uint16_t*)p; p += 2;
    uint64_t abbrev_offset = *(uint64_t*)p; p += 8;
    uint8_t  address_size  = *(uint8_t*)p; p += 1;

    printf("unit_length: %llu\n", (unsigned long long)unit_length);
    printf("version: %u\n", version);
    printf("abbrev_offset: %llu\n", (unsigned long long)abbrev_offset);
    printf("address_size: %u\n", address_size);





}



