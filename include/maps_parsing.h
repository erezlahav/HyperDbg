#pragma once


#include <sys/types.h>


#define MEMORY_MAPPINGS_SIZE 1024


typedef enum{
    READ = 1<<0,
    WRITE = 1<<1,
    EXECUTE = 1<<2
}permissions;


typedef enum{
    BINARY,
    HEAP,
    STACK,
    DATA,
    DATA_LOADER,
    DATA_LIBC,
    LOADER_CODE,
    LIBC_CODE,
    VDSO,
    UNKNOWN,
}region_type;


typedef struct{
    region_type type;
    int permissions;
    long start;
    long end; 
}memory_region;

typedef struct{
    memory_region* arr;
    int regions_count;
}regions_array;

void parse_lines_of_maps(char** lines,regions_array* arr_regions);
void print_mem_regions(regions_array* arr_regions);
void print_region(memory_region* region);
char* read_maps(pid_t pid);
long find_base();
int parse_maps(pid_t pid,regions_array* arr_regions);
char* get_region_name_by_address(long address);
char* get_region_name_by_enum(int enum_number);