#pragma once


#include <sys/types.h>


#define MEMORY_MAPPINGS_SIZE 1024

typedef enum{
    BINARY,
    HEAP,
    STACK,
    DATA
}region_type;


typedef struct{
    region_type type;
    long start;
    long end; 
}memory_region;

typedef struct{
    memory_region* arr;
    int regions_count;
}regions_array;

void parse_lines_of_maps(char** lines,regions_array* arr_regions);
void print_mem_regions();
char* read_maps(pid_t pid);
int parse_maps(pid_t pid,regions_array* arr_regions);