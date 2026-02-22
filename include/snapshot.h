#pragma once
#include <sys/user.h>

#include "maps_parsing.h"


#define PAGE_SIZE 4096
#define PAGE_ALIGN(size) (((size) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))


typedef struct{
    long start;
    size_t size;
    char dirty_bit;
}page;

typedef struct{
    int cnt_pages;
    page* pages;
}arr_pages;

typedef struct{
    arr_pages* pages_array;
    regions_array* arr_of_regions;
    pid_t tid;
    struct user_regs_struct regs;   
}snapshot;




typedef struct{
    snapshot* arr_snapshots;
    int current_snapshot;
}array_snapshots;




int in_snapshot_range(long adress);
int save_snapshot();
arr_pages* create_arr_pages(regions_array* regions_arr);
void print_current_snapshot();