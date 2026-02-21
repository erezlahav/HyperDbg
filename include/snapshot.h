#pragma once
#include <sys/user.h>

#include "maps_parsing.h"


#define PAGE_SIZE 4096



typedef struct{
    long start;
    size_t size;
    char dirty_bit;
}page;



typedef struct{
    page* pages;
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
void print_current_snapshot();