#pragma once
#include <sys/user.h>

#include "maps_parsing.h"


typedef struct{
    pid_t tid;
    struct user_regs_struct regs;   
    memory_region* thread_stack;
}thread_snapshot;



typedef struct{
    regions_array* arr_of_regions;
    thread_snapshot thread_info;
}snapshot;




typedef struct{
    snapshot* arr_snapshots;
    int cnt_snapshots;
}array_snapshots;