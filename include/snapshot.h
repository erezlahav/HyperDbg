#pragma once
#include <sys/user.h>

#include "maps_parsing.h"





typedef struct{
    regions_array* arr_of_regions;
    pid_t tid;
    struct user_regs_struct regs;   
}snapshot;




typedef struct{
    snapshot* arr_snapshots;
    int current_snapshot;
}array_snapshots;