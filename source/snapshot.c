#include <stdio.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <unistd.h>


#include "snapshot.h"
#include "debug.h"
#include "info_commands.h"


#define _GNU_SOURCE
#define MAX_SNAPSHOTS 50
extern debugee_process process_to_debug;

//soon...


int in_snapshot_range(long adress){
    snapshot* snapshots = process_to_debug.snapshots.arr_snapshots;
    int current_index = process_to_debug.snapshots.current_snapshot;

    snapshot* snapshot = &snapshots[current_index];
    for(int i = 0;i < snapshot->arr_of_regions->regions_count;i++){
        if( adress >= snapshot->arr_of_regions->arr[i].start || adress <= snapshot->arr_of_regions->arr[i].end){
            printf("found\n");
            return 1;
        }
    }
    return 0;
}

int save_snapshot(){
    static int snapshots_saved = 0;
    if(process_to_debug.proc_state == NOT_LOADED || process_to_debug.proc_state == LOADED){
        printf("not good\n");
        return 0;
    }
    if(snapshots_saved == 0){
        process_to_debug.snapshots.arr_snapshots = malloc(sizeof(snapshot) * MAX_SNAPSHOTS);
    }

    process_to_debug.snapshots.current_snapshot++;
    struct user_regs_struct regs;
    get_registers(process_to_debug.pid, &regs);
    process_to_debug.snapshots.arr_snapshots[process_to_debug.snapshots.current_snapshot].tid = gettid();
    process_to_debug.snapshots.arr_snapshots[process_to_debug.snapshots.current_snapshot].regs = regs;

    process_to_debug.snapshots.arr_snapshots[process_to_debug.snapshots.current_snapshot].arr_of_regions = malloc(sizeof(regions_array));
    
    snapshots_saved++;
}

void print_current_snapshot(){
    printf("current index  : %d\n",process_to_debug.snapshots.current_snapshot);
    snapshot curr_snapshot = process_to_debug.snapshots.arr_snapshots[process_to_debug.snapshots.current_snapshot];
    printf("current tid : %d\n",curr_snapshot.tid);
    print_registers(&curr_snapshot.regs);
}