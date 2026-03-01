#define _GNU_SOURCE 
#include <stdio.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>

#include "snapshot.h"
#include "debug.h"
#include "info_commands.h"
#include "maps_parsing.h"


#define MAX_SNAPSHOTS 50
#define MAX_PAGES 100


extern debugee_process process_to_debug;

//soon...


page* get_page_from_addr(long adress){
    snapshot* snapshots = process_to_debug.snapshots.arr_snapshots;
    int current_index = process_to_debug.snapshots.current_snapshot;
    if(current_index == -1){
        return NULL;
    }
    snapshot* snapshot = snapshots + current_index;
    arr_pages* pages_arr = snapshot->pages_array;
    for(int i = 0;i < pages_arr->cnt_pages;i++){
        if( adress >= pages_arr->pages[i].start && adress <= pages_arr->pages[i].start + pages_arr->pages[i].size){
            return &pages_arr->pages[i];
        }
    }
    return NULL;
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
    parse_maps(process_to_debug.pid,process_to_debug.snapshots.arr_snapshots[process_to_debug.snapshots.current_snapshot].arr_of_regions);
    arr_pages* pages = create_arr_pages(process_to_debug.snapshots.arr_snapshots[process_to_debug.snapshots.current_snapshot].arr_of_regions);
    process_to_debug.snapshots.arr_snapshots[process_to_debug.snapshots.current_snapshot].pages_array = pages;


    snapshots_saved++;
}



arr_pages* create_arr_pages(regions_array* regions_arr){
    int regions_cnt = regions_arr->regions_count;
    arr_pages* pages_arr = malloc(sizeof(arr_pages));
    pages_arr->cnt_pages = 0;
    int max_pages = MAX_PAGES;
    pages_arr->pages = malloc(max_pages * sizeof(page));
    memory_region* arr = regions_arr->arr;
    for(int i = 0; i < regions_cnt;i++){
        if(arr[i].type == BINARY) continue;
        size_t size = PAGE_ALIGN(arr[i].end - arr[i].start);
        int pages_cnt = size/PAGE_SIZE;
        page current_page;
        long offset_start = 0;
        for(int j = 0; j < pages_cnt;j++){
            if(pages_arr->cnt_pages >= max_pages){
                pages_arr->pages = realloc(pages_arr->pages, (max_pages + MAX_PAGES) * sizeof(page));
                max_pages += MAX_PAGES;
            }
            current_page.start = arr[i].start + offset_start;
            current_page.size = PAGE_SIZE;
            current_page.dirty_bit = 0;
            current_page.data = NULL;
            memcpy(pages_arr->pages + pages_arr->cnt_pages,&current_page,sizeof(page));
            offset_start += PAGE_SIZE;
            pages_arr->cnt_pages++;
        }

    }
    return pages_arr;
}


void print_pages(arr_pages* pages){
    for(int i = 0; i < pages->cnt_pages;i++){
        printf("index : %d, start : %lx\n",i,pages->pages[i].start);
    }
}


void print_current_snapshot(){
    printf("current index  : %d\n",process_to_debug.snapshots.current_snapshot);
    snapshot curr_snapshot = process_to_debug.snapshots.arr_snapshots[process_to_debug.snapshots.current_snapshot];
    printf("current tid : %d\n",curr_snapshot.tid);
    print_registers(&curr_snapshot.regs);
    print_mem_regions(process_to_debug.snapshots.arr_snapshots[process_to_debug.snapshots.current_snapshot].arr_of_regions);
    print_pages(process_to_debug.snapshots.arr_snapshots[process_to_debug.snapshots.current_snapshot].pages_array);
}



int remote_copy(void* local_addr,void* remote_addr,size_t size){
    struct iovec local_iov = { local_addr, size };
    struct iovec remote_iov = { remote_addr, size };
    ssize_t n = process_vm_readv(process_to_debug.pid, &local_iov, 1, &remote_iov, 1, 0);
    if (n == -1) {
        perror("process_vm_readv");
        return 0;
    }

    if ((size_t)n != size) {
        fprintf(stderr, "Partial copy: %zd/%zu bytes\n", n, size);
        return 0;
    }
    return 1;
}


int remote_write(void* local_addr,void* remote_addr,size_t size){
    struct iovec local_iov = { local_addr, size };
    struct iovec remote_iov = { remote_addr, size };
    ssize_t n = process_vm_writev(process_to_debug.pid, &local_iov, 1, &remote_iov, 1, 0);
    if (n == -1) {
        perror("process_vm_readv");
        return 0;
    }

    if ((size_t)n != size) {
        fprintf(stderr, "Partial copy: %zd/%zu bytes\n", n, size);
        return 0;
    }
    return 1;
}



int restore_pages(arr_pages* pages_arr){
    for(int i = 0;i < pages_arr->cnt_pages;i++){
        if(pages_arr->pages[i].dirty_bit == 1){
            remote_write(pages_arr->pages[i].data,pages_arr->pages[i].start,pages_arr->pages[i].size);
        }
    }
}



