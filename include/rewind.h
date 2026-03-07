#pragma once
#include <sys/user.h>

#include "maps_parsing.h"


#define PAGE_SIZE 4096
#define PAGE_ALIGN(size) (((size) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))


typedef struct{
    long start;
    size_t size;
    char dirty_bit;
    void* data;
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






page* get_page_from_addr(long adress);
int save_snapshot();
arr_pages* create_arr_pages(regions_array* regions_arr);
void print_current_snapshot();
int remote_copy(void* local_addr,void* remote_addr,size_t size);
void remote_read_string(pid_t pid, long remote_addr, char* buf, int maxlen);
int remote_write(void* local_addr,void* remote_addr,size_t size);
int restore_pages(arr_pages* pages_arr);
int restore_permissions(regions_array* arr_regions);
int delete_record();