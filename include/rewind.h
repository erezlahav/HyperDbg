#pragma once
#include <sys/user.h>
#include <sys/types.h>

#include "maps_parsing.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif


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


typedef enum{
    MMAP,
    MUNMAP
}mmap_type;

typedef struct live_mmap_node {
    mmap_type type;    
    int prot;          
    int flags;         
    int fd;            
    void* start;       
    size_t size;      
    off_t offset;      
    struct live_mmap_node* next; 
} live_mmap_node;

typedef struct{
    arr_pages* pages_array;
    regions_array* arr_of_regions;
    pid_t tid;
    struct user_regs_struct regs;  
    live_mmap_node* current_mmaps_head; 
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
int delete_record(int restore_perm);

int add_live_mmap(live_mmap_node** head, mmap_type type, void* addr, size_t size, int prot, int flags,int fd, off_t offset);
int remove_live_mmap(live_mmap_node** head, void* addr,mmap_type type);
int rewind_all_live_mmaps();
live_mmap_node* get_live_mmap_by_addr(live_mmap_node** head, long addr,mmap_type type); 