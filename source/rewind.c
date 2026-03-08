#define _GNU_SOURCE 
#include <stdio.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <errno.h>


#include "rewind.h"
#include "debug.h"
#include "info_commands.h"
#include "maps_parsing.h"
#include "syscall_injection.h"

#define MAX_SNAPSHOTS 50
#define MAX_PAGES 200


extern debugee_process process_to_debug;

//soon...


page* get_page_from_addr(long adress){
    snapshot* snapshot = process_to_debug.current_snapshot;
    if(snapshot == NULL){
        return NULL;
    }
    arr_pages* pages_arr = snapshot->pages_array;
    for(int i = 0;i < pages_arr->cnt_pages;i++){
        if( adress >= pages_arr->pages[i].start && adress <= pages_arr->pages[i].start + pages_arr->pages[i].size){
            return &pages_arr->pages[i];
        }
    }
    return NULL;
}


int save_snapshot(){
   if(process_to_debug.current_snapshot != NULL){
        printf("The process is already being recorded.  Use delete record to stop delete the recording first.\n");
        return 0;
   }
   else{
        process_to_debug.current_snapshot = malloc(sizeof(snapshot));
   }
    struct user_regs_struct regs;
    get_registers(process_to_debug.pid, &regs);
    
    process_to_debug.current_snapshot->tid = gettid();
    process_to_debug.current_snapshot->regs = regs;

    process_to_debug.current_snapshot->arr_of_regions = malloc(sizeof(regions_array));
    parse_maps(process_to_debug.pid,process_to_debug.current_snapshot->arr_of_regions);
    arr_pages* pages = create_arr_pages(process_to_debug.current_snapshot->arr_of_regions);
    process_to_debug.current_snapshot->pages_array = pages;
    process_to_debug.current_snapshot->current_mmaps_head = NULL;
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
    snapshot* curr_snapshot = process_to_debug.current_snapshot;
    printf("current tid : %d\n",curr_snapshot->tid);
    print_registers(&curr_snapshot->regs);
    print_mem_regions(curr_snapshot->arr_of_regions);
    print_pages(curr_snapshot->pages_array);
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



void remote_read_string(pid_t pid, long remote_addr, char* buf, int maxlen){
    int i = 0;
    long data;

    while(i < maxlen) {
        data = ptrace(PTRACE_PEEKDATA, pid, remote_addr + i, NULL);

        memcpy(buf + i, &data, sizeof(long));

        if(memchr(&data, 0, sizeof(long)) != NULL)
            break;

        i += sizeof(long);
    }

    buf[maxlen-1] = 0;
}


int remote_write(void* local_addr,void* remote_addr,size_t size){
    struct iovec local_iov = { local_addr, size };
    struct iovec remote_iov = { remote_addr, size };
    ssize_t n = process_vm_writev(process_to_debug.pid, &local_iov, 1, &remote_iov, 1, 0);
    if (n == -1) {
        perror("process_vm_write");
        printf("adress : 0x%lx\n",(long)remote_addr);
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
    return 1;
}


int restore_permissions(regions_array* arr_regions){

    for(int i = 0; i < arr_regions->regions_count;i++){
        if(((arr_regions->arr[i].permissions) & WRITE) != 0){
            int permissions = PROT_WRITE;
            if(((arr_regions->arr[i].permissions) & READ) != 0) permissions |= PROT_READ;
            if(((arr_regions->arr[i].permissions) & EXECUTE) != 0) permissions |= PROT_EXEC;
            inject_mprotect(arr_regions->arr[i].start,arr_regions->arr[i].end-arr_regions->arr[i].start,permissions);
        }
    }
    return 1;
}

int delete_record(){
    snapshot* snapshot = process_to_debug.current_snapshot;
    if(snapshot == NULL){
        printf("no snapshots saved yet\n");
        return 0;
    }

    regions_array* arr_regions = snapshot->arr_of_regions;

    free(snapshot->pages_array->pages);
    free(snapshot->pages_array);
    free(snapshot->arr_of_regions);
    free(snapshot);
    process_to_debug.current_snapshot = NULL;
}




int add_live_mmap(live_mmap_node** head, mmap_type type, void* addr, size_t size, int prot, int flags,int fd, off_t offset){



    live_mmap_node* node = malloc(sizeof(live_mmap_node));

    node->start = addr;
    node->size = size;
    node->type = type;
    node->prot = prot;
    node->flags = flags;
    node->fd = fd;
    node->offset = offset;

    node->next = *head;

    *head = node;
    return 1;
}


int remove_live_mmap(live_mmap_node** head, void* addr,mmap_type type){


    live_mmap_node* curr = *head;
    live_mmap_node* prev = NULL;

    while(curr != NULL){

        if(curr->start == addr && curr->type == type){

            if(prev == NULL)
                *head = curr->next;
            else
                prev->next = curr->next;

            free(curr);
            return 1;
        }

        prev = curr;
        curr = curr->next;
    }

    return 0;
}





int rewind_all_live_mmaps(){
    if(process_to_debug.current_snapshot == NULL) return 0;


    live_mmap_node* curr = process_to_debug.current_snapshot->current_mmaps_head;

    while(curr != NULL){ //from latest to earliest because mmap calls are lifo
        live_mmap_node* next = curr->next;
        if(curr->type == MMAP){ //if current is MMAP
            inject_munmap(curr->start,curr->size);
            remove_live_mmap(&process_to_debug.current_snapshot->current_mmaps_head, curr->start,curr->type);
        }

        else if(curr->type == MUNMAP){
            live_mmap_node* match_mmap = get_live_mmap_by_addr(&process_to_debug.current_snapshot->current_mmaps_head, curr->start,MMAP);
            if(match_mmap ){ //there is an mmap that match this munmap that happend during the record
                inject_mmap(match_mmap->start, match_mmap->size, match_mmap->prot, match_mmap->flags, match_mmap->fd, match_mmap->offset);
            }
            else{
                match_mmap = get_live_mmap_by_addr(&process_to_debug.live_mmaps, curr->start,MMAP);
                if(match_mmap){
                    inject_mmap(match_mmap->start, match_mmap->size, match_mmap->prot, match_mmap->flags, match_mmap->fd, match_mmap->offset);
                }
            }
             
        }
        curr = next;
    }

    return 0;
}



live_mmap_node* get_live_mmap_by_addr(live_mmap_node** head, long addr,mmap_type type){
    live_mmap_node* curr = *head;
    while(curr != NULL){ //from latest to earliest because mmap calls are lifo
        if(curr->start == (void*)addr && curr->type == type){
            return curr;
        }
        curr = curr->next;
    }
    return NULL;
}


