#include <sys/ptrace.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include "debug.h"
#include "elf_parser.h"
#include "utils.h"
#include "breakpoint.h"
#include "syscall_handling.h"

#define SIZE_OF_PATH 150
#define MAX_AMOUNT_OF_BREAKPOINTS 50
#define MAX_AMOUNT_OF_SYSCALL_BREAKPOINTS 2000


debugee_process process_to_debug;
int main(int argc,char* argv[],char* envp[]){
    

    if(argc != 3){
        printf("Usage: %s -mode <pid>/<path>\n",argv[0]);
        exit(0);
    }
    FILE* elf_target_ptr = NULL;

    process_to_debug.current_snapshot = NULL;
    process_to_debug.scratch_buffer = NULL;
    process_to_debug.array_of_breakpoints.number_of_breakpoints = 0;
    process_to_debug.array_of_breakpoints.number_of_syscall_breakpoints = 0;
    process_to_debug.array_of_breakpoints.arr_breakpoints = malloc(sizeof(breakpoint)* MAX_AMOUNT_OF_BREAKPOINTS);
    process_to_debug.array_of_breakpoints.syscall_arr_breakpoints = malloc(sizeof(breakpoint)* MAX_AMOUNT_OF_SYSCALL_BREAKPOINTS);
    process_to_debug.live_mmaps = NULL;

    if(strcmp(argv[1],"-run") == 0){
        printf("executing -run to process\n");
        process_to_debug.proc_state = NOT_LOADED;
        process_to_debug.elf_path = get_full_path(argv[2]);
        process_to_debug.pid = -1;
        elf_target_ptr = fopen(process_to_debug.elf_path,"rb");
        if(elf_target_ptr == NULL){
            printf("path : %s\n",process_to_debug.elf_path);
            printf("fopen failed!\n");
            exit(0);
        }

        if(!is_elf64(elf_target_ptr)){
            printf("error, target file is not elf 64 bit\n");
            exit(0);
        }
        process_to_debug.PIE = get_pie_status(elf_target_ptr);
        process_to_debug.text_segment_offset_va = get_loading_vaddr_of_text_segment(elf_target_ptr);
        process_to_debug.array_of_symbols = get_symbols_from_file(elf_target_ptr);
        fclose(elf_target_ptr);

        debug_process(process_to_debug.elf_path);
    }


    else if(strcmp(argv[1],"-attach") == 0){
        printf("executing -attach to process\n");
        process_to_debug.pid = atoi(argv[2]);
        process_to_debug.elf_path = get_elf_path_by_pid(process_to_debug.pid);
        elf_target_ptr = fopen(process_to_debug.elf_path,"rb");
        if(elf_target_ptr == NULL){
            printf("fopen failed!\n");
            exit(0);
        }
        if(!is_elf64(elf_target_ptr)){
            printf("error, target file is not elf 64 bit\n");
            exit(0);
        }


        int ptrace_res = ptrace(PTRACE_ATTACH,process_to_debug.pid,NULL,0);
        if(ptrace_res == -1){ //sending SIGSTOP to the currently running process
            printf("fail, errno : %s\n",strerror(errno));
            exit(0);
        }
        int status;
        waitpid(process_to_debug.pid,&status,0);
        if(WIFSTOPPED(status)){
            process_to_debug.proc_state = STOPPED;
            printf("process stopped\n");
        }
        process_to_debug.PIE = get_pie_status(elf_target_ptr);
        process_to_debug.text_segment_offset_va = get_loading_vaddr_of_text_segment(elf_target_ptr);
        process_to_debug.array_of_symbols = get_symbols_from_file(elf_target_ptr);   
        parse_maps(process_to_debug.pid,&process_to_debug.array_of_regions);
        update_adressing_of_symtab_symbols(process_to_debug.array_of_symbols, process_to_debug.array_of_regions.arr[0].start);
        put_syscalls_bps();
        fclose(elf_target_ptr);
        debug_process(process_to_debug.elf_path);
    }


    else{
        printf("mode undefined, use -run / -attach\n");
    }

}
