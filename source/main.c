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
#include "dwarf_parser.h"
#define SIZE_OF_PATH 150
#define MAX_AMOUNT_OF_BREAKPOINTS 100

debugee_process process_to_debug;
int main(int argc,char* argv[],char* envp[]){
    

    if(argc != 3){
        printf("Usage: %s -mode <pid>/<path>\n",argv[0]);
        exit(0);
    }
    FILE* elf_target_ptr = NULL;
    process_to_debug.array_of_breakpoints.number_of_breakpoints = 0;
    process_to_debug.array_of_breakpoints.arr_breakpoints = malloc(sizeof(breakpoint)* MAX_AMOUNT_OF_BREAKPOINTS);
    if(strcmp(argv[1],"-run") == 0){
        printf("executing -run to process\n");
        process_to_debug.proc_state = NOT_LOADED;
        process_to_debug.elf_path = get_full_path(argv[2]);
        process_to_debug.pid = -1;
        elf_target_ptr = fopen(process_to_debug.elf_path,"rb");
        if(elf_target_ptr == NULL){
            printf("fopen failed!\n");
            exit(0);
        }
//get status of elf file target process
        
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
        if(ptrace(PTRACE_ATTACH,process_to_debug.pid,NULL,0) == -1){ //sending SIGSTOP to the currently running process
            printf("fail\n");
        }
        int status;
        waitpid(process_to_debug.pid,&status,0);
        if(WIFSTOPPED(status)){
            process_to_debug.proc_state = STOPPED;
            printf("process stopped\n");
        }
        elf_target_ptr = fopen(process_to_debug.elf_path,"rb");
        if(elf_target_ptr == NULL){
            printf("fopen failed!\n");
            exit(0);
        }
        process_to_debug.PIE = get_pie_status(elf_target_ptr);
        process_to_debug.text_segment_offset_va = get_loading_vaddr_of_text_segment(elf_target_ptr);
        process_to_debug.array_of_symbols = get_symbols_from_file(elf_target_ptr);   
        load_proc_info(process_to_debug.pid);
        update_adressing_of_symtab_symbols(process_to_debug.array_of_symbols, process_to_debug.array_of_regions.arr[0].start);
        debug_process(process_to_debug.elf_path);
    }


    else{
        printf("mode undefined, use -run / -attach\n");
    }

}
