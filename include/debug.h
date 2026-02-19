#pragma once
#define INPUT_SIZE 200


#include "maps_parsing.h"
#include "breakpoint.h"
#include "elf_parser.h"
#include "snapshot.h"

typedef struct{
    char* command;
    int(*func_handler)(int argc, char** argv);
    char* help;
}command_table;

typedef enum{
    RUNNING,
    STOPPED,
    EXITED,
    LOADED,
    NOT_LOADED
}RUNNING_STATE;

typedef struct{
    char* elf_path;
    bool PIE;
    RUNNING_STATE proc_state;
    pid_t pid;
    long text_segment_offset_va;
    regions_array array_of_regions;
    breakpoints_array array_of_breakpoints;
    array_snapshots snapshots;
    symbols_array* array_of_symbols;
}debugee_process;



int get_registers(pid_t pid, struct user_regs_struct* regs);
int set_registers(pid_t pid, struct user_regs_struct* regs);
int handle_command(char* command);
int handle_stopped_process(pid_t pid, int status);
int debug_process(char* elf_path);