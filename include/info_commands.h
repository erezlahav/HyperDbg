#pragma once
#include <unistd.h>


typedef struct{
    char* command;
    int(*info_func_handler)(int argc,char** argv);
    char* help;
}info_commands;


int info(int argc,char** argv);

int info_registers(int argc, char** argv);
void print_registers(struct user_regs_struct* regs);
int info_functions(int argc, char** argv);
int info_breakpoints(int argc, char** argv);
int info_snapshots(int argc, char** argv);