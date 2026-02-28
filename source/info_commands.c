#include <stdio.h>
#include <string.h>
#include <sys/user.h>

#include "info_commands.h"
#include "elf_parser.h"
#include "debug.h"
#include "breakpoint.h"
extern debugee_process process_to_debug;
info_commands functions_info[] = {
    {"registers",info_registers,"info all the current thread registers"},
    {"functions",info_functions,"info all functions"},
    {"breakpoints",info_breakpoints,"info all breakpoints"},
    {"snapshots",info_snapshots,"info all snapshots"},
    {NULL,NULL,NULL}
};

int info(int argc,char** argv){
    if(argc != 2){
        return 0;
    }
    for(int i = 0; functions_info[i].command != NULL;i++){
        if(strcmp(argv[1],functions_info[i].command) == 0){
            functions_info[i].info_func_handler(argc,argv);
            return 1;
        }
    }

    return 0;
}

static void print_flags(unsigned long eflags){

    typedef struct{
        const char* name;
        unsigned long mask;
    }flag ;

    flag flags[]  = {
        {"CF", 0x00000001},
        {"PF", 0x00000004},
        {"AF", 0x00000010},
        {"ZF", 0x00000040},
        {"SF", 0x00000080},
        {"TF", 0x00000100},
        {"IF", 0x00000200},
        {"DF", 0x00000400},
        {"OF", 0x00000800},
        {"NT", 0x00004000},
        {"RF", 0x00010000},
        {"VM", 0x00020000},
        {"AC", 0x00040000},
        {"VIF",0x00080000},
        {"VIP",0x00100000},
        {"ID", 0x00200000},
        {NULL, 0}
    };
    printf("[ ");
    for(int i = 0; flags[i].name != NULL && flags[i].mask != 0;i++){
        if((eflags & flags[i].mask) == flags[i].mask){
            printf("%s ",flags[i].name);
        }
    }
    printf(" ]\n");

}

void print_registers(struct user_regs_struct* regs){
    printf("rax = 0x%016llx\n",regs->rax);
    printf("rbx = 0x%016llx\n",regs->rbx);
    printf("rcx = 0x%016llx\n",regs->rcx);
    printf("rdx = 0x%016llx\n",regs->rdx);
    printf("rsi = 0x%016llx\n",regs->rsi);
    printf("rdi = 0x%016llx\n",regs->rdi);
    printf("rbp = 0x%016llx\n",regs->rbp);
    printf("r8 = 0x%016llx\n",regs->r8);
    printf("r9 = 0x%016llx\n",regs->r9);
    printf("r10 = 0x%016llx\n",regs->r10);
    printf("r11 = 0x%016llx\n",regs->r11);
    printf("r12 = 0x%016llx\n",regs->r12);
    printf("r13 = 0x%016llx\n",regs->r13);
    printf("r14 = 0x%016llx\n",regs->r14);
    printf("r15 = 0x%016llx\n",regs->r15);
    printf("rip = 0x%016llx\n",regs->rip);
    printf("eflags = 0x%016llx\t",regs->eflags);
    print_flags(regs->eflags);
    printf("fs_base = 0x%016llx\n",regs->fs_base);
    printf("gs_base = 0x%016llx\n",regs->gs_base);
}


int info_registers(int argc, char** argv){
    if(process_to_debug.proc_state == STOPPED || process_to_debug.proc_state == RUNNING){
        struct user_regs_struct regs;
        get_registers(process_to_debug.pid, &regs);
        print_registers(&regs);
    }

    else{
        printf("The program has no registers now.\n");
    }
}



int info_functions(int argc, char** argv){
    if(process_to_debug.array_of_symbols->number_of_symbols == 0){
        printf("no symbols\n");
    }
    for(int i = 0; i < process_to_debug.array_of_symbols->number_of_symbols;i++){
        if(process_to_debug.array_of_symbols->symbols[i].type == FUNC){
            printf("0x%08lx     %s\n",process_to_debug.array_of_symbols->symbols[i].adress,process_to_debug.array_of_symbols->symbols[i].name);
        }
    }
}


int info_breakpoints(int argc, char** argv){
    print_breakpoints();
}

int info_snapshots(int argc, char** argv){
    printf("in info snapshots\n");
}