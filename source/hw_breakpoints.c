#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>

#include "debug.h"
#include "hw_breakpoints.h"
#include "breakpoint.h"


extern debugee_process process_to_debug;

int cmd_hardware_breakpoint(int argc,char** argv){
    if(argc != 2){
        printf("breakpoint syntax incorrect\n");
        return 0;
    }

    if(argv[1][0] != '*'){ //no * in argv[1]
        break_symbol(argv[1],HARDWARE | PERM);
    }
    else{ //* in argv, means its raw adrress or relitive symbol
        handle_star_breakpoint(argv,HARDWARE | PERM);
    }
}



unsigned long build_dr7_mask(unsigned long old_dr7, int index) {
    unsigned long dr7 = old_dr7;
    printf("old dr7 : %lx\n",dr7);

    dr7 |= (1UL << (index * 2)); // 


    dr7 &= ~(3UL << (16 + index*4));


    dr7 &= ~(3UL << (18 + index*4));

    return dr7;
}






int set_hardware_breakpoint(long adress){
    print_dr();
    unsigned long dr7_reg = ptrace(PTRACE_PEEKUSER,process_to_debug.pid,8*7,0);
    int avalieble_index = return_first_avalieble_hbp_register(dr7_reg);
    if(avalieble_index == -1){
        return 0;
    }
    printf("avalible index : %d\n",avalieble_index);
    ptrace(PTRACE_POKEUSER,process_to_debug.pid,8*6,0);
    //long res = ptrace(PTRACE_POKEUSER,process_to_debug.pid,8 * avalieble_index,adress);




    
    unsigned long dr7 = build_dr7_mask(dr7_reg,avalieble_index);


    //res = ptrace(PTRACE_POKEUSER,process_to_debug.pid,8*7,dr7);

    print_dr();
    return 0;
}


int clear_hardware_breakpoint(int index){
    ptrace(PTRACE_POKEUSER,process_to_debug.pid,8*index,0);
    ptrace(PTRACE_POKEUSER,process_to_debug.pid,8*6,0);



}


void print_dr(){
    long dr0 = ptrace(PTRACE_PEEKUSER,process_to_debug.pid,8*0,0);
    printf("dr0 : %lx\n",dr0);
    

    long dr7 = ptrace(PTRACE_PEEKUSER,process_to_debug.pid,8*7,0);
    printf("dr7 : %lx\n",dr7);
}

int return_first_avalieble_hbp_register(unsigned long dr7_reg){ //0 is dr0 , 1 is dr1 ....
    for(int i = 0; i < 4;i++){
        int current_local_dr = (dr7_reg >> i*2) & 0x1; 
        int current_global_dr = (dr7_reg >> (i*2+1)) & 0x1;
        if(current_local_dr == 0 && current_global_dr == 0){
            return i;
        }
    }
    return -1;
}