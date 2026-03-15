#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/user.h>

#include "utils.h"
#include "debug.h"

#define AMOUNT_OF_PATHS 100
#define MAX_PATH_SIZE 150
#define SIZE_OF_PATH 50
#define DELIM " \r\t\n"
#define AMOUNT_OF_COMMANDS 20
#define MAX_COMMAND_LENGTH 150
extern debugee_process process_to_debug;



char** parse_command(char* command,int* argc_out){
    char** commands = malloc(sizeof(char*) * AMOUNT_OF_COMMANDS);
    char* curr_substring = strtok(command,DELIM);
    int index = 0;
    while(curr_substring != NULL){
        commands[index] = malloc(MAX_COMMAND_LENGTH);
        strncpy(commands[index],curr_substring,MAX_COMMAND_LENGTH);
        commands[index][strlen(curr_substring)] = '\x00';
        curr_substring = strtok(NULL,DELIM);
        index++;
    }
    commands[index] = NULL;
    *argc_out = index;
    return commands;
}


unsigned long* get_register(struct user_regs_struct* regs_ptr,char* str_register){
    if (strcmp(str_register, "rip") == 0) return &regs_ptr->rip;
    if (strcmp(str_register, "rax") == 0) return &regs_ptr->rax;
    if (strcmp(str_register, "rbx") == 0) return &regs_ptr->rbx;
    if (strcmp(str_register, "rcx") == 0) return &regs_ptr->rcx;
    if (strcmp(str_register, "rdx") == 0) return &regs_ptr->rdx;
    if (strcmp(str_register, "rsi") == 0) return &regs_ptr->rsi;
    if (strcmp(str_register, "rdi") == 0) return &regs_ptr->rdi;
    if (strcmp(str_register, "rsp") == 0) return &regs_ptr->rsp;
    if (strcmp(str_register, "rbp") == 0) return &regs_ptr->rbp;


    return NULL;
}





char* get_elf_path_by_pid(pid_t pid){
    char* elf_path = malloc(MAX_PATH_SIZE);
    char symlink_path[MAX_PATH_SIZE];
    symlink_path[0] = '\x00'; //because strcat always search for null byte at the start to start copy the buffer to
    strcat(symlink_path,"/proc/");
    char pid_str[10];
    sprintf(pid_str, "%d", pid);
    strcat(symlink_path,pid_str);
    strcat(symlink_path,"/exe");
    ssize_t bytes_read = readlink(symlink_path,elf_path,MAX_PATH_SIZE);
    if(bytes_read == -1){
        printf("error accured!\n");
        return NULL;
    }
    elf_path[bytes_read] = '\x00';
    return elf_path;
}



char* get_full_path(char* path){
    int path_len = strlen(path);
    if(path_len >= MAX_PATH_SIZE){
        printf("path to long\n");
        return NULL;
    }
    char* full_path = malloc(MAX_PATH_SIZE);
    char copy_path[MAX_PATH_SIZE];
    strncpy(copy_path,path,path_len);
    copy_path[path_len] = '\x00';
    FILE* file_ptr = fopen(path,"rb");
    if(file_ptr != NULL){
        if(path[0] == '.'){
            getcwd(full_path,MAX_PATH_SIZE);
            strcat(full_path,copy_path+1);
        }
        else{
            strncpy(full_path,copy_path,path_len);
            full_path[path_len] = '\x00';
        }
        return full_path;
    }
    char* path_env;
    path_env = getenv("PATH");
    char** env_paths = parser(path_env,":");
    full_path = get_full_path_from_envs(env_paths,path);
    free_double_str_ptr(env_paths);
    return full_path;
}

char* get_full_path_from_envs(char** nullable_env_paths, char* target_file) {
    FILE* ptr_to_file;
    char* full_path = malloc(MAX_PATH_SIZE); 

    if (!full_path) {
        perror("malloc failed");
        return NULL;
    }

    for (int i = 0; nullable_env_paths[i] != NULL; i++) {
        snprintf(full_path, MAX_PATH_SIZE, "%s/%s", nullable_env_paths[i], target_file);

        ptr_to_file = fopen(full_path, "rb");
        if (ptr_to_file != NULL) {
            fclose(ptr_to_file); 
            return full_path; 
        }
    }

    free(full_path); 
    return NULL;
}


char** parser(char* str,char* delim){
    int size = AMOUNT_OF_PATHS * MAX_PATH_SIZE;
    char* copy_str = malloc(size);
    strncpy(copy_str,str,size);
    char** strings_arr = malloc(sizeof(char*) * AMOUNT_OF_PATHS);
    int current_index = 0;
    char* current_str = strtok(copy_str,delim);
    while(current_str != NULL){
        strings_arr[current_index] = malloc(MAX_PATH_SIZE);
        strncpy(strings_arr[current_index],current_str,MAX_PATH_SIZE);
        current_str = strtok(NULL,delim);
        current_index++;
    }
    free(copy_str);
    strings_arr[current_index] = NULL;
    return strings_arr;
}

int free_double_str_ptr(char** env_paths){
    for(int i = 0;env_paths[i] != NULL;i++){
        free(env_paths[i]);
    }
    free(env_paths);
}



symbol* get_symbol_by_adress(unsigned long adress){ //for backtrace
    symbol* symbol_array_ptr = process_to_debug.array_of_symbols->symbols;

    uint16_t number_of_symbols =  process_to_debug.array_of_symbols->number_of_symbols;

    for(int i = 0; i < number_of_symbols; i++){
        long start_adress = symbol_array_ptr[i].adress;
        long end_adress = symbol_array_ptr[i].adress + symbol_array_ptr[i].size;
        if(adress >= start_adress && adress <= end_adress && adress != end_adress){
            return &symbol_array_ptr[i];
        }
    }
    return NULL;
}
