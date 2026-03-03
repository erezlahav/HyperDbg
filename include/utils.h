#pragma once

#include "elf_parser.h"


char** parse_command(char* command,int* argc_out);
unsigned long* get_register(struct user_regs_struct* regs_ptr,char* str_register);
char* get_elf_path_by_pid(pid_t pid);
char* get_full_path(char* path);
char* get_full_path_from_envs(char** nullble_env_paths,char* target_file);
char** parser(char* str,char* delim);
int free_double_str_ptr(char** env_paths);
symbol* get_symbol_by_adress(unsigned long adress);
