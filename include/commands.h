#pragma once



int run_process(int argc,char** argv);
int continue_proc(int argc,char** argv);
int exemine(int argc,char** argv);
int disassemble_function(int argc,char** argv);
int step_into(int argc,char** argv);
int next_instruction(int argc,char** argv);
int cmd_delete(int argc,char** argv);
int print_backtrace(int argc,char** argv);
int record(int argc,char** argv);
int rewind_snapshot(int argc,char** argv);
int exit_debugger(int argc,char** argv);

