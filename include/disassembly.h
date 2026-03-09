#pragma once


void live_disassemble_symbol(symbol* symbol);
void static_disassemble_symbol(symbol* symbol);
void print_disassemble_bytes(unsigned char* bytes_array,size_t size,long start_addr,int user_count);
int is_call_instruction(long opcode);
int get_length_of_instruction(unsigned char* bytes_array,size_t size,long start_addr);