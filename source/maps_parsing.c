#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "maps_parsing.h"
#include "utils.h"
#include "debug.h"
#define CHUNK_SIZE 4096

extern debugee_process process_to_debug;


#define MAX_REGIONS_NUMBER 50



void parse_lines_of_maps(char** lines,regions_array* arr_regions){ //parsing the lines of maps file and putting it in global array of mappings 
    arr_regions->regions_count = 0;
    char** parts_of_line;
    char** two_adresses;
    long start_addr;
    long end_addr;
    for(int i = 0;lines[i] != NULL;i++){
        parts_of_line = parser(lines[i]," "); //0 index : adress , 1 index : permissions, 2 index : xxxx, 3 index : date of mapping, 4 index : xxxx, 5 index : name of segment
        
        char* segment_name;
        if(parts_of_line[5] == NULL ){
            segment_name = " ";
        }
        else{
            segment_name = parts_of_line[5];
        }
        char* segment_permissions = parts_of_line[1];
        char* segment_mapped_adress = parts_of_line[0];



        two_adresses = parser(segment_mapped_adress,"-");
        start_addr = strtol(two_adresses[0],NULL,16);
        end_addr = strtol(two_adresses[1],NULL,16);

        if(strstr(segment_name,process_to_debug.elf_path) != NULL && strstr(segment_permissions,"x") != NULL){
            arr_regions->arr[arr_regions->regions_count].type = BINARY;
            arr_regions->arr[arr_regions->regions_count].start = start_addr;
            arr_regions->arr[arr_regions->regions_count].end = end_addr;
            arr_regions->arr[arr_regions->regions_count].permissions = 0;
            if(strstr(segment_permissions,"x")) arr_regions->arr[arr_regions->regions_count].permissions |= EXECUTE;
            if(strstr(segment_permissions,"w")) arr_regions->arr[arr_regions->regions_count].permissions |= WRITE;
            if(strstr(segment_permissions,"r")) arr_regions->arr[arr_regions->regions_count].permissions |= READ;
            arr_regions->regions_count++;
        }
        else if(strstr(segment_name,process_to_debug.elf_path) != NULL && strstr(segment_permissions,"w") != NULL){
            arr_regions->arr[arr_regions->regions_count].type = DATA;
            arr_regions->arr[arr_regions->regions_count].start = start_addr;
            arr_regions->arr[arr_regions->regions_count].end = end_addr;
            arr_regions->arr[arr_regions->regions_count].permissions = 0;
            if(strstr(segment_permissions,"x")) arr_regions->arr[arr_regions->regions_count].permissions |= EXECUTE;
            if(strstr(segment_permissions,"w")) arr_regions->arr[arr_regions->regions_count].permissions |= WRITE;
            if(strstr(segment_permissions,"r")) arr_regions->arr[arr_regions->regions_count].permissions |= READ;
            arr_regions->regions_count++;
        }
        else if(strstr(segment_name,"[heap]") != NULL){
            arr_regions->arr[arr_regions->regions_count].type = HEAP;
            arr_regions->arr[arr_regions->regions_count].start = start_addr;
            arr_regions->arr[arr_regions->regions_count].end = end_addr;
            arr_regions->arr[arr_regions->regions_count].permissions = 0;
            if(strstr(segment_permissions,"x")) arr_regions->arr[arr_regions->regions_count].permissions |= EXECUTE;
            if(strstr(segment_permissions,"w")) arr_regions->arr[arr_regions->regions_count].permissions |= WRITE;
            if(strstr(segment_permissions,"r")) arr_regions->arr[arr_regions->regions_count].permissions |= READ;
            arr_regions->regions_count++;
        }
        else if(strstr(segment_name,"stack") != NULL){
            arr_regions->arr[arr_regions->regions_count].type = STACK;
            arr_regions->arr[arr_regions->regions_count].start = start_addr;
            arr_regions->arr[arr_regions->regions_count].end = end_addr;
            arr_regions->arr[arr_regions->regions_count].permissions = 0;
            if(strstr(segment_permissions,"x")) arr_regions->arr[arr_regions->regions_count].permissions |= EXECUTE;
            if(strstr(segment_permissions,"w")) arr_regions->arr[arr_regions->regions_count].permissions |= WRITE;
            if(strstr(segment_permissions,"r")) arr_regions->arr[arr_regions->regions_count].permissions |= READ;
            arr_regions->regions_count++;
        }
        free_double_str_ptr(two_adresses);
        free_double_str_ptr(parts_of_line);
    }
}

void print_mem_regions(regions_array* arr_regions){
    for(int i = 0; i < arr_regions->regions_count;i++){
        printf("mem region : ");
        switch (arr_regions->arr[i].type){
            case 0:
                printf("BINARY");
                break;
            case 1:
                printf("HEAP");
                break;
            case 2:
                printf("STACK");
                break;
            case 3:
                printf("DATA");
                break;
            
        }

        printf(", start : %lx, end : %lx,permissions : %d\n",arr_regions->arr[i].start, arr_regions->arr[i].end,arr_regions->arr[i].permissions);
    }
}

char* read_maps(pid_t pid){
    char pid_str[10];
    sprintf(pid_str,"%d",pid);
    char path_maps[50];
    strcpy(path_maps,"/proc/");
    strcat(path_maps,pid_str);
    strcat(path_maps,"/maps");

    
    FILE* maps_file_ptr = fopen(path_maps,"rb");
    if(maps_file_ptr == NULL){
        printf("fopen failed!\n");
        return NULL;
    }
    char* content = malloc(CHUNK_SIZE);
    int offset_to_content = 0;
    int bytes_read = 0;
    while((bytes_read = fread(content + offset_to_content,1,CHUNK_SIZE,maps_file_ptr)) > 0){
        offset_to_content += bytes_read;
        content = realloc(content,offset_to_content+CHUNK_SIZE);
    }
    content[offset_to_content] = '\x00';
    fclose(maps_file_ptr);

    return content;
}



int parse_maps(pid_t pid,regions_array* arr_regions){
    char* content = read_maps(pid);
    char** lines = parser(content,"\n\t\r");
    arr_regions->arr = malloc(sizeof(memory_region) * MAX_REGIONS_NUMBER);
    parse_lines_of_maps(lines,arr_regions);
    free(content);
    free_double_str_ptr(lines);
}







