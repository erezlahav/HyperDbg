#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ptrace.h>




int add(int a,int b){
    return a+b;
}

int c(void* ptr, size_t size){
    printf("ptr : %p\n",ptr);
    mprotect(ptr, 4096,PROT_READ);
    munmap(ptr,size);
}

int main(){
    /*
    int res = ptrace(PTRACE_TRACEME,getpid(),0,0);
    if(res == -1){
        printf("debugger dectected\n");
        return 0;
    }
    */
    char* gf = malloc(100);
    
    int fd = open("b.txt",0,0);
    printf("fd : %d\n",fd);
    

    void* ptr = mmap(NULL,4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,0, 0);
    munmap(ptr,4096);

    ptr = mmap(NULL,4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,0, 0);
    printf("new mapping : %p\n",ptr);


    printf("hello\n");
    int a = 0;
    int* b = malloc(sizeof(int));
    printf("enter b : \n");
    scanf("%d",b);
    c(ptr,4096);
    
    int sum = add(a,*b);
    printf("sum : %d\n",sum);
}
