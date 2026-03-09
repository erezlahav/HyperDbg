#pragma once

#include <sys/types.h>


long remote_syscall( 
    pid_t tid,
    long syscall_number,
    long arg1,
    long arg2,
    long arg3,
    long arg4,
    long arg5,
    long arg6);


int inject_mprotect(long adress,size_t size,int permissions);
int inject_mmap(long adress,size_t size,int prot, int flags, int fd,size_t offset);
int inject_munmap(long adress,size_t size);