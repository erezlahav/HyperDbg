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


long inject_mprotect(long adress,size_t size,int permissions);
long inject_mmap(long adress,size_t size,int prot, int flags, int fd,size_t offset);
long inject_munmap(long adress,size_t size);