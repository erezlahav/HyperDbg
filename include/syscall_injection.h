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