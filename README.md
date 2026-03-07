# debugger-project

My debugger is a GDB-like debugger written in C for Linux x86_64, supporting breakpoints, memory inspection, ELF parsing, register inspection, live process attachment, ASLR handling, Reverse debugging, Syscall monitoring, hooking, and parameter modification.

---

# Features

- **Execution Control:** run, continue (c), step into (si), step over (ni)  
- **Breakpoints:** Software (INT3) & hardware, set by address or symbol, delete and manage  
- **Backtrace:** Stack unwinding via RBP frame-pointer chain (bt)  
- **ELF & Symbols:** Parse .symtab / .dynsym, resolve addresses to functions  
- **Memory & Registers:** Inspect process memory and x86_64 registers  
- **Attach:** Debug already running processes  
- **ASLR Support:** Dynamically resolve memory addresses by parsing `/proc/<pid>/maps`  
- **Disassembly:** Function-level disassembly or arbitrary memory ranges (e.g., `x/10i $rip`)  
- **Reverse Debugging:** Rewind execution using Copy-On-Write snapshots
- **Syscalls Monitoring** monitor, hook and modify syscalls at runtime.

---

# Reverse Debugging Explanation:
1. First of all im extracting the writable regions of the program like stack,data,heap and more...
2. Then i inject the syscall MPROTECT to the debugged process on the writable pages of the program and change them to READONLY
3. Then im saving the registers of the program of the current snapshot
4. Now every time the process tries to change data of pages from stack,data,heap and more... he gets a page fault and the signal SIGSEGV is sent to him by the kernel
5. Then i catch the SIGSEGV, identify the address of the SIGSEGV from from `siginfo_t` `si_addr`(internally CR2 register) and identify the correct page
6. The entire page is copied using `process_vm_readv`, and the page is marked as dirty for future restoration.
7. Then when "rewind" command is being called i restore the last snapshot registers and write only the **changed pages** data to the process, and injecting MPROTECT syscall to reset the pages permissions
8. This way is pretty much linux COW implementation and is helping me to rewind to snapshot very effectively






# Commands

### Execution Control
- `run / r` — run the process, stopping before main  
- `continue / c` — continue execution  
- `step into / si` — execute one instruction, step into functions  
- `step over / ni` — execute one instruction, step over functions  

### Breakpoints
- `break <address|symbol>` — set a software breakpoint  
- `hbreak <address|symbol>` — set a hardware breakpoint  
- `delete <id>` — remove a breakpoint  

### Recording & Rewind
- `record` — save a snapshot of the current state  
- `rewind` — return to the last saved snapshot  
- `delete record` — removes the current record  

### Hooking Syscalls
- `hook <syscall>` — attach a hook to a system call (can modify parameters at runtime with `set` command)
- `unhook <syscall>` — remove a previously attached hook

### Program State Inspection (info commands)
- `info registers` — display all current thread registers  
- `info functions` — list all loaded functions  
- `info breakpoints` — show all active breakpoints  

### Memory & Disassembly
- `disass <function>` / `disassemble <function>` — print function disassembly  
- `x/<count><format> <address|register>` — examine memory or instructions (e.g., `x/100gx $rax`, `x/10i $rip`)
- `set $<register>` / `set <param_name>` in syscall 

### Other Commands
- `bt` — show backtrace of current function  
- `exit` — exit the debugger  

---

# Usage

```bash
./debugger -mode(run/attach) (<pid>/<path>)
```

---
# Dependencies

This project depends on Capstone disassembly framework.

On Ubuntu / Debian:
```bash
sudo apt install libcapstone4 libcapstone-dev
```