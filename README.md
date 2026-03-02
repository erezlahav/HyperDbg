# debugger-project

My debugger is a GDB-like debugger written in C for Linux x86_64, supporting breakpoints, memory inspection, ELF parsing, register inspection, live process attachment, ASLR handling, and Reverse debugging.

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

---

# Reverse Debugging Explanation:
first of all im extractning the writble regions of the program like stack,data,heap and more...
than i inject the syscall MPROTECT to the debugged process on the writble pages of the program and change them to READONLY
than im saving the registers of the program of the current snapshot
now everytime the process tries to change data of pages from stack,data,heap and more... he gets a page fault and the signal SIGSEGV is sent to him by the kernel
than i catch the SIGSEGV, identify the adress of the SIGSEGV from the CR2 register and identify the correct page
after that i copy the data of the page with process_vm_readv function, and than i know that i need to resore this page data at rewind
than when "rewind" command is being called i restore the last snapshot registers and write only the **changed pages** data to the process, and injecting MPROTECT syscall to reset the pages permissions
this way is pretty much linux COW implementation and is helping me to rewind to snap shot very effectively






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

### Program State Inspection (info commands)
- `info registers` — display all current thread registers  
- `info functions` — list all loaded functions  
- `info breakpoints` — show all active breakpoints  

### Memory & Disassembly
- `disass <function>` / `disassemble <function>` — print function disassembly  
- `x/<count><format> <address|register>` — examine memory or instructions (e.g., `x/100gx $rax`, `x/10i $rip`)  

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
