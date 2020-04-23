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

## From C to Shellcode
Now that the analysis of the TCP reverse shell C code is complete, it is easier to determine which system calls are necessary to create a functional TCP reverse shell in assembly. From analysis, it is clear that system calls will need to be made to the following functions in the following order:
1. `socket`
2. `connect`
3. `dup2`
4. `execve`

The mechanics of system calls in Linux x86 assembly were explained in an earlier post. To briefly reiterate, system calls are made through the `INT 0x80` software interrupt insruction. A system call number which will be in the `EAX` register before the `INT 0x80` instruction is encounter specifies the system call to be made. Each system call expects arguments which are most commonly passed through the `EBX`, `ECX`, and `EDX` registers.

In the sections following, the assembly code used to prepare for and execute the functions listed above will be explained. As the details of these functions and their purpose within a TCP reverse shell program were previously explained during the analysis of the C code, the following sections will focus on the assembly code used to prepare for and excute each function rather than on the purpose of the function within the program. Some of the assembly used for the TCP reverse shell is similar to the assembly used within the TCP bind shell explained in a previous post. These sections will be explained in less detail, as they have already been explained previously. The assembly code will come first, followed by the explanation of the code.


_This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:_

<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert>

_Student ID: SLAE-1469_

