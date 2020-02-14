---
title: "SLAE32 0x07: Custom Crypter"
date: 2019-11-24
category: [SLAE32]
tags: [assembly, python, exploit development, custom crypter, linux, SLAE32]
header:
    teaser: "/assets/images/slae/crypt.jpg"
---
In this post, a crypter program will be created and demonstrated that uses the Advanced Encryption Standard encryption specification, also known as AES. The AES standard is part of the block cipher family. It is also important to note that AES is a symmetric-key algorithm which means that the same key is used for encrypting and decrypting data. A crypter has two parts, an encryptor and a decryptor. The encryption and decryption programs will be written in Python.

In general, encryption is used to obfuscate and secure data in such a way that only authorized parties (those with the key) can access it. While encrypted messages can still be intercepted, the encrypted contents will be unintelligible to those without the decryption key. For shellcode, encryption and decryption can be used to obfuscate the shellcode within in an attempt to evade anti-virus softare. Shellcode can first be encrypted with an encryptor program, and then can be placed into a file along with decryption logic that can be compiled and run as a standalone program. The idea is that the shellcode will be obfuscated until the program is run which in turn decrypts and executes the original shellcode payload.

## Objectives
Create a custom crypter;
1. Any existing encryption schema may be used
2. Any programming language may be used

## Encryption/Decryption Demonstration
For this assignment, the `execve` shellcode from the custom encoding assignment will be reused to demonstrate the encryption and decryption process. This shellcode has been demonstrated, explained, and tested in previous posts. Upon execution, this shellcode will spawn a new `/bin/sh` shell. The unencrypted payload is shown below for future reference.

```shell
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80
```

In the sections below, the encryption and decryption programs will be demonstrated and explained.

### Encryption
The program code in full is shown below. The source code can be found on [GitHub](https://github.com/norrismw/SLAE). An overview of the program functionality will follow the code.

```python
#!/usr/bin/python3

from Crypto.Cipher import AES
import hashlib
import random

# Place plaintext shellcode here
shellcode = b'SHELLCODE_PLACEHOLDER'


# Generates 128 bit (16 byte) key 
def md5_key(key):
    b_key = str.encode(key)
    hashed_key = hashlib.md5(b_key)
    return hashed_key.hexdigest()


# Formats the shellcode for printing to terminal
def format_shellcode(bytes_obj):
    formatted = ''
    for byte in bytes_obj:
        formatted += '\\x'
        formatted += '%02x' % byte
    return formatted


# Pads the shellcode. AES encryption works on 16 byte blocks
def pad(shellcode):
    if len(shellcode) % 16 != 0:
        c = 16 - (len(shellcode) % 16)
        for i in range(c):
            shellcode += b'*'
    return shellcode


key = input("Key: ") # Takes user-chosen key
key = md5_key(key) # Generates key to 16 byte key
iv = ''.join([chr(random.randint(0, 0xFF)) for i in range(16)]) # Pseudo-random intialization vector
cipher = AES.new(key) # Cipher object for encryption
enc_shellcode = cipher.encrypt(pad(shellcode)) # Encrypted shellcode

print("\n[+] Encrypted shellcode:\n{}".format(format_shellcode(enc_shellcode)))
```

After placing the plaintext shellcode into the `shellcode` variable (it should replace the only the `SHELLCODE_PLACEHOLDER` text) and running the program, a key to be used for encryption should be entered by the user. For AES encryption, a keysize of 128, 192, or 256 bits is required. To faciliate for cases where the user-defined key is not 128, 192, or 256 bits in size, all keys are hashed using the MD5 algorithm, which returns 128 bit hash values. 

Following the key hashing process, the intialization vector (or the IV) is initialized. An IV is a required random or pseudo-random fixed-size input (16 bytes in the context of AES) that is used along with the user-specified hashed key value during the encryption process. For most block ciphers such as AES, the IV is the same size as the block size.

Next, a cipher object is created which will subsequently used to encrypt the plaintext shellcode. For block ciphers, the data to be encrypted must be evenly divisible by the block size. As stated previously, the block size for AES is 16 bytes. To account for instances where the number of the bytes in the plaintext shellcode is not evenly divisible by 16, a padding function is used to append `*` characters to the end of the plaintext shellcode until the length is evenly divisilble by 16. 

With the shellcode padded to a byte length that is evenly divisible by 16, the plaintext shellcode is encrypted and printed to the terminal. A demonstration of the program running is shown below.

```shell
root@kali:~/workspace/SLAE/assignments/0x07# python3 EncryptShellcode.py 
Key: SLAE-1469

[+] Encrypted shellcode:
\x8f\x03\x2b\xc7\x69\xa4\xe4\xe2\x5e\x44\x96\xa8\x47\x8a\xc3\xb5\xf8\x57\xad\xef\xe8\xbd\xed\x33\xc7\xe5\x1f\xe3\xd5\xc5\xd1\x02
```

### Decryption
The program code in full is shown below. The source code can be found on [GitHub](https://github.com/norrismw/SLAE). An overview of the program functionality will follow the code.

```python
#!/usr/bin/python3

from Crypto.Cipher import AES
import hashlib
import random

# Place encrypted shellcode here
enc_shellcode = b'ENC_SHELLCODE_PLACEHOLDER'


# Generates 128 bit (16 byte) key 
def md5_key(key):
    b_key = str.encode(key)
    hashed_key = hashlib.md5(b_key)
    return hashed_key.hexdigest()


# Formats the shellcode for printing to terminal
def format_shellcode(bytes_obj):
    formatted = ''
    for byte in bytes_obj:
        formatted += '\\x'
        formatted += '%02x' % byte
    return formatted


# Removes padding from decrypted shellcode
def unpad_shellcode(shellcode):
    shellcode = format_shellcode(shellcode)
    return shellcode.replace('\\x2a', '')


key = input("Key: ") # Takes user-chosen key
key = md5_key(key) # Generates key to 16 byte key
iv = ''.join([chr(random.randint(0, 0xFF)) for i in range(16)]) # Pseudo-random intialization vector
cipher = AES.new(key) # Cipher object for decryption
dec_shellcode = cipher.decrypt(enc_shellcode) # Decrypted shellcode with padding
shellcode = unpad_shellcode(dec_shellcode) # Decrypted shellcode; no padding

print("\n[+] Shellcode:\n{}".format(shellcode))
```

To decrypt the encrypted shellcode, the encrypted shellcode output provided from the encryption program should be placed into the `shellcode` variable (it should replace the only the `ENC_SHELLCODE_PLACEHOLDER` text). Upon running the decryption program, the same user-specified key used during the encryption process should be used for decryption. If the incorrect key is provided, then the encrypted shellcode will not be decrypted to the original plaintext shellcode. 

The same modifications to the user-supplied key occur within the decyption program as they ocurred in the encyrption program and the modificatoins serve the same purpose (to make the user-supplied key 128 bits in length). Also, the initialization of the IV variable and the cipher object follow the same principles within the decryption program as within the previously outlined encryption process. 

At this point, the encrypted shellcode can be decrypted back to its original plaintext form. As padding bytes were added to the plaintext shellcode before encyrption, this means that those same bytes must be removed after decryption. At this point, the shellcode is decrypted, but the padding is still intact. To remove the padding, the decrypted shellcode has all instances of `\x2a` replaced with `''`, which effectly removes the padding and restores the shellcode to it's original unencrypted plaintext form. 

The plaintext shellcode is then printed to the terminal. A demonstration of the decryption program is shown below which decrypts the payload encrypted by the encryption program. A demonstration of the decryption program running is shown below.

```shell
root@kali:~/workspace/SLAE/assignments/0x07# python3 DecryptShellcode.py 
Key: SLAE-1469

[+] Shellcode:
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80
```

Note that the above shellcode matches the shellcode that was encrypted with the encryption program (referenced in a previous section of this post.) The output below shows the result of an incorrect key being used to decrypt the payload that was encrypted with the key `SLAE-1469`. When any key other than `SLAE-1469` is used in an attempt to decrypt data encrypted with the the `SLAE-1469` key, the resulting shellcode will not match the original plaintext shellcode. A demonstration of this is shown below.

```shell
root@kali:~/workspace/SLAE/assignments/0x07# python3 DecryptShellcode.py 
Key: BAD_KEY

[+] Shellcode:
\x58\x68\xf5\x99\x39\x5e\xaa\x60\xef\x1b\x30\xa3\x9b\xb6\x7b\x40\x89\x15\x27\x23\x3c\xf2\xce\x3c\xe4\x4f\x2d\x71\x69\xcc\xb3\x7c
```

_This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:_

<http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert>

_Student ID: SLAE-1469_

