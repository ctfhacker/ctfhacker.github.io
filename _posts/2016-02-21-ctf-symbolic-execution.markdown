---
layout: post
title:  "test"
date:   2016-09-01 18:03:59
categories: python pentest pentestly
---

# Internetwache RE60 Writeup: Symbolic Execution tramples CTF challenge

I am always looking for problems that symbolic execution could be applied to in the capture the flag space. This past weekend, this challenge was met during the Internetwache CTF for its RE60 problem. Below I describe the application of symbolic execution to solve the challenge without much knowledge of the inner workings of the binary itself.

# Symbolic Execution 101

Symbolic Execution gives the reverse engineer the ability to find a specific path from Point A to Point B in a binary. This path is represented by a series of boolean expressions. These expressions can then be passed to a solver such as [Z3](https://z3.codeplex.com/) from Microsoft to solve the equation, creating an input that will exercise the found path.

If this is the first time seeing this concept, I highly recommend checking out the [MIT lecture](https://www.youtube.com/watch?v=mffhPgsl8Ws) on the subject. That lecture will give you enough prerequisite knowledge to unveil some of the black magic of symbolic execution.

# The challenge

(This challenge was performed entirely in [EpicTreasure](https://github.com/praetorian-inc/epictreasure). If you don't want to setup the tools listed in this writeup, simply install EpicTreasure and you are off to the races)

We begin by doing a bit of preliminary analysis to understand what the binary can do.

Let's see what `strace` shows us.

```
$ strace ./filechecker
execve("./filechecker", ["./filechecker"], [/* 24 vars */]) = 0
...snip...
open(".password", O_RDONLY)             = -1 ENOENT (No such file or directory)
write(1, "Fatal error: File does not exist", 32Fatal error: File does not exist) = 32
```

Ah, so it appears the binary is looking for a `.password` file of some kind. Let's satisfy the beast and see what else it wants.

```
echo Password123 > .password
```

```
$ strace ./filechecker
execve("./filechecker", ["./filechecker"], [/* 24 vars */]) = 0
...snip...
open(".password", O_RDONLY)             = 3
read(3, "Password123\n", 4096)          = 12
write(1, "Error: Wrong characters\n", 24Error: Wrong characters
```

Hm.. so we are now seeing that we have the wrong characters. A slightly deeper view might help at this point. Our good friend [radare2](https://github.com/radare/radare2) can definitely help with this. Let's find where we are in the binary currently.

<script type="text/javascript" src="https://asciinema.org/a/17uh0mbe4lq4ry6i0xbvwrcjl.js" id="asciicast-17uh0mbe4lq4ry6i0xbvwrcjl" async></script>

At this point we only know that the `.password` file is being read in by `fgetc`. Let's take a closer look at the for loop.

![forloop](/assets/images/ctf-symbolic/1_for_loop.png)

From the for loop, we see the `fgetc` and some black box function at `0x40079c`. Beyond this function, there is only some check and a branch to either the previously seen `Wrong characters` message (boo) and a `Congrats` message (yay!). Something in this function is deciding if this password is legitimate.

Below is the black box function (although understanding it isn't necessary):

![forloop](/assets/images/ctf-symbolic/2_blackbox.png)

For the purposes of this writeup, we don't really care what this function is doing. We could substitute this function with other number crunching shenanigans if we wanted to.

At this point, we can see this could be a job for a symbolic execution engine. Let's recap:

* We read in a file containing a supposed password
* This password is fed into a black box function that does some sort of validation
* There is a clear yes/no answer after this validation step

And our path that we believe we can follow is shown below:

![forloop](/assets/images/ctf-symbolic/3_path.png)

We take the leap of faith into the symbolic execution route and attempt to solve this purely symbolically.

# I choose you, angr!

The only big hurdle at this point is determining how to represent this file symbolically. Luckily, [angr](https://github.com/angr/angr) makes this bit fairly painless. angr is a "platform-agnostic binary analysis framework developed by the Computer Security Lab at UC Santa Barbara and their associated CTF team, Shellphish." (from their Github readme).

We begin our script by loading and analyzing the binary in angr.

```python
import angr
p = angr.Project('./filechecker', load_options={'auto_load_libs':False})
```

We also need a starting state in our execution. Because we will be executing from `main` forward, the `entry_state` is exactly what we need. This will begin execution at the entry point of the program. (If we were symbolically executing a smaller chunk of code, the `blank_state` would have been an more applicable state to choose).

```python
state = p.factory.entry_state()
```

Now the fun part, getting our symbolic file up and running. One particular snag in symbolic execution is when the length of a given input is unknown. Thankfully, we are given an upper bound of the password length right above our for loop.

![sym_len](/assets/images/ctf-symbolic/4_filesize.png)

With an input lenth of 15 (0xf) in hand, we can construct our `SimFile`. We create a symbolic input of 15 bytes as our upper bound shown above. This input is then stored in a symbolic memory region. This symbolic memory region is then mapped to a SimFile where the filename `.password` is associated with it.

```python
# Symbolic buffer of size 15
password_len = 0xf
s_password = state.se.BVS('password_bytes', password_len * 8)
    
# Symbolic memory region containing the symbolic buffer
content = simuvex.SimSymbolicMemory(memory_id='file_{}'.format(password_filename))
content.set_state(state)
content.store(0, s_password)

# Symbolic file which associates the symbolic memory region with a filename
password_file = simuvex.SimFile(password_filename, 'rw', size=15, content=content)
fs = {
    password_filename: password_file
}
state.posix.fs = fs
```

With the SimFile ready for action, we begin constructing the path constraints. We have highlighted a few places that we want to avoid when searching for a path. These places are essentially any place with an error or failed message. We begin a `path_group` starting at our `entry_state`. This `path_group` will manage all paths created and handle the checking of valid or invalid paths by verifying that each path has stayed away from the avoided locations.

```python
pg = p.factory.path_group(state)
pg.explore(find=0x400743, avoid=(0x400683, 0x4006b6, 0x400732))
```

These statements start the path traversal process of finding a valid path from `main` to our basic block that prints `Congrats`.

At this point we have a found path, but we need to solve the path to create a valid input that successfully completes the problem. We can ask angr to concretize the contents of a given file descriptor. We need to find the internal file descriptor of our file and pass that number to the `posix.dumps` utility to solve the path for the correct contents of the `.password` file.

```python
# Grab the found path traversal state
state = pg.found[0].state

# Grab current files from our files dict
files = state.posix.files

# The largest file ID is the content of the file we care about
"""
{0: <simuvex.storage.file.SimFile object at 0x7ffff0aa1410>, 1: <simuvex.storage.file.SimFile object at 0x7ffff0aa1690>, 2: <simuvex.storage.file.SimFile object at 0x7ffff0aa1910>, 3: <simuvex.storage.file.SimFile object at 0x7ffff5694960>, 4: <simuvex.storage.file.SimFile object at 0x7ffff5694960>, 3221227200L: <simuvex.storage.file.SimFile object at 0x7ffff089f5f0>}
"""
curr_file_id = max(files.keys())

print("[+] Solving for file content.. patience young grasshoppa..")
# Print contents of our file
print(state.posix.dumps(curr_file_id))
```

And if all goes well, we should have the correct contents of the `.password` file and the flag for the challenge.

<script type="text/javascript" src="https://asciinema.org/a/05f4ct14u50sukk8f49gui9w4.js" id="asciicast-05f4ct14u50sukk8f49gui9w4" async></script>
