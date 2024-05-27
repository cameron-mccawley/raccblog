---
title: "OSU League 2020/2021 - cowsay Writeup"
date: 2020-10-31
draft: false
description: ""
tags: ["ctf"]
---
We are given a link to a website for this challenge that has a login page.  I first tried the obvious stuff such as `admin`, `password`, etc.  But no such luck.  Thankfully, I remembered a Hack the Box challenge that dealt with a similar sceanario, that being SQL injection!!!

If we type in `'or''='` into both the user name and password fields, we can escape the query and make it return true without actually needing to supply the correct password.  So after entering that, I was in as admin.

```
 ______
< boop >
 ------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
```

The webiste then presented itself with a little cowsay program, along with a message telling us the flag is located at `/flag` on the server. After playing with the fun program for a bit, I noticed that certain characters would break it.  Things like extra `"` or `'`.  That's when I noticed the `$`, giving me the impression that this cowsay program was being excecuted on the server itself.  So all I would have to do is escape the program.  

So I typed in `boop' && cat /flag '`

```
$cowsay 'boop' && cat /flag '
 _______
< boop >
 -------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
flag{if_y0u_ev3r_see_php_in_ctf,-try_sql_injection_f1rst!}
```

Nice, we got da flag!  Pretty fun and easy web challenge.