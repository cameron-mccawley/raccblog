---
title: "OSU League 2020/2021 - RSA 2 Writeup"
date: 2020-11-13
draft: false
description: ""
tags: [""]
---
RSA 2 is a bit of a continuation off of RSA 1.  In order to access the challenge, we need to use openssl with the flag from RSA 1 to decrypt the TAR file.  To do this we can run `openssl enc -d -aes-256-ctr -pbkdf2 -nosalt -p -in rsa2.tar.gz.enc -out rsa2.tar.gz`, input the flag, and we get our challenge.

Looking at our `output.txt`, we can see that we are only given `N` and `c`.  And in our `puzzle.py`, which was used to encrypt the flag, we can see the `e` used.

The first thing I asked myself when looking at this challenge was: How is this different from RSA 1, and what difference is going to make it sovable without knowing `p` and `q`.  I figured once I was able to answer that, I would be able to solve the problem.  So let's look at the `puzzle.py` script.

```python
#!/usr/bin/env python3

from Crypto.Util.number import *
import secrets

e = 3

while True:
    p = getPrime(1024)
    q = getPrime(1024)

    if p % e != 1 and q % e != 1:
        break

N = p * q
print("N =", N)

with open("flag", "r") as f:
    flag = f.read().strip().encode()
assert(len(flag) == 85)

m = bytes_to_long(flag)
c = pow(m, e, N)
print("c =", c)
```

So this script here is pretty much the *exact* same as the one in RSA 1, except for one key difference.  RSA 1 had padding, this one does not.  So, does that mean if we have a short enough plaintext and no padding, we could break it?  The answer is yes!

After searching on Google a bit for an attack or equation I could use, I ended up realizing I was overthinking it way too much, and that I could just find `p` by solving for `C^(1/e)`, since both `e` and `p` were so small, this calculation would be trivial. I popped open python and got to work:

```python
from Crypto.Util.number import *
from gmpy2 import *

N = 20024632768768912637613287359025250387550004488851404049377259400752733388799951292405308777608649074330341018632991975552042961105732724798750078885720732546410418786078274826752459551907831138496403725485849646756740113916019193640901989276389787602195246817993403509392720749171364279691010448491334036637700351964364237754403848731229440797256383336989925714614422958744191860865576846549156703425246912067903570057484349243372272409500391122676452335000625444438716985883060699798470886987034772418020878266583441556260145028252207119825124743757209993244690345830406438267628658055946089838128377464948770248961
c = 10416535550287033495404277107932685706229928310455866710626825426018506529546436032322630363568176266525705927229405354921242317119687390060188542046814131758895088332943669483585493646367126873551375708025551792807707002805749920774977557070353890134393233641234747269714815176982007502479585261773126107779600519181310143005814281313336594030671597022196782553951724754446795277653708498088981084820085946862113135433044292888939221986395813120459623401016303004199435799452922439470903861727424783934455730514725133921915613149040534566451300960392495492478151972614574840283217508574285634813247276700284635237
e = 3

p = iroot(c, e)

p = long_to_bytes(p[0])

print(p)
```

And running the script, we get the flag!
```
osu{rs4-WI7Hout-P4dDiN9_iS-No7-vErY_SeCurE.-YoU-sH0ULD_u$e-OAEP_Or-4T-13aSt-PKCS1_5!}
```

While this was a much easier problem in a technical sense, I think this one requiered much more thought, as the solution isn't immediately obvious. 
