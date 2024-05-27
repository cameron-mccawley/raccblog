---
title: "OSU League 2020/2021 - Copper Writeup"
date: 2021-01-22
draft: false
description: ""
tags: ["ctf"]
---
## Writeup
> Time to smith some copper!

For this challenge, we are given a python script that was used to encrypt the flag, along with the output file that was created from it.
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
assert(len(flag) == 42)

padding = secrets.token_bytes(210)

print("leak =", "'" + padding.hex() + "'") # Oops

m = bytes_to_long(padding + flag)
c = pow(m, e, N)
print("c =", c)

```
We can see that we get a leak of the padding, specifically a leak of the most significant bits of the message.  Using something known as the Coppersmith Attack, we can actually find the rest of the message.

In the usual RSA model, you have a ciphertext `c`, a modulus `N`, and a public exponent `e`.  We find `m` such `m^e = c mod n`.  Now, this is a relaxed model that we can solve.  We have `c = (m+x)^e`, we know part of the message `m` from the leak, but we don't know `x`.  Since our leak is the same every tiem, Coppersmith says that if we are looking for `N^1/e` of the message, it is then a `small root` and we should be able to find it pretty quickly.

All we need to do is create our polynomial `f(x) = (m+x)^e - c`, which has a root we want to find `modulo n`.  This can be done pretty simply using sagemath.

```python
#!/usr/bin/env sage
from sage.all import *
from Crypto.Util.number import *

c= 17868294450269675883986469170882257064627428433707603500890067752063961604684654851805829469837273448999725432428147126421641016742425430357133618533629986319659863748262189446225365034508244240177060787410517018220032421721807953095837207003218011760432348606030572134907021265373169592163937292370872393174147157321516093197173216520335841446612508147601247895343214122792281835160338349714598182348561753092414308025112752919860278424873227347935031551007908454205414184850898725554932882780037415042307105104268365961626556278590673592416312815796753710080179427223832639267694963514301632816040398522317698229035
leak = 0x66c7e057ab2095241bc7b83cf6a7c6dde60693076d8573de510fc361889fb66e0960af222ead2da1b1c6fcf4a1cfcf0a20ee7cc61e976f3cad63958fb9852c32fe9e4698f87d07c30791a4e6407cf66a3cf93facdf1d276981e816dd3c0e7cbeb648c5297b0a5acc47afb46686eae964e0057a8be39b29fbdecd3774135bc88f6b067698571f05c5ba785dc4925892da19b3b7640b07807c6af3052b7ce29e125df0f97d4abcbcfd6d93ec94a90ee5c91d09a76e979977e774bb9ae1e1d287476c91d3f33a6018476d7e0040f930be848195
N = 18186023870103797120509091528210052017835202453642298117209863460505101021646819059351051653975541446071417302173552526656704895118368722200093087033737225264434273920451139462678043460481827716933677625256913291232865883170237072770097048652916180533727179614963237586711744465662269631274051008365748411477559298662467771638534575955123843497755288315232910699898049309025041620697001021306545139814617468700207648841194748772113954806702803092687574614539181545562465116769262452017256134407896879646761346081107053459497459090825261620696915937606342541436445863502433642370656618275284587683633176676092354921499
e = 3

R = Zmod(N)
P.<x> = PolynomialRing(R, implementation='NTL')

f = ((leak << (42*8)) + x)^e - c #We also need to bit shift our padding
flag = f.small_roots() [0]

print(long_to_bytes(flag))
```

And running it with sage we get the flag!
```
$sage sol.sage
osu{RSA-N3eD$_suPER-SECReT_R@NdOm_pAddiN9}
```
