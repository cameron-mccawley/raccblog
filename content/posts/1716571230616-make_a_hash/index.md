---
title: "OSU League 2020/2021 - make_a_hash Writeup"
date: 2021-02-12
draft: false
description: ""
tags: ["ctf"]
---
## Writeup
For this crypto challenge, we are given a service we can connect to along with the source code of that service.  Let's connect to it:

```
Welcome to secure_hash_TM bug bounty program! If you can find a second preimage to my hash, you will get a reward!
Press Enter to continue to your challenge

I hashed the hexstring 72432e1cd769b8ba328a8656ccaa9165023b26c87a0a7a2b9b83ccb882a6aabc4419c0ff35b2e6a6ce7202bb3ab590dcc957dcc946d3cfce5918d991db3e637f8e49ad48ec6fed47c73f7283e8d2d2136ea88bd67f1f1c0fd1dcac0c69d5aea4 using secure_hash_tm(), and my output was 1ab815160ddb4d48f00c472b59218b28a9b16f12efa40440d00c8709fb5ca8dee085f027460eeb642886ce71931147e658638dba71a4f2aa62011df4bfc69952 (feel free to check if you don't believe me)

Please find me a value 'x' such that secure_hash_tm(x) == 1ab815160ddb4d48f00c472b59218b28a9b16f12efa40440d00c8709fb5ca8dee085f027460eeb642886ce71931147e658638dba71a4f2aa62011df4bfc69952 but x != 72432e1cd769b8ba328a8656ccaa9165023b26c87a0a7a2b9b83ccb882a6aabc4419c0ff35b2e6a6ce7202bb3ab590dcc957dcc946d3cfce5918d991db3e637f8e49ad48ec6fed47c73f7283e8d2d2136ea88bd67f1f1c0fd1dcac0c69d5aea4 to demonstrate that you found a vulnerability in the hashing algorithm (pfft, I know it's fully secure so you'll never get it!)

Please provide your value for x (in hexstring form): 424242
When I ran secure_hash_tm(x), I got 9ddf7e70e5021544f4834bbee64a9e3789febc4be81470df629cad6ddb03320a5c, which does not equal 1ab815160ddb4d48f00c472b59218b28a9b16f12efa40440d00c8709fb5ca8dee085f027460eeb642886ce71931147e658638dba71a4f2aa62011df4bfc69952
```

So it looks like the goal of this challenge is to somehow find a different input that will be hashed to the same output, i.e. we are looking for a collision in however this hashing algorithm is implemented. Let's take a look at that hashing algorithm is implemented:

```python
#!/usr/bin/env python3

import binascii

from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

from typing import Iterator

with open('flag', 'r') as f:
    flag = f.read().strip()

def sha(data: bytes) -> bytes:
    algo = SHA256.new(data)
    return algo.digest()

def xor(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(a, b)])

# Evenly split 'data' into 'n' parts
def split_str(data: bytes, n: int) -> Iterator[bytes]:
    if len(data) % n != 0:
        print(f"Length of 'data' must be a multiple of {n}")
        raise ValueError

    section_len = len(data) // n
    return (data[i * section_len : (i + 1) * section_len] for i in range(n))

def secure_hash_tm(data: bytes) -> bytes:
    a, b, c = split_str(data, 3)
    w = xor(b, xor(sha(a), sha(c)))
    return xor(sha(w), a) + sha(c)


def to_hex(data: bytes) -> str:
    return binascii.hexlify(data).decode()

rnd = get_random_bytes(32 * 3)
rnd_hash = secure_hash_tm(rnd)

print("Welcome to secure_hash_TM bug bounty program! If you can find a second preimage to my hash, you will get a reward!")
input("Press Enter to continue to your challenge\n")

print(f"I hashed the hexstring {to_hex(rnd)} using secure_hash_tm(), and my output was {to_hex(rnd_hash)} (feel free to check if you don't believe me)\n")
print(f"Please find me a value 'x' such that secure_hash_tm(x) == {to_hex(rnd_hash)} but x != {to_hex(rnd)} to demonstrate that you found a vulnerability in the hashing algorithm (pfft, I know it's fully secure so you'll never get it!)\n")

try:
    x = bytes.fromhex(input("Please provide your value for x (in hexstring form): "))
except ValueError as e:
    print(f"Invalid input: {e}")
    exit(1)

x_hash = secure_hash_tm(x)
if x != rnd:
    if  x_hash == rnd_hash:
        print(f"Alright, fine: you found a preimage. Have your flag, just don't tell my Cryptography professor about this: {flag}")
    else:
        print(f"When I ran secure_hash_tm(x), I got {to_hex(x_hash)}, which does not equal {to_hex(rnd_hash)}")
else:
    print("Haha, you copied the value of x from rnd! That's not a second preimage ;)")

```
In particular, we will be focusing on the `secure_hash_tm` function to try and figure out what is really going on.

I've simplified the function to a more barebones logic algorithm below, using `||` to mean concatination:

```
HASH(a || b || c):
    w = b XOR (SHA(a) XOR SHA(c))
    return SHA(w) XOR a || SHA(c)
```

Here we can clearly see that our input c is not going to be able to be changed, as its SHA is directly appended to the output. This means that we will need to change `a` and `b` if we want to try and get a collision.  

Let's start by picking a random value for `w`, call it `w'`. This makes the most sense since the only way to find w is if we already know what we are going to choose for our inputs, so maybe we can use `w'` to reverse all of our inputs.

We can split our output into two halves: `out1` and `out2`. We know `out2` is just going to be equal to `SHA(c)`, so our `c' = c`.  

Next to find `a'` we reverse `out1`. `out1 = SHA(w') XOR a'`. Solving for `a'` gives `a' = out1 XOR SHA(w')`

Since we know `a'`, `c'`, and `w'`, we can find out last value `b'`. We just rearrange `w' = b' XOR (SHA(a') XOR SHA(c'))` to give `b' = w' XOR (SHA(a') XOR SHA(c'))`

`a' + b' + c'` is our attack! We can write a script to automate all of this (courtesy of Zander Work):

```python
import binascii
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from typing import Iterator
from pwn import *

def sha(data: bytes) -> bytes:
    algo = SHA256.new(data)
    return algo.digest()

def xor(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(a, b)])

# Evenly split 'data' into 'n' parts
def split_str(data: bytes, n: int) -> Iterator[bytes]:
    if len(data) % n != 0:
        print(f"Length of 'data' must be a multiple of {n}")
        raise ValueError

    section_len = len(data) // n
    return (data[i * section_len : (i + 1) * section_len] for i in range(n))

p = remote("ctf-league.osusec.org", 31312)
p.recvline()
p.recvline()
p.sendline("")

string= p.recvline().decode().strip().split()
rnd = binascii.unhexlify(string[4])
rnd_hash = binascii.unhexlify(string[11])
c1, c2 = split_str(rnd_hash, 2)

a, b, c = split_str(rnd, 3)
cprime = c

wprime = b"\x00"*len(a)
sha_wprime = sha(wprime)
aprime = xor(sha_wprime, c1)

bprime = xor(wprime, xor(sha(aprime), sha(cprime)))

p.sendline(binascii.hexlify(aprime + bprime + cprime))

print(p.recvall(timeout=0.5).decode())
```

And running it we get the flag!

```
[+] Opening connection to ctf-league.osusec.org on port 31312: Done
[+] Receiving all data: Done (709B)
[*] Closed connection to ctf-league.osusec.org port 31312

Please find me a value 'x' such that secure_hash_tm(x) == 43f0966aba662d16380a64ff6dc0e2220270196e82fec996e6433ad53e2ccac4575453b2e04087834d358bea1974785e6815cf9ed64d858eee3125d5120381e5 but x != 23d437c8eb55aa14fdce984afe3b50218b3155d78311f81112910ed47b037a52e3f9f3797dddb64001e9834ab77f23139437aba822c28d9dab2fd4e54c636757b46aaaa26f20a6a0d1a058564b691545978f1371efca700b68a2e2c63b17cb6c to demonstrate that you found a vulnerability in the hashing algorithm (pfft, I know it's fully secure so you'll never get it!)

Please provide your value for x (in hexstring form): Alright, fine: you found a preimage. Have your flag, just don't tell my Cryptography professor about this: osu{L0ng-L1v3-L1niCrYpt-2016}
```