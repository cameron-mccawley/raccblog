---
title: "OSU League 2020/2021 - scrambled_noodles Writeup"
date: 2021-04-18
draft: false
description: ""
tags: ["ctf"]
---
## Writeup
> My assistant sent me this .wav as an update on a case he is working on, however I dont know what to do with it. Such a frustrating April Fools Joke, and I'm missing an update on this case.

For this challenge, we are given a WAV file that when played, Rick Rolls us....
Thank you Lyell, very cool.

After messing around with the file for a bit trying to figure out what to do with it, we eventually realized that there were frequencies in the song that were much too high to show up in audacity, so using an online tool to look at the file's spectrogram, we see a link!

{{< figure src="/img/osint-1.png" >}}

Great! Following that link leads us to a pastebin with the following text:

```
Case 20210410-001 Update: 4/16/2021
 
Haha, I made you solve a stego chall to get an update on this case! Happy late April fools!
 
I've looked into that WLAN hotspot thing and I think I've got a lead. It's a guy who goes by "Barron Benedict Jr. III", an alleged resident of Ascension island... I've seen him use online username "TwoBoatsMan2", but apart from that, I have no further progress, I've been addicted to this game AmongUs...
```

So we have a username: "TwoBoatsMan2". Let's run this through [namechk.com](https://namechk.com/) to see what accounts are linked to that username:

{{< figure src="/img/osint-2.png" >}}

Looks like it found a twitter account with that username! We can check to see if it's what we are looking for by simply following the link to the twitter account:

{{< figure src="/img/osint-3.png" >}}

And sure enough, we find the account we are looking for. Scrolling through the tweets (they're not that many of them), we see that this user poseted an image of their desktop. Interesting...

{{< figure src="/img/osint-4.png" >}}

Upon closer inspection, we can see that the user has reddit open in one of their tabs with the username of "ascension-wlan". Going to their reddit account, we see a similar post to the twitter one we just looked at, except this time we can see a bit more of that network connection info window behind the web browser.

{{< figure src="/img/osint-6.png" >}}

And zooming in:

{{< figure src="/img/osint-7.png" >}}

We get all sorts of info here, but the juciest thing is that physical MAC address. Looking below the post, we see a comment that says:

```
HAHA Maybe later I will share the full Hotspot Story! My third neighbor (who will remain anonymous) was really out of his gourd this time, claiming he was scanning my network, and that now the world knows I'm operating a hotspot.. whatever that means.
```

> Now the world knows I'm operating a hotspot

Oh man, now this is getting good. If the whole world can see he is operating a hotspot, how can we see that?
Digging through [osintframework.com](https://osintframework.com/) we see a tool titled "WiGLE: Wireless Network Mapping". Through this site, we can just enter in a MAC address and see not only where that device is emmitting a wireless signal, but also the name of that wireless network. Typing in our MAC address we got from the screenshot and we get our flag!

{{< figure src="/img/osint-8.png" >}}

`OSU{OSINT_aint_that_hard}`
