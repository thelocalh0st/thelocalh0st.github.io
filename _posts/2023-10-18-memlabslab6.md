---
title: <img width="50" height="50" alt="front-page port 80-shoopyu" src="https://repository-images.githubusercontent.com/203713308/0ed14700-ffd3-11ea-9c3a-ec9166b4dd01">MemLabs Lab6 🛡️
date: 2023-10-18 00:00:02 +730
categories: [Write Up, memoryforensics]
comments: true
tags: [memlabs, lab6, memoryforensics,digitalforensics] # TAG names should always be lowercase


---
## [**Challenge Description**](https://github.com/stuxnet999/MemLabs/tree/master/Lab%206#challenge-description)

>We received this memory dump from the Intelligence Bureau Department. They say this evidence might hold some secrets of the underworld gangster David Benjamin. This memory dump was taken from one of his workers whom the FBI busted earlier this week. Your job is to go through the memory dump and see if you can figure something out. FBI also says that David communicated with his workers via the internet so that might be a good place to start.
>
>**Note**: This challenge is composed of 1 flag split into 2 parts.
>
>The flag format for this lab is:  **inctf{s0me_l33t_Str1ng}**
>
>**Challenge file**:  [MemLabs_Lab6](https://mega.nz/#!C0pjUKxI!LnedePAfsJvFgD-Uaa4-f1Tu0kl5bFDzW6Mn2Ng6pnM)


First we need to identify the operating system of the memory image.

```
$ volatility -f MemoryDump_Lab6.raw imageinfo

```

![1](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/a50cb0e0-7241-49c1-bfa3-3b5a7820ee48)

Next, let’s check the running processes.

```
$ volatility -f MemoryDump_Lab6.raw --profile Win7SP1x64 pslist

```

![2](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/8ed84b67-b0b3-4909-b6eb-2623101d40d9)

We can see some interesting processes here like  `WinRAR`,  `chrome`  and  `firefox`  so let’s start with  `WinRAR`.

```
$ volatility --plugins=plugins/ -f MemoryDump_Lab6.raw --profile Win7SP1x64 cmdline | grep WinRAR.exe
Volatility Foundation Volatility Framework 2.6.1
WinRAR.exe pid:   3716
Command line : "C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\Jaffa\Desktop\pr0t3ct3d\flag.rar"

```

Oh, that file name is interesting, let’s dump it.

```
$ volatility -f MemoryDump_Lab6.raw --profile Win7SP1x64 filescan | grep flag.rar
Volatility Foundation Volatility Framework 2.6.1
0x000000005fcfc4b0     16      0 R--rwd \Device\HarddiskVolume2\Users\Jaffa\Desktop\pr0t3ct3d\flag.rar

$ volatility -f MemoryDump_Lab6.raw --profile Win7SP1x64 dumpfiles -Q 0x000000005fcfc4b0 -D lab6_output/
Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x5fcfc4b0   None   \Device\HarddiskVolume2\Users\Jaffa\Desktop\pr0t3ct3d\flag.rar

```

Next, let’s try to unrar it.

```
$ unrar e flag.rar 
UNRAR 5.61 beta 1 freeware      Copyright (c) 1993-2018 Alexander Roshal
Extracting from flag.rar
Enter password (will not be echoed) for flag2.png: 

```

Of course it’s encrypted :(

Let’s take a step back and try more plugins.

```
$ volatility --plugins=plugins/ -f MemoryDump_Lab6.raw --profile Win7SP1x64 consoles

```

![3](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/c078e36c-3a97-43b2-980f-70fc9093ef03)

I noticed the author is running  `env`  command, I suspect it’s a hint for us.

So let’s try dumping the environment variables for  `WinRAR`.

![4](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/643026fd-769a-4d84-975a-18f51a593e75)

Awesome, not we now that the rar password is:  `easypeasyvirus`.

```
$ unrar e flag.rar 
UNRAR 5.61 beta 1 freeware      Copyright (c) 1993-2018 Alexander Roshal
Extracting from flag.rar
Enter password (will not be echoed) for flag2.png: 
Extracting  flag2.png                                                 OK 
All OK

```

![5](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/97246c22-e591-4551-bc91-98e249103eb1)

Great, that looks like the second half of the flag.

> #### Second half: aN_Am4zINg_!_i_gU3Ss???_}[Permalink](https://n1ght-w0lf.github.io/ctf%20writeups/memlabs-lab6/#second-half-an_am4zing__i_gu3ss_ "Permalink")

Let’s return back the the chrome process, the first thing is to check the browsing history.

This amazing github repo has the plugin we need:  [Volatility-Plugins](https://github.com/superponible/volatility-plugins)

```
$ volatility --plugins=plugins/ -f MemoryDump_Lab6.raw --profile Win7SP1x64 chromehistory > chromehistory.txt

```

Scrolling through the history dump, I notices a pastebin link (`https://pastebin.com/RSGSi1hk`).

![6](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/ff76bf47-2625-4dc2-a3be-dd0c7c98cca3)

Here is what I found.

![7](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/c4b12143-2af0-4f64-9f53-1fe651c8374f)

There is a link to a google drive doc along with the note  `David sent the key in mail`.

The doc file is just some lorem ipsum text, but if you look carefully you can see a mega link (took me a while).
![8](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/75b8166d-8e1e-43cc-ae22-d14f7c271452)


Let’s see what this mega link has.

![9](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/8dd7f36f-cb28-4942-8507-35db4b6e6b98)

Another password, I hate my life :(

At this point I got stuck, so I tried every volatility plugin I know about. Then the magic happened.

The  `screenshot`  plugin saved the day.

```
$ volatility --plugins=plugins/ -f MemoryDump_Lab6.raw --profile Win7SP1x64 screenshot -D lab6_output

```

It dumped 13 images, all of them are just white images except for this one.

![10](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/9cdf2c14-de51-4261-8ea5-73dcd69907cf)

There is a windows with the title  `Mega Drive Key ....`, that looks promising. so let’s search for this string in memory.

```
$ strings MemoryDump_Lab6.raw | grep "Mega Drive Key"
.........
Mega Drive Key - davidbenjamin939@gmail.com - Gmail
top['GM_TRACING_THREAD_DETAILS_CHUNK_START'] = (window.performance && window.performance.now) ? window.performance.now() : null; top._GM_setData({"Cl6csf":[["simls",0,"{\"2\":[{\"1\":0,\"2\":{\"1\":\"Mega Drive Key\",\"2\":\"THE KEY IS zyWxCjCYYSEMA-hZe552qWVXiPwa5TecODbjnsscMIU\"
.........

```

Look at that, we got the key (a good pair of eyes required). the key is:  `zyWxCjCYYSEMA-hZe552qWVXiPwa5TecODbjnsscMIU`.

After decrypting the file, it turned out to be an image. but unfortunately it was corrupted.

Opening it with hexedit, the IHDR part was corrupted (iHDR). so all we need to do is to change  `i (69)`  to  `I (49)`.

![11](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/9e3aeb2f-b2ae-411a-aeaa-832dea1c7983)

Finally we got the first part of the flag, that was a long journey.

![12](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/ffdda212-46e7-4244-93c6-d752fd5908e4)

> #### Flag: inctf{thi5_cH4LL3Ng3_!s_g0nn4_b3_?_aN_Am4zINg_!_i_gU3Ss???_}[Permalink](https://n1ght-w0lf.github.io/ctf%20writeups/memlabs-lab6/#flag-inctfthi5ch4ll3ng3_s_g0nn4_b3__an_am4zing__i_gu3ss "Permalink")
<br>
<br>
<br>

![enter image description here](https://media.giphy.com/media/DAtJCG1t3im1G/giphy.gif)
