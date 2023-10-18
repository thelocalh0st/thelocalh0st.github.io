---
title: <img width="50" height="50" alt="front-page port 80-shoopyu" src="https://repository-images.githubusercontent.com/203713308/0ed14700-ffd3-11ea-9c3a-ec9166b4dd01">MemLabs Lab5 🛡️
date: 2023-10-18 00:00:02 +730
categories: [Write Up, memoryforensics]
comments: true
tags: [memlabs, lab5, memoryforensics,digitalforensics] # TAG names should always be lowercase


---
 ## **Challenge Description**
> 
> This challenge is composed of 2 flags but do you really think so? Maybe a little flag is hiding somewhere.
> 
> **Note**: There was a small mistake when making this challenge. If you find any string which has the string “**_L4B_3_D0n3*!!**” in it, please change it to “_**L4B_5_D0n3*!!**” and then proceed.
> 
> **Hint**: You’ll get the stage 2 flag only when you have the stage 1 flag.
> 
> **Challenge file**:  [MemLabs_Lab5](https://mega.nz/#!Ps5ViIqZ!UQtKmUuKUcqqtt6elP_9OJtnAbpwwMD7lVKN1iWGoec)

First we need to identify the operating system of the memory image.

```
$ volatility -f MemoryDump_Lab5.raw imageinfo

```
![1](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/42cddeeb-6fef-420c-8233-f02bb45b1715)


Next, let’s check the processes list.

```
$ volatility -f MemoryDump_Lab5.raw --profile Win7SP1x64 pslist

```

![2](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/45a0d85f-715d-49c3-bea0-bf657be8ad2f)

Interesting, there’s a  `WinRAR.exe`  process, let’s see what the cmdline for that process is.

```
$ volatility -f MemoryDump_Lab5.raw --profile Win7SP1x64 cmdline | grep WinRAR.exe
Volatility Foundation Volatility Framework 2.6.1
WinRAR.exe pid:   2924
Command line : "C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\SmartNet\Documents\SW1wb3J0YW50.rar"

```

The rar file name is  `SW1wb3J0YW50.rar`, let’s dump this file.

```
$ volatility -f MemoryDump_Lab5.raw --profile Win7SP1x64 filescan | grep SW1wb3J0YW50.rar
Volatility Foundation Volatility Framework 2.6.1
0x000000003eed56f0      1      0 R--r-- \Device\HarddiskVolume2\Users\SmartNet\Documents\SW1wb3J0YW50.rar

$ volatility -f MemoryDump_Lab5.raw --profile Win7SP1x64 dumpfiles -Q 0x000000003eed56f0 -D lab5_output/
Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x3eed56f0   None   \Device\HarddiskVolume2\Users\SmartNet\Documents\SW1wb3J0YW50.rar

```

Going ahead to unrar this file and I saw this comment.

```
$ unrar e SW1wb3J0YW50.rar 
UNRAR 5.61 beta 1 freeware      Copyright (c) 1993-2018 Alexander Roshal
Extracting from SW1wb3J0YW50.rar
Enter password (will not be echoed) for Stage2.png: 

```

Clearly this is stage2’s flag and the password for this file is stage1’s flag, so we need to get stage1’s flag first.

At this point I had no clue of what to do, so I tried my luck with  `iehistory`  (I explained it in the previous lab) and I notices something interesting.

```
$ volatility -f MemoryDump_Lab5.raw --profile Win7SP1x64 iehistory
.........
Process: 1396 explorer.exe
Cache type "URL " at 0x28c5900
Record length: 0x100
Location: Visited: Alissa Simpson@file:///C:/Users/Alissa%20Simpson/Pictures/ZmxhZ3shIV93M0xMX2QwbjNfU3Q0ZzMtMV8wZl9MNEJfM19EMG4zXyEhfQ.bmp
.........
Process: 1396 explorer.exe
Cache type "URL " at 0x28c5a00
Record length: 0x100
Location: Visited: Alissa Simpson@file:///C:/Users/Alissa%20Simpson/Pictures/ZmxhZ3shIV93M0xMX2QwbjNfU3Q0ZzMtMV8wZl9MNEJfNV9EMG4zXyEhfQ.bmp
.........
Process: 1396 explorer.exe
Cache type "URL " at 0x28c5c00
Record length: 0x100
Location: Visited: Alissa Simpson@file:///C:/Windows/AppPatch/ZmxhZ3shIV93M0xMX2QwbjNfU3Q0ZzMtMV8wZl9MNEJfNV9EMG4zXyEhfQ.bmp

```

This  `.bmp`  file is repeated multiple times and it’s names looks like Base64 string, so I tries to decode it.

```
$ echo ZmxhZ3shIV93M0xMX2QwbjNfU3Q0ZzMtMV8wZl9MNEJfNV9EMG4zXyEhfQ | base64 -d
flag{!!_w3LL_d0n3_St4g3-1_0f_L4B_5_D0n3_!!}

```

Voila! we got the flag of stage1.

> #### Flag 1: flag{!!_w3LL_d0n3_St4g3-1_0f_L4B_5_D0n3_!!}

Now let’s return back to the rar file.

```
$ unrar e SW1wb3J0YW50.rar 
UNRAR 5.61 beta 1 freeware      Copyright (c) 1993-2018 Alexander Roshal
Extracting from SW1wb3J0YW50.rar
Enter password (will not be echoed) for Stage2.png: 
Extracting  Stage2.png                                                OK 
All OK

```

As I said before, the password is stage1’s flag.

![3](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/c57251e4-3b65-445b-bc9f-374b9bb43c6a)

> #### Flag 2: flag{W1th_th1s_$taGe_2_1s_c0mPL3T3_!!}
<br>
<br>
<br>

![enter image description here](https://media.giphy.com/media/DAtJCG1t3im1G/giphy.gif)
