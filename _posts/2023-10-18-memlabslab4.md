---
title: <img width="50" height="50" alt="front-page port 80-shoopyu" src="https://repository-images.githubusercontent.com/203713308/0ed14700-ffd3-11ea-9c3a-ec9166b4dd01">MemLabs Lab4 🛡️
date: 2023-10-18 00:00:02 +730
categories: [Write Up, memoryforensics]
comments: true
tags: [memlabs, lab4, memoryforensics,digitalforensics] # TAG names should always be lowercase


---
 ## **Challenge Description**
> 
> My system was recently compromised. The Hacker stole a lot of information but he also deleted a very important file of mine. I have no idea on how to recover it. The only evidence we have, at this point of time is this memory dump. Please help me.
> 
> **Note**: This challenge is composed of only 1 flag.
> 
> The flag format for this lab is:  **inctf{s0me_l33t_Str1ng}**
> 
> **Challenge file**:  [MemLabs_Lab4](https://mega.nz/#!Tx41jC5K!ifdu9DUair0sHncj5QWImJovfxixcAY-gt72mCXmYrE)

First we need to identify the operating system of the memory image.

```
$ volatility -f MemoryDump_Lab4.raw imageinfo

```

![1](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/e8220ed9-c756-4ce0-b755-f49bb2969280)

The next thing is to check running processes.

```
$ volatility -f MemoryDump_Lab4.raw --profile Win7SP1x64 pslist

```
![2](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/8594f36c-1dae-431b-af68-972872f32d74)


The only interesting process here is  `StikyNot.exe`  (this is a rabbit hole, nothing important there).

Looking back at the challenge description, it says something about files and a deleted file. So we can use  `filescan`  to search for interesting files in memory, but for the sake of variety, I will use  `iehistory`  plugin instead.

> `iehistory`  plugin recovers fragments of IE history index.dat cache files. It can find basic accessed links (via FTP or HTTP), redirected links (–REDR), and deleted entries (–LEAK). It applies to any process which loads and uses the wininet.dll library, not just Internet Explorer. Typically that includes Windows Explorer and even malware samples.

so we can use it to view the history of visited files and directories by windows explorer.

```
$ volatility -f MemoryDump_Lab4.raw --profile Win7SP1x64 iehistory
..........
Process: 3012 explorer.exe
Cache type "URL " at 0x42f5000
Record length: 0x100
Location: :2019062920190630: SlimShady@file:///C:/Users/SlimShady/Desktop/Important.txt
Last modified: 2019-06-29 12:59:43 UTC+0000
Last accessed: 2019-06-29 07:29:43 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0x0

```

What do we have here, a text file that looks important!!!

Now let’s scan for this file in memory to dump it out.

```
$ volatility -f MemoryDump_Lab4.raw --profile Win7SP1x64 filescan | grep Important.txt
Volatility Foundation Volatility Framework 2.6.1
0x000000003fc398d0     16      0 R--rw- \Device\HarddiskVolume2\Users\SlimShady\Desktop\Important.txt

$ volatility -f MemoryDump_Lab4.raw --profile Win7SP1x64 dumpfiles -Q 0x000000003fc398d0 -D lab4_output/
Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x3fc398d0   None   \Device\HarddiskVolume2\Users\SlimShady\Desktop\Important.txt

```

Unfortunately,  `dumpfiles`  was not able to dump the text file (it was deleted by the hacker).

We need to know a little bit about the MFT table to solve this challenge.

> -   The NTFS file system contains a file called the master file table, or MFT. There is at least one entry in the MFT for every file on an NTFS file system volume. All information about a file, including its name, size, time and date stamps, permissions, and data content, is stored either in MFT entries, or in space outside the MFT that is described by MFT entries.
>     
> -   As files are added to an NTFS file system volume, more entries are added to the MFT and the MFT increases in size. When files are deleted from an NTFS file system volume, their MFT entries are marked as free and may be reused. However, disk space that has been allocated for these entries is not reallocated, and the size of the MFT does not decrease.
>     
> -   A file whose size is less than or equal to 1024 bytes will be stored directly in the MFT table (named “resident” file), if it exceeds 1024 bytes the table will only contain the information of its location (named “non-resident” file).
>     

So let’s search for  `Important.txt`  in the MFT table.

```
$ volatility -f MemoryDump_Lab4.raw --profile Win7SP1x64 mftparser > mft.txt

```

[![3](https://n1ght-w0lf.github.io/assets/images/ctf-writeups/memlabs/lab4/3.png)](https://n1ght-w0lf.github.io/assets/images/ctf-writeups/memlabs/lab4/3.png)

And here it’s, the flag characters are scattered across the file, anti-strings technique :)

> #### Flag: inctf{1_is_n0t_EQu4l_7o_2_bUt_th1s_d0s3nt_m4ke_s3ns3}
<br>
<br>
<br>

![enter image description here](https://media.giphy.com/media/DAtJCG1t3im1G/giphy.gif)
