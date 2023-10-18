
---
title: <img width="50" height="50" alt="front-page port 80-shoopyu" src="https://repository-images.githubusercontent.com/203713308/0ed14700-ffd3-11ea-9c3a-ec9166b4dd01">MemLabs Lab3 🛡️
date: 2023-10-18 00:00:02 +730
categories: [Write Up, memoryforensics]
comments: true
tags: [memlabs, lab3, memoryforensics,digitalforensics] # TAG names should always be lowercase


---

 ## **Challenge Description**
 
> A malicious script encrypted a very secret piece of information I had on my system. Can you recover the information for me please?
> 
> **Note**: This challenge is composed of only 1 flag and split into 2 parts.
> 
> **Hint**: You’ll need the first half of the flag to get the second.
> 
> You will need this additional tool to solve the challenge,
> 
> ```
> $ sudo apt install steghide
> 
> ```
> 
> The flag format for this lab is:  **inctf{s0me_l33t_Str1ng}**
> 
> **Challenge file**:  [MemLabs_Lab3](https://mega.nz/#!2ohlTAzL!1T5iGzhUWdn88zS1yrDJA06yUouZxC-VstzXFSRuzVg)


<br>
<br>
<hr>
First we need to identify the operating system of the memory image.

```
$ volatility -f MemoryDump_Lab3.raw imageinfo

```


![1](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/2788b9db-0b70-4ea5-ba78-82469723fe06)


Next, let’s check the arguments given while running the programs through `commandline`

```
$ volatility -f MemoryDump_Lab3.raw --profile Win7SP1x86_23418 cmdline
Volatility Foundation Volatility Framework 2.6.1
........
notepad.exe pid:   3736
Command line : "C:\Windows\system32\NOTEPAD.EXE" C:\Users\hello\Desktop\evilscript.py
************************************************************************
notepad.exe pid:   3432
Command line : "C:\Windows\system32\NOTEPAD.EXE" C:\Users\hello\Desktop\vip.txt

```

Interesting, we got two files.  `evilscript.py`  which as the name implies is evil and  `vip.txt`  which look like an important file.

Let’s search for these two files in memory.

```
$ volatility -f MemoryDump_Lab3.raw --profile Win7SP1x86_23418 filescan | egrep "evilscript.py|vip.txt"
Volatility Foundation Volatility Framework 2.6.1
0x000000003de1b5f0      8      0 R--rw- \Device\HarddiskVolume2\Users\hello\Desktop\evilscript.py.py
.........
0x000000003e727e50      8      0 -W-rw- \Device\HarddiskVolume2\Users\hello\Desktop\vip.txt

```

Now that we have the offsets of the two files, let’s dump them.

```
$ volatility -f MemoryDump_Lab3.raw --profile Win7SP1x86_23418 dumpfiles -Q 0x000000003de1b5f0 -D lab3_output/
$ volatility -f MemoryDump_Lab3.raw --profile Win7SP1x86_23418 dumpfiles -Q 0x000000003de1b5f0 -D lab3_output

```

Here is the dumped python file:

```
import sys
import string

def xor(s):
	a = ''.join(chr(ord(i)^3) for i in s)
	return a

def encoder(x):
	return x.encode("base64")

if __name__ == "__main__":
	f = open("C:\\Users\\hello\\Desktop\\vip.txt", "w")
	arr = sys.argv[1]
	arr = encoder(xor(arr))
	f.write(arr)
	f.close()

```

This evil script is XORing the file  `vip.txt`  with a single character then Base64 encoding it.

And here is the content of the dumped text file:

```
am1gd2V4M20wXGs3b2U=

```

So we first need to Base64 decode it then XOR it again with same character to retrieve the original text.

```
$ python
>>> s = 'am1gd2V4M20wXGs3b2U='
>>> s = s.decode('base64')
>>> ''.join(chr(ord(i)^3) for i in s)
inctf{0n3_h4lf

```

> #### First half: inctf{0n3_h4lf

Now that we have the first half of the flag, let’s hunt for the other half.

This one took me sometime, then I looked at the hint and it says something about  `steghide`.

Steghide is a steganography program that is able to hide data in images and audio files and it supports JPEG and BMP images, so I decided to search memory for JPEG images.

```
$ volatility -f MemoryDump_Lab3.raw --profile Win7SP1x86_23418 filescan | grep ".jpeg"
Volatility Foundation Volatility Framework 2.6.1
0x0000000004f34148      2      0 RW---- \Device\HarddiskVolume2\Users\hello\Desktop\suspision1.jpeg

```

Would you look at that!!!, only one image and it looks suspicious :)

So let’s dump it.

![2](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/504b901c-6eb3-42ff-987b-eb1edd2172ef)

It’s just a normal image, or is it ???

Here comes  `steghide`, this image must have something hidden.

```
$ steghide extract -sf lab3_output/suspision1.jpeg 
Enter passphrase:

```

It’s asking for a passphrase, the hint clearly says that:  `You'll need the first half of the flag to get the second`.

Let’s try the first half of the flag as the passphrase.

```
$ steghide extract -sf lab3_output/suspision1.jpeg 
Enter passphrase:
wrote extracted data to "secret text".

```

Voila!!! let’s get this secret text.

```
$ cat secret\ text 
_1s_n0t_3n0ugh}

```

> #### Flag: inctf{0n3_h4lf_1s_n0t_3n0ugh
<br>
<br>
<br>

![enter image description here](https://media.giphy.com/media/DAtJCG1t3im1G/giphy.gif)
