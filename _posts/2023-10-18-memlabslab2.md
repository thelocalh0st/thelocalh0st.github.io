---
title: <img width="50" height="50" alt="front-page port 80-shoopyu" src="https://repository-images.githubusercontent.com/203713308/0ed14700-ffd3-11ea-9c3a-ec9166b4dd01">MemLabs Lab2 🛡️
date: 2023-10-18 00:00:02 +730
categories: [Write Up, memoryforensics]
comments: true
tags: [memlabs, lab2, memoryforensics,digitalforensics] # TAG names should always be lowercase


---

 ## **Challenge Description**
> 
> One of the clients of our company, lost the access to his system due to an unknown error. He is supposedly a very popular “environmental” activist. As a part of the investigation, he told us that his go to applications are browsers, his password managers etc. We hope that you can dig into this memory dump and find his important stuff and give it back to us.
> 
> **Note**: This challenge is composed of 3 flags.
> 
> **Challenge file**:  [MemLabs_Lab2](https://mega.nz/#!ChoDHaja!1XvuQd49c7-7kgJvPXIEAst-NXi8L3ggwienE1uoZTk)

First we need to identify the operating system of the memory file.

```
$ volatility -f MemoryDump_Lab2.raw imageinfo

```

![1](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/453bfc9f-62db-4986-9eaf-a45daa9e4abd)



```
$ volatility -f MemoryDump_Lab2.raw --profile Win7SP1x64 pslist

```

![2](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/69b407ac-ac21-4020-9e0e-7cd564c47f42)

We can see interesting processes like  `chrome`  and  `KeePass`. but in  the description, its  quoted the  word  `"environmental"`.  so let’s go down this way first.

```
$ volatility -f MemoryDump_Lab2.raw --profile Win7SP1x64 envars
........
320 csrss.exe      0x0000000000481320    NEW_TMP    C:\Windows\ZmxhZ3t3M2xjMG0zX1QwXyRUNGczXyFfT2ZfTDRCXzJ9
........
424 wininit.exe    0x000000000030a600    NEW_TMP    C:\Windows\ZmxhZ3t3M2xjMG0zX1QwXyRUNGczXyFfT2ZfTDRCXzJ9
........
812 svchost.exe    0x0000000000221320    NEW_TMP    C:\Windows\ZmxhZ3t3M2xjMG0zX1QwXyRUNGczXyFfT2ZfTDRCXzJ9
........

```

We can see the environment variable  `NEW_TMP`  in every process with a value that looks like Base64. so let’s decode it.

```
$ echo ZmxhZ3t3M2xjMG0zX1QwXyRUNGczXyFfT2ZfTDRCXzJ9 | base64 -d
flag{w3lc0m3_T0_$T4g3_!_Of_L4B_2}

```
first stage is completed

> #### Flag 1: flag{w3lc0m3_T0_$T4g3_!_Of_L4B_2}
<br>
<br>


Next, let’s check this  `KeePass`  process,  Keepass is the  password manager.

 KeePass stores the passwords in a database with the extension  `".kdbx"`  and looks it with a master password.

So let’s check if this database is in memory.

```
$ volatility -f MemoryDump_Lab2.raw --profile Win7SP1x64 filescan | grep ".kdbx"
Volatility Foundation Volatility Framework 2.6.1
0x000000003fb112a0     16      0 R--r-- \Device\HarddiskVolume2\Users\SmartNet\Secrets\Hidden.kdbx

```

And here it’s, now let’s dump it

```
$ volatility -f MemoryDump_Lab2.raw --profile Win7SP1x64 dumpfiles -Q 0x000000003fb112a0 -D lab2_output/
Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x3fb112a0   None   \Device\HarddiskVolume2\Users\SmartNet\Secrets\Hidden.kdbx

```

The only thing left is to get the master password, Iet's scan files for any password like file.

```
$ volatility -f MemoryDump_Lab2.raw --profile Win7SP1x64 filescan | grep -i "password"
Volatility Foundation Volatility Framework 2.6.1
.........
0x000000003fce1c70      1      0 R--r-d \Device\HarddiskVolume2\Users\Alissa Simpson\Pictures\Password.png
.........

```

here we can see image named Password!!! looks interesting, let’s dump it.

```
$ volatility -f MemoryDump_Lab2.raw --profile Win7SP1x64 dumpfiles -Q 0x000000003fce1c70 -D lab2_output/
Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x3fce1c70   None   \Device\HarddiskVolume2\Users\Alissa Simpson\Pictures\Password.png

```

![3](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/f29c5799-c7ae-4974-8643-0c3e03e58d6d)

If you look closely at the bottom right, you can spot the password.

Now let’s use this password to open the database in KeePass.

![4](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/d875ac2a-b406-4129-8e38-cc39f712466f)

![5](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/abeaced7-2f4b-4d98-ba81-bc334bdbe4ad)

The flag is the copied password.

> #### Flag 2: flag{w0w_th1s_1s_Th3_SeC0nD_ST4g3_!!}

Now let’s return back the the  `chrome`  process, the first thing is to check the browsing history.

This amazing github repo has the plugin we need:  [Volatility-Plugins](https://github.com/superponible/volatility-plugins)

```
volatility --plugins=plugins/ -f MemoryDump_Lab2.raw --profile Win7SP1x64 chromehistory > chromehistory.txt

```
![6](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/2c9760da-e1b3-4ee2-880d-efac8c880219)


We have a mega link, the mega folder name is  `MemLabs_Lab2_Stage3`  and it contained a single zip file named  `Important.zip`  (password protected).

I tried unzipping it with  `unzip`  but it gave me an error, so I used  `7z`.

![7](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/911293d3-ad73-4408-9cd0-fab3a33da591)

Let’s get the password.

```
$ echo -n flag{w3ll_3rd_stage_was_easy} | sha1sum 
6045dd90029719a039fd2d2ebcca718439dd100a

```

After unzipping the file, I got this image.

![8](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/2b7f1045-ec10-43f4-82da-c30a623b45e2)

<br>
<br>

> #### Flag 3: flag{oK_So_Now_St4g3_3_is_DoNE!!}
<br>
<br>

![enter image description here](https://media.giphy.com/media/DAtJCG1t3im1G/giphy.gif)
