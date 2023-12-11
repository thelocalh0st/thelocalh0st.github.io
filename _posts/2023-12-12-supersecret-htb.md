---
title: <img width="50" height="50" alt="front-page port 80-shoopyu" src="https://github.com/thelocalh0st/thelocalh0st.github.io/assets/95465072/b1357428-9893-4400-96c9-69e05733354a"> Dignostics | Hack The Box | Forensics 
date: 2023-11-12 00:00:02 +730
categories: [Write Up, HackTheBox]
tags: [dignostics,hackthebox,forensics,100-days-of-cybersecurity] # TAG names should always be lowercase


---


<h1 style="color: cyan; text-align: center">100 Day's Of Cybersecurity - Day 3</h1>

![](image-goes-here)

## Challenge Description 
Our SOC has identified numerous phishing emails coming in claiming to have a document about an upcoming round of layoffs in the company. The emails all contain a link to diagnostic.htb/layoffs.doc. The DNS for that domain has since stopped resolving, but the server is still hosting the malicious document (your docker). Take a look and figure out what's going on.

## Volllllatility!!

`imageinfo`
```
┌──(root㉿kali)-[/home/kali/Desktop/challenge-files]
└─# volatility -f TrueSecrets.raw imageinfo             
Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/kali/Desktop/challenge-files/TrueSecrets.raw)
                      PAE type : PAE
                           DTB : 0x185000L
                          KDBG : 0x82732c78L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0x82733d00L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2022-12-14 21:33:30 UTC+0000
     Image local date and time : 2022-12-14 13:33:30 -0800
  ```
<br>

`pslist`

```
                                                                                                               
┌──(root㉿kali)-[/home/kali/Desktop/challenge-files]
└─# volatility -f TrueSecrets.raw --profile=Win7SP1x86_23418 pslist    
Volatility Foundation Volatility Framework 2.6
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          
---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0x8378ed28 System                    4      0     87      475 ------      0 2022-12-15 06:08:19 UTC+0000                                 
0x83e7e020 smss.exe                252      4      2       29 ------      0 2022-12-15 06:08:19 UTC+0000                                 
0x843cf980 csrss.exe               320    312      9      375      0      0 2022-12-15 06:08:19 UTC+0000                                 
0x837f6280 wininit.exe             356    312      3       79      0      0 2022-12-15 06:08:19 UTC+0000                                 
0x84402d28 csrss.exe               368    348      7      203      1      0 2022-12-15 06:08:19 UTC+0000                                 
0x84409030 winlogon.exe            396    348      3      110      1      0 2022-12-15 06:08:19 UTC+0000                                 
0x844577a0 services.exe            452    356      9      213      0      0 2022-12-15 06:08:19 UTC+0000                                 
0x8445e030 lsass.exe               468    356      7      591      0      0 2022-12-15 06:08:19 UTC+0000                                 
0x8445f030 lsm.exe                 476    356     10      142      0      0 2022-12-15 06:08:19 UTC+0000                                 
0x84488030 svchost.exe             584    452     10      347      0      0 2022-12-15 06:08:19 UTC+0000                                 
0x844a2030 VBoxService.ex          644    452     11      116      0      0 2022-12-15 06:08:19 UTC+0000                                 
0x844ab478 svchost.exe             696    452      7      243      0      0 2022-12-14 21:08:21 UTC+0000                                 
0x844c3030 svchost.exe             752    452     18      457      0      0 2022-12-14 21:08:21 UTC+0000                                 
0x845f5030 svchost.exe             864    452     16      399      0      0 2022-12-14 21:08:21 UTC+0000                                 
0x845fcd28 svchost.exe             904    452     15      311      0      0 2022-12-14 21:08:21 UTC+0000                                 
0x84484d28 svchost.exe             928    452     23      956      0      0 2022-12-14 21:08:21 UTC+0000                                 
0x8e013488 svchost.exe             992    452      5      114      0      0 2022-12-14 21:08:21 UTC+0000                                 
0x8e030a38 svchost.exe            1116    452     18      398      0      0 2022-12-14 21:08:21 UTC+0000                                 
0x8e0525b0 spoolsv.exe            1228    452     13      275      0      0 2022-12-14 21:08:21 UTC+0000                                 
0x84477d28 svchost.exe            1268    452     19      337      0      0 2022-12-14 21:08:21 UTC+0000                                 
0x8e0a2658 taskhost.exe           1352    452      9      223      1      0 2022-12-14 21:08:22 UTC+0000                                 
0x844d2d28 dwm.exe                1448    864      3       69      1      0 2022-12-14 21:08:22 UTC+0000                                 
0x8e0d3a40 explorer.exe           1464   1436     32     1069      1      0 2022-12-14 21:08:22 UTC+0000                                 
0x8e1023a0 svchost.exe            1636    452     10      183      0      0 2022-12-14 21:08:22 UTC+0000                                 
0x8e10d998 svchost.exe            1680    452     14      224      0      0 2022-12-14 21:08:22 UTC+0000                                 
0x8e07d900 wlms.exe               1776    452      4       45      0      0 2022-12-14 21:08:22 UTC+0000                                 
0x83825540 VBoxTray.exe           1832   1464     12      140      1      0 2022-12-14 21:08:22 UTC+0000                                 
0x8e1cd8d0 sppsvc.exe              352    452      4      144      0      0 2022-12-14 21:08:23 UTC+0000                                 
0x8e1f6a40 svchost.exe            1632    452      5       91      0      0 2022-12-14 21:08:23 UTC+0000                                 
0x8e06f2d0 SearchIndexer.          856    452     13      626      0      0 2022-12-14 21:08:28 UTC+0000                                 
0x91892030 TrueCrypt.exe          2128   1464      4      262      1      0 2022-12-14 21:08:31 UTC+0000                                 
0x91865790 svchost.exe            2760    452     13      362      0      0 2022-12-14 21:10:23 UTC+0000                                 
0x83911848 WmiPrvSE.exe           2332    584      5      112      0      0 2022-12-14 21:12:23 UTC+0000                                 
0x8e1ef208 taskhost.exe           2580    452      5       86      1      0 2022-12-14 21:13:01 UTC+0000                                 
0x8382f198 7zFM.exe               2176   1464      3      135      1      0 2022-12-14 21:22:44 UTC+0000                                 
0x83c1d030 DumpIt.exe             3212   1464      2       38      1      0 2022-12-14 21:33:28 UTC+0000                                 
0x83c0a030 conhost.exe             272    368      2       34      1      0 2022-12-14 21:33:28 UTC+0000                                 
```

<br>
In the process list  `TrueCrypt.exe and 7zFM.exe` stands out Lets Investigate that! 

`cmdline`
```
┌──(root㉿kali)-[/home/kali/Desktop/challenge-files]
└─# volatility -f TrueSecrets.raw --profile=Win7SP1x86_23418 cmdline           
Volatility Foundation Volatility Framework 2.6
************************************************************************
System pid:      4
************************************************************************
smss.exe pid:    252
Command line : \SystemRoot\System32\smss.exe
************************************************************************
csrss.exe pid:    320
Command line : %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,12288,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
************************************************************************
wininit.exe pid:    356
Command line : 
************************************************************************
csrss.exe pid:    368
Command line : %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,12288,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
************************************************************************
winlogon.exe pid:    396
************************************************************************
services.exe pid:    452
Command line : C:\Windows\system32\services.exe
************************************************************************
lsass.exe pid:    468
Command line : C:\Windows\system32\lsass.exe
************************************************************************
lsm.exe pid:    476
Command line : C:\Windows\system32\lsm.exe
************************************************************************
svchost.exe pid:    584
Command line : C:\Windows\system32\svchost.exe -k DcomLaunch
************************************************************************
VBoxService.ex pid:    644
Command line : C:\Windows\System32\VBoxService.exe
************************************************************************
svchost.exe pid:    696
Command line : C:\Windows\system32\svchost.exe -k RPCSS
************************************************************************
svchost.exe pid:    752
Command line : C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted
************************************************************************
svchost.exe pid:    864
Command line : C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted
************************************************************************
svchost.exe pid:    904
Command line : C:\Windows\system32\svchost.exe -k LocalService
************************************************************************
svchost.exe pid:    928
Command line : C:\Windows\system32\svchost.exe -k netsvcs
************************************************************************
svchost.exe pid:    992
************************************************************************
svchost.exe pid:   1116
Command line : C:\Windows\system32\svchost.exe -k NetworkService
************************************************************************
spoolsv.exe pid:   1228
Command line : C:\Windows\System32\spoolsv.exe
************************************************************************
svchost.exe pid:   1268
Command line : C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork
************************************************************************
taskhost.exe pid:   1352
Command line : "taskhost.exe"
************************************************************************
dwm.exe pid:   1448
Command line : 
************************************************************************
explorer.exe pid:   1464
Command line : C:\Windows\Explorer.EXE
************************************************************************
svchost.exe pid:   1636
Command line : C:\Windows\System32\svchost.exe -k utcsvc
************************************************************************
svchost.exe pid:   1680
Command line : C:\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation
************************************************************************
wlms.exe pid:   1776
************************************************************************
VBoxTray.exe pid:   1832
Command line : "C:\Windows\System32\VBoxTray.exe" 
************************************************************************
sppsvc.exe pid:    352
************************************************************************
svchost.exe pid:   1632
************************************************************************
SearchIndexer. pid:    856
Command line : C:\Windows\system32\SearchIndexer.exe /Embedding
************************************************************************
TrueCrypt.exe pid:   2128
Command line : "C:\Program Files\TrueCrypt\TrueCrypt.exe" 
************************************************************************
svchost.exe pid:   2760
Command line : C:\Windows\System32\svchost.exe -k secsvcs
************************************************************************
WmiPrvSE.exe pid:   2332
Command line : C:\Windows\system32\wbem\wmiprvse.exe
************************************************************************
taskhost.exe pid:   2580
Command line : 
************************************************************************
7zFM.exe pid:   2176
Command line : "C:\Program Files\7-Zip\7zFM.exe" "C:\Users\IEUser\Documents\backup_development.zip"
************************************************************************
DumpIt.exe pid:   3212
Command line : "C:\Users\IEUser\Downloads\DumpIt.exe" 
************************************************************************
conhost.exe pid:    272
Command line : \??\C:\Windows\system32\conhost.exe "-180402527637560752-8319479621992226886-774806053592412399-20651748-1013740728
```

Under PID 2176 we can see that there's one intresting ZIP File called `backup_development.zip` Lets Get that into our system for further analysis 


## Memory Dump

 - As the memory dump is a zip file renmae it to `.zip` and unzip it! 
 - now the file extension is turned to `.tc`  which means truecrypt!!!

Download the TrueCrypt  -- [Click here to download](https://truecrypt.en.softonic.com/)


After doing some research on truecrypt i found a volatility argument to fetch the password! here you go 

image-goes here


## TrueCrypt Mounted Successfully

There are 4 files in-total 
one is `AgentServer.c` and other 3 encrypted files 

```C#
using  System;

using  System.IO;

using  System.Net;

using  System.Net.Sockets;

using  System.Text;

using  System.Security.Cryptography;

  

class  AgentServer  {

static  void  Main(String[]  args)

{

var  localPort  =  40001;

IPAddress  localAddress  = IPAddress.Any;

TcpListener  listener  =  new  TcpListener(localAddress, localPort);

listener.Start();

Console.WriteLine("Waiting for remote connection from remote agents (infected machines)...");

TcpClient  client  = listener.AcceptTcpClient();

Console.WriteLine("Received remote connection");

NetworkStream  cStream  = client.GetStream();

string  sessionID  = Guid.NewGuid().ToString();

while  (true)

{

string  cmd  = Console.ReadLine();

byte[]  cmdBytes  = Encoding.UTF8.GetBytes(cmd);

cStream.Write(cmdBytes,  0, cmdBytes.Length);

byte[]  buffer  =  new  byte[client.ReceiveBufferSize];

int  bytesRead  = cStream.Read(buffer,  0, client.ReceiveBufferSize);

string  cmdOut  = Encoding.ASCII.GetString(buffer,  0, bytesRead);

string  sessionFile  = sessionID +  ".log.enc";

File.AppendAllText(@"sessions\"  + sessionFile,

Encrypt(

"Cmd: "  + cmd + Environment.NewLine + cmdOut

)  + Environment.NewLine

);

}

}

private  static  string  Encrypt(string  pt)

{

string  key  =  "AKaPdSgV";

string  iv  =  "QeThWmYq";

byte[]  keyBytes  = Encoding.UTF8.GetBytes(key);

byte[]  ivBytes  = Encoding.UTF8.GetBytes(iv);

byte[]  inputBytes  = System.Text.Encoding.UTF8.GetBytes(pt);

using  (DESCryptoServiceProvider  dsp  =  new  DESCryptoServiceProvider())

{

var  mstr  =  new  MemoryStream();

var  crystr  =  new  CryptoStream(mstr, dsp.CreateEncryptor(keyBytes, ivBytes), CryptoStreamMode.Write);

crystr.Write(inputBytes,  0, inputBytes.Length);

crystr.FlushFinalBlock();

return Convert.ToBase64String(mstr.ToArray());

}

}

}
```

In the above file there's `Key` and the `iv` (Initialization Vector) 

Lets Decrypt the other 3 files through online DES Decryptors [https://devtoolcafe.com/tools/des](https://devtoolcafe.com/tools/des)

I tried to decrypt all the three files and found the flag in the `third file` 




## Flag 

### HTB{570**g_53*************************}

![](https://media.giphy.com/media/DAtJCG1t3im1G/giphy.gif)