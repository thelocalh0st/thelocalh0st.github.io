---
title: <img width="50" height="50" alt="front-page port 80-shoopyu" src="https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/a862b8fe-2adb-4176-a222-6a20cbe4ef2c">Investigating Windows | Tryhackme
date: 2023-06-20 00:00:02 +730
categories: [Write Up, TryHackMe]
comments: true
tags: [blueteam, forensics, tryhackme, windows] # TAG names should always be lowercase


---

![banner](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/a862b8fe-2adb-4176-a222-6a20cbe4ef2c)
<br><br><br>

This is a challenge that is exactly what is says on the tin, there are a few challenges around investigating a windows machine that has been previously compromised.

Connect to the machine using RDP. The credentials the machine are as follows:

`Username`: `Administrator`  
`Password:`:`letmein123!`

Please note that this machine does not respond to ping (ICMP) and may take a few minutes to boot up.



>1.What is the version and year of  windows machine?
{: .prompt-info }
![1](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/9e0cf089-f0a0-4b63-94e9-8de71aa91c47)

<br>

```Answer
Windows server 2016
```
<br><br>

>2.Which user logged in last?
{: .prompt-info }
<br>

```Answer
administrator
```
<br><br>

>3.When did john log onto system last?
{: .prompt-info }
![3](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/2cef5068-1afe-4144-b57a-3608a30df868)

<br>

```Answer
03/02/2019 5:48:32 PM
```
<br><br>


>4.What IP does the system connect to when it first starts?
{: .prompt-info }
![4](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/c1042a54-b025-42e8-8784-fdc658d029fa)

<br><br>

```Answer
10.34.2.3
```
<br><br>


>5.What two accounts had administrative privileges (other than the Administrator user)?
{: .prompt-info }

![5](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/02e960b2-cd8f-4acd-a12c-b2e86ec53638)
<br><br>
Answer format: username1, username2

Open run command using Ctrl+R and type `lusrmgr.msc`
```Answer
Jenny, Guest
```
<br><br>


>6.Whats the name of the scheduled task that is malicous.
{: .prompt-info }
<br>

```Answer
Clean file system
```
<br><br>


>7.What file was the task trying to run daily?
{: .prompt-info }
<br>
![7](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/30985fd6-7ba8-4c27-9721-c2689a0bc6c1)

```Answer
nc.ps1
```
<br><br>


>8.What port did this file listen locally for?
{: .prompt-info }
<br>
![8](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/93901b82-98d7-479e-bb9d-869c78881814)

```Answer
1348
```
<br><br>

>9.When did Jenny last logon?
{: .prompt-info }
<br>


```Answer
never
```
<br><br>

>10 .At what date did the compromise take place?
{: .prompt-info }
<br>


```Answer
03/02/2019
```
<br><br>

>11 .At what time did Windows first assign special privileges to a new logon?
{: .prompt-info }
![11](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/2d4848c8-2bad-48a8-8d12-7b2abd346165)

<br>


```Answer
03/02/2019 4:04:49 PM
```
<br><br>

>12 .What tool was used to get Windows passwords?
{: .prompt-info }

<br>


```Answer
Mimikatz
```
<br><br>

>13 .What was the attackers external control and command servers IP?
{: .prompt-info }
![13](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/8228ed5b-ad0f-4e07-9420-85100aa0e6c3)

<br>


```Answer
76.32.97.132
```
<br><br>

>14 .What was the extension name of the shell uploaded via the servers website?
{: .prompt-info }
<br>


```Answer
.jsp
```
<br><br>

>15 .What was the last port the attacker opened?
{: .prompt-info }
![15](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/125783410/3d6b0e8f-a755-49a8-8f65-08afe37fd902)


<br>


```Answer
1337
```
<br><br>

>16 .Check for DNS poisoning, what site was targeted?
{: .prompt-info }
<br>


```Answer
google.com
```
<br><br>
