---
title: <img width="50" height="50" alt="front-page port 80-shoopyu" src="/assets/images/linuxforensics.jpg">Linux Forensics Essentials
date: 2025-01-11 00:00:02 +730
categories: [Resources, DFIR]
comments: true
# pin: true
tags: [linuxforensics, artifacts, dfir] # TAG names should always be lowercase


---
![](/assets/images/linuxforensics.jpg)



**Commands and Artifacts Every Investigator Needs**

Here’s a streamlined guide to key Linux artifacts and the commands to extract and analyze them efficiently, enabling forensics investigators to focus on what matters.

### **1. User Account/Data**

Investigators need to understand the users on the system and any potential modifications to their accounts. Here are the key files and directories:

-   **User Directories:**  
    Command to list user directories:
    
    ```bash
    ls /home/
    
    ```
    
    Investigate individual user directories for suspicious activity:
    
    ```bash
    ls -la /home/%username%/
    
    ```
    
-   **User Information:**  
    To see user account details:
    
    ```bash
    cat /etc/passwd  
    cat /etc/shadow  
    cat /etc/sudoers  
    cat /etc/group  
    
    ```
    
    Look for unauthorized users, changes to sudo privileges, or strange accounts.
    

### **2. Web Browsing Activity**

Web browsing activity often leaves traces of user actions, especially on browsers like Chrome, Firefox, and Opera. Check these locations:

-   **Google Chrome:**
    
    ```bash
    ls -la /home/%username%/.config/google-chrome/
    
    ```
    
-   **Mozilla Firefox:**
    
    ```bash
    ls -la /home/%username%/.mozilla/Firefox/
    
    ```
    
-   **Opera:**
    
    ```bash
    ls -la /home/%username%/.config/Opera/
    
    ```
    
-   **Cache files:**
    
    ```bash
    ls -la /home/%username%/.cache/
    
    ```
    

Look for evidence of recent visits, cached credentials, or data exfiltration attempts.

### **3. Startup Items**

To identify persistent malware or unauthorized services that launch at startup, inspect these directories:

-   **Systemd services:**
    
    ```bash
    ls -la /etc/systemd/system/  
    ls -la /usr/lib/systemd/system/
    
    ```
    
-   **Init scripts (Older systems):**
    
    ```bash
    ls -la /etc/init*
    
    ```
    

### **4. Scheduled Tasks**

Scheduled tasks, including cron jobs, can maintain persistence or automate malicious activity. Check these locations:

-   **Cron Jobs:**
    
    ```bash
    ls -la /etc/cron*
    ls -la /var/spool/crontabs
    
    ```
    
-   **At Jobs:**
    
    ```bash
    ls -la /var/spool/atjobs
    
    ```
    
-   **Anacron Jobs:**
    
    ```bash
    ls -la /etc/anacron
    
    ```
    

Review the files for any unusual tasks or scripts set to execute at scheduled intervals.

### **5. System & Application Logs**

Logs can provide a wealth of evidence regarding system activities. Focus on these locations:

-   **System logs (Syslog, Auth Logs, etc.):**
    
    ```bash
    cat /var/log/syslog  
    cat /var/log/auth.log  
    cat /var/log/messages  
    cat /var/log/secure  
    
    ```
    
-   **Application logs (e.g., service-specific logs):**
    
    ```bash
    ls -la /var/log/
    
    ```
    

Look for unusual login attempts, failed service starts, or entries suggesting system tampering.

### **6. System Files**

System configuration files often hold clues to system changes, especially after an attack.

-   **OS Version and Hostname:**
    
    ```bash
    cat /etc/*-release  
    cat /etc/hostname  
    
    ```
    
-   **Hosts File:**
    
    ```bash
    cat /etc/hosts
    
    ```
    
-   **Network Configuration Files:**
    
    ```bash
    ls -la /var/lib/networkmanager/
    cat /var/lib/dhclient*
    cat /var/lib/dhcp*
    
    ```
    

These files can reveal unauthorized changes to network settings, or indicators of malicious configuration.

### **7. Bash History**

The **.bash_history** file is invaluable for tracing a user’s command-line activities.

-   **Bash History:**
    
    ```bash
    cat /home/%username%/.bash_history
    
    ```
    

Look for suspicious commands like `curl`, `wget`, or any commands related to malware installation or system manipulation. Keep in mind that this file can be cleared or altered, but artifacts can sometimes remain in other places (like `wtmp`, `utmp`).

### **8. Trash**

Sometimes deleted files end up in the Trash, which can provide valuable evidence if the attacker hasn’t permanently deleted them.

-   **Trash location:**
    
    ```bash
    ls -la /home/%username%/.local/share/Trash/
    
    ```
    

### **9. Recent Files**

**Recent files** may point to data that was recently accessed or manipulated by an attacker.

-   **Recent files:**
    
    ```bash
    cat /home/%username%/.local/share/recently-used.xbel
    
    ```
    

This file can reveal the most recently opened files and documents, possibly showing patterns of suspicious behavior.

### **10. SSH Files**

Investigating **SSH-related files** can reveal unauthorized remote access or attempts to establish persistent remote access.

-   **Authorized keys (for key-based login):**
    
    ```bash
    ls -la /home/%username%/.ssh/authorized_keys
    
    ```
    
-   **SSH known hosts (possible evidence of remote connections):**
    
    ```bash
    ls -la /home/%username%/.ssh/known_hosts
    
    ```
    
-   **SSH config and private keys:**
    
    ```bash
    ls -la /home/%username%/.ssh/config
    ls -la /home/%username%/.ssh/id_rsa
    
    ```
    

Check for signs of unauthorized key pairs or unexpected entries indicating compromised access.

----------


### **Conclusion**

Linux forensics can be daunting due to the variety of artifacts and potential for attackers to cover their tracks. However, focusing on key system and user artifacts like **bash history**, **SSH files**, **system logs**, and **scheduled tasks** is critical. By leveraging tools like **Magnet Axiom**, you can automate the process of collecting, analyzing, and correlating evidence from multiple sources.

Focusing on these key Linux artifacts and using the right forensic tools will allow you to efficiently uncover the truth, whether you're responding to a cyberattack, investigating insider threats, or conducting routine security audits.


![](https://media.giphy.com/media/DAtJCG1t3im1G/giphy.gif)
