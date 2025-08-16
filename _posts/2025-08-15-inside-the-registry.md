---
title: <img width="50" height="50" src="/assets/images/HKLM.png"> Inside The Registry
date: 2025-08-10 00:00:02 +730
categories: [Resources, DFIR]
comments: true
pin: true
mermaid: true
tags: [windows-forensics, artifacts, registry,HKCR,HKLM,HKU,HKCC, forensics,] # TAG names should always be lowercase
---
# What are these HKCR, HKCU, HKLM 💭

<img width="1536" height="1024" alt="registry1" src="https://github.com/user-attachments/assets/f0c5cc15-f094-462a-b598-6e1b6b270860" />
<br><br>
The Windows Registry is the foundation of evidence in many digital investigations. Understanding the differences among its root hives—**HKCR**, **HKCU**, **HKLM**, **HKU**, and **HKCC**—is vital for any forensic analyst searching for artifacts. This guide offers a clear breakdown, focusing on what digital evidence each hive might contain and where to look.


#  HKEY_CLASSES_ROOT (HKCR)

### HKCR controls `file extensions` and `application associations`. If you want evidence on what program opened .docx files, or which handler processed URLs, start here.

-   **Artifacts:** File association traces, COM object history
    
-   **Example:** Investigating malware that hijacks .pdf files to execute malicious code instead of opening with Adobe Reader
	- `HKEY_CLASSES_ROOT\.pdf\(Default)`    
	- This shows which program identifier handles .pdf files. Follow the trail to:


# HKEY_CURRENT_USER (HKCU)

### HKCU is the goldmine for `current user’s settin`. It includes user preferences, run history, MRU (Most Recently Used) lists, and many more.

-   **Artifacts:** User startup programs, typed URLs, application history, recentdocs, RunMRU, USB Mountpoints etc
    
-   **Example:** Tracks recently accessed documents by extension type.
	- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
	- Shows a user opened projectX.docx before copying it to a USB drive.
    

# HKEY_LOCAL_MACHINE (HKLM)

### HKLM holds `system-wide settings` including installed applications, services, hardware configuration, and driver data.

-   **Artifacts:** Software installations, system services, device drivers
    
-   **Example:** Correlating unauthorized software installations on a system
	- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
	- Complete list of installed programs with installation dates, versions, and uninstall commands. Each subkey represents one installed application
    

## HKEY_USERS (HKU)

### HKU contains a registry structure for **all users**. Each SID key relates to a user profile (including system accounts).

-   **Artifacts:** User-specific settings for all users on the system
    
-   **Example:** Discovering unauthorized software installations
	- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
	- Complete list of installed programs with installation dates, versions, and uninstall commands. Each subkey represents one installed application

    

## HKEY_CURRENT_CONFIG (HKCC)

HKCC refers to the **current hardware profile** in use. It’s less relevant to most forensic investigations but can still reveal hardware changes.

-   **Artifacts:** Current display and printer settings, active hardware profile information
    
-   **Example:** Checking for evidence of hardware manipulation or configuration 
	- Stores details of connected monitors.
	- `HKEY_CURRENT_CONFIG\System\CurrentControlSet\Enum\DISPLAY`
    

----------

## Where to Hunt for Evidence

-   **User activity:** HKCU, HKU (per-profile history, MRUs, recent files)
    
-   **System changes:** HKLM (software installs, service creations)
    
-   **File handling:** HKCR (file type associations, protocol handlers)
    
-   **Hardware events:** HKCC (profile and device changes)
    

----------

## Pictorial Representation
![](/assets/images/insidetheregistry.png)

----------

Knowing where evidence lives in the Registry is half the battle. Each hive offers unique digital traces—target your search accordingly for fast, thorough forensic results.


---

![](https://media.giphy.com/media/DAtJCG1t3im1G/giphy.gif)
