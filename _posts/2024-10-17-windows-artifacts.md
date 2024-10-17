---
title: <img width="50" height="50" alt="front-page port 80-shoopyu" src="https://github.com/user-attachments/assets/d424c2cf-c85b-4f9a-ade6-fdb7b71f65a0">Windows Artifacts
date: 2020-10-18 00:00:02 +730
categories: [Resources, DFIR]
comments: true
tags: [windows-forensics, artifacts] # TAG names should always be lowercase


---
System and User Information
(via Registry)

| Artifact | Filesystem Location | Tools or Commands | Operating System Version |
| --- | --- | --- | --- |
| System Information | SOFTWARE\Microsoft\Windows NT\CurrentVersion | Registry Explorer |  |
| Computer Name | SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName | Registry Explorer |  |
| System Last Shutdown Time | SYSTEM\CurrentControlSet\Control\Windows | Registry Explorer |  |
| Cloud Account Details | SAM\Domains\Account\Users\<RID>\InternetUserName | Registry Explorer |  |
| User Accounts | SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList | Registry Explorer |  |
| Last Login and Password Change | SAM\Domains\Account\Users | Registry Explorer |  |

Application Execution
**

| Artifact | Filesystem Location | Tools or Commands |
| --- | --- | --- |
| Shimcache | SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache | RegRipper |
| Amcache.hve | C:\Windows\AppCompat\Programs\Amcache.hve | Registry Explorer |
| UserAssist | NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\ | Registry Explorer |
| Win10 Timeline | C:\%USERPROFILE%\AppData\Local\ConnectedDevicesPlatform\L.Administrator\ActivitiesCache.db | WxTCmd.exe |
| SRUM | C:\Windows\System32\sru\SRUDB.dat | srum-dump |
| BAM / DAM | SYSTEM\ControlSet001\Services\bam\State\UserSettings\ | Registry Explorer |
| Prefetch, MFT, USNJ | C:\Windows\prefetch | PECmd.exe |

File and Folder Opening
**

| Artifact | Filesystem Location | Tools or Commands |
| --- | --- | --- |
| Shellbag | NTUSER.dat\Software\Microsoft\Windows\Shell\Bags | Shellbags Explorer |
| Open/Save MRU | NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMRU | Registry Explorer |
| Shortcut (LNK) Files | %USERPROFILE%\AppData\Roaming\Microsoft\Windows|Office\Recent\ | Autopsy |
| Jumplist | C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations | Jumplist Explorer |

Deleted Items and File Existence
**

| Artifact | Filesystem Location | Tools or Commands |
| --- | --- | --- |
| Recycle Bin | C:\$Recycle.Bin | Recbin |
| Thumbcache | %USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer | Thumbcache Viewer |
| User Typed Paths | NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths | Registry Explorer |

Browser Activity
**

| Artifact | Filesystem Location | Tools or Commands |
| --- | --- | --- |
| Browser activity | C:\Users\%user%\AppData\Local\\Roaming\BrowserName | DBBrowser |

Network Usage
**

| Artifact | Filesystem Location | Tools or Commands |
| --- | --- | --- |
| Network History | SOFTWARE\Microsoft\Windows NT\CurrentVersion\Network* | Registry Explorer |
| Timezone | SYSTEM\CurrentControlSet\Control\TimeZoneInformation | Registry Explorer |
| WLAN Event Log | Microsoft-Windows-WLAN-AutoConfig Operational.evtx | Event log viewer |

USB Usage
**

| Artifact | Filesystem Location | Tools or Commands |
| --- | --- | --- |
| USB Device Identification | SYSTEM\CurrentControlSet\Enum\* | Registry Explorer |
| Drive Letter and Volume Name | SOFTWARE\Microsoft\Windows Portable Devices\Devices and SYSTEM\MountedDevices | Registry Explorer |

AntiVirus Logs
**

| AntiVirus | Filesystem Location |
| --- | --- |
| Avast | C:\ProgramData\Avast Software\ |
| AVG | C:\ProgramData\AVG\Antivirus\ |
| Avira | C:\ProgramData\Avira\Antivirus\LOGFILES\ |
| Bitdefender | C:\Program Files*\Bitdefender*\ |



## Other Artifacts

| Artifact | Filesystem Location | Tools or Commands |
| --- | --- | --- |
| Startup folder (user) | C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup | Autopsy |
| Shadow copy |  | Shadow Explorer |
| Hiberfil.sys | C:\ | Hibernation Recon |
| Pagefile.sys | C:\ | strings, Unalloc |
| Anydesk | C:\Users\%user%\AppData\Roaming\AnyDesk\* or C:\ProgramData\AnyDesk\* | Autopsy |
| WMI persistence | C:\WINDOWS\system32\wbem\Repository\OBJECTS.DATA | WMI_Forensics |
| RDP Cache | C:\%USERPROFILE%\AppData/Local/Microsoft/Terminal Server Client/Cache | BMC-Tools |
