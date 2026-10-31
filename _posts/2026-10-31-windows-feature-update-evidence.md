---
title: "The Upgrade Ate My Timeline: Windows Feature Update Forensics"
date: 2026-10-31 23:55:00 +0530
categories: [Resources, DFIR]
comments: true
pin: true
description: "What a Windows feature update resets, what survives, the four timestamp traps it sets, and DeviceMigration: a pre-upgrade device timeline nobody parses. With a paste-and-decode upgrade history tool, a PowerShell triage script, an offline hive parser, a RECmd batch file and a Velociraptor artifact."
image:
  path: /assets/images/feature-update/fu-banner.png
  alt: The upgrade ate my timeline. Windows feature update forensics
tags: [windows-forensics, feature-update, devicemigration, registry, timeline, usb-forensics, incident-response, recmd, velociraptor]
---

> **"No Prefetch before February. No USB history before February. The machine was built in February."**

All three sound like findings. On my laptop the last one is wrong by almost five years, and the first two only mean *not recorded*.

A Windows feature update is the quietest evidence killer on a fleet. It reinstalls the OS, carries some artifacts across and starts others from zero. In September, Alexandru Stamate ([AlexSta CyberSecurity](https://alexsta-cybersecurity.com/field-notes/windows-feature-update-evidence/)) published careful controlled tests of exactly this, and noted that no common tool parses one of the most useful keys it leaves behind. I took the same questions to a real machine, my own laptop with **five in-place upgrades since 2021**, and built the tooling that was missing.

> **TL;DR**
> - `InstallDate` is the **last upgrade**, not the first install. The oldest `HKLM\SYSTEM\Setup\Source OS (Updated on …)` key holds the real one.
> - After a media upgrade, Prefetch, BAM, PCA, most event logs, setupapi and the live USBSTOR / Enum tree **start at the upgrade**. Nothing before that date means *not recorded*, not *did not happen*.
> - `DeviceMigration` keeps the old OS's device list, and every disconnected device carries **`LastPresentDate`** and a readable name. On my laptop: 53 devices the live Enum no longer has, including an Android phone with ADB, last connected a month before the upgrade.
> - Four timestamp traps: `InstallDate`, reset key LastWrite times, local-vs-UTC with a gap of days, and clean files that look timestomped.
> - Paste one line into the **[Upgrade History Decoder](#decode-your-own-host)**, or grab the [kit](#the-feature-update-evidence-kit): PowerShell, an offline hive parser, RECmd and Velociraptor.
{: .prompt-tip }

## One laptop, five upgrades

![One laptop, five upgrades, one misleading InstallDate](/assets/images/feature-update/fu-timeline.svg){: w="1200" h="560" }
_The real upgrade history of my lab laptop, read from the registry_

Every in-place upgrade leaves a key under `HKLM\SYSTEM\Setup` named `Source OS (Updated on <date>)`. It holds the `CurrentVersion` values of the OS that was **replaced**. Sort them by their `InstallDate` and you have the machine's whole life.

![Exhibit 1: the Source OS keys and what they decode to](/assets/images/feature-update/fu-exhibit1-source-os.png){: w="1600" h="742" }
_Exhibit 1: five Source OS keys, one of them opened, and the decoded history_

Reading Exhibit 1:

- **Amber, the key names:** when each upgrade *began*, in local time. The 2025 and 2026 upgrades began 11 and 7 days before the new OS finished installing. Anything in that gap still ran on the old OS.
- **Blue, the values:** the old OS's build and its `InstallDate`. The last row's new `InstallDate`, 2026-02-07, is what every tool reports as "installed".
- **Green, the oldest record:** the real first install, 2021-04-09.
- **Rose, `ProductName`:** still "Windows 10" on every Windows 11 build. Trust `CurrentBuild` (22000 and up is Windows 11).
- **No key between 22H2 and 23H2:** that step was an enablement package. It left no record and didn't touch `InstallDate`. A build that moved without a new Source OS key was most likely an enablement package, and AlexSta found those rebuild nothing.

### Decode your own host

Run the one line on any host (PowerShell, Live Response, your EDR's shell), paste the output, done. It runs in your browser.

<div id="upd"></div>
<script src="/assets/js/upgrade-decoder.js"></script>

## What resets, what survives

![What resets, what survives, where to look instead](/assets/images/feature-update/fu-reset-carry.svg){: w="1200" h="600" }
_The evidence floor, and the bridges across it_

I measured what a standard user can read on the laptop, nine months after its last upgrade:

![Exhibit 3: evidence floor on the lab laptop](/assets/images/feature-update/fu-exhibit3-evidence-floor.png){: w="1600" h="775" }
_Exhibit 3: what starts on upgrade day, and what crossed it_

- **Amber rows:** Defender, Partition and Kernel-PnP logs start within minutes of the upgrade, and PCA's file was created two minutes after `InstallDate`. That is the evidence floor.
- **Blue, in the notes panel:** System and Application start later, but they are 100% full. That is rollover, not the upgrade. Check log fullness before you blame the upgrade (the script does).
- **Green rows:** UserAssist values, jump lists and LNK files crossed the February upgrade intact.

One thing I didn't expect: all three green artifacts start on 11 and 12 June 2025, the day of the **same-build repair reinstall**, not the feature update. One laptop isn't proof, but a "repair" reinstall may cut deeper than a feature update. Check yours.
{: .prompt-info }

## DeviceMigration: a device timeline nobody parses

![DeviceMigration: the device history Setup keeps](/assets/images/feature-update/fu-devicemigration.svg){: w="1200" h="560" }
_Setup snapshots the old OS's device database before it rebuilds Enum_

During the upgrade, Setup copies the old OS's Plug and Play database into `DeviceMigration`. It sits in two places:

| Location | Who can read it live |
| --- | --- |
| `HKLM\SYSTEM\Setup\Upgrade\PnP\CurrentControlSet\Control\DeviceMigration` | any user |
| `HKLM\SYSTEM\ControlSet00N\Control\DeviceMigration` | SYSTEM only (empty to a normal user) |

![Exhibit 2: DeviceMigration record for a disconnected phone](/assets/images/feature-update/fu-exhibit2-devicemigration.png){: w="1600" h="867" }
_Exhibit 2: one phone the new OS never saw, and the timeline the snapshot gives you_

Reading Exhibit 2:

- **`Present` = 0 (rose):** the device was not connected when the snapshot was taken.
- **`LastPresentDate` (amber):** a FILETIME, when that device was last connected. Every one of the 26 disconnected devices on my laptop had one.
- **`BusDeviceDesc` (blue):** the device's own name, here with its serial number. The phone's second interface reads `ADB Interface`: USB debugging was on.
- **53 instances exist only in the snapshot.** The rebuilt Enum tree has no trace of them: a Bluetooth headset, a webcam, the phone, an iPhone's MTP interface.

AlexSta found USB storage in DeviceMigration that the live USBSTOR key had lost. My laptop never had a USB drive, but phones, an iPhone, a webcam and Bluetooth audio came through, with names and last-connected times. In a data-theft case, that is exactly the pre-upgrade history the rebuilt USBSTOR can't give you.

## Four timestamp traps

![Four timestamp traps a feature update sets](/assets/images/feature-update/fu-traps.svg){: w="1200" h="600" }
_Write these at the top of the timeline before anyone reads it_

Trap 2 surprised me most: the last upgrade rewrote **every** Source OS key, so all five share one LastWrite time, 2026-02-08 01:07Z. The names and values keep the history; the key times don't.

## The Feature Update Evidence Kit

| File | What it does |
| --- | --- |
| [Get-UpgradeEvidence.ps1](/assets/files/feature-update/Get-UpgradeEvidence.ps1) | Live triage in seconds: upgrade history, evidence floor per artifact (with log fullness), DeviceMigration diffed against Enum with `LastPresentDate`, Windows.old, the old app list. CSVs out. Run elevated for Prefetch, BAM, SRUM and the Security log |
| [upgrade_hive.py](/assets/files/feature-update/upgrade_hive.py) | Offline: reads raw SYSTEM and SOFTWARE hives (its own regf parser, stdlib only). Upgrade history, both DeviceMigration copies, `OnlyInSnapshot`, `LastPresentDate`, vendors, the old OS's apps |
| [FeatureUpdateEvidence.reb](/assets/files/feature-update/FeatureUpdateEvidence.reb) | RECmd batch file: Source OS keys, DeviceMigration (both copies, `LastPresentDate` as FILETIME), `InstallDate` |
| [Custom.Windows.Registry.FeatureUpdateEvidence.yaml](/assets/files/feature-update/Custom.Windows.Registry.FeatureUpdateEvidence.yaml) | Velociraptor artifact: the same, across the fleet, with live-Enum lookups |

```powershell
powershell -ExecutionPolicy Bypass -File .\Get-UpgradeEvidence.ps1
```

```bash
python3 upgrade_hive.py SYSTEM --software SOFTWARE -o upgrade_evidence/
RECmd.exe -f SYSTEM --bn FeatureUpdateEvidence.reb --csv out
```

> Tested in the lab: the PowerShell script on the laptop above, and `upgrade_hive.py` on hives written by Windows' own Offline Registry Library from the same keys (a standard user can't `reg save`). Both produced the numbers in this post. The RECmd batch file and the Velociraptor artifact validate as YAML but haven't been run in those tools yet; tell me in the comments if either misbehaves.
{: .prompt-info }

## Response checklist

1. **Decode the upgrade history first.** Write the evidence floor (the last `InstallDate`) at the top of the timeline.
2. **Upgrade younger than 10 days?** Image `C:\Windows.old`, `C:\$WINDOWS.~BT` and `C:\Windows\Panther` now. Windows deletes them when the rollback window closes (`DISM /Online /Get-OSUninstallWindow`, 10 days by default).
3. **Pull DeviceMigration** (both copies), diff it with `Enum`, and add every `LastPresentDate` to the device timeline.
4. **Before the floor, pivot** to what carries over: jump lists, LNK, browser history, SRUM, UserAssist values, NetworkList.
5. **Don't read absence as innocence** before the floor, and don't call `$SI ≠ $FN` on system files timestomping until you've ruled out install-image files.
6. **Name the upgrade kind** in your report: feature update, same-build repair, or enablement package. They wipe different things.

## References

- Alexandru Stamate, AlexSta CyberSecurity: [What a Windows feature update does to forensic evidence](https://alexsta-cybersecurity.com/field-notes/windows-feature-update-evidence/) (the controlled tests this post builds on)
- Microsoft: [DISM operating system uninstall command-line options](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-operating-system-uninstall-command-line-options) · [Offline Registry Library](https://learn.microsoft.com/en-us/windows/win32/devnotes/offline-registry-library-portal)
- Eric Zimmerman: [RECmd](https://github.com/EricZimmerman/RECmd) · [Velociraptor docs](https://docs.velociraptor.app/)
- On this blog: [the PCA artifact](/posts/pca-artifact/) · [Amcache](/posts/amcache/) · [Inside the registry](/posts/inside-the-registry/)

---

![](https://media.giphy.com/media/DAtJCG1t3im1G/giphy.gif)
