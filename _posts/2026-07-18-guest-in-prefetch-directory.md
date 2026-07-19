---
title: Prefetch Alternate Data Stream How Malware Hides Execution
date: 2026-07-18 00:00:02 +0530
categories: [Resources, DFIR]
comments: true
pin: true
mermaid: true
image:
  path: /assets/images/prefetch.png
  alt: prefetch in ads
tags: [prefetch,ads,hidden-prefetch,execution-artifact]
---
![](/assets/images/prefetch.png)

# Guest in C:\Windows\Prefetch:

Ever opened `C:\Windows\Prefetch` and seen a file that **wasn't** a `.pf`?

A `.txt`. A `.png`. Something with zero business being in a folder that only ever holds `.pf` files, `Layout.ini`, and `ReadyBoot`.

If not yet — you will. Here's what it means when it happens.

## The Alert

My colleague **Mihir** was working a case where EDR fired on a process-creation event. Nothing subtle about the telemetry — it was all right there:

```
Event ID:     1 (Process Create)
Image:        C:\Users\username\Pictures\Screenshot 2026-06-22 002415.png:malware.exe
CommandLine:  "C:\Users\username\Pictures\Screenshot 2026-06-22 002415.png:malware.exe"
ParentImage:  C:\Windows\System32\wbem\WMIC.exe

```

That colon in the `Image` field is the giveaway: `malware.exe` never existed as a standalone file. It was executed straight out of an **Alternate Data Stream (ADS)** hidden on a screenshot — a real, documented Windows tradecraft technique, catalogued as [MITRE ATT&CK T1564.004](https://attack.mitre.org/techniques/T1564/004/), and one seen in the wild from groups like APT32 and malware families like Valak and WastedLocker.

So far, not a mystery — EDR told him exactly what ran and how.

## What the ADS Actually Looked Like

NTFS lets any file carry more than one stream. What you see is the default stream. A second, named stream can ride along invisibly:

```
Screenshot 2026-06-22 002415.png          ← what Explorer shows you (a normal image)
Screenshot 2026-06-22 002415.png:svc.exe  ← the payload, riding in a hidden stream

```

Size in Explorer doesn't change. Hash of the visible file doesn't change. `dir` shows nothing unusual. That's the entire point of the technique.

## Going to Prefetch to Corroborate

EDR gives you _what ran_. Prefetch gives you _run count, timestamps, and what it touched_ — useful even when EDR retention doesn't go back far enough, or you need a second independent source for the timeline.

Expected :

```
C:\Windows\Prefetch\
├── CHROME.EXE-1A2B3C4D.pf
├── EXPLORER.EXE-9F8E7D6C.pf
├── SVC.EXE-3F2A9C10.pf                    ← expected
├── Layout.ini

```

He got this:

```
C:\Windows\Prefetch\
├── CHROME.EXE-1A2B3C4D.pf
├── EXPLORER.EXE-9F8E7D6C.pf
├── Screenshot 2026-06-22 002415.png       ← 0 bytes. Shouldn't be here at all.
├── Layout.ini

```

No `MALWARE.EXE-*.pf` anywhere. Instead, the original screenshot filename — sitting inside the one Windows folder that's supposed to be off-limits to anything but the Prefetcher itself.

## Where the .pf Actually Went

Standard move for a suspicious file: check it for hidden streams.

```powershell
Get-Item -Path "C:\Windows\Prefetch\Screenshot 2026-06-22 002415.png" -Stream * |
  Where-Object Stream -ne ':$DATA'

```

```
FileName : C:\Windows\Prefetch\Screenshot 2026-06-22 002415.png
Stream   : SVC.EXE-3F2A9C10.pf
Length   : 32768

```

**The Prefetch entry was never missing.** It was hiding inside a stream on a placeholder file that had taken the screenshot's name.

This exact behavior was first documented publicly in 2019 by researcher Ali Hadi ([binary-zone.com](https://www.binary-zone.com/2019/05/26/creating-a-hidden-prefetch-file-to-bypass-normal-forensic-analysis/)), who hid binaries in the ADS of `.txt` files and saw the identical pattern: the real `.pf` ends up as a stream on a file carrying the _original container's name_. This case is the same mechanism, just a `.png` instead of a `.txt`.

## Why This Happens

Prefetch filenames follow one rule: `<EXECUTABLE NAME>-<HASH>.pf`, built from the image path the process launched with.

```
CreateProcess() launched with:
  ...\Screenshot 2026-06-22 002415.png:svc.exe
            │
            ▼
Prefetcher builds an output name from that full string:
  Screenshot 2026-06-22 002415.png:SVC.EXE-3F2A9C10.pf
            │
            ▼
NTFS reads that colon as a stream delimiter — not a literal character
            │
            ▼
Result: a placeholder base file "Screenshot....png"
        + a hidden stream "SVC.EXE-3F2A9C10.pf" (the real Prefetch trace)

```

No documented Microsoft source confirms this internal step — this is the most consistent explanation from repeated hands-on testing, not a confirmed API contract. But the pattern is exact and reproducible: it's Windows' own naming logic tripping over the same colon that made the ADS execution possible in the first place. The attacker doesn't need to engineer this — they get it for free.

## Extracting and Parsing It

Standard Prefetch parsers (PECmd, WinPrefetchView) scan by `.pf` extension and won't resolve a `base:stream` path directly. Pull the stream to a flat file first:

```powershell
Copy-Item -Path "C:\Windows\Prefetch\Screenshot 2026-06-22 002415.png:SVC.EXE-3F2A9C10.pf" `
          -Destination "C:\Analysis\SVC.EXE-3F2A9C10.pf"

```

```cmd
:: cmd.exe equivalent
copy /b "C:\Windows\Prefetch\Screenshot 2026-06-22 002415.png:SVC.EXE-3F2A9C10.pf" C:\Analysis\SVC.EXE-3F2A9C10.pf

```

Then parse it normally:

```
PECmd.exe -f "C:\Analysis\SVC.EXE-3F2A9C10.pf"

```

You now get run count, last-run timestamps, and the "resources loaded" list — same as any other Prefetch file, once it's out of the stream.


## Hunting Checklist

-   Flag anything in `C:\Windows\Prefetch` that isn't `.pf`, `Layout.ini`, or `ReadyBoot` — especially 0-byte entries.
-   Sweep the folder for hidden streams:
    
    ```powershell
    Get-ChildItem "C:\Windows\Prefetch" -Force |  ForEach-Object { Get-Item -Path $_.FullName -Stream * -ErrorAction SilentlyContinue } |  Where-Object Stream -ne ':$DATA'
    
    ```
    
-   Enable **Sysmon Event ID 15** (FileCreateStreamHash) — the cleanest signal for ADS creation, anywhere on disk.
-   Alert on a second colon in a process `Image`/`CommandLine` field — a legitimate exe path never has one.
-   If EDR/Amcache says something ran but your Prefetch parser shows nothing for it, that mismatch _is_ the finding — don't conclude "Prefetch wasn't available" without checking for a stream first.
-   Confirm your collection tooling actually preserves NTFS streams (KAPE, FTK Imager, full images: yes; many ad-hoc "grab this folder" scripts and non-NTFS destinations: often no).


## Key Takeaways

-   A missing `.pf` for a binary you know ran isn't proof Prefetch has no record — it may mean the record was renamed out from under you.
-   Any non-`.pf` file in `C:\Windows\Prefetch` is an immediate anomaly. Check it for streams before dismissing it.
-   ADS execution (T1564.004) is real-world tradecraft. Its side effect on Prefetch naming is a bonus the attacker likely didn't plan for.
-   Extract the stream to a flat file before parsing — PECmd won't read a `base:stream` path directly.
-   Corroborate with Amcache, ShimCache, Sysmon 15, and the MFT/USN Journal. One artifact is a fact; four is a timeline.

## Sources

-   [MITRE ATT&CK T1564.004 — NTFS File Attributes](https://attack.mitre.org/techniques/T1564/004/)
-   [Ali Hadi — Creating a Hidden Prefetch File to Bypass Normal Forensic Analysis](https://www.binary-zone.com/2019/05/26/creating-a-hidden-prefetch-file-to-bypass-normal-forensic-analysis/)
-   [TrustedSec — Prefetch: The Little Snitch That Tells on You](https://trustedsec.com/blog/prefetch-the-little-snitch-that-tells-on-you)
-   [MITRE CAR-2020-08-001 — NTFS ADS Execution](https://car.mitre.org/analytics/CAR-2020-08-001/)


---

![](https://media.giphy.com/media/DAtJCG1t3im1G/giphy.gif)
