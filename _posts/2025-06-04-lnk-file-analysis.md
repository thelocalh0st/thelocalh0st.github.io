---
title: <img width="50" height="50" src="/assets/images/lnk.png">LNK File Forensics — Experimental Case Study
date: 2025-04-06 00:00:02 +730
categories: [Resources, DFIR]
comments: true
tags: [windows-forensics, artifacts, lnk, linkfileanalysis] # TAG names should always be lowercase


---
![](/assets/images/lnk.png)

## 🔍 Objective

To analyze and demystify the subtle, less-documented behaviors of `.LNK` (Windows Shortcut) files during document creation, modification, and reopening using real-time forensic testing.
 

## 📑 Scenario Summary

### 🧾 Document Timeline

|Timestamp|Action Description|
|--|--|
|07:18:40 PM|Right-click ➝ New ➝ Excel document created
|07:19:57 PM|File creation timestamp in metadata
|07:20 PM|Document opened for the first time
|07:31 PM|Data written ➝ File saved ➝ Closed (1.41 MB)
|08:02 PM|Document opened again (2nd time)
|08:06 PM|Redacted ➝ Saved ➝ Closed (10 KB)

----------

## 📂 LNK Analysis Phase-wise Comparison

### 🔹 Phase 1 – After First Open & Save

| Attribute           | Value                                 |
|---------------------|----------------------------------------|
| **Source Created**  | 07-Jun-25 07:31:12 PM                  |
| **Source Modified** | 07-Jun-25 07:20:18 PM                  |
| **Source Accessed** | 07-Jun-25 07:47:43 PM                  |
| **Target Created**  | 07-Jun-25 07:19:57 PM                  |
| **Target Modified** | 07-Jun-25 07:19:57 PM                  |
| **Target Accessed** | 07-Jun-25 07:20:17 PM                  |
| **LNK File Size**   | 6,192 bytes (approx. 6 KB)             |
| **Target File Size**| Not reflected post edit (remains ~6 KB)|

![](/assets/images/1.png)<br><br>

### 🔹 Phase 2 – After Reopening & Redaction

| Attribute            | Value                                 |
|----------------------|----------------------------------------|
| **Source Created**   | 07-Jun-25 08:03:09 PM                  |
| **Source Modified**  | 07-Jun-25 08:02:03 PM                  |
| **Source Accessed**  | 07-Jun-25 08:03:32 PM                  |
| **Target Created**   | 07-Jun-25 07:19:57 PM                  |
| **Target Modified**  | 07-Jun-25 07:31:39 PM                  |
| **Target Accessed**  | 07-Jun-25 08:02:03 PM                  |
| **LNK File Size**    | 1,484,420 bytes (~1.41 MB)             |
| **Redacted File Size**| 10 KB (not reflected as LNK wasn’t updated)|

![](/assets/images/2.png)<br><br>

> ⚠️ **Note:** After redacting and saving the document at 08:06 PM, if the document was _not reopened_, the final size (10 KB) **was not reflected in the LNK file**. The `.LNK` file holds the **last known size during the last access**, meaning: **if you don't open it post-edit, it doesn't get updated**.

----------

## 🧠 Forensic Gems (Uncommon Insights)

-   **LNK files aren’t updated on file system changes alone** — Opening the file is the trigger.
    
-   **`Source Modified` < `Source Created`?** Yes, that’s possible. LNK files copy attributes from the target file — so a modified timestamp from the target can predate the shortcut file's own creation.
    
-   **File size discrepancy**: The `.LNK` snapshot of file size only updates when the file is opened. Merely modifying (like redaction) doesn’t affect the shortcut's stored size unless reopened.
    
-   **LNK's `Tracker Database Block`** offers MAC address and machine ID insights — very helpful in multi-user/endpoint environments.
    

----------

## ✅ Key Takeaways

-   `.LNK` files are **not passive bystanders** — they capture valuable forensic evidence such as access timestamps, file sizes, paths, and user activity.
    
-   Always **correlate LNK artifacts with $MFT, USN Journal, and prefetch** to build a conclusive timeline.
    
-   Unusual behaviors, like the delayed file size updates, **can be pivotal in investigations** — especially in proving redaction, tampering, or staged file manipulation.
    

----------

## 🔬 Call to Action

Conduct your own variations of this test:

-   Move the document to a different folder and reopen.
    
-   Copy the document to a pen drive and open from another machine.
    
-   Open using third-party viewers (like LibreOffice).
    

Log what changes in the `.LNK` files — and what doesn't.

Let’s keep pushing the edges of what’s known in Windows forensics.

![](https://media.giphy.com/media/DAtJCG1t3im1G/giphy.gif)
