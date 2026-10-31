#Requires -Version 5.1
<#
.SYNOPSIS
    Feature-update triage: when was this Windows upgraded, which artifacts start at the
    upgrade, and which devices survive only in DeviceMigration.

.DESCRIPTION
    1. Upgrade history from HKLM\SYSTEM\Setup\Source OS (Updated on ...) keys: every
       previous OS build, its install date, and when the upgrade to the next one began.
    2. Evidence floor: the oldest record in each common artifact, compared with the last
       upgrade. "Starts at upgrade" means: no evidence before that date, which is not the
       same as "nothing happened" before it.
    3. DeviceMigration: the PnP snapshot Setup takes of the old OS, diffed with the live
       Enum tree. Devices only in the snapshot were connected before the upgrade.
    4. Windows.old, $WINDOWS.~BT and the pre-upgrade app list (Setup\Upgrade\Appx).

    Read-only. Run elevated for Prefetch, Amcache, PCA, SRUM, BAM and the Security log;
    without elevation those rows say so instead of guessing.

.PARAMETER OutDir
    Where the CSVs go. Default: .\UpgradeEvidence_<HOST>_<UTC>

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-UpgradeEvidence.ps1

.NOTES
    Feature Update Evidence Kit by Sujay Adkesar - https://thelocalh0st.com   License: MIT
#>
[CmdletBinding()]
param([string]$OutDir)

$ErrorActionPreference = 'SilentlyContinue'
$Now = [DateTime]::UtcNow
if (-not $OutDir) { $OutDir = Join-Path (Get-Location) ('UpgradeEvidence_{0}_{1}' -f $env:COMPUTERNAME, $Now.ToString('yyyyMMddTHHmmssZ')) }
[void][IO.Directory]::CreateDirectory($OutDir)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Add-Type -Namespace UpEv -Name Reg -MemberDefinition @'
[DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
static extern int RegOpenKeyEx(UIntPtr hKey, string subKey, int options, int samDesired, out UIntPtr phkResult);
[DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
static extern int RegQueryInfoKey(UIntPtr hKey, IntPtr lpClass, IntPtr lpcClass, IntPtr lpReserved, IntPtr lpcSubKeys, IntPtr lpcMaxSubKeyLen,
    IntPtr lpcMaxClassLen, IntPtr lpcValues, IntPtr lpcMaxValueNameLen, IntPtr lpcMaxValueLen, IntPtr lpcbSecurityDescriptor, out long lpftLastWriteTime);
[DllImport("advapi32.dll")] static extern int RegCloseKey(UIntPtr hKey);
public static DateTime? LastWrite(string subKey) {
    UIntPtr h; if (RegOpenKeyEx(new UIntPtr(0x80000002u), subKey, 0, 0x20019, out h) != 0) return null;
    long ft; int r = RegQueryInfoKey(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out ft);
    RegCloseKey(h); if (r != 0) return null; return DateTime.FromFileTimeUtc(ft);
}
'@

function Say([string]$t, [string]$c = 'Gray') { Write-Host $t -ForegroundColor $c }
function Iso($d) { if ($d) { ([DateTime]$d).ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + 'Z' } else { '' } }

Say ''
Say '  Feature Update Evidence Kit  |  what the last Windows upgrade did to your timeline' 'Cyan'
Say ('  host {0}  |  elevated {1}' -f $env:COMPUTERNAME, $isAdmin) 'DarkGray'

#region 1. upgrade history ---------------------------------------------------------------------
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$curInstall = [DateTimeOffset]::FromUnixTimeSeconds([int64]$cv.InstallDate).UtcDateTime
$history = foreach ($k in Get-ChildItem 'HKLM:\SYSTEM\Setup' | Where-Object PSChildName -like 'Source OS*') {
    $p = Get-ItemProperty $k.PSPath
    $stamp = $null
    if ($k.PSChildName -match 'Updated on (.+)\)') { $stamp = [DateTime]::ParseExact($Matches[1], 'M/d/yyyy HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) }
    [pscustomobject]@{
        OldBuild          = '{0}.{1}' -f $p.CurrentBuild, $p.UBR
        OldVersion        = $p.DisplayVersion
        OldInstalledUtc   = [DateTimeOffset]::FromUnixTimeSeconds([int64]$p.InstallDate).UtcDateTime
        UpgradeKeyName    = $stamp
        UpgradeKeyWritten = [UpEv.Reg]::LastWrite('SYSTEM\Setup\' + $k.PSChildName)
        ProductName       = $p.ProductName
    }
}
$history = @($history | Sort-Object OldInstalledUtc)
$rows = for ($i = 0; $i -lt $history.Count; $i++) {
    $h = $history[$i]
    $next = if ($i + 1 -lt $history.Count) { $history[$i + 1] } else { $null }
    $newInstalled = if ($next) { $next.OldInstalledUtc } else { $curInstall }
    $newBuild = if ($next) { $next.OldBuild } else { '{0}.{1}' -f $cv.CurrentBuild, $cv.UBR }
    $kind = if (($h.OldBuild -split '\.')[0] -eq ($newBuild -split '\.')[0]) { 'same build (repair / reinstall)' } else { 'feature update' }
    [pscustomobject]@{
        From = '{0} ({1})' -f $h.OldBuild, $h.OldVersion; To = $newBuild; Kind = $kind
        FromInstalledUtc = Iso $h.OldInstalledUtc
        UpgradeStartedLocal = if ($h.UpgradeKeyName) { $h.UpgradeKeyName.ToString('yyyy-MM-dd HH:mm') } else { '' }
        SourceOSKeyWrittenUtc = Iso $h.UpgradeKeyWritten
        NewInstallDateUtc = Iso $newInstalled
    }
}
$lastUpgrade = if ($history) { $curInstall } else { $null }
Say ''
Say '  Upgrade history (HKLM\SYSTEM\Setup\Source OS keys)' 'Cyan'
if (-not $rows) { Say '    no Source OS keys: no in-place upgrade on record (clean install or wiped)' 'Yellow' }
foreach ($r in $rows) { Say ('    {0,-20} -> {1,-12} upgrade began {2} local, new OS installed {3}   {4}' -f $r.From, $r.To, $r.UpgradeStartedLocal, $r.NewInstallDateUtc, $(if ($r.Kind -like 'same*') { '[same build]' } else { '' })) }
Say ('    current: {0} {1}.{2}, InstallDate {3}  <- reset by the last upgrade, not the first install' -f $cv.DisplayVersion, $cv.CurrentBuild, $cv.UBR, (Iso $curInstall)) 'Yellow'
if ($history) { Say ('    first install on record: {0}   (Source OS key write times are all reset by each upgrade: use the names and values)' -f (Iso $history[0].OldInstalledUtc)) 'Green' }
$rows | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $OutDir 'upgrade_history.csv')
#endregion

#region 2. evidence floor ----------------------------------------------------------------------
$floor = New-Object System.Collections.Generic.List[object]
function Add-Floor([string]$Artifact, $Oldest, [string]$Note) {
    $status = if ($Oldest -is [string]) { $Oldest } elseif (-not $Oldest) { 'no data' }
    elseif (-not $lastUpgrade) { 'no upgrade on record' }
    elseif ($Oldest -lt $lastUpgrade.AddDays(-1)) { 'CARRIED OVER: predates the upgrade' }
    elseif ($Oldest -lt $lastUpgrade.AddDays(3)) { 'STARTS AT UPGRADE: no history before it' }
    else { 'starts after the upgrade (rollover or retention?)' }
    $floor.Add([pscustomobject]@{ Artifact = $Artifact; OldestUtc = $(if ($Oldest -is [DateTime]) { Iso $Oldest } else { '' }); Status = $status; Note = $Note })
}
function Oldest-File([string]$Glob, [string]$Prop = 'CreationTimeUtc') {
    $f = @(Get-ChildItem $Glob -Force -ErrorAction SilentlyContinue)
    if (-not $f) { if (Test-Path (Split-Path $Glob -Parent)) { if ($isAdmin) { return $null } else { return 'access denied: run elevated' } } else { return $null } }
    ($f | Measure-Object -Property $Prop -Minimum).Minimum
}

$logs = 'System', 'Application', 'Security', 'Setup', 'Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational',
'Microsoft-Windows-TaskScheduler/Operational', 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
'Microsoft-Windows-Windows Defender/Operational', 'Microsoft-Windows-Bits-Client/Operational', 'Microsoft-Windows-Partition/Diagnostic',
'Microsoft-Windows-Kernel-PnP/Configuration', 'Microsoft-Windows-Shell-Core/Operational', 'Microsoft-Windows-NetworkProfile/Operational'
foreach ($l in $logs) {
    $e = $null; $err = $null
    try { $e = Get-WinEvent -LogName $l -MaxEvents 1 -Oldest -ErrorAction Stop } catch { $err = $_.Exception.Message }
    $info = Get-WinEvent -ListLog $l -ErrorAction SilentlyContinue
    $full = if ($info -and $info.MaximumSizeInBytes) { [math]::Round(100 * $info.FileSize / $info.MaximumSizeInBytes) } else { $null }
    $note = if ($info) { '{0:n0} records, file {1}% of max size{2}' -f $info.RecordCount, $full, $(if ($full -ge 90) { ': FULL, so rollover can explain a late start' } else { '' }) } else { '' }
    if ($e) { Add-Floor ('Event log: ' + $l) $e.TimeCreated.ToUniversalTime() $note }
    elseif ($err -match 'unauthorized|denied|privilege') { Add-Floor ('Event log: ' + $l) 'access denied: run elevated' '' }
    else { Add-Floor ('Event log: ' + $l) $null $note }
}
Add-Floor 'Prefetch (*.pf)' (Oldest-File 'C:\Windows\Prefetch\*.pf') 'only the newest 1024 entries are kept, so a late start can be normal'
Add-Floor 'Amcache.hve (file created)' (Oldest-File 'C:\Windows\appcompat\Programs\Amcache.hve') 'may be rebuilt or carried; check entry dates inside'
Add-Floor 'PCA (PcaAppLaunchDic.txt)' (Oldest-File 'C:\Windows\appcompat\pca\PcaAppLaunchDic.txt') 'file creation time'
Add-Floor 'SRUM (SRUDB.dat created)' (Oldest-File 'C:\Windows\System32\sru\SRUDB.dat') 'SRUM data is migrated; entries can predate this'
$sa = Get-Content 'C:\Windows\INF\setupapi.dev.log' -TotalCount 200 -ErrorAction SilentlyContinue | Select-String '>>>  Section start (\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)' | Select-Object -First 1
Add-Floor 'setupapi.dev.log (first section)' $(if ($sa) { [DateTime]::ParseExact($sa.Matches[0].Groups[1].Value, 'yyyy/MM/dd HH:mm:ss', $null) } else { $null }) 'local time; device first-install log'
$up = Get-Item 'C:\Windows\INF\setupapi.upgrade.log' -ErrorAction SilentlyContinue
if ($up) { $floor.Add([pscustomobject]@{ Artifact = 'setupapi.upgrade.log'; OldestUtc = Iso $up.CreationTimeUtc; Status = 'present'; Note = 'device migration during setup is logged here' }) }

$usb = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -ErrorAction SilentlyContinue | ForEach-Object { Get-ChildItem $_.PSPath } |
    ForEach-Object { [UpEv.Reg]::LastWrite($_.Name -replace '^HKEY_LOCAL_MACHINE\\', '') } | Where-Object { $_ })
Add-Floor 'USBSTOR (oldest instance key write)' $(if ($usb) { ($usb | Measure-Object -Minimum).Minimum } else { $null }) 'live Enum: rebuilt by a media upgrade'

$bam = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings' -ErrorAction SilentlyContinue
if ($bam) {
    $t = foreach ($s in $bam) { (Get-ItemProperty $s.PSPath).PSObject.Properties | Where-Object { $_.Value -is [byte[]] -and $_.Value.Length -ge 8 } | ForEach-Object { [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($_.Value, 0)) } }
    Add-Floor 'BAM (oldest execution)' (($t | Where-Object { $_.Year -gt 2000 }) | Measure-Object -Minimum).Minimum 'about a week of history at most, by design'
} else { Add-Floor 'BAM (oldest execution)' $(if ($isAdmin) { $null } else { 'access denied: run elevated' }) '' }

$np = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles' -ErrorAction SilentlyContinue
$npT = foreach ($p in $np) { $b = (Get-ItemProperty $p.PSPath).DateCreated; if ($b -is [byte[]] -and $b.Length -ge 16) {
        try { New-Object DateTime ([BitConverter]::ToUInt16($b, 0)), ([BitConverter]::ToUInt16($b, 2)), ([BitConverter]::ToUInt16($b, 6)), ([BitConverter]::ToUInt16($b, 8)), ([BitConverter]::ToUInt16($b, 10)), ([BitConverter]::ToUInt16($b, 12)) } catch { } } }
Add-Floor 'NetworkList profiles (oldest DateCreated)' $(if ($npT) { ($npT | Measure-Object -Minimum).Minimum } elseif (-not $isAdmin) { 'access denied: run elevated' } else { $null }) 'local time; Wi-Fi and network history'

$ua = foreach ($g in Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist' -ErrorAction SilentlyContinue) {
    (Get-ItemProperty (Join-Path $g.PSPath 'Count')).PSObject.Properties | Where-Object { $_.Value -is [byte[]] -and $_.Value.Length -ge 68 } |
        ForEach-Object { $ft = [BitConverter]::ToInt64($_.Value, 60); if ($ft -gt 116444736000000000) { [DateTime]::FromFileTimeUtc($ft) } } }
Add-Floor 'UserAssist, current user (oldest last-run)' $(if ($ua) { ($ua | Measure-Object -Minimum).Minimum } else { $null }) 'replayed into the new hive; embedded times survive, key write times do not'
Add-Floor 'Jump lists, current user' (Oldest-File "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*" 'LastWriteTimeUtc') 'user data: carried across'
Add-Floor 'LNK files, current user' (Oldest-File "$env:APPDATA\Microsoft\Windows\Recent\*.lnk" 'CreationTimeUtc') 'user data: carried across'
$floor | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $OutDir 'evidence_floor.csv')
Say ''
Say ('  Evidence floor vs the last upgrade ({0})' -f (Iso $lastUpgrade)) 'Cyan'
foreach ($f in $floor) {
    $c = switch -Wildcard ($f.Status) { 'CARRIED*' { 'Green' } 'STARTS AT*' { 'Yellow' } 'access*' { 'DarkGray' } default { 'Gray' } }
    Say ('    {0,-58} {1,-18} {2}' -f $f.Artifact, $f.OldestUtc, $f.Status) $c
}
#endregion

#region 3. DeviceMigration -------------------------------------------------------------------------
$migRoots = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceMigration', 'HKLM:\SYSTEM\Setup\Upgrade\PnP\CurrentControlSet\Control\DeviceMigration'
$mig = New-Object System.Collections.Generic.List[object]
foreach ($root in $migRoots) {
    if (-not (Test-Path $root)) { continue }
    $mt = (Get-ItemProperty $root).MigrationTime
    $mtime = if ($mt -is [byte[]]) { [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($mt, 0)) } else { $null }
    foreach ($e in Get-ChildItem "$root\Devices") { foreach ($id in Get-ChildItem $e.PSPath) { foreach ($inst in Get-ChildItem $id.PSPath) {
                $p = Get-ItemProperty $inst.PSPath
                $live = Test-Path ('HKLM:\SYSTEM\CurrentControlSet\Enum\{0}\{1}\{2}' -f $e.PSChildName, $id.PSChildName, $inst.PSChildName)
                $lp = if ($p.LastPresentDate -is [byte[]] -and $p.LastPresentDate.Length -ge 8) { [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($p.LastPresentDate, 0)) } else { $null }
                $mig.Add([pscustomobject]@{
                        Enumerator = $e.PSChildName; DeviceId = $id.PSChildName; Instance = $inst.PSChildName
                        PresentAtUpgrade = $p.Present; LastPresentUtc = Iso $lp; Description = $p.BusDeviceDesc
                        InLiveEnum = $live; Class = $p.ClassGuid; Inf = $p.DriverInfName
                        HardwareId = @($p.HardwareIds)[0]; LocationPath = @($p.LocationPaths)[0]; MigrationTimeUtc = Iso $mtime
                        Source = ($root -replace '^HKLM:\\', 'HKLM\')
                    }) } } }
    if ($mig.Count) { break }   # same snapshot in both places; the first readable one wins
}
$mig | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $OutDir 'device_migration.csv')
$only = @($mig | Where-Object { -not $_.InLiveEnum })
Say ''
Say '  DeviceMigration (what the old OS knew about, at upgrade time)' 'Cyan'
if (-not $mig.Count) { Say '    not readable or not present' 'DarkGray' }
else {
    Say ('    {0} device instances, snapshot {1}, {2} not present at upgrade time' -f $mig.Count, $mig[0].MigrationTimeUtc, @($mig | Where-Object { $_.PresentAtUpgrade -eq 0 }).Count)
    Say ('    {0} exist ONLY in the snapshot (gone from the live Enum tree)' -f $only.Count) 'Yellow'
    Say ('    {0} carry LastPresentDate, i.e. when a disconnected device was last seen:' -f @($mig | Where-Object LastPresentUtc).Count) 'Yellow'
    foreach ($m in ($mig | Where-Object { $_.LastPresentUtc -and $_.Enumerator -in 'USB', 'USBSTOR', 'SCSI', 'BTHENUM', 'WPDBUSENUM', 'STORAGE', 'SWD' } | Sort-Object LastPresentUtc -Descending | Select-Object -First 15)) {
        Say ('      last present {0}  {1,-8} {2,-30} {3}' -f $m.LastPresentUtc, $m.Enumerator, $m.DeviceId.Substring(0, [Math]::Min(30, $m.DeviceId.Length)), $m.Description)
    }
}
#endregion

#region 4. leftovers -------------------------------------------------------------------------------
$extra = New-Object System.Collections.Generic.List[object]
foreach ($d in 'C:\Windows.old', 'C:\$WINDOWS.~BT', 'C:\$Windows.~WS') {
    $i = Get-Item -LiteralPath $d -Force -ErrorAction SilentlyContinue
    $extra.Add([pscustomobject]@{ Item = $d; Present = [bool]$i; CreatedUtc = $(if ($i) { Iso $i.CreationTimeUtc } else { '' }); Note = $(if ($d -like '*Windows.old') { 'the old OS: perishable, removed by cleanup after the rollback window' } else { 'setup working folder' }) })
}
$appx = @(Get-ChildItem 'HKLM:\SYSTEM\Setup\Upgrade\Appx\Applications' -ErrorAction SilentlyContinue)
$extra.Add([pscustomobject]@{ Item = 'HKLM\SYSTEM\Setup\Upgrade\Appx\Applications'; Present = [bool]$appx; CreatedUtc = ''; Note = ('{0} apps from the old OS inventory' -f $appx.Count) })
$extra | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $OutDir 'leftovers.csv')
Say ''
Say '  Leftovers' 'Cyan'
foreach ($x in $extra) { Say ('    {0,-46} {1,-6} {2} {3}' -f $x.Item, $x.Present, $x.CreatedUtc, $x.Note) }
Say ''
Say ('  CSVs: {0}' -f $OutDir) 'Green'
Say ''
#endregion
