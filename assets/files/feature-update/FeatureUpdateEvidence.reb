Description: Windows feature-update evidence - upgrade history, DeviceMigration snapshots, current install date
Author: Sujay Adkesar
Version: 1.0
Id: 6f1c2b8e-4a7d-4e2b-9c3a-5d8e1f0a7b21
Keys:
    -
        Description: Upgrade history (one key per in-place upgrade)
        HiveType: SYSTEM
        Category: Feature Update
        KeyPath: Setup\Source OS*
        Recursive: false
        Comment: "Key name = when the upgrade began (local time). Values = the OLD OS: CurrentBuild, UBR, DisplayVersion, InstallDate (epoch), ProductName. Key LastWrite is reset by every later upgrade."
    -
        Description: Setup image tag
        HiveType: SYSTEM
        Category: Feature Update
        KeyPath: Setup
        ValueName: CloneTag
        Recursive: false
        Comment: "Build date of the install image"
    -
        Description: Rollback source version
        HiveType: SYSTEM
        Category: Feature Update
        KeyPath: Setup
        ValueName: UninstallSourceVersion
        Recursive: false
        Comment: "The build Windows would roll back to"
    -
        Description: DeviceMigration snapshot time (Setup copy)
        HiveType: SYSTEM
        Category: Feature Update
        KeyPath: Setup\Upgrade\PnP\CurrentControlSet\Control\DeviceMigration
        ValueName: MigrationTime
        IncludeBinary: true
        BinaryConvert: FILETIME
        Recursive: false
        Comment: "When Setup took the PnP snapshot of the old OS"
    -
        Description: DeviceMigration snapshot time (control set copy)
        HiveType: SYSTEM
        Category: Feature Update
        KeyPath: ControlSet00*\Control\DeviceMigration
        ValueName: MigrationTime
        IncludeBinary: true
        BinaryConvert: FILETIME
        Recursive: false
        Comment: "When Setup took the PnP snapshot of the old OS"
    -
        Description: DeviceMigration devices (Setup copy)
        HiveType: SYSTEM
        Category: Feature Update
        KeyPath: Setup\Upgrade\PnP\CurrentControlSet\Control\DeviceMigration\Devices\*\*\*
        Recursive: false
        Comment: 'Every device the old OS knew: Present (1/0 at upgrade time), BusDeviceDesc, HardwareIds, LocationPaths, DriverInfName, ClassGuid. Compare with ControlSet00*\Enum: devices only here were connected before the upgrade.'
    -
        Description: DeviceMigration last present time (Setup copy)
        HiveType: SYSTEM
        Category: Feature Update
        KeyPath: Setup\Upgrade\PnP\CurrentControlSet\Control\DeviceMigration\Devices\*\*\*
        ValueName: LastPresentDate
        IncludeBinary: true
        BinaryConvert: FILETIME
        Recursive: false
        Comment: "Devices not connected at upgrade time: when each was last seen. BusDeviceDesc names it."
    -
        Description: DeviceMigration devices (control set copy)
        HiveType: SYSTEM
        Category: Feature Update
        KeyPath: ControlSet00*\Control\DeviceMigration\Devices\*\*\*
        Recursive: false
        Comment: "Same snapshot; readable only with SYSTEM rights on a live box"
    -
        Description: Current OS install date (reset by every feature upgrade)
        HiveType: SOFTWARE
        Category: Feature Update
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: InstallDate
        Recursive: false
        Comment: "Epoch seconds. This is the LAST upgrade, not the first install; the oldest Source OS key holds that."
    -
        Description: Current OS build
        HiveType: SOFTWARE
        Category: Feature Update
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: CurrentBuild
        Recursive: false
    -
        Description: Current OS display version
        HiveType: SOFTWARE
        Category: Feature Update
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: DisplayVersion
        Recursive: false
