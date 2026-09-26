<#
.SYNOPSIS
    Setup Controller - Phase 1 audit collector (READ-ONLY).

.DESCRIPTION
    Collects the evidence needed for the Setup Controller technical audit:
    Windows version, motherboard, installed RGB/vendor software, services, processes, listening ports,
    USB/HID identifiers, network adapters and drivers, Wi-Fi capabilities and power settings,
    Windows Mobile Hotspot state, Internet Connection Sharing, PPPoE, relevant vendor config files,
    read-only local API probes and relevant event-log entries.

    What this script does NOT do:
      - change any setting, registry value, service, driver, adapter, firewall rule, hotspot or profile
      - send any USB/HID command to any device
      - POST/PUT/PATCH to any API (only HTTP GET to SignalRGB on 127.0.0.1:16038 and TCP connect tests)
      - talk to the WiZ bulb (use Probe-WizBulb.ps1 for that)
      - read Wi-Fi keys, PPPoE credentials, tokens or the hotspot passphrase

    Output is written to .\output\audit-<timestamp>\ :
      audit-report.json   full structured evidence (redacted)
      audit-summary.txt   human-readable summary (redacted)

    Redaction: Windows user/computer name, SSIDs, e-mail addresses, the device-specific half of MAC
    addresses, public IPv4 / global IPv6 addresses, USB serial numbers. Private LAN addresses
    (e.g. 192.168.137.x) are kept because they are needed to diagnose the WiZ problem.

.PARAMETER EventDays
    How many days of event-log history to scan (default 14).

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Collect-SetupAudit.ps1
#>
[CmdletBinding()]
param(
    [string]$OutputDir,
    [ValidateRange(1, 90)][int]$EventDays = 14,
    [ValidateRange(50, 5000)][int]$MaxEventsPerLog = 1500
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\AuditCommon.ps1')

$ScriptVersion = '1.0.0'
if (-not $OutputDir) {
    $OutputDir = Join-Path $PSScriptRoot ('output\audit-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

Register-StandardRedactions

# Vendor / software names relevant to this audit (lighting software and anything known to fight over RGB devices).
$VendorRegex = '(?i)signal\s*rgb|whirlwind|vortx|gigabyte|aorus|rgb\s*fusion|control\s*center|gcc|easytune|app\s*center|' +
'steelseries|sonar|hyperx|ngenuity|kingston|redragon|k557|kala|\bwiz\b|openrgb|icue|corsair|armou?ry|aura|lightingservice|' +
'razer|synapse|logitech|lghub|g\s*hub|msi\s*center|mystic|dragon\s*center|nzxt|polychrome|asrock|l-connect|lian\s*li|' +
'thermaltake|tt\s*rgb|cooler\s*master|masterplus|nahimic|alexa|amazon|wireshark|npcap|usbpcap|zadig|libusb'

$NetworkServiceNames = @(
    'SharedAccess', 'icssvc', 'WlanSvc', 'RasMan', 'RasAuto', 'Dhcp', 'Dnscache', 'NlaSvc', 'netprofm', 'Netman',
    'WFDSConMgrSvc', 'wcncsvc', 'iphlpsvc', 'BFE', 'mpssvc', 'WwanSvc', 'SstpSvc', 'RemoteAccess', 'WinHttpAutoProxySvc'
)

# Hardware identifiers taken from the sources cited in docs/AUDIT_REPORT.md. Used only to label what is found.
$KnownDevices = @(
    @{ Vid = '1038'; Pid = '1832'; Name = 'SteelSeries Sensei TEN'; Source = 'rivalcfg sensei_ten.py; SignalRGB Steelseries_Sensi_Ten_Mouse.js' }
    @{ Vid = '1038'; Pid = '1834'; Name = 'SteelSeries Sensei TEN CS:GO Neon Rider Edition'; Source = 'rivalcfg sensei_ten.py' }
    @{ Vid = '0951'; Pid = '171F'; Name = 'HyperX QuadCast S (Kingston VID)'; Source = 'OpenRGB HyperXMicrophoneController; QuadcastRGB; SignalRGB HyperX_Quadcast_S.js' }
    @{ Vid = '03F0'; Pid = '0F8B'; Name = 'HyperX QuadCast S (HP VID)'; Source = 'OpenRGB; QuadcastRGB; SignalRGB' }
    @{ Vid = '03F0'; Pid = '068C'; Name = 'HyperX QuadCast S (HP VID)'; Source = 'OpenRGB; QuadcastRGB; SignalRGB' }
    @{ Vid = '03F0'; Pid = '0294'; Name = 'HyperX QuadCast S (HP VID)'; Source = 'OpenRGB' }
    @{ Vid = '03F0'; Pid = '028C'; Name = 'HyperX QuadCast S (HP VID)'; Source = 'OpenRGB; QuadcastRGB; SignalRGB' }
    @{ Vid = '03F0'; Pid = '048C'; Name = 'HyperX QuadCast S (HP VID)'; Source = 'OpenRGB; QuadcastRGB; SignalRGB' }
    @{ Vid = '03F0'; Pid = '0D8B'; Name = 'HyperX QuadCast S (HP VID)'; Source = 'OpenRGB' }
    @{ Vid = '03F0'; Pid = '098C'; Name = 'HyperX DuoCast (NOT QuadCast S)'; Source = 'OpenRGB; QuadcastRGB' }
    @{ Vid = '03F0'; Pid = '02B5'; Name = 'HyperX QuadCast 2 S (different protocol)'; Source = 'OpenRGB HyperXMicrophoneV2Controller' }
    @{ Vid = '048D'; Pid = '5702'; Name = 'ITE IT5702 - Gigabyte RGB Fusion 2 USB (B650 GAMING X AX V2 = layout 24)'; Source = 'OpenRGB GigabyteFusion2USB_Devices.cpp; SignalRGB Gigabyte_Motherboard_Controller.js' }
    @{ Vid = '048D'; Pid = '5711'; Name = 'ITE IT5711 - Gigabyte RGB Fusion 2 USB'; Source = 'OpenRGB' }
    @{ Vid = '048D'; Pid = '8297'; Name = 'ITE IT8297 - Gigabyte RGB Fusion 2 USB'; Source = 'OpenRGB; SignalRGB' }
    @{ Vid = '320F'; Pid = '5000'; Name = 'EVision keyboard - claimed Redragon K557 Kala V2 (unverified community plugin)'; Source = 'vinemelo/SignalRGB-Redragon-K557-Kala-V2; OpenRGB EVisionKeyboardController' }
    @{ Vid = '320F'; Pid = '5055'; Name = 'EVision keyboard - claimed Redragon K557 Kala V2 (unverified community plugin)'; Source = 'vinemelo/SignalRGB-Redragon-K557-Kala-V2' }
)
$InterestingVids = @('1038', '0951', '03F0', '048D', '320F', '0C45', '258A', '04D9', '1A2C', '3151', '1EA7', '05AC')

function Get-VidPidInfo {
    param([string]$Id)
    $m = [regex]::Match($Id, '(?i)VID_([0-9A-F]{4})&PID_([0-9A-F]{4})(?:&REV_[0-9A-F]{4})?(?:&MI_([0-9A-F]{2}))?(?:&COL([0-9A-F]{2}))?')
    if (-not $m.Success) { return $null }
    return [ordered]@{
        vid = $m.Groups[1].Value.ToUpperInvariant()
        pid = $m.Groups[2].Value.ToUpperInvariant()
        mi  = $(if ($m.Groups[3].Success) { $m.Groups[3].Value } else { $null })
        col = $(if ($m.Groups[4].Success) { $m.Groups[4].Value } else { $null })
    }
}

function Get-SanitizedInstanceId {
    <# The last segment of a USB instance ID is a serial number when it contains no '&'. #>
    param([string]$InstanceId)
    $parts = $InstanceId.Split('\')
    if ($parts.Count -ge 3 -and $parts[2] -notmatch '&') { $parts[2] = '<serial>' }
    return ($parts -join '\')
}

function Get-SafeRegistryValues {
    <# Returns registry values, hiding anything that could be a credential. #>
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $item = Get-Item -LiteralPath $Path
    $values = [ordered]@{}
    foreach ($name in $item.GetValueNames()) {
        $kind = $item.GetValueKind($name).ToString()
        $label = $(if ($name -eq '') { '(default)' } else { $name })
        if ($name -match '(?i)token|key|secret|pass|auth|session|cookie|mail|user|account|licen|serial|credential|cert') {
            $values[$label] = "<hidden:$kind>"
            continue
        }
        $v = $item.GetValue($name)
        if ($kind -eq 'Binary') { $values[$label] = "<binary:$(@($v).Count) bytes>"; continue }
        if ($v -is [string] -and ($v.Length -gt 120 -or $v -match '^[A-Za-z0-9+/=_-]{32,}$')) {
            $values[$label] = "<hidden:long-string>"
            continue
        }
        $values[$label] = $v
    }
    return $values
}

function Join-PathSafe {
    <# Join-Path that tolerates a missing root (e.g. an unset environment variable). #>
    param([string]$Root, [string]$Child)
    if ([string]::IsNullOrEmpty($Root)) { return $null }
    return (Join-Path $Root $Child)
}

function Get-FileVersionSafe {
    param([string]$Path)
    try {
        if ($Path -and (Test-Path -LiteralPath $Path)) {
            $vi = (Get-Item -LiteralPath $Path).VersionInfo
            return [ordered]@{ fileVersion = $vi.FileVersion; productVersion = $vi.ProductVersion; product = $vi.ProductName }
        }
    }
    catch { }
    return $null
}

function Get-ChildNamesSafe {
    param([string]$Path, [int]$Depth = 1, [int]$Max = 200)
    if ([string]::IsNullOrEmpty($Path) -or -not (Test-Path -LiteralPath $Path)) { return $null }
    $items = @(Get-ChildItem -LiteralPath $Path -Recurse -Depth $Depth -ErrorAction SilentlyContinue | Select-Object -First $Max)
    return @($items | ForEach-Object { $_.FullName.Substring($Path.Length).TrimStart('\') })
}

$report = [ordered]@{}
$report['meta'] = [ordered]@{
    scriptVersion  = $ScriptVersion
    collectedAt    = (Get-Date).ToString('o')
    psVersion      = $PSVersionTable.PSVersion.ToString()
    psEdition      = $PSVersionTable.PSEdition
    isAdministrator = (Test-IsAdministrator)
    eventDays      = $EventDays
    note           = 'Read-only collection. Redacted: user/computer names, SSIDs, e-mails, MAC device bytes, public IPs, USB serials.'
}
if ($PSVersionTable.PSEdition -ne 'Desktop') {
    Write-Warning 'Running in PowerShell 7: the Mobile Hotspot (WinRT) section will be skipped. Use powershell.exe (Windows PowerShell 5.1) for a complete audit.'
}
if (-not $report['meta'].isAdministrator) {
    Write-Host 'Note: not running as Administrator. A few read-only items (per-device power management) will be skipped.' -ForegroundColor Cyan
}

Write-Host "Collecting audit data into $OutputDir"

# ---------------------------------------------------------------------------
Invoke-Section $report 'windows' {
    $os = Get-CimInstance Win32_OperatingSystem
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    [ordered]@{
        caption        = $os.Caption
        version        = $os.Version
        build          = $os.BuildNumber
        ubr            = $cv.UBR
        displayVersion = $cv.DisplayVersion
        editionId      = $cv.EditionID
        architecture   = $os.OSArchitecture
        locale         = (Get-Culture).Name
        uiLanguage     = (Get-UICulture).Name
        lastBoot       = $os.LastBootUpTime.ToString('o')
        uptimeHours    = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)
    }
}

Invoke-Section $report 'hardware' {
    $bb = Get-CimInstance Win32_BaseBoard
    $bios = Get-CimInstance Win32_BIOS
    $cs = Get-CimInstance Win32_ComputerSystem
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    [ordered]@{
        baseBoardManufacturer = $bb.Manufacturer
        baseBoardProduct      = $bb.Product
        baseBoardVersion      = $bb.Version   # Gigabyte usually reports the PCB revision here (e.g. "x.x")
        biosVendor            = $bios.Manufacturer
        biosVersion           = $bios.SMBIOSBIOSVersion
        biosReleaseDate       = $(if ($bios.ReleaseDate) { $bios.ReleaseDate.ToString('yyyy-MM-dd') } else { $null })
        systemManufacturer    = $cs.Manufacturer
        systemModel           = $cs.Model
        pcSystemType          = $cs.PCSystemType
        cpu                   = $cpu.Name
    }
}

Invoke-Section $report 'power' {
    $wirelessSubgroup = '19cbb8fa-5279-450e-9fac-8a3d5fedd0c1'   # "Wireless Adapter Settings"
    [ordered]@{
        activeScheme          = ((Invoke-NativeLines 'powercfg.exe' @('/getactivescheme')) -join ' ').Trim()
        availableSleepStates  = (Invoke-NativeLines 'powercfg.exe' @('/a'))
        wirelessAdapterPolicy = (Invoke-NativeLines 'powercfg.exe' @('/query', 'SCHEME_CURRENT', $wirelessSubgroup))
        sleepPolicy           = (Invoke-NativeLines 'powercfg.exe' @('/query', 'SCHEME_CURRENT', 'SUB_SLEEP'))
    }
}

# ---------------------------------------------------------------------------
Invoke-Section $report 'installedSoftware' {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $apps = foreach ($p in $paths) {
        Get-ItemProperty -Path $p -ErrorAction SilentlyContinue | Where-Object {
            $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -and
            (($_.DisplayName -match $VendorRegex) -or ($_.PSObject.Properties['Publisher'] -and $_.Publisher -match $VendorRegex))
        } | ForEach-Object {
            [ordered]@{
                name            = $_.DisplayName
                version         = $(if ($_.PSObject.Properties['DisplayVersion']) { $_.DisplayVersion } else { $null })
                publisher       = $(if ($_.PSObject.Properties['Publisher']) { $_.Publisher } else { $null })
                installDate     = $(if ($_.PSObject.Properties['InstallDate']) { $_.InstallDate } else { $null })
                installLocation = $(if ($_.PSObject.Properties['InstallLocation']) { $_.InstallLocation } else { $null })
                scope           = $(if ($p -like 'HKCU*') { 'user' } else { 'machine' })
            }
        }
    }
    $appx = @()
    try {
        $appx = @(Get-AppxPackage -ErrorAction Stop | Where-Object { $_.Name -match $VendorRegex -or $_.Publisher -match $VendorRegex } | ForEach-Object {
                [ordered]@{ name = $_.Name; version = $_.Version.ToString(); publisherId = $_.PublisherId; installLocation = $_.InstallLocation }
            })
    }
    catch { $appx = @([ordered]@{ error = $_.Exception.Message }) }
    [ordered]@{ win32 = @($apps); storeApps = $appx }
}

Invoke-Section $report 'services' {
    $all = Get-CimInstance Win32_Service
    $rows = $all | Where-Object {
        ($NetworkServiceNames -contains $_.Name) -or ($_.Name -match $VendorRegex) -or ($_.DisplayName -match $VendorRegex) -or ($_.PathName -match $VendorRegex)
    } | ForEach-Object {
        [ordered]@{
            name        = $_.Name
            displayName = $_.DisplayName
            state       = $_.State
            startMode   = $_.StartMode
            delayedAutoStart = $(if ($_.PSObject.Properties['DelayedAutoStart']) { $_.DelayedAutoStart } else { $null })
            processId   = $_.ProcessId
            account     = $_.StartName
            path        = $_.PathName
            category    = $(if ($NetworkServiceNames -contains $_.Name) { 'windows-network' } else { 'vendor' })
        }
    }
    , @($rows)
}

Invoke-Section $report 'processes' {
    $procs = Get-CimInstance Win32_Process | Where-Object {
        ($_.Name -match $VendorRegex) -or ($_.ExecutablePath -and $_.ExecutablePath -match $VendorRegex)
    }
    , @($procs | ForEach-Object {
            [ordered]@{
                name        = $_.Name
                processId   = $_.ProcessId
                path        = $_.ExecutablePath
                started     = $(if ($_.CreationDate) { $_.CreationDate.ToString('o') } else { $null })
                fileVersion = (Get-FileVersionSafe $_.ExecutablePath)
            }
        })
}

Invoke-Section $report 'listeningPorts' {
    $relevantPids = @{}
    foreach ($p in @($report['processes'])) {
        if ($p -is [System.Collections.IDictionary] -and $p.Contains('processId')) { $relevantPids[[int]$p['processId']] = $p['name'] }
    }
    $interestingPorts = @(16038, 6742, 38899, 38900)
    $tcp = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object {
            $relevantPids.ContainsKey([int]$_.OwningProcess) -or ($interestingPorts -contains [int]$_.LocalPort)
        } | ForEach-Object {
            $owner = $(if ($relevantPids.ContainsKey([int]$_.OwningProcess)) { $relevantPids[[int]$_.OwningProcess] } else { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName })
            [ordered]@{ protocol = 'TCP'; localAddress = $_.LocalAddress; localPort = $_.LocalPort; processId = $_.OwningProcess; process = $owner }
        })
    $udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object {
            $relevantPids.ContainsKey([int]$_.OwningProcess) -or ($interestingPorts -contains [int]$_.LocalPort)
        } | ForEach-Object {
            $owner = $(if ($relevantPids.ContainsKey([int]$_.OwningProcess)) { $relevantPids[[int]$_.OwningProcess] } else { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName })
            [ordered]@{ protocol = 'UDP'; localAddress = $_.LocalAddress; localPort = $_.LocalPort; processId = $_.OwningProcess; process = $owner }
        })
    [ordered]@{ tcp = $tcp; udp = $udp }
}

# ---------------------------------------------------------------------------
Invoke-Section $report 'usbHidDevices' {
    $keys = @(
        'DEVPKEY_Device_BusReportedDeviceDesc', 'DEVPKEY_Device_Manufacturer', 'DEVPKEY_Device_DriverVersion',
        'DEVPKEY_Device_DriverProvider', 'DEVPKEY_Device_DriverInfPath', 'DEVPKEY_Device_Service',
        'DEVPKEY_Device_HardwareIds', 'DEVPKEY_Device_ContainerId', 'DEVPKEY_Device_LocationInfo'
    )
    $devices = @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -match '^(USB|HID)\\VID_' })
    $rows = foreach ($d in $devices) {
        $ids = Get-VidPidInfo $d.InstanceId
        if ($null -eq $ids) { continue }
        $row = [ordered]@{
            vid          = $ids.vid
            pid          = $ids.pid
            interface    = $ids.mi
            collection   = $ids.col
            class        = $d.Class
            friendlyName = $d.FriendlyName
            status       = $d.Status
            instanceId   = (Get-SanitizedInstanceId $d.InstanceId)
        }
        if ($InterestingVids -contains $ids.vid -or $d.Class -in @('Keyboard', 'Mouse', 'HIDClass', 'AudioEndpoint', 'MEDIA')) {
            $props = @{}
            try {
                foreach ($prop in @(Get-PnpDeviceProperty -InstanceId $d.InstanceId -KeyName $keys -ErrorAction SilentlyContinue)) {
                    $props[$prop.KeyName] = $prop.Data
                }
            }
            catch { }
            $hw = @()
            if ($props.ContainsKey('DEVPKEY_Device_HardwareIds') -and $props['DEVPKEY_Device_HardwareIds']) { $hw = @($props['DEVPKEY_Device_HardwareIds']) }
            $usage = $hw | ForEach-Object { [regex]::Match($_, '(?i)HID_DEVICE_UP:([0-9A-F]{4})_U:([0-9A-F]{4})') } | Where-Object { $_.Success } | Select-Object -First 1
            $row['busReportedName'] = $props['DEVPKEY_Device_BusReportedDeviceDesc']
            $row['manufacturer'] = $props['DEVPKEY_Device_Manufacturer']
            $row['driverService'] = $props['DEVPKEY_Device_Service']
            $row['driverProvider'] = $props['DEVPKEY_Device_DriverProvider']
            $row['driverVersion'] = $props['DEVPKEY_Device_DriverVersion']
            $row['driverInf'] = $props['DEVPKEY_Device_DriverInfPath']
            $row['hidUsagePage'] = $(if ($usage) { $usage.Groups[1].Value.ToUpperInvariant() } else { $null })
            $row['hidUsage'] = $(if ($usage) { $usage.Groups[2].Value.ToUpperInvariant() } else { $null })
            $row['containerId'] = $(if ($props['DEVPKEY_Device_ContainerId']) { $props['DEVPKEY_Device_ContainerId'].ToString() } else { $null })
            $row['location'] = $props['DEVPKEY_Device_LocationInfo']
        }
        $known = $KnownDevices | Where-Object { $_.Vid -eq $ids.vid -and $_.Pid -eq $ids.pid } | Select-Object -First 1
        if ($known) { $row['knownAs'] = $known.Name; $row['knownSource'] = $known.Source }
        $row
    }
    , @($rows)
}

Invoke-Section $report 'inputAndAudioDevices' {
    $classes = @('Keyboard', 'Mouse', 'AudioEndpoint', 'MEDIA')
    , @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $classes -contains $_.Class } | ForEach-Object {
            $ids = Get-VidPidInfo $_.InstanceId
            [ordered]@{
                class        = $_.Class
                friendlyName = $_.FriendlyName
                status       = $_.Status
                vid          = $(if ($ids) { $ids.vid } else { $null })
                pid          = $(if ($ids) { $ids.pid } else { $null })
                instanceId   = (Get-SanitizedInstanceId $_.InstanceId)
            }
        })
}

# ---------------------------------------------------------------------------
Invoke-Section $report 'networkAdapters' {
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    $pm = @{}
    if ($report['meta'].isAdministrator) {
        try {
            foreach ($e in @(Get-CimInstance -Namespace root\wmi -ClassName MSPower_DeviceEnable -ErrorAction Stop)) {
                $pm[($e.InstanceName -replace '_\d+$', '').ToUpperInvariant()] = $e.Enable
            }
        }
        catch { }
    }
    , @($adapters | ForEach-Object {
            $a = $_
            $isWifi = ($a.NdisPhysicalMedium -eq 9) -or ($a.PhysicalMediaType -match '802\.11') -or ($a.InterfaceDescription -match '(?i)wi-?fi|wireless|wlan|802\.11')
            $isRelevantPhysical = (-not $a.Virtual) -and $a.HardwareInterface
            $row = [ordered]@{
                name                 = $a.Name
                description          = $a.InterfaceDescription
                ifIndex              = $a.ifIndex
                status               = $a.Status
                mediaConnectionState = "$($a.MediaConnectionState)"
                linkSpeed            = $a.LinkSpeed
                mac                  = $a.MacAddress
                mtu                  = $a.MtuSize
                virtual              = $a.Virtual
                hidden               = $a.Hidden
                hardwareInterface    = $a.HardwareInterface
                physicalMediaType    = $a.PhysicalMediaType
                ndisPhysicalMedium   = $a.NdisPhysicalMedium
                driverProvider       = $a.DriverProvider
                driverVersion        = $a.DriverVersionString
                driverDate           = $a.DriverDate
                driverDescription    = $a.DriverDescription
                componentId          = $a.ComponentID
                pnpDeviceId          = $(if ($a.PnPDeviceID) { Get-SanitizedInstanceId $a.PnPDeviceID } else { $null })
                isWifi               = $isWifi
            }
            if ($isRelevantPhysical) {
                try {
                    $row['advancedProperties'] = @(Get-NetAdapterAdvancedProperty -Name $a.Name -AllProperties -ErrorAction Stop | ForEach-Object {
                            [ordered]@{ name = $_.DisplayName; value = $_.DisplayValue; keyword = $_.RegistryKeyword }
                        })
                }
                catch { $row['advancedProperties'] = "unavailable: $($_.Exception.Message)" }
                try {
                    $p = Get-NetAdapterPowerManagement -Name $a.Name -ErrorAction Stop
                    $row['powerManagement'] = [ordered]@{
                        allowComputerToTurnOffDevice = "$($p.AllowComputerToTurnOffDevice)"
                        deviceSleepOnDisconnect      = "$($p.DeviceSleepOnDisconnect)"
                        selectiveSuspend             = "$($p.SelectiveSuspend)"
                        wakeOnMagicPacket            = "$($p.WakeOnMagicPacket)"
                        wakeOnPattern                = "$($p.WakeOnPattern)"
                    }
                }
                catch { $row['powerManagement'] = "unavailable: $($_.Exception.Message)" }
                if ($a.PnPDeviceID -and $pm.ContainsKey($a.PnPDeviceID.ToUpperInvariant())) {
                    $row['deviceManagerAllowTurnOffToSavePower'] = $pm[$a.PnPDeviceID.ToUpperInvariant()]
                }
            }
            $row
        })
}

Invoke-Section $report 'ipConfiguration' {
    $ipv4 = @(Get-NetIPAddress -ErrorAction SilentlyContinue | ForEach-Object {
            $addr = $_.IPAddress
            if ($_.AddressFamily -eq 'IPv4' -and (Test-IsPublicIPv4 $addr)) { $addr = '<public-ip>' }
            [ordered]@{ interface = $_.InterfaceAlias; ifIndex = $_.InterfaceIndex; family = "$($_.AddressFamily)"; address = $addr; prefix = $_.PrefixLength; origin = "$($_.PrefixOrigin)"; state = "$($_.AddressState)" }
        })
    $routes = @(Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0', '::/0') } | ForEach-Object {
            $nh = $_.NextHop
            if ($nh -match '^\d+\.\d+\.\d+\.\d+$' -and (Test-IsPublicIPv4 $nh)) { $nh = '<public-ip>' }
            [ordered]@{ destination = $_.DestinationPrefix; interface = $_.InterfaceAlias; ifIndex = $_.InterfaceIndex; nextHop = $nh; routeMetric = $_.RouteMetric; protocol = "$($_.Protocol)" }
        })
    $interfaces = @(Get-NetIPInterface -ErrorAction SilentlyContinue | ForEach-Object {
            [ordered]@{ interface = $_.InterfaceAlias; ifIndex = $_.InterfaceIndex; family = "$($_.AddressFamily)"; mtu = $_.NlMtu; metric = $_.InterfaceMetric; dhcp = "$($_.Dhcp)"; connection = "$($_.ConnectionState)"; forwarding = "$($_.Forwarding)" }
        })
    $dns = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses } | ForEach-Object {
            [ordered]@{ interface = $_.InterfaceAlias; family = $(if ($_.AddressFamily -eq 2) { 'IPv4' } else { 'IPv6' }); servers = @($_.ServerAddresses) }
        })
    $profiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.InterfaceAlias -match '(?i)wi-?fi|wlan|wireless') { Add-RedactionToken -Value $_.Name -Label 'ssid' }
            [ordered]@{ name = $_.Name; interface = $_.InterfaceAlias; category = "$($_.NetworkCategory)"; ipv4 = "$($_.IPv4Connectivity)"; ipv6 = "$($_.IPv6Connectivity)" }
        })
    $firewall = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ profile = $_.Name; enabled = "$($_.Enabled)" } })
    [ordered]@{ addresses = $ipv4; defaultRoutes = $routes; ipInterfaces = $interfaces; dnsServers = $dns; connectionProfiles = $profiles; firewallProfilesEnabled = $firewall }
}

Invoke-Section $report 'wlanNetsh' {
    # Wi-Fi profile names are SSIDs: register them for redaction but do not output them.
    foreach ($line in (Invoke-NativeLines 'netsh.exe' @('wlan', 'show', 'profiles'))) {
        $m = [regex]::Match($line, ':\s*(.+)$')
        if ($line -match '(?i)profile|profil' -and $m.Success) { Add-RedactionToken -Value $m.Groups[1].Value.Trim() -Label 'ssid' }
    }
    $interfacesText = (Invoke-NativeLines 'netsh.exe' @('wlan', 'show', 'interfaces'))
    foreach ($line in $interfacesText) {
        if ($line -match '^\s*(SSID|Profile|Profil)\s*:\s*(.+)$') { Add-RedactionToken -Value $Matches[2].Trim() -Label 'ssid' }
    }
    $hosted = (Invoke-NativeLines 'netsh.exe' @('wlan', 'show', 'hostednetwork'))
    foreach ($line in $hosted) {
        if ($line -match '^\s*SSID name\s*:\s*"?(.+?)"?\s*$') { Add-RedactionToken -Value $Matches[1].Trim() -Label 'ssid' }
    }
    [ordered]@{
        drivers              = (Invoke-NativeLines 'netsh.exe' @('wlan', 'show', 'drivers'))
        wirelessCapabilities = (Invoke-NativeLines 'netsh.exe' @('wlan', 'show', 'wirelesscapabilities'))
        interfaces           = $interfacesText
        settings             = (Invoke-NativeLines 'netsh.exe' @('wlan', 'show', 'settings'))
        hostedNetwork        = $hosted
        ipv4Subinterfaces    = (Invoke-NativeLines 'netsh.exe' @('interface', 'ipv4', 'show', 'subinterfaces'))
    }
}

# ---------------------------------------------------------------------------
Invoke-Section $report 'mobileHotspot' {
    if (-not (Initialize-WinRtNetworking)) {
        return [ordered]@{ skipped = 'WinRT unavailable. Run with Windows PowerShell 5.1 (powershell.exe).' }
    }
    $tmType = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]
    $infoType = [Windows.Networking.Connectivity.NetworkInformation]
    $internetProfile = $infoType::GetInternetConnectionProfile()
    $out = [ordered]@{}
    try { $out['noConnectionsTimeoutEnabled'] = $tmType::IsNoConnectionsTimeoutEnabled() } catch { $out['noConnectionsTimeoutEnabled'] = "unavailable: $($_.Exception.Message)" }
    $out['internetProfile'] = $(if ($internetProfile) { $internetProfile.ProfileName } else { $null })
    $profileRows = @()
    $activeManager = $null
    foreach ($cp in @($infoType::GetConnectionProfiles())) {
        $row = [ordered]@{
            profileName  = $cp.ProfileName
            isWlan       = $cp.IsWlanConnectionProfile
            isWwan       = $cp.IsWwanConnectionProfile
            ianaIfType   = $(if ($cp.NetworkAdapter) { $cp.NetworkAdapter.IanaInterfaceType } else { $null })
            adapterId    = $(if ($cp.NetworkAdapter) { $cp.NetworkAdapter.NetworkAdapterId.ToString() } else { $null })
            connectivity = $cp.GetNetworkConnectivityLevel().ToString()
            isInternetProfile = ($null -ne $internetProfile -and $cp.ProfileName -eq $internetProfile.ProfileName)
        }
        if ($cp.IsWlanConnectionProfile) { Add-RedactionToken -Value $cp.ProfileName -Label 'ssid' }
        try { $row['tetheringCapability'] = $tmType::GetTetheringCapabilityFromConnectionProfile($cp).ToString() } catch { $row['tetheringCapability'] = "error: $($_.Exception.Message)" }
        try {
            $m = $tmType::CreateFromConnectionProfile($cp)
            $row['tetheringState'] = $m.TetheringOperationalState.ToString()
            if ($null -eq $activeManager -or $row['tetheringState'] -eq 'On') { $activeManager = $m }
        }
        catch { $row['tetheringState'] = "error: $((Get-InnermostException $_.Exception).Message)" }
        $profileRows += $row
    }
    $out['connectionProfiles'] = $profileRows
    if ($null -ne $activeManager) {
        $out['operationalState'] = $activeManager.TetheringOperationalState.ToString()
        $out['clientCount'] = $activeManager.ClientCount
        $out['maxClientCount'] = $activeManager.MaxClientCount
        $cfg = $activeManager.GetCurrentAccessPointConfiguration()
        # The passphrase is intentionally never read.
        Add-RedactionToken -Value $cfg.Ssid -Label 'hotspot-ssid'
        $out['ssid'] = $cfg.Ssid
        $out['band'] = $cfg.Band.ToString()
        try { $out['authenticationKind'] = $cfg.AuthenticationKind.ToString() } catch { $out['authenticationKind'] = 'not exposed by this Windows build' }
        $bandSupport = [ordered]@{}
        foreach ($b in @('TwoPointFourGigahertz', 'FiveGigahertz', 'SixGigahertz')) {
            try { $bandSupport[$b] = $cfg.IsBandSupported([Windows.Networking.NetworkOperators.TetheringWiFiBand]$b) } catch { $bandSupport[$b] = 'unknown' }
        }
        $out['bandSupported'] = $bandSupport
        $authSupport = [ordered]@{}
        foreach ($k in @('Wpa2', 'Wpa3TransitionMode', 'Wpa3')) {
            try { $authSupport[$k] = $cfg.IsAuthenticationKindSupported([Windows.Networking.NetworkOperators.TetheringWiFiAuthenticationKind]$k) } catch { $authSupport[$k] = 'unknown' }
        }
        $out['authenticationKindSupported'] = $authSupport
        try {
            $out['clients'] = @($activeManager.GetTetheringClients() | ForEach-Object {
                    [ordered]@{ mac = $_.MacAddress; hostNames = @($_.HostNames | ForEach-Object { $_.DisplayName }) }
                })
        }
        catch { $out['clients'] = "unavailable: $($_.Exception.Message)" }
    }
    $out
}

Invoke-Section $report 'internetConnectionSharing' {
    $mediaTypes = @{ 0 = 'NONE'; 1 = 'DIRECT'; 2 = 'ISDN'; 3 = 'LAN'; 4 = 'PHONE'; 5 = 'TUNNEL'; 6 = 'PPPOE'; 7 = 'BRIDGE'; 8 = 'SHAREDACCESSHOST_LAN'; 9 = 'SHAREDACCESSHOST_RAS' }
    $statuses = @{ 0 = 'DISCONNECTED'; 1 = 'CONNECTING'; 2 = 'CONNECTED'; 3 = 'DISCONNECTING'; 4 = 'HARDWARE_NOT_PRESENT'; 5 = 'HARDWARE_DISABLED'; 6 = 'HARDWARE_MALFUNCTION'; 7 = 'MEDIA_DISCONNECTED'; 8 = 'AUTHENTICATING'; 9 = 'AUTHENTICATION_SUCCEEDED'; 10 = 'AUTHENTICATION_FAILED'; 11 = 'INVALID_ADDRESS'; 12 = 'CREDENTIALS_REQUIRED' }
    $connections = @()
    try {
        $share = New-Object -ComObject HNetCfg.HNetShare
        foreach ($c in $share.EnumEveryConnection) {
            $props = $share.NetConnectionProps.Invoke($c)
            $cfg = $share.INetSharingConfigurationForINetConnection.Invoke($c)
            $connections += [ordered]@{
                name              = $props.Name
                device            = $props.DeviceName
                mediaType         = $mediaTypes[[int]$props.MediaType]
                status            = $statuses[[int]$props.Status]
                sharingEnabled    = $cfg.SharingEnabled
                sharingRole       = $(if ($cfg.SharingEnabled) { if ($cfg.SharingConnectionType -eq 0) { 'PUBLIC (shared internet source)' } else { 'PRIVATE (clients side)' } } else { $null })
            }
        }
    }
    catch { $connections = "unavailable: $((Get-InnermostException $_.Exception).Message)" }
    $hostsIcs = @()
    try { $hostsIcs = @(Get-HostsIcsEntries) } catch { $hostsIcs = "unavailable: $($_.Exception.Message)" }
    [ordered]@{
        connections           = $connections
        hostsIcs              = $hostsIcs
        sharedAccessParameters = (Get-SafeRegistryValues 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters')
        icssvcSettings        = (Get-SafeRegistryValues 'HKLM:\SYSTEM\CurrentControlSet\Services\icssvc\Settings')
        icssvcSettingsNote    = 'A missing icssvc\Settings key means Windows defaults are in use.'
    }
}

Invoke-Section $report 'pppoe' {
    $ppp = @([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object { $_.NetworkInterfaceType -eq 'Ppp' } | ForEach-Object {
            $ipProps = $_.GetIPProperties()
            $mtu = $null
            try { $mtu = $ipProps.GetIPv4Properties().Mtu } catch { }
            [ordered]@{
                name         = $_.Name
                description  = $_.Description
                status       = $_.OperationalStatus.ToString()
                speedBps     = $_.Speed
                ipv4Mtu      = $mtu
                dnsServers   = @($ipProps.DnsAddresses | ForEach-Object { $_.ToString() })
            }
        })
    $phonebooks = @()
    $keep = '^(Type|DEVICE|Device|MEDIA|IdleDisconnectSeconds|Redial.*|IpPrioritizeRemote|IpInterfaceMetric|Ipv6PrioritizeRemote|AutoTiggerCapable|AlwaysOnCapable|PreviewUserPw|UseRasCredentials|ShowMonitorIconInTaskBar)$'
    foreach ($pbk in @((Join-Path $env:APPDATA 'Microsoft\Network\Connections\Pbk\rasphone.pbk'), (Join-Path $env:ProgramData 'Microsoft\Network\Connections\Pbk\rasphone.pbk'))) {
        if (-not (Test-Path -LiteralPath $pbk)) { continue }
        $entries = @()
        $current = $null
        foreach ($line in (Get-Content -LiteralPath $pbk)) {
            if ($line -match '^\[(.+)\]$') { $current = [ordered]@{ entry = $Matches[1] }; $entries += $current; continue }
            if ($null -ne $current -and $line -match '^([^=]+)=(.*)$') {
                $k = $Matches[1].Trim()
                if ($k -match $keep -and -not $current.Contains($k)) { $current[$k] = $Matches[2].Trim() }
            }
        }
        $phonebooks += [ordered]@{ file = $pbk; entries = $entries }
    }
    $tasks = @()
    try {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
                @($_.Actions | Where-Object { ($_.PSObject.Properties['Execute'] -and $_.Execute -match '(?i)rasdial|rasphone') -or ($_.PSObject.Properties['Arguments'] -and $_.Arguments -match '(?i)rasdial|rasphone') }).Count -gt 0
            } | ForEach-Object {
                [ordered]@{
                    task     = ($_.TaskPath + $_.TaskName)
                    state    = $_.State.ToString()
                    triggers = @($_.Triggers | ForEach-Object { $_.CimClass.CimClassName })
                    note     = 'Action arguments intentionally not collected (they can contain PPPoE credentials).'
                }
            })
    }
    catch { $tasks = "unavailable: $($_.Exception.Message)" }
    [ordered]@{ pppInterfaces = $ppp; phonebooks = $phonebooks; dialerScheduledTasks = $tasks }
}

# ---------------------------------------------------------------------------
Invoke-Section $report 'vendorConfiguration' {
    $out = [ordered]@{}
    # Each part is isolated so one missing folder or unreadable key does not hide the others.
    $part = {
        param([string]$Name, [scriptblock]$Body)
        try { $out[$Name] = & $Body }
        catch { $out[$Name] = [ordered]@{ error = (Get-InnermostException $_.Exception).Message } }
    }

    # SteelSeries GameSense discovery file (official location + the location used by SteelSeries GG).
    & $part 'steelSeriesCoreProps' {
        $coreProps = @()
        foreach ($path in @((Join-PathSafe $env:ProgramData 'SteelSeries\SteelSeries Engine 3\coreProps.json'), (Join-PathSafe $env:ProgramData 'SteelSeries\GG\coreProps.json'))) {
            if (-not $path) { continue }
            $entry = [ordered]@{ path = $path; exists = (Test-Path -LiteralPath $path) }
            if ($entry.exists) {
                try {
                    $json = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
                    $entry['keys'] = @($json.PSObject.Properties.Name)
                    $addr = [ordered]@{}
                    foreach ($p in $json.PSObject.Properties) { if ($p.Name -match '(?i)address') { $addr[$p.Name] = $p.Value } }
                    $entry['addresses'] = $addr
                    $entry['lastWriteTime'] = (Get-Item -LiteralPath $path).LastWriteTime.ToString('o')
                }
                catch { $entry['error'] = $_.Exception.Message }
            }
            $coreProps += $entry
        }
        , $coreProps
    }

    # SignalRGB: install folder, version, plugin files, settings key names (values filtered).
    & $part 'signalRgb' {
        $signal = [ordered]@{}
        $vortx = Join-PathSafe $env:LOCALAPPDATA 'VortxEngine'
        $signal['vortxEngineFolder'] = (Get-ChildNamesSafe $vortx 0)
        $exe = @()
        if ($vortx -and (Test-Path -LiteralPath $vortx)) {
            $exe = @(Get-ChildItem -LiteralPath $vortx -Filter 'SignalRgb*.exe' -Recurse -Depth 2 -ErrorAction SilentlyContinue | Select-Object -First 3)
        }
        $signal['executables'] = @($exe | ForEach-Object { [ordered]@{ path = $_.FullName; version = (Get-FileVersionSafe $_.FullName) } })
        $docs = [Environment]::GetFolderPath('MyDocuments')
        $signal['userPluginsFolder'] = (Get-ChildNamesSafe (Join-PathSafe $docs 'WhirlwindFX\Plugins') 2)
        $regRoot = 'HKCU:\Software\WhirlwindFX'
        if (Test-Path -LiteralPath $regRoot) {
            $keysOut = @()
            foreach ($k in @(Get-ChildItem -LiteralPath $regRoot -Recurse -Depth 3 -ErrorAction SilentlyContinue | Select-Object -First 400)) {
                $keysOut += [ordered]@{ key = ($k.Name -replace '^HKEY_CURRENT_USER', 'HKCU'); values = (Get-SafeRegistryValues $k.PSPath) }
            }
            $signal['registry'] = [ordered]@{ root = (Get-SafeRegistryValues $regRoot); subkeys = $keysOut }
        }
        else { $signal['registry'] = $null }
        $signal
    }

    # Gigabyte software folders (names only).
    & $part 'gigabyteFolders' {
        [ordered]@{
            programFilesX86 = (Get-ChildNamesSafe (Join-PathSafe ${env:ProgramFiles(x86)} 'GIGABYTE') 1)
            programFiles    = (Get-ChildNamesSafe (Join-PathSafe $env:ProgramFiles 'GIGABYTE') 1)
        }
    }

    # Redragon software is often not registered as an installed program: look for folders and shortcuts.
    & $part 'redragon' {
        $redragon = @()
        foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
            if (-not $root -or -not (Test-Path -LiteralPath $root)) { continue }
            foreach ($d in @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)redragon|k557|kala' })) {
                $redragon += [ordered]@{ folder = $d.FullName; contents = (Get-ChildNamesSafe $d.FullName 1 100) }
            }
        }
        $shortcuts = @()
        foreach ($sm in @((Join-PathSafe $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'), (Join-PathSafe $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'), [Environment]::GetFolderPath('Desktop'))) {
            if (-not $sm -or -not (Test-Path -LiteralPath $sm)) { continue }
            $shortcuts += @(Get-ChildItem -LiteralPath $sm -Filter '*.lnk' -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)redragon|k557|kala|keyboard' } | ForEach-Object { $_.FullName })
        }
        [ordered]@{ folders = $redragon; shortcuts = $shortcuts }
    }

    # HyperX NGENUITY is a Microsoft Store app; its package appears under installedSoftware.storeApps.
    & $part 'ngenuityPackageFolders' {
        $pkgRoot = Join-PathSafe $env:LOCALAPPDATA 'Packages'
        if (-not $pkgRoot -or -not (Test-Path -LiteralPath $pkgRoot)) { return , @() }
        , @(Get-ChildItem -LiteralPath $pkgRoot -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)hyperx|ngenuity' } | ForEach-Object { $_.Name })
    }
    & $part 'openRgbConfigFolderExists' {
        $p = Join-PathSafe $env:APPDATA 'OpenRGB'
        [bool]($p -and (Test-Path -LiteralPath $p))
    }
    $out
}

Invoke-Section $report 'localApiProbes' {
    $out = [ordered]@{}

    # SignalRGB REST API (documented read-only GET endpoints).
    $sig = [ordered]@{ portOpen = (Test-TcpPort -HostName '127.0.0.1' -Port 16038) }
    if ($sig.portOpen) {
        $lighting = Invoke-LocalHttpGet 'http://127.0.0.1:16038/api/v1/lighting'
        $sig['lightingStatus'] = $lighting['status']
        if ($lighting['reachable'] -and $lighting['status'] -eq 200) {
            try {
                $j = $lighting['body'] | ConvertFrom-Json
                $sig['currentEffect'] = $j.data.attributes.name
                $sig['enabled'] = $j.data.attributes.enabled
                $sig['globalBrightness'] = $j.data.attributes.global_brightness
            }
            catch { $sig['lightingBody'] = $lighting['body'].Substring(0, [math]::Min(500, $lighting['body'].Length)) }
        }
        elseif ($lighting['reachable']) {
            $sig['lightingBody'] = $lighting['body'].Substring(0, [math]::Min(500, $lighting['body'].Length))
        }
        else { $sig['lightingError'] = $lighting['error'] }
        $effects = Invoke-LocalHttpGet 'http://127.0.0.1:16038/api/v1/lighting/effects'
        $sig['effectsStatus'] = $effects['status']
        if ($effects['reachable'] -and $effects['status'] -eq 200) {
            try {
                $items = @(($effects['body'] | ConvertFrom-Json).data.items)
                $sig['effectCount'] = $items.Count
                $sig['effectNamesSample'] = @($items | Select-Object -First 60 | ForEach-Object { $_.attributes.name })
            }
            catch { }
        }
        $layout = Invoke-LocalHttpGet 'http://127.0.0.1:16038/api/v1/scenes/current_layout'
        $sig['currentLayoutStatus'] = $layout['status']
    }
    $out['signalRgb'] = $sig

    # SteelSeries GameSense: TCP connect test only. GameSense endpoints are POST-only and would register an
    # application inside SteelSeries GG, which is a configuration change that is out of scope for this audit.
    $gs = @()
    foreach ($cp in @($report['vendorConfiguration']['steelSeriesCoreProps'])) {
        if (-not ($cp -is [System.Collections.IDictionary]) -or -not $cp.Contains('addresses')) { continue }
        foreach ($name in @($cp['addresses'].Keys)) {
            $value = [string]$cp['addresses'][$name]
            $m = [regex]::Match($value, '(?:https?://)?([^:/]+):(\d+)')
            if ($m.Success) {
                $gs += [ordered]@{ file = $cp['path']; key = $name; host = $m.Groups[1].Value; port = [int]$m.Groups[2].Value; portOpen = (Test-TcpPort -HostName $m.Groups[1].Value -Port ([int]$m.Groups[2].Value)) }
            }
        }
    }
    $out['steelSeriesGameSense'] = $gs

    # OpenRGB SDK server (only to learn whether OpenRGB is already running).
    $out['openRgbSdkPortOpen'] = (Test-TcpPort -HostName '127.0.0.1' -Port 6742)
    $out
}

# ---------------------------------------------------------------------------
Invoke-Section $report 'eventLogs' {
    $start = (Get-Date).AddDays(-$EventDays)
    $ms = [int64]($EventDays * 86400000)
    $out = [ordered]@{ since = $start.ToString('o') }

    function ConvertTo-EventRow {
        param($e)
        $msg = $null
        try { $msg = $e.Message } catch { }
        if ($msg) { $msg = ($msg -replace '\s+', ' ').Trim(); if ($msg.Length -gt 500) { $msg = $msg.Substring(0, 500) + '...' } }
        $level = $null
        try { $level = $e.LevelDisplayName } catch { $level = "$($e.Level)" }
        [ordered]@{ time = $e.TimeCreated.ToString('o'); log = $e.LogName; provider = $e.ProviderName; id = $e.Id; level = $level; message = $msg }
    }

    # 1) Which System-log providers were active in the window (cheap: no message formatting).
    $providerCounts = @{}
    $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery('System', [System.Diagnostics.Eventing.Reader.PathType]::LogName, "*[System[TimeCreated[timediff(@SystemTime) <= $ms]]]")
    $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)
    try {
        while ($true) {
            $rec = $reader.ReadEvent()
            if ($null -eq $rec) { break }
            $pn = $rec.ProviderName
            if ($providerCounts.ContainsKey($pn)) { $providerCounts[$pn]++ } else { $providerCounts[$pn] = 1 }
            $rec.Dispose()
        }
    }
    finally { $reader.Dispose() }
    $out['systemProviderCounts'] = $providerCounts

    # 2) Network-, Wi-Fi-, hotspot-, ICS-, RAS- and power-related System providers.
    $providerRegex = '(?i)SharedAccess|icssvc|Tether|WLAN|Wi-?Fi|WiFi|Netwtw|mtk|rtw|rtl|Realtek|\brt6|\brt8|rtcx|e2f|Intel|NDIS|Kernel-Power|Power-Troubleshooter|RasMan|Rasl2tp|Tcpip|Dhcp|DNS-Client|Iphlpsvc|NlaSvc|NCSI|WFD|Wcmsvc|WwanSvc|Netman|Kernel-PnP'
    $matched = @($providerCounts.Keys | Where-Object { $_ -match $providerRegex })
    $out['systemProvidersMatched'] = $matched
    $sys = @()
    if ($matched.Count -gt 0) {
        $sys = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = $matched; StartTime = $start } -MaxEvents $MaxEventsPerLog -ErrorAction SilentlyContinue | ForEach-Object { ConvertTo-EventRow $_ })
    }
    $out['systemEvents'] = $sys

    # 3) Service start/stop events for the hotspot, ICS, WLAN and RAS services (display names are localized).
    $displayNames = @(Get-Service -Name $NetworkServiceNames -ErrorAction SilentlyContinue | ForEach-Object { $_.DisplayName })
    $scm = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = @(7031, 7034, 7036, 7040, 7043); StartTime = $start } -MaxEvents 20000 -ErrorAction SilentlyContinue | Where-Object {
            $first = $null
            try { $first = [string]$_.Properties[0].Value } catch { }
            $first -and ($displayNames -contains $first)
        } | Select-Object -First $MaxEventsPerLog | ForEach-Object { ConvertTo-EventRow $_ })
    $out['networkServiceStateChanges'] = $scm

    # 4) PPPoE dial / disconnect history.
    $out['rasClientEvents'] = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'RasClient'; StartTime = $start } -MaxEvents $MaxEventsPerLog -ErrorAction SilentlyContinue | ForEach-Object { ConvertTo-EventRow $_ })

    # 5) Operational channels related to Wi-Fi, hotspot, network profile and connectivity detection.
    $channelRegex = '(?i)WLAN-AutoConfig/Operational|NetworkProfile/Operational|NCSI/Operational|Tether|SharedAccess|icssvc|WiFiDirect|WFD|MobileHotspot|WiFiNetworkManager|Dhcp-Client/Admin|WiFi-?Direct'
    $channels = @(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.LogName -match $channelRegex -and $_.RecordCount -gt 0 })
    $ops = [ordered]@{}
    foreach ($ch in $channels) {
        $ops[$ch.LogName] = @(Get-WinEvent -FilterHashtable @{ LogName = $ch.LogName; StartTime = $start } -MaxEvents $MaxEventsPerLog -ErrorAction SilentlyContinue | ForEach-Object { ConvertTo-EventRow $_ })
    }
    $out['operationalChannels'] = $ops
    $out
}

# ---------------------------------------------------------------------------
# Write redacted output (JSON first, so the evidence survives even if the summary fails)
# ---------------------------------------------------------------------------
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$json = $report | ConvertTo-Json -Depth 12
[System.IO.File]::WriteAllText((Join-Path $OutputDir 'audit-report.json'), (Protect-Text $json), $utf8NoBom)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
function Get-Value { param($Dict, [string[]]$Path) $cur = $Dict; foreach ($p in $Path) { if ($cur -is [System.Collections.IDictionary] -and $cur.Contains($p)) { $cur = $cur[$p] } else { return $null } }; return $cur }

try {
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("SETUP CONTROLLER - AUDIT SUMMARY (collector v$ScriptVersion, $((Get-Date).ToString('yyyy-MM-dd HH:mm')))")
    $lines.Add('Read-only collection. Review before sharing; sensitive values are redacted.')
    $lines.Add('')
    $w = $report['windows']
    if ($w -is [System.Collections.IDictionary] -and $w.Contains('caption')) { $lines.Add("[WINDOWS] $($w.caption) $($w.displayVersion) build $($w.build).$($w.ubr) | uptime $($w.uptimeHours) h") }
    $h = $report['hardware']
    if ($h -is [System.Collections.IDictionary] -and $h.Contains('baseBoardProduct')) { $lines.Add("[BOARD] $($h.baseBoardManufacturer) $($h.baseBoardProduct) (board version '$($h.baseBoardVersion)') BIOS $($h.biosVersion) $($h.biosReleaseDate)") }

    $lines.Add('')
    $lines.Add('[DEVICES] Known lighting controllers found (VID:PID, interfaces):')
    $usb = @($report['usbHidDevices'])
    $knownFound = @($usb | Where-Object { $_ -is [System.Collections.IDictionary] -and $_.Contains('knownAs') })
    if ($knownFound.Count -eq 0) { $lines.Add('  none of the reference IDs were found - see usbHidDevices / inputAndAudioDevices') }
    foreach ($g in ($knownFound | Group-Object -Property { $_['vid'] + ':' + $_['pid'] })) {
        $first = $g.Group[0]
        $ifs = @($g.Group | ForEach-Object { $x = 'MI_' + $(if ($_['interface']) { $_['interface'] } else { '--' }); if ($_['collection']) { $x += '/COL' + $_['collection'] }; if ($_.Contains('hidUsagePage') -and $_['hidUsagePage']) { $x += "(UP:$($_['hidUsagePage']) U:$($_['hidUsage']))" }; $x } | Sort-Object -Unique)
        $lines.Add("  $($g.Name)  $($first['knownAs'])")
        $lines.Add("      interfaces: $($ifs -join ', ')")
    }
    $lines.Add('[DEVICES] Keyboards / mice / audio endpoints present:')
    foreach ($d in @($report['inputAndAudioDevices'])) {
        if ($d -is [System.Collections.IDictionary] -and $d.Contains('class')) {
            $id = $(if ($d['vid']) { "$($d['vid']):$($d['pid'])" } else { 'n/a' })
            $lines.Add("  [$($d['class'])] $($d['friendlyName']) ($id) $($d['status'])")
        }
    }

    $lines.Add('')
    $lines.Add('[SOFTWARE] Vendor software found:')
    foreach ($s in @(Get-Value $report @('installedSoftware', 'win32'))) { if ($s -is [System.Collections.IDictionary]) { $lines.Add("  $($s['name']) $($s['version'])") } }
    foreach ($s in @(Get-Value $report @('installedSoftware', 'storeApps'))) { if ($s -is [System.Collections.IDictionary] -and $s.Contains('name')) { $lines.Add("  [Store] $($s['name']) $($s['version'])") } }
    $lines.Add('[SOFTWARE] Vendor processes running:')
    foreach ($p in @($report['processes'])) { if ($p -is [System.Collections.IDictionary] -and $p.Contains('name')) { $lines.Add("  $($p['name']) (pid $($p['processId']))") } }
    $lines.Add('[SOFTWARE] Vendor services:')
    foreach ($s in @($report['services'])) { if ($s -is [System.Collections.IDictionary] -and $s['category'] -eq 'vendor') { $lines.Add("  $($s['name']) [$($s['state']), $($s['startMode'])]") } }

    $lines.Add('')
    $sig = Get-Value $report @('localApiProbes', 'signalRgb')
    if ($sig) { $lines.Add("[SIGNALRGB API] port 16038 open: $($sig['portOpen']); GET /lighting status: $($sig['lightingStatus']); effect: $($sig['currentEffect']); enabled: $($sig['enabled']); brightness: $($sig['globalBrightness'])") }
    foreach ($g in @(Get-Value $report @('localApiProbes', 'steelSeriesGameSense'))) { if ($g -is [System.Collections.IDictionary]) { $lines.Add("[GAMESENSE] $($g['key']) -> $($g['host']):$($g['port']) open: $($g['portOpen'])") } }
    $lines.Add("[OPENRGB] SDK port 6742 open: $(Get-Value $report @('localApiProbes', 'openRgbSdkPortOpen'))")

    $lines.Add('')
    $hs = $report['mobileHotspot']
    if ($hs -is [System.Collections.IDictionary] -and $hs.Contains('operationalState')) {
        $lines.Add("[HOTSPOT] state: $($hs['operationalState']) | clients: $($hs['clientCount'])/$($hs['maxClientCount']) | band: $($hs['band']) | auth: $($hs['authenticationKind']) | no-connections timeout: $($hs['noConnectionsTimeoutEnabled'])")
        $lines.Add("[HOTSPOT] band support: $((($hs['bandSupported'].GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '))")
    }
    elseif ($hs -is [System.Collections.IDictionary]) { $lines.Add("[HOTSPOT] $(($hs.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ')") }
    foreach ($c in @(Get-Value $report @('internetConnectionSharing', 'connections'))) {
        if ($c -is [System.Collections.IDictionary] -and $c['sharingEnabled']) { $lines.Add("[ICS] $($c['name']) [$($c['mediaType'])] -> $($c['sharingRole'])") }
    }
    foreach ($e in @(Get-Value $report @('internetConnectionSharing', 'hostsIcs'))) { if ($e -is [pscustomobject]) { $lines.Add("[ICS DHCP] $($e.ip) $($e.hostName)") } }
    foreach ($p in @(Get-Value $report @('pppoe', 'pppInterfaces'))) { if ($p -is [System.Collections.IDictionary]) { $lines.Add("[PPPOE] $($p['name']) status=$($p['status']) mtu=$($p['ipv4Mtu'])") } }
    foreach ($a in @($report['networkAdapters'])) {
        if ($a -is [System.Collections.IDictionary] -and $a['isWifi'] -and $a['hardwareInterface']) {
            $lines.Add("[WIFI] $($a['description']) | driver $($a['driverProvider']) $($a['driverVersion']) ($($a['driverDate'])) | status $($a['status'])")
            if ($a.Contains('powerManagement') -and $a['powerManagement'] -is [System.Collections.IDictionary]) { $lines.Add("[WIFI] allow computer to turn off device: $($a['powerManagement']['allowComputerToTurnOffDevice'])") }
        }
    }

    $lines.Add('')
    $ev = $report['eventLogs']
    if ($ev -is [System.Collections.IDictionary] -and $ev.Contains('rasClientEvents')) {
        $lines.Add("[EVENTS] last $EventDays days:")
        $lines.Add("  RasClient (PPPoE) events by id: $((@($ev['rasClientEvents']) | Group-Object { $_['id'] } | ForEach-Object { "$($_.Name)x$($_.Count)" }) -join ', ')")
        $lines.Add("  Hotspot/ICS/WLAN/RAS service state changes: $(@($ev['networkServiceStateChanges']).Count)")
        $lines.Add("  Matched System events by provider: $((@($ev['systemEvents']) | Group-Object { $_['provider'] } | ForEach-Object { "$($_.Name)x$($_.Count)" }) -join ', ')")
    }
    $lines.Add('')
    $lines.Add("Section timings (s): $((($report['_timings'].GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '))")
    $summarySafe = Protect-Text ($lines -join "`r`n")
}
catch {
    $summarySafe = "Summary generation failed: $((Get-InnermostException $_.Exception).Message). The full evidence is in audit-report.json."
}
[System.IO.File]::WriteAllText((Join-Path $OutputDir 'audit-summary.txt'), $summarySafe, $utf8NoBom)

Write-Host ''
Write-Host $summarySafe
Write-Host ''
Write-Host "Done. Files written to: $OutputDir" -ForegroundColor Green
Write-Host 'Please review both files before sharing them.' -ForegroundColor Green
