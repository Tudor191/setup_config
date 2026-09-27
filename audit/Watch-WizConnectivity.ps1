<#
.SYNOPSIS
    Setup Controller - long-running WiZ connectivity monitor (READ-ONLY), version 2.

.DESCRIPTION
    Built to catch the WiZ bulb failure while it happens naturally, and to show which layer fails first.

    Every -IntervalSeconds (default 10 s), without sending anything to the bulb, it records:
      PC internet (TCP 443) and DNS; Mobile Hotspot state, client count and interface; the hotspot virtual
      adapter; the Realtek Wi-Fi adapter's status, PnP status, device power state (D0/D3), re-enumeration
      time and traffic counters; hotspot/ICS/WLAN service state and process IDs; whether the bulb is in the
      hotspot's client list; its DHCP lease (hosts.ics); its ARP state on the hotspot interface; user idle time.

    Every -ProbeSeconds (default 30 s), and every check while a failure is in progress, it also sends one
    ICMP ping and the read-only WiZ query getPilot (UDP 38899).

    Windows events are collected continuously: System-log events from the Wi-Fi driver, NDIS, PnP, power,
    TCP/IP, DHCP and ICS providers, start/stop of the hotspot/ICS/WLAN services, and the WLAN-AutoConfig,
    NetworkProfile, NCSI, Kernel-PnP and any tethering/Wi-Fi-Direct operational channels.

    When the bulb stops answering (two failed probes in a row), it takes a detailed snapshot, beeps, and
    writes an incident analysis that answers: did the hotspot stay on, did the adapter stay up or get
    powered down / re-initialised, was there internet, was the bulb still associated / in DHCP / pingable,
    did UDP 38899 stop, which Windows events happened around that moment, and which layer failed first.

    Press M in this window when you notice Alexa can no longer control the bulb. The moment is recorded
    and a snapshot is taken (this also catches a cloud-only failure where everything local still works).

    What it never does: change any setting, driver, adapter, power option, registry, firewall, hotspot or
    service; restart anything; send any command to the bulb other than getPilot/getSystemConfig; keep the
    PC awake. The only change is inside this console window: "QuickEdit" text selection is switched off for
    this window, so a stray mouse click cannot pause the monitor for hours. It is back to normal when the
    window closes.

    Output folder .\output\longrun-<timestamp>\ :
      watch-report.txt   run summary, incident analysis (A-K), all state changes   <- send this
      watch.csv          one row per check                                       <- send this
      events.log         all captured Windows events                             <- send this
      changes.log        state changes as they happen (also inside the report)
      snapshot-*.txt     detailed state at each incident / key press (also inside the report)

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Watch-WizConnectivity.ps1
#>
[CmdletBinding()]
param(
    [string]$WizIp,
    [ValidateRange(5, 300)][int]$IntervalSeconds = 10,
    [ValidateRange(10, 900)][int]$ProbeSeconds = 30,
    [ValidateRange(0, 72)][double]$DurationHours = 0,
    [string]$InternetProbeHost = '1.1.1.1',
    [string]$InternetProbeHost2 = '8.8.8.8',
    [string]$DnsProbeName = 'www.msftconnecttest.com',
    [string]$OutputDir
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\AuditCommon.ps1')

$ScriptVersion = '2.0.0'
if (-not $OutputDir) {
    $OutputDir = Join-Path $PSScriptRoot ('output\longrun-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$csvPath = Join-Path $OutputDir 'watch.csv'
$changesPath = Join-Path $OutputDir 'changes.log'
$eventsPath = Join-Path $OutputDir 'events.log'
$reportPath = Join-Path $OutputDir 'watch-report.txt'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
Register-StandardRedactions

$HealthServices = @('icssvc', 'SharedAccess', 'WlanSvc')
$WatchedServices = @('icssvc', 'SharedAccess', 'WlanSvc', 'WFDSConMgrSvc')

function Get-Now { return (Get-Date) }
function Format-Time { param([datetime]$T) return $T.ToString('yyyy-MM-dd HH:mm:ss') }

function Write-Change {
    param([string]$Text)
    Add-Content -LiteralPath $changesPath -Value (Protect-Text $Text) -Encoding UTF8
}

# ---------------------------------------------------------------------------
# Console helpers (this window only)
# ---------------------------------------------------------------------------
$script:NativeOk = $false
try {
    Add-Type -Namespace SetupAudit -Name Native -MemberDefinition @'
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
public struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }
[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern System.IntPtr GetStdHandle(int nStdHandle);
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern bool GetConsoleMode(System.IntPtr hConsoleHandle, out uint lpMode);
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern bool SetConsoleMode(System.IntPtr hConsoleHandle, uint dwMode);
public static long IdleMilliseconds() {
    LASTINPUTINFO l = new LASTINPUTINFO();
    l.cbSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf(l);
    if (!GetLastInputInfo(ref l)) { return -1; }
    return (long)(unchecked((uint)System.Environment.TickCount - l.dwTime));
}
'@ -ErrorAction Stop
    $script:NativeOk = $true
}
catch { }

function Get-IdleSeconds {
    if (-not $script:NativeOk) { return '' }
    try { $ms = [SetupAudit.Native]::IdleMilliseconds(); if ($ms -ge 0) { return [int]($ms / 1000) } } catch { }
    return ''
}

function Disable-QuickEditForThisWindow {
    # A click in a console with QuickEdit on freezes the script until Esc/Enter. This affects only this
    # console window's current input mode; nothing is stored and it ends when the window closes.
    if (-not $script:NativeOk) { return $false }
    try {
        $h = [SetupAudit.Native]::GetStdHandle(-10)
        $mode = [uint32]0
        if (-not [SetupAudit.Native]::GetConsoleMode($h, [ref]$mode)) { return $false }
        $new = ($mode -band (-bnot [uint32]0x0040)) -bor [uint32]0x0080
        return [SetupAudit.Native]::SetConsoleMode($h, [uint32]$new)
    }
    catch { return $false }
}

# ---------------------------------------------------------------------------
# Read-only state readers
# ---------------------------------------------------------------------------
function Get-HotspotConfigInfo {
    if (-not (Initialize-WinRtNetworking)) { return $null }
    $tmType = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]
    $infoType = [Windows.Networking.Connectivity.NetworkInformation]
    $profiles = @()
    $ip = $infoType::GetInternetConnectionProfile()
    if ($ip) { $profiles += $ip }
    $profiles += @($infoType::GetConnectionProfiles())
    foreach ($p in $profiles) {
        try {
            $m = $tmType::CreateFromConnectionProfile($p)
            $cfg = $m.GetCurrentAccessPointConfiguration()   # the passphrase is never read
            $auth = 'n/a'; try { $auth = $cfg.AuthenticationKind.ToString() } catch { }
            $timeout = 'n/a'; try { $timeout = $tmType::IsNoConnectionsTimeoutEnabled() } catch { }
            return [pscustomobject]@{ ssid = $cfg.Ssid; band = $cfg.Band.ToString(); auth = $auth; noConnectionsTimeout = $timeout; maxClients = $m.MaxClientCount }
        }
        catch { continue }
    }
    return $null
}

function Get-HotspotClientDetails {
    if (-not (Initialize-WinRtNetworking)) { return @() }
    $tmType = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]
    $infoType = [Windows.Networking.Connectivity.NetworkInformation]
    $profiles = @()
    $ip = $infoType::GetInternetConnectionProfile()
    if ($ip) { $profiles += $ip }
    $profiles += @($infoType::GetConnectionProfiles())
    foreach ($p in $profiles) {
        try {
            $m = $tmType::CreateFromConnectionProfile($p)
            if ("$($m.TetheringOperationalState)" -ne 'On') { continue }
            return @($m.GetTetheringClients() | ForEach-Object {
                    "mac=$(Protect-WizMac $_.MacAddress) names=$((@($_.HostNames | ForEach-Object { $_.DisplayName })) -join ',')"
                })
        }
        catch { continue }
    }
    return @()
}

function Get-DevicePowerInfo {
    <# Device power state (from DEVPKEY_Device_PowerData), PnP status and last (re)arrival time. #>
    param([string]$InstanceId)
    $info = [ordered]@{ pnp = 'unknown'; dState = 'unknown'; lastArrival = '' }
    if (-not $InstanceId) { return $info }
    try { $info.pnp = "$((Get-PnpDevice -InstanceId $InstanceId -ErrorAction Stop).Status)" } catch { }
    # Each property is read on its own so that one unsupported key cannot hide the other.
    try {
        $p = Get-PnpDeviceProperty -InstanceId $InstanceId -KeyName 'DEVPKEY_Device_PowerData' -ErrorAction Stop
        if ($p.Data -is [byte[]] -and $p.Data.Length -ge 8) {
            $state = [BitConverter]::ToInt32($p.Data, 4)   # CM_POWER_DATA.PD_MostRecentPowerState
            $info.dState = $(switch ($state) { 1 { 'D0' } 2 { 'D1' } 3 { 'D2' } 4 { 'D3' } default { "unspecified($state)" } })
        }
    }
    catch { }
    try {
        $p = Get-PnpDeviceProperty -InstanceId $InstanceId -KeyName 'DEVPKEY_Device_LastArrivalDate' -ErrorAction Stop
        if ($p.Data) { $info.lastArrival = ([datetime]$p.Data).ToString('yyyy-MM-dd HH:mm:ss') }
    }
    catch { }
    return $info
}

function Get-AdapterCounters {
    param([string]$Name, [switch]$Hidden)
    try {
        $s = $(if ($Hidden) { Get-NetAdapterStatistics -Name $Name -IncludeHidden -ErrorAction Stop } else { Get-NetAdapterStatistics -Name $Name -ErrorAction Stop })
        return [pscustomobject]@{ rx = [int64]$s.ReceivedBytes; tx = [int64]$s.SentBytes }
    }
    catch { return $null }
}

function Get-ServiceSnapshot {
    $out = [ordered]@{}
    try {
        $filter = ($WatchedServices | ForEach-Object { "Name='$_'" }) -join ' OR '
        foreach ($s in @(Get-CimInstance Win32_Service -Filter $filter -ErrorAction Stop)) { $out[$s.Name] = [pscustomobject]@{ state = $s.State; pid = $s.ProcessId } }
    }
    catch { }
    return $out
}

function Test-Dns {
    param([string]$Name, [string]$Server)
    try {
        if ($Server) { $null = Resolve-DnsName -Name $Name -Type A -Server $Server -DnsOnly -QuickTimeout -ErrorAction Stop }
        else { $null = Resolve-DnsName -Name $Name -Type A -DnsOnly -QuickTimeout -ErrorAction Stop }
        return 'OK'
    }
    catch { return 'FAIL' }
}

# ---------------------------------------------------------------------------
# Windows events
# ---------------------------------------------------------------------------
$script:SeenEvents = New-Object 'System.Collections.Generic.HashSet[string]'
$script:EventHistory = New-Object System.Collections.Generic.List[object]
$script:Channels = @()
$script:SysProviderRegex = '(?i)SharedAccess|icssvc|Tether|WLAN|Wi-?Fi|WiFi|NDIS|Kernel-Power|Power-Troubleshooter|Kernel-PnP|Tcpip|Dhcp|Iphlpsvc|NlaSvc|NCSI|WFD|Wcmsvc|Netman|Realtek|\brtw|\brtl'

function Get-EventCategory {
    param([string]$Log, [string]$Provider, [string]$Service)
    if ($Service) { return 'hotspot-service' }
    # The Wi-Fi driver's own provider is checked first (its name may contain "wlan").
    if ($Provider -match $script:AdapterProviderRegex -or $Provider -match '(?i)NDIS|Realtek|\brtw|\brtl') { return 'adapter' }
    if ($Provider -match '(?i)SharedAccess|icssvc|Tether|WFD|WiFiDirect' -or $Log -match '(?i)Tether|SharedAccess|icssvc|WiFiDirect|WFD|MobileHotspot') { return 'hotspot-service' }
    if ($Provider -match '(?i)WLAN|WiFi|Wi-Fi' -or $Log -match '(?i)WLAN') { return 'wlan' }
    if ($Provider -match '(?i)Kernel-PnP' -or $Log -match '(?i)Kernel-PnP') { return 'pnp' }
    if ($Provider -match '(?i)Kernel-Power|Power-Troubleshooter') { return 'power' }
    return 'network'
}

function Read-NewEvents {
    param([datetime]$Since)
    $rows = New-Object System.Collections.Generic.List[object]
    $sources = @(@{ log = 'System'; all = $false }) + @($script:Channels | ForEach-Object { @{ log = $_; all = $true } })
    foreach ($src in $sources) {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = $src.log; StartTime = $Since } -ErrorAction SilentlyContinue)
        foreach ($e in $events) {
            $key = "$($e.LogName)|$($e.RecordId)"
            if ($script:SeenEvents.Contains($key)) { continue }
            $service = $null
            $keep = $src.all
            if (-not $keep) {
                if ($e.ProviderName -match $script:SysProviderRegex -or ($script:AdapterProviderRegex -and $e.ProviderName -match $script:AdapterProviderRegex)) { $keep = $true }
                elseif ($e.ProviderName -eq 'Service Control Manager') {
                    $service = Get-ScmEventServiceName $e
                    if ($service -and ($WatchedServices -contains $service)) { $keep = $true }
                }
            }
            if (-not $keep) { continue }
            [void]$script:SeenEvents.Add($key)
            $msg = $null
            try { $msg = $e.Message } catch { }
            if ($msg) { $msg = ($msg -replace '\s+', ' ').Trim(); if ($msg.Length -gt 400) { $msg = $msg.Substring(0, 400) + '...' } }
            $level = $null
            try { $level = $e.LevelDisplayName } catch { $level = "$($e.Level)" }
            $rows.Add([pscustomobject]@{
                    time     = $e.TimeCreated
                    log      = $e.LogName
                    provider = $e.ProviderName
                    id       = $e.Id
                    level    = $level
                    service  = $service
                    category = (Get-EventCategory -Log $e.LogName -Provider $e.ProviderName -Service $service)
                    message  = (Protect-Text $msg)
                })
        }
    }
    $sorted = @($rows | Sort-Object time)
    foreach ($r in $sorted) {
        $script:EventHistory.Add($r)
        Add-Content -LiteralPath $eventsPath -Encoding UTF8 -Value ("{0} | {1} | {2} | {3} | id {4} | {5} | {6}{7}" -f (Format-Time $r.time), $r.category, $r.log, $r.provider, $r.id, $r.level, $(if ($r.service) { "[$($r.service)] " } else { '' }), $r.message)
    }
    return $sorted
}

function Get-EventsBetween {
    param([datetime]$From, [datetime]$To, [string[]]$Categories)
    return @($script:EventHistory | Where-Object { $_.time -ge $From -and $_.time -le $To -and (-not $Categories -or ($Categories -contains $_.category)) })
}

function Format-EventLine { param($e) return ("    {0} [{1}] {2} id {3} {4}{5}" -f (Format-Time $e.time), $e.category, $e.provider, $e.id, $(if ($e.service) { "[$($e.service)] " } else { '' }), $(if ($e.message) { $e.message.Substring(0, [math]::Min(220, $e.message.Length)) } else { '' })) }

# ---------------------------------------------------------------------------
# Start-up: identify bulb, adapters, event sources; record the configuration
# ---------------------------------------------------------------------------
if ($PSVersionTable.PSEdition -ne 'Desktop') {
    Write-Warning 'PowerShell 7 detected. The Mobile Hotspot state cannot be read here. Please run with powershell.exe (Windows PowerShell 5.1).'
}

$hotspotCfg = $null
try { $hotspotCfg = Get-HotspotConfigInfo } catch { }
if ($hotspotCfg) { Add-RedactionToken -Value $hotspotCfg.ssid -Label 'hotspot-ssid' }

# Bulb: IP, MAC and DHCP host name
$bulbMac = ''
$bulbHost = ''
$bulbInfo = $null
if (-not $WizIp) {
    $ics = @()
    try { $ics = @(Get-HostsIcsEntries) } catch { }
    $cands = @($ics | Where-Object { $_.hostName -match '^(?i)wiz_' } | ForEach-Object { $_.ip }) + @($ics | ForEach-Object { $_.ip })
    $hsTmp = Get-HotspotInterfaceIPv4
    if ($hsTmp) {
        $cands += @(Get-NetNeighbor -InterfaceIndex $hsTmp.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress })
    }
    $ownIp = $(if ($hsTmp) { $hsTmp.IPAddress } else { '' })
    foreach ($c in ($cands | Where-Object { $_ -and $_ -ne $ownIp -and $_ -notlike '*.255' } | Select-Object -Unique)) {
        $r = Invoke-WizQuery -IpAddress $c -Method getSystemConfig -TimeoutMs 800 -Attempts 2
        if ($r.ok -and $r.json -and $r.json.PSObject.Properties['result']) { $WizIp = $c; $bulbInfo = $r.json.result; break }
    }
    if (-not $WizIp) { throw 'No WiZ bulb answered. Make sure it is on, then run again with -WizIp <address> (see Probe-WizBulb.ps1).' }
}
else {
    $r = Invoke-WizQuery -IpAddress $WizIp -Method getSystemConfig -TimeoutMs 1000 -Attempts 3
    if ($r.ok -and $r.json -and $r.json.PSObject.Properties['result']) { $bulbInfo = $r.json.result }
    else { Write-Warning "The bulb at $WizIp did not answer now; monitoring starts anyway." }
}
if ($bulbInfo) { $bulbMac = ConvertTo-NormalizedMac ([string]$bulbInfo.mac) }
try { $e0 = @(Get-HostsIcsEntries) | Where-Object { $_.ip -eq $WizIp } | Select-Object -First 1; if ($e0) { $bulbHost = $e0.hostName } } catch { }
$maskedMac = $(if ($bulbMac) { Protect-WizMac $bulbMac } else { 'unknown' })

# Adapters
$wifi = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.NdisPhysicalMedium -eq 9 -and $_.HardwareInterface } | Select-Object -First 1
$wifiName = $(if ($wifi) { $wifi.Name } else { $null })
$wifiPnpId = $(if ($wifi) { $wifi.PnPDeviceID } else { $null })
$driverService = $null
if ($wifiPnpId) { try { $driverService = (Get-PnpDeviceProperty -InstanceId $wifiPnpId -KeyName 'DEVPKEY_Device_Service' -ErrorAction Stop).Data } catch { } }
$script:AdapterProviderRegex = $(if ($driverService) { '(?i)^' + [regex]::Escape([string]$driverService) } else { '(?i)^$' })

# Event channels that exist on this PC
$channelRegex = '(?i)WLAN-AutoConfig/Operational|NetworkProfile/Operational|NCSI/Operational|Tether|SharedAccess|icssvc|WiFiDirect|WFD|MobileHotspot|WiFiNetworkManager|Wcmsvc/Operational|Kernel-PnP/Configuration|Dhcp-Client/Admin'
try { $script:Channels = @(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.LogName -match $channelRegex -and $_.IsEnabled } | ForEach-Object { $_.LogName }) } catch { }

# Configuration record (read-only)
$startTime = Get-Now
$config = New-Object System.Collections.Generic.List[string]
$config.Add("Monitor version $ScriptVersion, started $(Format-Time $startTime), check every $IntervalSeconds s, bulb probe every $ProbeSeconds s")
$config.Add("Windows PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition)); administrator: $(Test-IsAdministrator)")
$config.Add("Bulb: IP $WizIp, MAC $maskedMac, DHCP name $(if ($bulbHost) { $bulbHost } else { 'unknown' }), module $(if ($bulbInfo) { $bulbInfo.moduleName } else { '?' }), firmware $(if ($bulbInfo) { $bulbInfo.fwVersion } else { '?' })")
if ($hotspotCfg) { $config.Add("Hotspot: band $($hotspotCfg.band), security $($hotspotCfg.auth), no-connections timeout $($hotspotCfg.noConnectionsTimeout), max clients $($hotspotCfg.maxClients)") }
else { $config.Add('Hotspot configuration: not readable (WinRT unavailable)') }
if ($wifi) {
    $config.Add("Wi-Fi adapter: '$($wifi.Name)' $($wifi.InterfaceDescription), driver $($wifi.DriverProvider) $($wifi.DriverVersionString) ($($wifi.DriverDate)), driver service '$driverService'")
    try {
        $pm = Get-NetAdapterPowerManagement -Name $wifi.Name -ErrorAction Stop
        $config.Add("Wi-Fi power management: AllowComputerToTurnOffDevice=$($pm.AllowComputerToTurnOffDevice) DeviceSleepOnDisconnect=$($pm.DeviceSleepOnDisconnect) SelectiveSuspend=$($pm.SelectiveSuspend)")
    }
    catch { $config.Add("Wi-Fi power management: not readable ($($_.Exception.Message))") }
    $p0 = Get-DevicePowerInfo $wifiPnpId
    $config.Add("Wi-Fi device at start: PnP $($p0.pnp), power state $($p0.dState), last (re)arrival $($p0.lastArrival)")
}
else { $config.Add('Wi-Fi adapter: not found') }
$config.Add('Power plan (read-only queries):')
foreach ($q in @(@('/getactivescheme'), @('/query', 'SCHEME_CURRENT', '19cbb8fa-5279-450e-9fac-8a3d5fedd0c1', '12bbebe6-58d6-4636-95bb-3217ef867c1a'), @('/query', 'SCHEME_CURRENT', 'SUB_SLEEP', 'STANDBYIDLE'), @('/query', 'SCHEME_CURRENT', 'SUB_VIDEO', 'VIDEOIDLE'))) {
    foreach ($l in (Invoke-NativeLines 'powercfg.exe' $q)) { if ($l.Trim()) { $config.Add('    ' + $l.Trim()) } }
}
try {
    $active = @(Get-NetNeighbor -IPAddress $WizIp -ErrorAction SilentlyContinue | ForEach-Object { "ifIndex=$($_.InterfaceIndex) '$($_.InterfaceAlias)' state=$($_.State)" })
    $persistent = @(Get-NetNeighbor -IPAddress $WizIp -PolicyStore PersistentStore -ErrorAction SilentlyContinue | ForEach-Object { "ifIndex=$($_.InterfaceIndex) '$($_.InterfaceAlias)' state=$($_.State)" })
    $config.Add("ARP entries for the bulb IP: $(if ($active.Count) { $active -join '; ' } else { 'none' }); static (persistent) entries: $(if ($persistent.Count) { $persistent -join '; ' } else { 'none' })")
}
catch { }
$config.Add("Event channels watched: System (filtered) + $(if ($script:Channels.Count) { $script:Channels -join ', ' } else { 'none found' })")
$config.Add("QuickEdit disabled for this window: $(Disable-QuickEditForThisWindow)")
Write-Change "$(Format-Time $startTime) START $($config -join ' | ')"

# Prime the event history with the 30 minutes before the start (context only).
try { $null = Read-NewEvents -Since $startTime.AddMinutes(-30) } catch { }
$lastEventPoll = Get-Now

# ---------------------------------------------------------------------------
# State tracking
# ---------------------------------------------------------------------------
$ping = New-Object System.Net.NetworkInformation.Ping
$deadline = $(if ($DurationHours -gt 0) { $startTime.AddHours($DurationHours) } else { [datetime]::MaxValue })
$watched = @('defaultRouteIf', 'internet', 'dns', 'hotspotState', 'hotspotClients', 'hotspotIf', 'hotspotAdapter', 'wifiStatus', 'wifiPnp', 'wifiDState', 'services', 'bulbIp', 'bulbAssociated', 'bulbInHostsIcs', 'bulbLeaseEnd', 'bulbArpClass', 'bulbPing', 'bulbUdp')
$layerOrder = @('internet', 'dns', 'hotspotState', 'hotspotAdapter', 'wifiPnp', 'wifiDState', 'services', 'bulbAssociated', 'bulbInHostsIcs', 'bulbArpClass', 'bulbPing', 'bulbUdp')
$changeHistory = New-Object System.Collections.Generic.List[object]
$indicators = New-Object System.Collections.Generic.List[object]
$marks = New-Object System.Collections.Generic.List[object]
$incidents = New-Object System.Collections.Generic.List[object]
$snapshots = New-Object System.Collections.Generic.List[string]
$firstBad = @{}
$previous = $null
$probe = [ordered]@{ bulbPing = 'not-yet'; bulbPingMs = ''; bulbUdp = 'not-yet'; bulbUdpMs = ''; bulbRssi = ''; bulbOn = '' }
$lastProbeTime = $null
$lastBulbOk = $null
$suspectSince = $null
$current = $null
$prevCounters = @{}
$prevArrival = $null
$prevDState = $null
$prevHotspotIf = $null
$prevPids = @{}
$lastTickTime = $null
$lastReportWrite = Get-Now
$ticks = 0

function Add-Indicator {
    param([datetime]$T, [string]$Kind, [string]$Text)
    $script:indicators.Add([pscustomobject]@{ time = $T; kind = $Kind; text = $Text })
    Write-Change "$(Format-Time $T) INDICATOR [$Kind] $Text"
}

function Get-LayerHealth {
    <# $true = healthy, $false = failed, $null = unknown (not counted) #>
    param($Row)
    $h = [ordered]@{}
    $h['internet'] = ($Row.internet -eq 'OK')
    $h['dns'] = ($Row.dns -eq 'OK')
    $h['hotspotState'] = $(if ($Row.hotspotState -eq 'n/a') { $null } else { $Row.hotspotState -eq 'On' })
    $h['hotspotAdapter'] = ($Row.hotspotAdapter -eq 'Up')
    $h['wifiPnp'] = $(if ($Row.wifiPnp -eq 'unknown') { $null } else { $Row.wifiPnp -eq 'OK' })
    $h['wifiDState'] = $(if ($Row.wifiDState -notmatch '^D\d$') { $null } else { $Row.wifiDState -eq 'D0' })
    $h['services'] = ($Row.services -notmatch '(icssvc|SharedAccess|WlanSvc)=(?!Running)')
    $h['bulbAssociated'] = $(if ($Row.bulbAssociated -eq 'unknown') { $null } else { $Row.bulbAssociated -eq 'YES' })
    $h['bulbInHostsIcs'] = ($Row.bulbInHostsIcs -eq 'YES')
    $h['bulbArpClass'] = ($Row.bulbArpClass -eq 'OK')
    $h['bulbPing'] = $(if ($Row.bulbPing -eq 'not-yet') { $null } else { $Row.bulbPing -eq 'OK' })
    $h['bulbUdp'] = $(if ($Row.bulbUdp -eq 'not-yet') { $null } else { $Row.bulbUdp -eq 'OK' })
    return $h
}

function Invoke-BulbProbe {
    param([string]$Ip)
    $res = [ordered]@{ bulbPing = 'NO_IP'; bulbPingMs = ''; bulbUdp = 'NO_IP'; bulbUdpMs = ''; bulbRssi = ''; bulbOn = '' }
    if (-not $Ip) { return $res }
    try {
        $reply = $script:ping.Send($Ip, 1000)
        $res.bulbPing = $(if ($reply.Status -eq 'Success') { 'OK' } else { "$($reply.Status)" })
        $res.bulbPingMs = $(if ($reply.Status -eq 'Success') { $reply.RoundtripTime } else { '' })
    }
    catch { $res.bulbPing = 'ERROR' }
    $q = Invoke-WizQuery -IpAddress $Ip -Method getPilot -TimeoutMs 1500 -Attempts 2
    if ($q.ok -and $q.json -and $q.json.PSObject.Properties['result']) {
        $res.bulbUdp = 'OK'
        $res.bulbUdpMs = $q.rttMs
        if ($q.json.result.PSObject.Properties['rssi']) { $res.bulbRssi = $q.json.result.rssi }
        if ($q.json.result.PSObject.Properties['state']) { $res.bulbOn = $q.json.result.state }
    }
    elseif ($q.ok) { $res.bulbUdp = 'BAD_REPLY' }
    elseif ("$($q.error)" -like 'port-unreachable*') { $res.bulbUdp = 'PORT_UNREACHABLE' }
    elseif ("$($q.error)" -eq 'timeout') { $res.bulbUdp = 'TIMEOUT' }
    else { $res.bulbUdp = 'ERROR' }
    return $res
}

function Write-Snapshot {
    param([string]$Reason, $Row)
    $t = Get-Now
    $path = Join-Path $OutputDir ('snapshot-' + $t.ToString('yyyyMMdd-HHmmss') + '.txt')
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add("SNAPSHOT $(Format-Time $t) - $Reason")
    if ($Row) { $l.Add('State: ' + (($Row.Keys | ForEach-Object { "$_=$($Row[$_])" }) -join ' ')) }
    $l.Add('Extra probes (ping / getPilot / getSystemConfig):')
    for ($i = 1; $i -le 3; $i++) {
        $pr = Invoke-BulbProbe $script:WizIp
        $l.Add("  #$i ping=$($pr.bulbPing) $($pr.bulbPingMs)ms udp=$($pr.bulbUdp) $($pr.bulbUdpMs)ms rssi=$($pr.bulbRssi)")
        Start-Sleep -Milliseconds 700
    }
    $sc = Invoke-WizQuery -IpAddress $script:WizIp -Method getSystemConfig -TimeoutMs 1500 -Attempts 2
    $l.Add("  getSystemConfig: $(if ($sc.ok) { 'answered' } else { "no answer ($($sc.error))" })")
    $l.Add('Hotspot clients:')
    try { foreach ($c in @(Get-HotspotClientDetails)) { $l.Add("  $c") } } catch { $l.Add("  unreadable: $($_.Exception.Message)") }
    $hs = Get-HotspotInterfaceIPv4
    $l.Add("Hotspot interface: $(if ($hs) { "$($hs.InterfaceAlias) ifIndex $($hs.InterfaceIndex) $($hs.IPAddress)/$($hs.PrefixLength)" } else { 'none with 192.168.137.x' })")
    if ($hs) {
        $l.Add('ARP table on the hotspot interface:')
        foreach ($n in @(Get-NetNeighbor -InterfaceIndex $hs.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)) { $l.Add("  $($n.IPAddress) $(Protect-WizMac $n.LinkLayerAddress) $($n.State)") }
    }
    $l.Add('hosts.ics (ICS DHCP):')
    try { foreach ($e in @(Get-HostsIcsEntries)) { $l.Add("  $($e.ip) $($e.hostName) lease end $($e.leaseEnd)") } } catch { }
    $l.Add('Adapters:')
    foreach ($a in @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.NdisPhysicalMedium -eq 9 -or $_.InterfaceDescription -match '(?i)Wi-Fi Direct|Virtual Adapter' })) {
        $l.Add("  '$($a.Name)' $($a.InterfaceDescription) ifIndex $($a.ifIndex) status $($a.Status) media $($a.MediaConnectionState) speed $($a.LinkSpeed)")
    }
    $pw = Get-DevicePowerInfo $script:wifiPnpId
    $l.Add("Wi-Fi device: PnP $($pw.pnp), power state $($pw.dState), last (re)arrival $($pw.lastArrival)")
    $l.Add('Services:')
    foreach ($kv in (Get-ServiceSnapshot).GetEnumerator()) { $l.Add("  $($kv.Key) $($kv.Value.state) pid $($kv.Value.pid)") }
    $l.Add('netsh wlan show interfaces:')
    foreach ($x in (Invoke-NativeLines 'netsh.exe' @('wlan', 'show', 'interfaces'))) { if ($x.Trim()) { $l.Add('  ' + $x.Trim()) } }
    try { $null = Read-NewEvents -Since $script:lastEventPoll.AddSeconds(-5); $script:lastEventPoll = Get-Now } catch { }
    $l.Add('Windows events in the last 20 minutes:')
    foreach ($e in (Get-EventsBetween -From $t.AddMinutes(-20) -To $t)) { $l.Add((Format-EventLine $e)) }
    [System.IO.File]::WriteAllText($path, (Protect-Text ($l -join "`r`n")), $script:utf8NoBom)
    $script:snapshots.Add($path)
    return $path
}

function Get-IncidentAnalysis {
    param($Inc)
    $t = $Inc.detected
    $r = $Inc.row
    $from30 = $t.AddMinutes(-30)
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add("INCIDENT $($Inc.number): the WiZ bulb stopped answering at $(Format-Time $Inc.firstMiss) (confirmed $(Format-Time $t))")
    $l.Add("  Recovery: $(if ($Inc.recovered) { "$(Format-Time $Inc.recovered) after $([int]($Inc.recovered - $Inc.firstMiss).TotalSeconds) s" } else { 'not recovered while monitoring' })")
    # Layers that were already failing while the bulb still answered are not the cause of this incident.
    $cut = $(if ($Inc.lastBulbOk) { $Inc.lastBulbOk } else { [datetime]::MinValue })
    $sortedBad = @($Inc.firstBad.GetEnumerator() | Sort-Object { $_.Value })
    $bad = @($sortedBad | Where-Object { $_.Value -gt $cut } | ForEach-Object { "$($_.Key) @ $(Format-Time $_.Value)" })
    $pre = @($sortedBad | Where-Object { $_.Value -le $cut } | ForEach-Object { "$($_.Key) (since $(Format-Time $_.Value))" })
    $newBad = @($sortedBad | Where-Object { $_.Value -gt $cut })
    $firstLayer = 'none recorded'
    if ($newBad.Count) {
        $t0 = $newBad[0].Value
        $same = @($newBad | Where-Object { $_.Value -eq $t0 } | ForEach-Object { $_.Key })
        $firstLayer = $(if ($same.Count -gt 1) { "$($same -join ' + ') (all at the same check, $(Format-Time $t0); order within one check is unknown)" } else { "$($same[0]) @ $(Format-Time $t0)" })
    }
    $l.Add("  Last good answer from the bulb: $(if ($Inc.lastBulbOk) { Format-Time $Inc.lastBulbOk } else { 'none during this run' })")
    $l.Add("  FIRST FAILING LAYER: $firstLayer")
    $l.Add("  Layers that failed after the last good answer, in order: $(if ($bad.Count) { $bad -join ' -> ' } else { 'none' })")
    $l.Add("  Already failing before (not the cause): $(if ($pre.Count) { $pre -join ', ' } else { 'none' })")
    $l.Add("  Still healthy at confirmation: $((@($Inc.health.GetEnumerator() | Where-Object { $_.Value -eq $true } | ForEach-Object { $_.Key })) -join ', ')")
    $l.Add("  (precision: passive layers every $IntervalSeconds s; ping/UDP every $ProbeSeconds s until the first miss, then every check)")
    $chg = { param($field) @($script:changeHistory | Where-Object { $_.field -eq $field -and $_.time -ge $from30 -and $_.time -le $t.AddMinutes(2) } | ForEach-Object { "$(Format-Time $_.time) $($_.old)->$($_.new)" }) }
    $ind = { param($kinds) @($script:indicators | Where-Object { ($kinds -contains $_.kind) -and $_.time -ge $from30 -and $_.time -le $t.AddMinutes(5) } | ForEach-Object { "$(Format-Time $_.time) $($_.text)" }) }
    $x = & $chg 'hotspotState'
    $l.Add("  A. Hotspot still ON? $($r.hotspotState). Changes in the previous 30 min: $(if ($x.Count) { $x -join '; ' } else { 'none' })")
    $x = @(& $chg 'wifiStatus') + @(& $chg 'wifiPnp') + @(& $chg 'wifiDState') + @(& $ind @('adapter-reset', 'adapter-rearrival', 'adapter-power'))
    $l.Add("  B. Wi-Fi adapter active? status=$($r.wifiStatus) PnP=$($r.wifiPnp) power=$($r.wifiDState). Power-down / re-initialisation signs (-30 .. +5 min): $(if ($x.Count) { $x -join '; ' } else { 'none' })")
    $x = & $chg 'internet'
    $l.Add("  C. PC internet? $($r.internet), DNS $($r.dns). Internet changes in the previous 30 min: $(if ($x.Count) { $x -join '; ' } else { 'none' })")
    $l.Add("  D. Bulb reachable locally? ping=$($r.bulbPing), ARP=$($r.bulbArp)")
    $l.Add("  E. UDP 38899 (getPilot)? $($r.bulbUdp)  (TIMEOUT = no answer; PORT_UNREACHABLE = bulb up but nothing listening)")
    $l.Add("  F. Bulb still in the hotspot's client list (Wi-Fi association)? $($r.bulbAssociated)")
    $x = @(& $chg 'bulbIp') + @(& $chg 'bulbInHostsIcs') + @(& $chg 'bulbLeaseEnd')
    $l.Add("  G. DHCP: in hosts.ics=$($r.bulbInHostsIcs), IP=$($r.bulbIp), lease end=$($r.bulbLeaseEnd). IP/lease changes in the previous 30 min: $(if ($x.Count) { $x -join '; ' } else { 'none' })")
    $h = ($r.bulbPing -eq 'OK' -and $r.bulbUdp -ne 'OK')
    $l.Add("  H. Reachable locally but not answering WiZ commands? $(if ($h) { 'YES (ping OK, UDP not)' } else { 'no' })")
    $ev = Get-EventsBetween -From $Inc.firstMiss.AddMinutes(-5) -To $t.AddMinutes(5)
    $l.Add("  I. Windows events from 5 min before the first miss to 5 min after confirmation: $($ev.Count)")
    foreach ($e in $ev) { $l.Add((Format-EventLine $e)) }
    $ev = Get-EventsBetween -From $Inc.firstMiss.AddMinutes(-10) -To $t.AddMinutes(5) -Categories @('adapter', 'wlan', 'power', 'pnp')
    $x = & $ind @('adapter-reset', 'adapter-rearrival', 'adapter-power', 'gap')
    $l.Add("  J. Wi-Fi adapter (Realtek driver / NDIS / PnP / WLAN / power) events (-10 .. +5 min): $($ev.Count); other signs: $(if ($x.Count) { $x -join '; ' } else { 'none' })")
    $ev = Get-EventsBetween -From $Inc.firstMiss.AddMinutes(-10) -To $t.AddMinutes(5) -Categories @('hotspot-service')
    $x = & $ind @('service-restart', 'hotspot-interface')
    $l.Add("  K. Hotspot / ICS service events (-10 .. +5 min): $($ev.Count); other signs: $(if ($x.Count) { $x -join '; ' } else { 'none' })")
    foreach ($e in $ev) { $l.Add((Format-EventLine $e)) }
    $l.Add("  User idle at confirmation: $(if ("$($r.idleSec)" -ne '') { "$([int]([int]$r.idleSec / 60)) min" } else { 'unknown' })")
    $m = @($script:marks | Where-Object { $_.time -ge $Inc.firstMiss.AddMinutes(-30) -and $_.time -le $t.AddMinutes(30) } | ForEach-Object { Format-Time $_.time })
    $l.Add("  Your 'M' presses near this incident: $(if ($m.Count) { $m -join ', ' } else { 'none' })")
    return $l
}

function Write-Report {
    param([string]$Status)
    $now = Get-Now
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add("WIZ LONG-RUN MONITOR REPORT - $Status - written $(Format-Time $now)")
    $l.Add("Running for $([math]::Round(($now - $script:startTime).TotalHours, 2)) h, $($script:ticks) checks")
    $l.Add('')
    $l.Add('CONFIGURATION AT START')
    foreach ($c in $script:config) { $l.Add('  ' + $c) }
    $l.Add('')
    $l.Add('RESULT')
    if ($script:incidents.Count -eq 0) {
        if ($script:current) { $l.Add("  No bulb failure captured so far. Last check: bulb API $($script:current.bulbUdp), associated $($script:current.bulbAssociated), hotspot $($script:current.hotspotState), internet $($script:current.internet).") }
        else { $l.Add('  No check completed yet.') }
    }
    foreach ($inc in $script:incidents) { foreach ($x in (Get-IncidentAnalysis $inc)) { $l.Add($x) }; $l.Add('') }
    $l.Add('YOUR M KEY PRESSES')
    if ($script:marks.Count -eq 0) { $l.Add('  none') }
    foreach ($m in $script:marks) { $l.Add("  $(Format-Time $m.time) bulb API $($m.api), associated $($m.assoc), ping $($m.ping), internet $($m.internet), hotspot $($m.hotspot)") }
    $l.Add('')
    $l.Add('RE-INITIALISATION / POWER / GAP INDICATORS')
    if ($script:indicators.Count -eq 0) { $l.Add('  none') }
    foreach ($i in $script:indicators) { $l.Add("  $(Format-Time $i.time) [$($i.kind)] $($i.text)") }
    $l.Add('')
    $l.Add('ALL STATE CHANGES')
    foreach ($c in $script:changeHistory) { $l.Add("  $(Format-Time $c.time) $($c.field): $($c.old) -> $($c.new)") }
    $l.Add('')
    $l.Add('WINDOWS EVENTS BY CATEGORY (whole run; full list in events.log)')
    foreach ($g in @($script:EventHistory | Group-Object category)) { $l.Add("  $($g.Name): $($g.Count)") }
    $l.Add('')
    $l.Add('SNAPSHOTS')
    foreach ($s in $script:snapshots) {
        $l.Add('----- ' + (Split-Path -Leaf $s))
        try { foreach ($x in (Get-Content -LiteralPath $s)) { $l.Add($x) } } catch { }
    }
    [System.IO.File]::WriteAllText($reportPath, (Protect-Text ($l -join "`r`n")), $script:utf8NoBom)
}

function Invoke-KeyCheck {
    try {
        while ([Console]::KeyAvailable) {
            $k = [Console]::ReadKey($true)
            if ($k.Key -eq 'M') {
                $t = Get-Now
                $c = $script:current
                $script:marks.Add([pscustomobject]@{ time = $t; api = $c.bulbUdp; assoc = $c.bulbAssociated; ping = $c.bulbPing; internet = $c.internet; hotspot = $c.hotspotState })
                Write-Change "$(Format-Time $t) USER MARK (M): Alexa problem noticed | bulbApi=$($c.bulbUdp) associated=$($c.bulbAssociated) ping=$($c.bulbPing) internet=$($c.internet) hotspot=$($c.hotspotState)"
                Write-Host "[$($t.ToString('HH:mm:ss'))] Mark recorded. Taking a snapshot..." -ForegroundColor Cyan
                $p = Write-Snapshot -Reason 'user pressed M (Alexa cannot control the bulb)' -Row $c
                Write-Host "  snapshot saved: $(Split-Path -Leaf $p)" -ForegroundColor Cyan
                Write-Report -Status 'running'
            }
        }
    }
    catch { }
}

Write-Host ''
Write-Host "WiZ long-run monitor v$ScriptVersion - bulb $WizIp (MAC $maskedMac). Output: $OutputDir" -ForegroundColor Green
Write-Host 'Leave this window open. Press M when Alexa can no longer control the bulb. Ctrl+C to stop.' -ForegroundColor Green
Write-Host ''

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
try {
    while ((Get-Now) -lt $deadline) {
        $tick = Get-Now
        try {
            if ($lastTickTime -and (($tick - $lastTickTime).TotalSeconds -gt (3 * $IntervalSeconds + 5))) {
                Add-Indicator -T $tick -Kind 'gap' -Text "no checks for $([int]($tick - $lastTickTime).TotalSeconds) s (PC asleep, frozen, or monitor paused)"
            }
            $row = [ordered]@{
                time = (Format-Time $tick); idleSec = (Get-IdleSeconds); defaultRouteIf = ''; internet = ''; dns = ''
                hotspotState = ''; hotspotClients = ''; hotspotIf = ''; hotspotAdapter = ''
                wifiStatus = ''; wifiPnp = ''; wifiDState = ''; services = ''
                bulbIp = ''; bulbAssociated = ''; bulbInHostsIcs = ''; bulbLeaseEnd = ''; bulbArp = ''; bulbArpClass = ''
                probed = ''; bulbPing = ''; bulbPingMs = ''; bulbUdp = ''; bulbUdpMs = ''; bulbRssi = ''; bulbOn = ''
                wifiRxBytes = ''; wifiTxBytes = ''; hotspotRxBytes = ''; hotspotTxBytes = ''
            }

            # --- PC internet --------------------------------------------------
            $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object -Property RouteMetric | Select-Object -First 1
            $row.defaultRouteIf = $(if ($route) { $route.InterfaceAlias } else { 'NONE' })
            $inet = (Test-TcpPort -HostName $InternetProbeHost -Port 443 -TimeoutMs 2000) -or (Test-TcpPort -HostName $InternetProbeHost2 -Port 443 -TimeoutMs 2000)
            $row.internet = $(if ($inet) { 'OK' } else { 'FAIL' })
            $dnsServer = $null
            if ($route) { $dnsServer = (Get-DnsClientServerAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).ServerAddresses | Select-Object -First 1 }
            $row.dns = Test-Dns -Name $DnsProbeName -Server $dnsServer

            # --- Hotspot --------------------------------------------------------
            $hs = $null
            try { $hs = Get-HotspotRuntimeState } catch { }
            $row.hotspotState = $(if ($hs) { $hs.state } else { 'n/a' })
            $row.hotspotClients = $(if ($hs) { $hs.clientCount } else { '' })
            $row.bulbAssociated = $(if ($hs -and $bulbMac) { if (@($hs.clientMacs) -contains $bulbMac) { 'YES' } else { 'NO' } } else { 'unknown' })
            $hsIf = Get-HotspotInterfaceIPv4
            $row.hotspotIf = $(if ($hsIf) { $hsIf.InterfaceIndex } else { 'none' })
            $hsAdapter = $(if ($hsIf) { Get-NetAdapter -IncludeHidden -InterfaceIndex $hsIf.InterfaceIndex -ErrorAction SilentlyContinue } else { $null })
            $row.hotspotAdapter = $(if ($hsAdapter) { "$($hsAdapter.Status)" } else { 'NO_192.168.137.x_INTERFACE' })
            if ($prevHotspotIf -and $hsIf -and "$prevHotspotIf" -ne "$($hsIf.InterfaceIndex)") {
                Add-Indicator -T $tick -Kind 'hotspot-interface' -Text "hotspot interface index changed $prevHotspotIf -> $($hsIf.InterfaceIndex) (hotspot interface recreated)"
            }
            if ($hsIf) { $prevHotspotIf = $hsIf.InterfaceIndex }

            # --- Wi-Fi adapter (status, PnP, power state, re-arrival, counters) --
            if ($wifiName) {
                $w = Get-NetAdapter -Name $wifiName -ErrorAction SilentlyContinue
                $row.wifiStatus = $(if ($w) { "$($w.Status)" } else { 'NOT_FOUND' })
                $pw = Get-DevicePowerInfo $wifiPnpId
                $row.wifiPnp = $pw.pnp
                $row.wifiDState = $pw.dState
                if ($prevArrival -and $pw.lastArrival -and $pw.lastArrival -ne $prevArrival) {
                    Add-Indicator -T $tick -Kind 'adapter-rearrival' -Text "Wi-Fi adapter re-enumerated by Windows (last arrival $prevArrival -> $($pw.lastArrival))"
                }
                if ($pw.lastArrival) { $prevArrival = $pw.lastArrival }
                if ($pw.dState -match '^D[1-3]$' -and $pw.dState -ne $prevDState) { Add-Indicator -T $tick -Kind 'adapter-power' -Text "Wi-Fi adapter entered power state $($pw.dState) (not fully on)" }
                $prevDState = $pw.dState
                $cw = Get-AdapterCounters -Name $wifiName
                if ($cw) {
                    $row.wifiRxBytes = $cw.rx; $row.wifiTxBytes = $cw.tx
                    if ($prevCounters.ContainsKey('wifi') -and ($cw.rx -lt $prevCounters['wifi'].rx -or $cw.tx -lt $prevCounters['wifi'].tx)) {
                        Add-Indicator -T $tick -Kind 'adapter-reset' -Text 'Wi-Fi adapter traffic counters went backwards (adapter re-initialised)'
                    }
                    $prevCounters['wifi'] = $cw
                }
            }
            else { $row.wifiStatus = 'NOT_FOUND'; $row.wifiPnp = 'unknown'; $row.wifiDState = 'unknown' }
            if ($hsAdapter) {
                $ch = Get-AdapterCounters -Name $hsAdapter.Name -Hidden
                if ($ch) {
                    $row.hotspotRxBytes = $ch.rx; $row.hotspotTxBytes = $ch.tx
                    if ($prevCounters.ContainsKey('hotspot') -and ($ch.rx -lt $prevCounters['hotspot'].rx -or $ch.tx -lt $prevCounters['hotspot'].tx)) {
                        Add-Indicator -T $tick -Kind 'adapter-reset' -Text 'Hotspot virtual adapter traffic counters went backwards (hotspot adapter re-initialised)'
                    }
                    $prevCounters['hotspot'] = $ch
                }
            }

            # --- Services -------------------------------------------------------
            $svc = Get-ServiceSnapshot
            $row.services = (($WatchedServices | ForEach-Object { if ($svc.Contains($_)) { "$_=$($svc[$_].state)" } else { "$_=?" } }) -join ' ')
            foreach ($name in $WatchedServices) {
                if (-not $svc.Contains($name)) { continue }
                $newPid = [int]$svc[$name].pid
                if ($prevPids.ContainsKey($name) -and $prevPids[$name] -gt 0 -and $newPid -gt 0 -and $prevPids[$name] -ne $newPid) {
                    Add-Indicator -T $tick -Kind 'service-restart' -Text "service $name restarted (process $($prevPids[$name]) -> $newPid)"
                }
                $prevPids[$name] = $newPid
            }

            # --- Bulb: IP (followed by MAC), DHCP, ARP ---------------------------
            if ($bulbMac -and $hsIf) {
                $byMac = Get-NetNeighbor -InterfaceIndex $hsIf.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { (ConvertTo-NormalizedMac $_.LinkLayerAddress) -eq $bulbMac } | Select-Object -First 1
                if ($byMac -and $byMac.IPAddress -ne $WizIp) { Add-Indicator -T $tick -Kind 'bulb-ip' -Text "bulb IP changed $WizIp -> $($byMac.IPAddress) (found by MAC)"; $WizIp = $byMac.IPAddress }
            }
            $ics = @()
            try { $ics = @(Get-HostsIcsEntries) } catch { }
            $entry = $null
            if ($bulbHost) { $entry = $ics | Where-Object { $_.hostName -eq $bulbHost } | Select-Object -First 1 }
            if (-not $entry) { $entry = $ics | Where-Object { $_.ip -eq $WizIp } | Select-Object -First 1 }
            if ($entry -and $entry.ip -ne $WizIp) { Add-Indicator -T $tick -Kind 'bulb-ip' -Text "bulb IP changed $WizIp -> $($entry.ip) (DHCP table)"; $WizIp = $entry.ip }
            $row.bulbIp = $WizIp
            $row.bulbInHostsIcs = $(if ($entry) { 'YES' } else { 'NO' })
            $row.bulbLeaseEnd = $(if ($entry) { $entry.leaseEnd } else { '' })
            $nb = $(if ($hsIf) { Get-NetNeighbor -IPAddress $WizIp -InterfaceIndex $hsIf.InterfaceIndex -ErrorAction SilentlyContinue | Select-Object -First 1 } else { $null })
            $row.bulbArp = $(if (-not $hsIf) { 'NO_HOTSPOT_IF' } elseif ($nb) { "$($nb.State)" } else { 'NONE' })
            $row.bulbArpClass = $(if ($row.bulbArp -in @('Reachable', 'Stale', 'Delay', 'Probe', 'Permanent')) { 'OK' } else { $row.bulbArp.ToUpperInvariant() })

            # --- Bulb probes (ping + read-only getPilot) --------------------------
            $assocLost = ($null -ne $previous -and $previous.bulbAssociated -eq 'YES' -and $row.bulbAssociated -eq 'NO')
            $doProbe = ($null -eq $lastProbeTime) -or (($tick - $lastProbeTime).TotalSeconds -ge ($ProbeSeconds - 1)) -or ($null -ne $suspectSince) -or $assocLost -or ($incidents.Count -gt 0 -and -not $incidents[$incidents.Count - 1].recovered)
            if ($doProbe) {
                $probe = Invoke-BulbProbe $WizIp
                $lastProbeTime = $tick
                $row.probed = 'yes'
            }
            foreach ($k in @('bulbPing', 'bulbPingMs', 'bulbUdp', 'bulbUdpMs', 'bulbRssi', 'bulbOn')) { $row[$k] = $probe[$k] }
            $current = $row

            # --- Write row, detect changes -----------------------------------------
            [pscustomobject]$row | Export-Csv -LiteralPath $csvPath -Append -NoTypeInformation -Encoding UTF8
            $ticks++
            if ($null -eq $previous) {
                Write-Change "$($row.time) INITIAL STATE | $(($watched | ForEach-Object { "$_=$($row[$_])" }) -join ' ')"
            }
            else {
                foreach ($k in $watched) {
                    if ("$($previous[$k])" -ne "$($row[$k])") {
                        $changeHistory.Add([pscustomobject]@{ time = $tick; field = $k; old = "$($previous[$k])"; new = "$($row[$k])" })
                        Write-Change "$($row.time) CHANGE $k : $($previous[$k]) -> $($row[$k]) | $(($watched | ForEach-Object { "$_=$($row[$_])" }) -join ' ')"
                    }
                }
            }

            # --- Layer tracking: first moment each layer went bad ---------------
            $health = Get-LayerHealth $row
            foreach ($layer in $layerOrder) {
                if ($health[$layer] -eq $false) { if (-not $firstBad.ContainsKey($layer)) { $firstBad[$layer] = $tick } }
                elseif ($health[$layer] -eq $true) { $firstBad.Remove($layer) }
            }

            # --- Incident detection ---------------------------------------------------
            $open = ($incidents.Count -gt 0 -and -not $incidents[$incidents.Count - 1].recovered)
            if ($doProbe) {
                if ($row.bulbUdp -ne 'OK') {
                    if (-not $open) {
                        if ($null -eq $suspectSince) {
                            $suspectSince = $tick
                            Write-Change "$($row.time) SUSPECT bulb did not answer (udp=$($row.bulbUdp), ping=$($row.bulbPing)); re-checking every $IntervalSeconds s"
                        }
                        else {
                            $inc = [pscustomobject]@{
                                number = $incidents.Count + 1; firstMiss = $suspectSince; detected = $tick; recovered = $null
                                lastBulbOk = $lastBulbOk; row = $row; health = $health; firstBad = $firstBad.Clone()
                            }
                            $incidents.Add($inc)
                            $suspectSince = $null
                            Write-Change "$($row.time) INCIDENT $($inc.number) CONFIRMED (first miss $(Format-Time $inc.firstMiss))"
                            try { $null = Read-NewEvents -Since $lastEventPoll.AddSeconds(-5); $lastEventPoll = Get-Now } catch { }
                            $snap = Write-Snapshot -Reason "incident $($inc.number): bulb stopped answering" -Row $row
                            foreach ($x in (Get-IncidentAnalysis $inc)) { Write-Change $x }
                            Write-Report -Status 'running'
                            try { [Console]::Beep(880, 400); [Console]::Beep(660, 400) } catch { }
                            Write-Host ''
                            Write-Host '==================================================================' -ForegroundColor Red
                            Write-Host " WiZ BULB STOPPED ANSWERING at $($inc.firstMiss.ToString('HH:mm:ss'))  (snapshot: $(Split-Path -Leaf $snap))" -ForegroundColor Red
                            Write-Host ' 1. Check Alexa. If it cannot control the bulb, press M in this window.' -ForegroundColor Red
                            Write-Host ' 2. Leave the PC, hotspot and bulb untouched for 5 minutes.' -ForegroundColor Red
                            Write-Host ' 3. Then fix it the way you normally do (power-cycle the bulb)' -ForegroundColor Red
                            Write-Host '    and wait until this window says RECOVERED.' -ForegroundColor Red
                            Write-Host ' 4. Press Ctrl+C and send watch-report.txt, watch.csv, events.log.' -ForegroundColor Red
                            Write-Host '==================================================================' -ForegroundColor Red
                            Write-Host ''
                        }
                    }
                }
                else {
                    $lastBulbOk = $tick
                    if ($null -ne $suspectSince) {
                        Add-Indicator -T $tick -Kind 'transient' -Text "single missed answer at $(Format-Time $suspectSince), answered again"
                        $suspectSince = $null
                    }
                    if ($open) {
                        $last = $incidents[$incidents.Count - 1]
                        $last.recovered = $tick
                        Write-Change "$($row.time) RECOVERED incident $($last.number) after $([int]($tick - $last.firstMiss).TotalSeconds) s | $(($watched | ForEach-Object { "$_=$($row[$_])" }) -join ' ')"
                        Write-Report -Status 'running'
                        Write-Host "[$($tick.ToString('HH:mm:ss'))] RECOVERED: the bulb answers again. You can press Ctrl+C now." -ForegroundColor Green
                    }
                }
            }

            # --- Windows events (every probe interval) ----------------------------
            if ((($tick - $lastEventPoll).TotalSeconds) -ge $ProbeSeconds) {
                try {
                    $new = Read-NewEvents -Since $lastEventPoll.AddSeconds(-5)
                    $lastEventPoll = $tick
                    foreach ($e in $new) { if ($e.category -in @('adapter', 'hotspot-service', 'wlan', 'power', 'pnp')) { Write-Change "$(Format-Time $e.time) WINEVENT [$($e.category)] $($e.provider) id $($e.id) $(if ($e.service) { "[$($e.service)] " })$($e.message)" } }
                }
                catch { }
            }

            # --- Console line -------------------------------------------------------------
            $color = $(if ($row.bulbUdp -eq 'OK') { 'Gray' } else { 'Yellow' })
            Write-Host ("[{0}] NET {1}/{2} | HOTSPOT {3} c={4} if={5} | WIFI {6} pnp={7} {8} | BULB assoc={9} dhcp={10} arp={11} ping={12} udp={13} {14}ms rssi={15} | idle {16}s" -f `
                    $tick.ToString('HH:mm:ss'), $row.internet, $row.dns, $row.hotspotState, $row.hotspotClients, $row.hotspotIf, $row.wifiStatus, $row.wifiPnp, $row.wifiDState,
                $row.bulbAssociated, $row.bulbInHostsIcs, $row.bulbArp, $row.bulbPing, $row.bulbUdp, $row.bulbUdpMs, $row.bulbRssi, $row.idleSec) -ForegroundColor $color

            if (((Get-Now) - $lastReportWrite).TotalMinutes -ge 10) { Write-Report -Status 'running'; $lastReportWrite = Get-Now }
            $previous = $row
        }
        catch {
            $msg = (Get-InnermostException $_.Exception).Message
            Write-Change "$(Format-Time $tick) ERROR during check: $msg"
            Write-Host "[$($tick.ToString('HH:mm:ss'))] check failed: $msg" -ForegroundColor Red
        }
        $lastTickTime = $tick

        # Wait for the next check, reacting to the M key every second.
        $waitUntil = $tick.AddSeconds($IntervalSeconds)
        while ((Get-Now) -lt $waitUntil) { Invoke-KeyCheck; Start-Sleep -Milliseconds 500 }
    }
}
finally {
    Write-Change "$(Format-Time (Get-Now)) STOP monitoring ended after $([math]::Round(((Get-Now) - $startTime).TotalHours, 2)) h; last check started at $(if ($lastTickTime) { Format-Time $lastTickTime } else { 'none' })"
    try { $null = Read-NewEvents -Since $lastEventPoll.AddSeconds(-5) } catch { }
    try { Write-Report -Status 'final' } catch { }
    Write-Host "Report written: $reportPath" -ForegroundColor Green
}
