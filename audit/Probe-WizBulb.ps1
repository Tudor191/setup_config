<#
.SYNOPSIS
    Setup Controller - read-only WiZ bulb probe.

.DESCRIPTION
    Finds the WiZ bulb on the Mobile Hotspot network and queries it over the documented local UDP API
    (port 38899). Only these read-only methods are ever sent:
        getSystemConfig, getModelConfig, getPilot, getUserConfig
    The bulb's state, settings, WiZ/Alexa registration and Wi-Fi configuration are not touched.
    No broadcast "registration" message is sent (that is what discovery tools use; it is avoided here).

    Candidate IP addresses come from, in order:
      1. -IpAddress (if given)
      2. hosts.ics (DHCP clients of Internet Connection Sharing)
      3. the neighbour (ARP) table of the hotspot interface
      4. -SweepHotspotSubnet: one unicast getSystemConfig per address of the hotspot /24

    Output: .\output\wiz-<timestamp>\wiz-probe.json and wiz-probe.txt (bulb MAC and WiZ home/room IDs redacted).

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Probe-WizBulb.ps1
.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Probe-WizBulb.ps1 -IpAddress 192.168.137.25
#>
[CmdletBinding()]
param(
    [string[]]$IpAddress,
    [switch]$SweepHotspotSubnet,
    [ValidateRange(200, 5000)][int]$TimeoutMs = 1000,
    [ValidateRange(1, 5)][int]$Attempts = 3,
    [ValidateRange(1, 50)][int]$LatencySamples = 10,
    [string]$OutputDir
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\AuditCommon.ps1')

if (-not $OutputDir) {
    $OutputDir = Join-Path $PSScriptRoot ('output\wiz-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
Register-StandardRedactions

$result = [ordered]@{
    collectedAt   = (Get-Date).ToString('o')
    methodsUsed   = @('getSystemConfig', 'getModelConfig', 'getPilot', 'getUserConfig')
    candidates    = @()
    bulbs         = @()
}

# ---------------------------------------------------------------------------
# Candidate discovery (no packets are sent to the bulb in this step)
# ---------------------------------------------------------------------------
$candidates = New-Object System.Collections.Generic.List[string]
function Add-Candidate([string]$Ip, [string]$Source) {
    if ([string]::IsNullOrWhiteSpace($Ip)) { return }
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$parsed)) { return }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return }
    if ($Ip.EndsWith('.255') -or $Ip.EndsWith('.0')) { return }
    if (-not $candidates.Contains($Ip)) {
        $candidates.Add($Ip)
        $script:result['candidates'] += [ordered]@{ ip = $Ip; source = $Source }
    }
}

foreach ($ip in @($IpAddress)) { Add-Candidate $ip 'parameter' }

$hotspotIp = $null
if ($IsWindows -or $env:OS -eq 'Windows_NT') {
    try { foreach ($e in @(Get-HostsIcsEntries)) { Add-Candidate $e.ip ("hosts.ics: " + $e.hostName) } } catch { }
    $hotspot = Get-HotspotInterfaceIPv4
    if ($hotspot) {
        $hotspotIp = $hotspot.IPAddress
        $result['hotspotInterface'] = [ordered]@{ alias = $hotspot.InterfaceAlias; ipv4 = $hotspot.IPAddress; prefix = $hotspot.PrefixLength }
        foreach ($n in @(Get-NetNeighbor -InterfaceIndex $hotspot.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
            if ("$($n.State)" -in @('Reachable', 'Stale', 'Delay', 'Probe')) { Add-Candidate $n.IPAddress ("neighbour table: " + $n.State) }
        }
    }
    else {
        $result['hotspotInterface'] = 'not found (is the Mobile Hotspot on?)'
    }
}

if ($SweepHotspotSubnet) {
    if (-not $hotspotIp) { throw 'Cannot sweep: the hotspot interface / subnet was not found.' }
    $prefix = $hotspotIp.Substring(0, $hotspotIp.LastIndexOf('.') + 1)
    for ($i = 1; $i -le 254; $i++) {
        $ip = $prefix + $i
        if ($ip -ne $hotspotIp) { Add-Candidate $ip 'subnet sweep' }
    }
}

if ($hotspotIp) { $candidates.Remove($hotspotIp) | Out-Null }
Write-Host ("Probing {0} candidate address(es) with read-only getSystemConfig ..." -f $candidates.Count)

# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------
# A sweep sends a single short-timeout query per address so it finishes in a few minutes at most.
$sweepAttempts = $(if ($SweepHotspotSubnet) { 1 } else { $Attempts })
$sweepTimeout = $(if ($SweepHotspotSubnet) { [math]::Min($TimeoutMs, 500) } else { $TimeoutMs })
foreach ($ip in $candidates) {
    $sys = Invoke-WizQuery -IpAddress $ip -Method getSystemConfig -TimeoutMs $sweepTimeout -Attempts $sweepAttempts
    if (-not $sys.ok -or $null -eq $sys.json -or -not $sys.json.PSObject.Properties['result']) { continue }

    Write-Host "  WiZ device answered at $ip"
    $bulb = [ordered]@{
        ip           = $ip
        systemConfig = (Protect-WizResult $sys.json.result)
        firstRttMs   = $sys.rttMs
    }
    $model = Invoke-WizQuery -IpAddress $ip -Method getModelConfig -TimeoutMs $TimeoutMs -Attempts $Attempts
    $bulb['modelConfig'] = $(if ($model.ok -and $model.json -and $model.json.PSObject.Properties['result']) { Protect-WizResult $model.json.result } elseif ($model.ok) { $model.raw } else { "no answer: $($model.error)" })
    $user = Invoke-WizQuery -IpAddress $ip -Method getUserConfig -TimeoutMs $TimeoutMs -Attempts $Attempts
    $bulb['userConfig'] = $(if ($user.ok -and $user.json -and $user.json.PSObject.Properties['result']) { Protect-WizResult $user.json.result } elseif ($user.ok) { $user.raw } else { "no answer: $($user.error)" })

    $rtts = @()
    $lost = 0
    $lastPilot = $null
    for ($s = 0; $s -lt $LatencySamples; $s++) {
        $pilot = Invoke-WizQuery -IpAddress $ip -Method getPilot -TimeoutMs $TimeoutMs -Attempts 1
        if ($pilot.ok -and $pilot.json -and $pilot.json.PSObject.Properties['result']) { $rtts += $pilot.rttMs; $lastPilot = $pilot.json.result } else { $lost++ }
        Start-Sleep -Milliseconds 250
    }
    $bulb['pilot'] = (Protect-WizResult $lastPilot)
    $bulb['latency'] = [ordered]@{
        samples = $LatencySamples
        lost    = $lost
        minMs   = $(if ($rtts.Count) { ($rtts | Measure-Object -Minimum).Minimum } else { $null })
        avgMs   = $(if ($rtts.Count) { [math]::Round(($rtts | Measure-Object -Average).Average, 1) } else { $null })
        maxMs   = $(if ($rtts.Count) { ($rtts | Measure-Object -Maximum).Maximum } else { $null })
    }
    $result['bulbs'] += $bulb
}

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("WIZ PROBE ($((Get-Date).ToString('yyyy-MM-dd HH:mm'))) - read-only methods only")
if ($result.Contains('hotspotInterface')) { $lines.Add("[HOTSPOT] interface: $(if ($result['hotspotInterface'] -is [System.Collections.IDictionary]) { "$($result['hotspotInterface']['alias']) $($result['hotspotInterface']['ipv4'])/$($result['hotspotInterface']['prefix'])" } else { $result['hotspotInterface'] })") }
$lines.Add("[WIZ] candidates probed: $($candidates.Count)")
if ($result['bulbs'].Count -eq 0) {
    $lines.Add('[WIZ] Device discovered: NO')
    $lines.Add('[WIZ] Local API: no answer on UDP 38899 from any candidate.')
    $lines.Add('      Next steps: confirm the bulb is on and connected, pass -IpAddress, or run with -SweepHotspotSubnet.')
    $lines.Add('      Also check the WiZ app setting "Allow local communication".')
}
foreach ($b in $result['bulbs']) {
    $sc = $b['systemConfig']
    $lines.Add('[WIZ] Device discovered: YES')
    $lines.Add("[WIZ] IP: $($b['ip'])")
    $lines.Add("[WIZ] Local API: ONLINE (first answer $($b['firstRttMs']) ms)")
    $lines.Add("[WIZ] Module: $($sc['moduleName']) | firmware: $($sc['fwVersion']) | typeId: $($sc['typeId']) | MAC: $($sc['mac'])")
    if ($b['pilot']) { $lines.Add("[WIZ] State: on=$($b['pilot']['state']) dimming=$($b['pilot']['dimming']) sceneId=$($b['pilot']['sceneId']) rssi=$($b['pilot']['rssi']) dBm") }
    $lines.Add("[WIZ] Latency: min $($b['latency']['minMs']) / avg $($b['latency']['avgMs']) / max $($b['latency']['maxMs']) ms, lost $($b['latency']['lost'])/$($b['latency']['samples'])")
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText((Join-Path $OutputDir 'wiz-probe.json'), (Protect-Text ($result | ConvertTo-Json -Depth 8)), $utf8NoBom)
$summary = Protect-Text ($lines -join "`r`n")
[System.IO.File]::WriteAllText((Join-Path $OutputDir 'wiz-probe.txt'), $summary, $utf8NoBom)
Write-Host ''
Write-Host $summary
Write-Host ''
Write-Host "Files written to: $OutputDir" -ForegroundColor Green
