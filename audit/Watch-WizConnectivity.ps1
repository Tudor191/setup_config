<#
.SYNOPSIS
    Setup Controller - passive WiZ / hotspot / PPPoE connectivity logger (READ-ONLY).

.DESCRIPTION
    Evidence collection for the WiZ disconnection investigation. Every -IntervalSeconds it records, side by side:

      [NETWORK]  PPPoE interface up?  Default route?  Internet reachable (TCP 443)?  DNS answering?
      [HOTSPOT]  Mobile Hotspot state and client count (WinRT), Wi-Fi adapter status, hotspot adapter status
      [WIZ]      bulb associated to the hotspot (MAC in client list), DHCP entry (hosts.ics), neighbour state,
                 ICMP ping, local UDP API (read-only getPilot) latency and RSSI

    When any of these values changes, a CHANGE line is written, so the moment the bulb drops can be matched
    against what happened to PPPoE, the hotspot, the adapter and DHCP just before it.

    It never changes anything: no hotspot/adapter/service control, no bulb commands other than getPilot /
    getSystemConfig, no recovery actions. Stop it with Ctrl+C.

    Output (in .\output\watch-<timestamp>\): watch.csv (one row per check), changes.log (transitions only).
    The bulb MAC is written with its device-specific half masked. Private IPs are kept.

.PARAMETER WizIp
    Bulb IP. If omitted, hosts.ics and the neighbour table are searched for a device that answers getSystemConfig.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Watch-WizConnectivity.ps1 -WizIp 192.168.137.25
#>
[CmdletBinding()]
param(
    [string]$WizIp,
    [ValidateRange(10, 600)][int]$IntervalSeconds = 30,
    [ValidateRange(0, 720)][double]$DurationHours = 0,
    [string]$InternetProbeHost = '1.1.1.1',
    [string]$InternetProbeHost2 = '8.8.8.8',
    [string]$DnsProbeName = 'www.msftconnecttest.com',
    [string]$OutputDir
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\AuditCommon.ps1')

if (-not $OutputDir) {
    $OutputDir = Join-Path $PSScriptRoot ('output\watch-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$csvPath = Join-Path $OutputDir 'watch.csv'
$changesPath = Join-Path $OutputDir 'changes.log'

if ($PSVersionTable.PSEdition -ne 'Desktop') {
    Write-Warning 'PowerShell 7 detected: hotspot state/client columns will be "n/a". Use powershell.exe (Windows PowerShell 5.1) for complete data.'
}

function Find-WizBulb {
    $candidates = @()
    try { $candidates += @(Get-HostsIcsEntries | ForEach-Object { $_.ip }) } catch { }
    $hs = Get-HotspotInterfaceIPv4
    if ($hs) {
        $candidates += @(Get-NetNeighbor -InterfaceIndex $hs.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { "$($_.State)" -in @('Reachable', 'Stale', 'Delay', 'Probe') } | ForEach-Object { $_.IPAddress })
    }
    foreach ($ip in ($candidates | Select-Object -Unique)) {
        if ($hs -and $ip -eq $hs.IPAddress) { continue }
        $r = Invoke-WizQuery -IpAddress $ip -Method getSystemConfig -TimeoutMs 800 -Attempts 2
        if ($r.ok -and $r.json -and $r.json.PSObject.Properties['result']) { return @{ ip = $ip; mac = [string]$r.json.result.mac } }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Identify the bulb once (IP + MAC). The MAC lets us follow the bulb if DHCP gives it a new address.
# ---------------------------------------------------------------------------
$bulbMac = ''
if ($WizIp) {
    $r = Invoke-WizQuery -IpAddress $WizIp -Method getSystemConfig -TimeoutMs 1000 -Attempts 3
    if ($r.ok -and $r.json -and $r.json.PSObject.Properties['result']) { $bulbMac = ConvertTo-NormalizedMac ([string]$r.json.result.mac) }
    else { Write-Warning "The bulb at $WizIp did not answer now. Logging continues; MAC-based tracking is disabled until it answers." }
}
else {
    $found = Find-WizBulb
    if ($null -eq $found) { throw 'No WiZ bulb found. Pass -WizIp <address> (see Probe-WizBulb.ps1).' }
    $WizIp = $found.ip
    $bulbMac = ConvertTo-NormalizedMac $found.mac
}
$maskedMac = $(if ($bulbMac) { Protect-WizMac $bulbMac } else { 'unknown' })
Write-Host "Watching WiZ bulb $WizIp (MAC $maskedMac) every $IntervalSeconds s. Ctrl+C to stop."
Write-Host "Output: $OutputDir"

function Get-NeighborMacIp {
    <# Current IP of the bulb according to the neighbour table, looked up by MAC. #>
    param([string]$Mac)
    if (-not $Mac) { return $null }
    $n = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { (ConvertTo-NormalizedMac $_.LinkLayerAddress) -eq $Mac } | Select-Object -First 1
    if ($n) { return $n.IPAddress }
    return $null
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

$ping = New-Object System.Net.NetworkInformation.Ping
$deadline = $(if ($DurationHours -gt 0) { (Get-Date).AddHours($DurationHours) } else { [datetime]::MaxValue })
$previous = $null
$watched = @('pppUp', 'defaultRouteIf', 'internet', 'dns', 'hotspotState', 'bulbAssociated', 'wifiAdapter', 'hotspotAdapter', 'bulbIp', 'bulbInHostsIcs', 'bulbNeighbor', 'bulbPing', 'bulbApi')

while ((Get-Date) -lt $deadline) {
    $tick = Get-Date
    try {
        $row = [ordered]@{ time = $tick.ToString('yyyy-MM-dd HH:mm:ss') }

        # --- NETWORK / PPPoE ---------------------------------------------------
        $pppIfs = @([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object { $_.NetworkInterfaceType -eq 'Ppp' })
        $row['pppUp'] = $(if ($pppIfs.Count -eq 0) { 'NO_PPP_INTERFACE' } elseif (@($pppIfs | Where-Object { "$($_.OperationalStatus)" -eq 'Up' }).Count -gt 0) { 'UP' } else { 'DOWN' })
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object -Property { $_.RouteMetric + $_.InterfaceMetric } | Select-Object -First 1
        $row['defaultRouteIf'] = $(if ($route) { $route.InterfaceAlias } else { 'NONE' })
        $inet = (Test-TcpPort -HostName $InternetProbeHost -Port 443 -TimeoutMs 2000) -or (Test-TcpPort -HostName $InternetProbeHost2 -Port 443 -TimeoutMs 2000)
        $row['internet'] = $(if ($inet) { 'OK' } else { 'FAIL' })
        $dnsServer = $null
        if ($route) {
            $dnsServer = (Get-DnsClientServerAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).ServerAddresses | Select-Object -First 1
        }
        $row['dns'] = Test-Dns -Name $DnsProbeName -Server $dnsServer

        # --- HOTSPOT -----------------------------------------------------------
        $hs = $null
        try { $hs = Get-HotspotRuntimeState } catch { }
        $row['hotspotState'] = $(if ($hs) { $hs.state } else { 'n/a' })
        $row['hotspotClients'] = $(if ($hs) { $hs.clientCount } else { '' })
        $row['bulbAssociated'] = $(if ($hs -and $bulbMac) { if (@($hs.clientMacs) -contains $bulbMac) { 'YES' } else { 'NO' } } else { 'unknown' })

        $wifi = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.NdisPhysicalMedium -eq 9 -and $_.HardwareInterface } | Select-Object -First 1
        $row['wifiAdapter'] = $(if ($wifi) { "$($wifi.Status)" } else { 'NOT_FOUND' })
        $hsIf = Get-HotspotInterfaceIPv4
        $hsAdapter = $(if ($hsIf) { Get-NetAdapter -IncludeHidden -InterfaceIndex $hsIf.InterfaceIndex -ErrorAction SilentlyContinue } else { $null })
        $row['hotspotAdapter'] = $(if ($hsAdapter) { "$($hsAdapter.Status)" } else { 'NO_192.168.137.x_INTERFACE' })

        # --- WIZ ---------------------------------------------------------------
        $currentIp = Get-NeighborMacIp $bulbMac
        if ($currentIp -and $currentIp -ne $WizIp) {
            Add-Content -LiteralPath $changesPath -Value "$($row.time) BULB IP CHANGED $WizIp -> $currentIp"
            $WizIp = $currentIp
        }
        $row['bulbIp'] = $WizIp
        $icsEntries = @()
        try { $icsEntries = @(Get-HostsIcsEntries) } catch { }
        $row['bulbInHostsIcs'] = $(if (@($icsEntries | Where-Object { $_.ip -eq $WizIp }).Count -gt 0) { 'YES' } else { 'NO' })
        $neighbor = Get-NetNeighbor -IPAddress $WizIp -ErrorAction SilentlyContinue | Select-Object -First 1
        $row['bulbNeighbor'] = $(if ($neighbor) { "$($neighbor.State)" } else { 'NONE' })
        try {
            $reply = $ping.Send($WizIp, 1000)
            $row['bulbPing'] = $(if ($reply.Status -eq 'Success') { 'OK' } else { "$($reply.Status)" })
            $row['bulbPingMs'] = $(if ($reply.Status -eq 'Success') { $reply.RoundtripTime } else { '' })
        }
        catch { $row['bulbPing'] = 'ERROR'; $row['bulbPingMs'] = '' }
        $pilot = Invoke-WizQuery -IpAddress $WizIp -Method getPilot -TimeoutMs 1000 -Attempts 2
        $row['bulbApi'] = $(if ($pilot.ok -and $pilot.json -and $pilot.json.PSObject.Properties['result']) { 'ONLINE' } else { 'OFFLINE' })
        $row['bulbApiMs'] = $(if ($row['bulbApi'] -eq 'ONLINE') { $pilot.rttMs } else { '' })
        $row['bulbRssi'] = $(if ($row['bulbApi'] -eq 'ONLINE' -and $pilot.json.result.PSObject.Properties['rssi']) { $pilot.json.result.rssi } else { '' })
        $row['bulbOn'] = $(if ($row['bulbApi'] -eq 'ONLINE' -and $pilot.json.result.PSObject.Properties['state']) { $pilot.json.result.state } else { '' })
        if (-not $bulbMac -and $row['bulbApi'] -eq 'ONLINE') {
            $sys = Invoke-WizQuery -IpAddress $WizIp -Method getSystemConfig -TimeoutMs 1000 -Attempts 2
            if ($sys.ok -and $sys.json -and $sys.json.PSObject.Properties['result']) { $bulbMac = ConvertTo-NormalizedMac ([string]$sys.json.result.mac); $maskedMac = Protect-WizMac $bulbMac }
        }
        $row['bulbMac'] = $maskedMac

        # --- write ---------------------------------------------------------------
        [pscustomobject]$row | Export-Csv -LiteralPath $csvPath -Append -NoTypeInformation -Encoding UTF8
        if ($null -ne $previous) {
            foreach ($k in $watched) {
                if ("$($previous[$k])" -ne "$($row[$k])") {
                    $context = ($watched | ForEach-Object { "$_=$($row[$_])" }) -join ' '
                    Add-Content -LiteralPath $changesPath -Value "$($row.time) CHANGE $k : $($previous[$k]) -> $($row[$k]) | $context"
                }
            }
        }
        $previous = $row

        $status = "[{0}] [NETWORK] PPPoE: {1} Internet: {2} DNS: {3} | [HOTSPOT] {4} clients={5} wifi={6} | [WIZ] assoc={7} dhcp={8} arp={9} ping={10} api={11} {12}ms rssi={13}" -f `
            $row.time, $row['pppUp'], $row['internet'], $row['dns'], $row['hotspotState'], $row['hotspotClients'], $row['wifiAdapter'],
        $row['bulbAssociated'], $row['bulbInHostsIcs'], $row['bulbNeighbor'], $row['bulbPing'], $row['bulbApi'], $row['bulbApiMs'], $row['bulbRssi']
        $color = $(if ($row['bulbApi'] -eq 'ONLINE') { 'Gray' } else { 'Yellow' })
        Write-Host $status -ForegroundColor $color
    }
    catch {
        $msg = (Get-InnermostException $_.Exception).Message
        Add-Content -LiteralPath $changesPath -Value "$($tick.ToString('yyyy-MM-dd HH:mm:ss')) ERROR during check: $msg"
        Write-Host "[$($tick.ToString('HH:mm:ss'))] check failed: $msg" -ForegroundColor Red
    }

    $elapsed = ((Get-Date) - $tick).TotalSeconds
    $sleep = [math]::Max(1, $IntervalSeconds - $elapsed)
    Start-Sleep -Seconds ([int]$sleep)
}
