# Shared helpers for the Setup Controller audit scripts.
#
# Everything in this file is READ-ONLY with respect to the system:
#   - no registry writes, no service changes, no driver or adapter changes
#   - no USB/HID traffic
#   - network: localhost HTTP GET, TCP connect tests, and WiZ UDP "get*" queries only
#
# Target runtime: Windows PowerShell 5.1 (powershell.exe). Most helpers also work in PowerShell 7.

# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

$script:RedactionTokens = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::OrdinalIgnoreCase)
$script:RedactionCounters = @{}

function Add-RedactionToken {
    <# Registers a literal string (username, SSID, ...) that must never appear in output. #>
    param(
        [AllowNull()][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    $v = $Value.Trim()
    if ($v.Length -lt 3) { return }
    if ($script:RedactionTokens.ContainsKey($v)) { return }
    if (-not $script:RedactionCounters.ContainsKey($Label)) { $script:RedactionCounters[$Label] = 0 }
    $script:RedactionCounters[$Label]++
    $placeholder = '<' + $Label + '-' + $script:RedactionCounters[$Label] + '>'
    $script:RedactionTokens[$v] = $placeholder
    # Also register the JSON-escaped form so tokens containing quotes/backslashes are caught in JSON text.
    $quoted = ConvertTo-Json -InputObject $v -Compress
    $escaped = $quoted.Substring(1, $quoted.Length - 2)
    if ($escaped -ne $v -and -not $script:RedactionTokens.ContainsKey($escaped)) {
        $script:RedactionTokens[$escaped] = $placeholder
    }
}

function Test-IsPublicIPv4 {
    param([string]$Address)
    $parts = $Address.Split('.')
    if ($parts.Count -ne 4) { return $false }
    $o = @()
    foreach ($p in $parts) {
        $n = 0
        if (-not [int]::TryParse($p, [ref]$n) -or $n -lt 0 -or $n -gt 255) { return $false }
        $o += $n
    }
    if ($o[0] -eq 10) { return $false }                                   # RFC1918
    if ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) { return $false }
    if ($o[0] -eq 192 -and $o[1] -eq 168) { return $false }
    if ($o[0] -eq 127) { return $false }                                  # loopback
    if ($o[0] -eq 169 -and $o[1] -eq 254) { return $false }               # link-local
    if ($o[0] -eq 100 -and $o[1] -ge 64 -and $o[1] -le 127) { return $false } # CGNAT (not globally routable)
    if ($o[0] -eq 0 -or $o[0] -ge 224) { return $false }                  # unspecified, multicast, reserved, masks
    # Well-known public resolvers used as reachability probes are not personal data.
    if (@('1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9') -contains $Address) { return $false }
    return $true
}

function Protect-Text {
    <#
      Applies all redaction rules to a block of text:
        - registered literal tokens (username, computer name, SSIDs, ...)
        - MAC addresses (vendor OUI kept, device part masked)
        - public IPv4 / global IPv6 addresses (lines mentioning "version"/"driver"/"build" are skipped for IPv4,
          because driver version strings look like IPv4 addresses)
        - e-mail addresses (PPPoE user names are often in this form)
        - WiZ DHCP host names (wiz_<last 6 MAC hex digits>)
    #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }

    $result = $Text
    $keys = @($script:RedactionTokens.Keys | Sort-Object -Property Length -Descending)
    foreach ($k in $keys) {
        $pattern = '(?<![A-Za-z0-9])' + [regex]::Escape($k) + '(?![A-Za-z0-9])'
        $result = [regex]::Replace($result, $pattern, $script:RedactionTokens[$k], 'IgnoreCase')
    }

    $result = [regex]::Replace($result,
        '(?<![0-9A-Fa-f])([0-9A-Fa-f]{2})([:-])([0-9A-Fa-f]{2})\2([0-9A-Fa-f]{2})\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}(?![0-9A-Fa-f])',
        '${1}${2}${3}${2}${4}${2}xx${2}xx${2}xx')

    $result = [regex]::Replace($result, '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', '<email>')

    # WiZ DHCP host names end with the last 6 hex digits of the bulb's MAC address.
    $result = [regex]::Replace($result, '(?i)\bwiz_[0-9a-f]{6}\b', 'wiz_xxxxxx')

    $lines = $result -split "`n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -notmatch '(?i)version|driver|build|\bver\b') {
            $line = [regex]::Replace($line, '(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])', {
                    param($m)
                    if (Test-IsPublicIPv4 $m.Groups[1].Value) { '<public-ip>' } else { $m.Value }
                })
        }
        $line = [regex]::Replace($line, '(?i)(?<![0-9a-f:])[23][0-9a-f]{3}:(?:[0-9a-f]{0,4}:){1,6}[0-9a-f]{0,4}(?![0-9a-f:])', '<ipv6-global>')
        $lines[$i] = $line
    }
    return ($lines -join "`n")
}

function Protect-WizMac {
    <# WiZ reports MACs as 12 hex digits without separators. Keep the vendor OUI only. #>
    param([AllowNull()][string]$Mac)
    if ([string]::IsNullOrEmpty($Mac)) { return $Mac }
    $clean = ($Mac -replace '[^0-9A-Fa-f]', '')
    if ($clean.Length -ne 12) { return '<mac>' }
    return $clean.Substring(0, 6).ToLowerInvariant() + 'xxxxxx'
}

function ConvertTo-NormalizedMac {
    param([AllowNull()][string]$Mac)
    if ([string]::IsNullOrEmpty($Mac)) { return '' }
    return ($Mac -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
}

function Register-StandardRedactions {
    Add-RedactionToken -Value $env:USERNAME -Label 'user'
    Add-RedactionToken -Value $env:COMPUTERNAME -Label 'computer'
    if ($env:USERDOMAIN -and $env:USERDOMAIN -ne $env:COMPUTERNAME) {
        Add-RedactionToken -Value $env:USERDOMAIN -Label 'domain'
    }
    if ($env:USERPROFILE) {
        Add-RedactionToken -Value (Split-Path -Leaf $env:USERPROFILE) -Label 'user'
    }
}

# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

function Get-InnermostException {
    param($Exception)
    $e = $Exception
    while ($null -ne $e -and $null -ne $e.InnerException) { $e = $e.InnerException }
    return $e
}

function Invoke-Section {
    <# Runs one audit section; a failure is recorded instead of aborting the whole audit. #>
    param(
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Report,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )
    Write-Host ("  - {0} ..." -f $Name)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $Report[$Name] = & $Body
    }
    catch {
        $inner = Get-InnermostException $_.Exception
        $Report[$Name] = [ordered]@{ error = $inner.Message; errorType = $inner.GetType().FullName }
        Write-Host ("    ! {0}: {1}" -f $Name, $inner.Message) -ForegroundColor Yellow
    }
    $sw.Stop()
    if (-not $Report.Contains('_timings')) { $Report['_timings'] = [ordered]@{} }
    $Report['_timings'][$Name] = [math]::Round($sw.Elapsed.TotalSeconds, 2)
}

function Invoke-NativeLines {
    <#
      Runs a native read-only command (netsh, powercfg, ...) and returns its output lines.
      Windows PowerShell 5.1 turns native stderr into terminating errors when ErrorActionPreference is
      'Stop', so the preference is relaxed for the duration of the call.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @()
    )
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        return @(& $FilePath @Arguments 2>&1 | ForEach-Object { "$_" })
    }
    finally { $ErrorActionPreference = $previous }
}

function Test-IsAdministrator {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

function Test-TcpPort {
    <# TCP connect test only; closes immediately without sending any data. #>
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][int]$Port,
        [int]$TimeoutMs = 1500
    )
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs)) { return $false }
        $client.EndConnect($ar)
        return $client.Connected
    }
    catch { return $false }
    finally { $client.Close() }
}

function Invoke-LocalHttpGet {
    <# HTTP GET without proxy. Used only for documented read-only endpoints on 127.0.0.1. #>
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [int]$TimeoutMs = 3000
    )
    $request = [System.Net.HttpWebRequest]::Create($Url)
    $request.Method = 'GET'
    $request.Timeout = $TimeoutMs
    $request.ReadWriteTimeout = $TimeoutMs
    $request.Proxy = $null
    $response = $null
    try {
        $response = $request.GetResponse()
    }
    catch {
        $inner = Get-InnermostException $_.Exception
        $webEx = $_.Exception
        while ($null -ne $webEx -and -not ($webEx -is [System.Net.WebException])) { $webEx = $webEx.InnerException }
        if ($null -ne $webEx -and $null -ne $webEx.Response) {
            $response = $webEx.Response
        }
        else {
            return [ordered]@{ url = $Url; reachable = $false; error = $inner.Message }
        }
    }
    try {
        $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
        $body = $reader.ReadToEnd()
        $reader.Close()
        return [ordered]@{ url = $Url; reachable = $true; status = [int]$response.StatusCode; body = $body }
    }
    finally { $response.Close() }
}

# ---------------------------------------------------------------------------
# WiZ local UDP protocol (read-only subset)
# ---------------------------------------------------------------------------
# Port 38899/UDP, JSON messages (see pywizlight: pywizlight/bulb.py). Only the four "get*" methods below are
# ever sent by these audit scripts. setPilot, registration, reboot, reset and every other method are
# deliberately impossible to send through this helper.

$script:WizPort = 38899
$script:WizReadOnlyMethods = @('getSystemConfig', 'getModelConfig', 'getPilot', 'getUserConfig')

function Invoke-WizQuery {
    param(
        [Parameter(Mandatory = $true)][string]$IpAddress,
        [Parameter(Mandatory = $true)][ValidateSet('getSystemConfig', 'getModelConfig', 'getPilot', 'getUserConfig')][string]$Method,
        [int]$TimeoutMs = 1000,
        [int]$Attempts = 3,
        [int]$Port = $script:WizPort
    )
    if ($script:WizReadOnlyMethods -notcontains $Method) { throw "Method '$Method' is not in the read-only allow-list." }

    $address = [System.Net.IPAddress]::Parse($IpAddress)
    $payload = '{"method":"' + $Method + '","params":{}}'
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($payload)
    $udp = New-Object System.Net.Sockets.UdpClient(0)
    try {
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $endpoint = New-Object System.Net.IPEndPoint($address, $Port)
        for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            [void]$udp.Send($bytes, $bytes.Length, $endpoint)
            try {
                $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $data = $udp.Receive([ref]$remote)
                $sw.Stop()
                $text = [System.Text.Encoding]::UTF8.GetString($data)
                $json = $null
                try { $json = $text | ConvertFrom-Json } catch { }
                return [pscustomobject]@{
                    ok       = $true
                    method   = $Method
                    attempt  = $attempt
                    rttMs    = [math]::Round($sw.Elapsed.TotalMilliseconds, 1)
                    from     = $remote.Address.ToString()
                    raw      = $text
                    json     = $json
                }
            }
            catch {
                $inner = Get-InnermostException $_.Exception
                if ($inner -is [System.Net.Sockets.SocketException]) {
                    $code = $inner.SocketErrorCode
                    if ($code -eq [System.Net.Sockets.SocketError]::TimedOut -or $code -eq [System.Net.Sockets.SocketError]::WouldBlock) {
                        continue
                    }
                    if ($code -eq [System.Net.Sockets.SocketError]::ConnectionReset) {
                        # Windows reports an ICMP "port unreachable" this way: the host is up but nothing listens on 38899.
                        return [pscustomobject]@{ ok = $false; method = $Method; attempt = $attempt; error = 'port-unreachable (host is not a WiZ device)' }
                    }
                }
                return [pscustomobject]@{ ok = $false; method = $Method; attempt = $attempt; error = $inner.Message }
            }
        }
        return [pscustomobject]@{ ok = $false; method = $Method; attempt = $Attempts; error = 'timeout' }
    }
    finally { $udp.Close() }
}

function Protect-WizResult {
    <# Returns a copy of a WiZ "result" object with identifiers masked. #>
    param($Result)
    if ($null -eq $Result) { return $null }
    $copy = [ordered]@{}
    foreach ($p in $Result.PSObject.Properties) {
        switch -Regex ($p.Name) {
            '^mac$' { $copy[$p.Name] = Protect-WizMac ([string]$p.Value); break }
            '^(homeId|roomId|groupId|uid|ownerId)$' { $copy[$p.Name] = '<redacted>'; break }
            '(?i)(key|token|secret|pass)' { $copy[$p.Name] = '<redacted>'; break }
            default { $copy[$p.Name] = $p.Value }
        }
    }
    return $copy
}

# ---------------------------------------------------------------------------
# Windows Mobile Hotspot (WinRT, Windows PowerShell 5.1 only)
# ---------------------------------------------------------------------------

function Initialize-WinRtNetworking {
    if ($PSVersionTable.PSEdition -ne 'Desktop') { return $false }
    try {
        Add-Type -AssemblyName System.Runtime.WindowsRuntime
        $null = [Windows.Networking.Connectivity.NetworkInformation, Windows.Networking.Connectivity, ContentType = WindowsRuntime]
        $null = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager, Windows.Networking.NetworkOperators, ContentType = WindowsRuntime]
        return $true
    }
    catch { return $false }
}

function Get-HotspotRuntimeState {
    <#
      Reads the Mobile Hotspot state through NetworkOperatorTetheringManager.
      Tries the internet profile first and then every other connection profile, so the hotspot state can
      still be read while the PPPoE (internet) connection is down.
      Never reads or returns the passphrase. Returns $null if WinRT is unavailable.
    #>
    if (-not (Initialize-WinRtNetworking)) { return $null }
    $tmType = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]
    $infoType = [Windows.Networking.Connectivity.NetworkInformation]
    $ordered = @()
    $internetProfile = $infoType::GetInternetConnectionProfile()
    if ($null -ne $internetProfile) { $ordered += $internetProfile }
    foreach ($p in @($infoType::GetConnectionProfiles())) { $ordered += $p }

    $fallback = $null
    foreach ($connectionProfile in $ordered) {
        try {
            $manager = $tmType::CreateFromConnectionProfile($connectionProfile)
            $macs = @()
            try { $macs = @($manager.GetTetheringClients() | ForEach-Object { ConvertTo-NormalizedMac $_.MacAddress }) } catch { }
            $snapshot = [pscustomobject]@{
                state            = $manager.TetheringOperationalState.ToString()
                clientCount      = $manager.ClientCount
                clientMacs       = $macs
                viaInternetProfile = ($null -ne $internetProfile -and [object]::ReferenceEquals($connectionProfile, $internetProfile))
            }
            if ($snapshot.state -eq 'On') { return $snapshot }
            if ($null -eq $fallback) { $fallback = $snapshot }
        }
        catch { continue }
    }
    if ($null -ne $fallback) { return $fallback }
    return [pscustomobject]@{ state = 'Unavailable'; clientCount = $null; clientMacs = @(); viaInternetProfile = $false }
}

function Get-HostsIcsEntries {
    <# ICS writes DHCP clients (IP + host name) to hosts.ics. #>
    $path = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts.ics'
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    $entries = @()
    foreach ($line in (Get-Content -LiteralPath $path -ErrorAction Stop)) {
        $t = $line.Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        $parts = $t -split '\s+'
        if ($parts.Count -ge 2) {
            $entries += [pscustomobject]@{ ip = $parts[0]; hostName = ($parts[1..($parts.Count - 1)] -join ' ') }
        }
    }
    return $entries
}

function Get-HotspotInterfaceIPv4 {
    <# Finds the IPv4 address of the interface that serves the hotspot / ICS private network. #>
    $candidates = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
            $_.IPAddress -like '192.168.137.*'
        })
    if ($candidates.Count -eq 0) {
        $wfd = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object {
                $_.InterfaceDescription -like '*Wi-Fi Direct Virtual Adapter*' -and $_.Status -eq 'Up'
            })
        foreach ($a in $wfd) {
            $candidates += @(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue)
        }
    }
    return ($candidates | Select-Object -First 1)
}
