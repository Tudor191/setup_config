# Setup Controller – Phase 1 audit tools (read-only)

These scripts collect the on-PC evidence that the audit report (`docs/AUDIT_REPORT.md`) still needs.
The audit was prepared in a cloud sandbox that cannot see your PC. The report therefore marks every
machine-specific finding as **PENDING** until these scripts have been run on the PC.

## Safety guarantees

All three scripts are **read-only**:

| Never done | How it is enforced |
|---|---|
| Change settings, registry, services, drivers, adapters, firewall, hotspot | Only `Get-*` cmdlets, `netsh … show`, `powercfg /query`, and WinRT *getters* are used |
| Send USB/HID commands | No HID/USB API is used at all |
| Change SignalRGB / SteelSeries GG / NGENUITY / Redragon / Gigabyte state | SignalRGB: HTTP **GET** only. GameSense: TCP connect test only (its API is POST-only and would register an app inside GG) |
| Change the WiZ bulb | Only `getSystemConfig`, `getModelConfig`, `getPilot`, `getUserConfig` can be sent: the method parameter is restricted with `ValidateSet`. No broadcast `registration` message is sent. |
| Read secrets | The Wi-Fi keys, hotspot passphrase, PPPoE credentials, tokens and `rasdial` task arguments are never read |

Output is **redacted**: Windows user and computer name, SSIDs, e-mail addresses, the device half of MAC
addresses (the vendor OUI is kept), public IPv4/global IPv6 addresses, USB serial numbers, WiZ home/room IDs.
Private LAN addresses (for example `192.168.137.x`) are kept because the WiZ investigation needs them.
Please still read the output before sharing it.

## How to run

Use **Windows PowerShell 5.1** (`powershell.exe`), not PowerShell 7. The Mobile Hotspot API (WinRT) is only
reachable from 5.1. Administrator rights are optional: running as Administrator adds the Device Manager
"allow the computer to turn off this device" flag for the network adapters.

`-ExecutionPolicy Bypass` applies only to that one process. It does not change your system policy.

```powershell
cd <path-to-repo>\audit

# 1) Full system inventory (about 1 minute)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Collect-SetupAudit.ps1

# 2) WiZ bulb local-API check (bulb must be powered and connected)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Probe-WizBulb.ps1
#    If nothing is found:  -IpAddress 192.168.137.x   or   -SweepHotspotSubnet

# 3) WiZ long-run monitor (v2): leave it running until the bulb fails (can be hours).
#    Press M in its window when Alexa stops controlling the bulb. Stop with Ctrl+C.
#    It only observes; it never tries to recover anything.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Watch-WizConnectivity.ps1
```

When the bulb drops, please also note (outside the PC): does the WiZ app on your phone show it offline?
Does Alexa? Is the bulb physically on? This separates Wi-Fi loss from cloud loss.

## Output

Everything goes to `audit\output\` (git-ignored):

| File | Content |
|---|---|
| `audit-<ts>\audit-summary.txt` | Short human-readable summary: **start here** |
| `audit-<ts>\audit-report.json` | Full structured evidence |
| `wiz-<ts>\wiz-probe.txt / .json` | Bulb module, firmware, RSSI, local API latency |
| `longrun-<ts>\watch-report.txt` | Monitor summary: configuration, **incident analysis (first failing layer, questions A–K)**, all state changes, snapshots. **Send this.** |
| `longrun-<ts>\watch.csv` | One row per check (internet, DNS, hotspot, Wi-Fi adapter power state, services, DHCP, ARP, ping, WiZ API, idle time). **Send this.** |
| `longrun-<ts>\events.log` | Captured Windows events (Wi-Fi driver, NDIS, PnP, power, hotspot/ICS/WLAN services). **Send this.** |
| `longrun-<ts>\changes.log`, `snapshot-*.txt` | Live change log and detailed snapshots (already included in the report) |

To share results: attach `audit-summary.txt`, `wiz-probe.txt`, `changes.log` and **`watch.csv`**. Attach
`audit-report.json` too: it holds the details the summary leaves out. Or commit the reviewed files
with `git add -f audit/output/...`.

Tool versions: collector **1.1** (summary now reports the internet path, ICS roles and "no PPPoE"
explicitly; service restarts are matched by service name; the `wiz_xxxxxx` host name is masked). Watch:
the ARP column now reads only the hotspot interface.

## What each script looks at

**Collect-SetupAudit.ps1**: Windows version and build; motherboard model, revision and BIOS; power plan and
wireless power-saving policy; installed RGB and vendor software (including Store apps); vendor and network
services; vendor processes and the ports they listen on; every USB/HID device with VID, PID, interface,
HID usage page and driver; keyboards, mice and audio endpoints; network adapters with driver version,
advanced properties and power management; IP, routes, DNS and connection profiles; `netsh wlan` driver
capabilities; Mobile Hotspot state, band, security, client list and no-connections timeout; ICS sharing roles,
`hosts.ics` DHCP table and ICS registry settings; PPPoE interfaces, MTU and phonebook redial settings;
SteelSeries `coreProps.json`; SignalRGB version, plugins and settings key names; Gigabyte and Redragon
folders; read-only SignalRGB API GETs; event logs (PPPoE dial and disconnect, hotspot and ICS service
restarts, Wi-Fi driver, NDIS, power and sleep) for the last 14 days.

**Probe-WizBulb.ps1**: finds the bulb via `hosts.ics` and the hotspot's neighbour table, then reads its
module name, firmware, current state, RSSI and UDP latency.

**Watch-WizConnectivity.ps1** (v2, long-run monitor): every 10 s it checks internet, DNS, hotspot, the
Wi-Fi adapter (including its device power state, re-enumeration and traffic counters), the hotspot/ICS/WLAN
services, and the bulb's association, DHCP entry and ARP state. It pings the bulb and sends the read-only
`getPilot` every 30 s. It collects the relevant Windows events continuously. When the bulb stops
answering it writes an incident analysis naming the first failing layer. Details:
[`docs/AUDIT_UPDATE_02_LONGRUN_TEST.md`](../docs/AUDIT_UPDATE_02_LONGRUN_TEST.md). The only thing it
changes is its own console window's QuickEdit mode (so a stray click cannot pause it); that ends when
the window closes.
