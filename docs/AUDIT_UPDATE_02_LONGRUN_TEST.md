# Audit update 2: the long-running WiZ failure and how to capture it

| | |
|---|---|
| Date | 2026-09-27 |
| Phase | Still **audit only**. Nothing is changed on the PC; the monitor is read-only. |
| Previous | [AUDIT_UPDATE_01_PC_RESULTS.md](AUDIT_UPDATE_01_PC_RESULTS.md) |

## 1. What your hotspot-restart test established

**[YOUR TEST]** After the Mobile Hotspot is switched Off and On again, the bulb **reconnects by itself**.

Conclusions:
* **Refuted:** "the bulb cannot rejoin after the hotspot disappears" (update 1, test C outcome 3). A
  hotspot restart does *not* reproduce the problem.
* Your real failure is different: **after roughly an hour or more of normal, untouched running**, the
  bulb becomes unavailable while the PC still has internet and the hotspot *appears* to stay on. A
  power cycle of the bulb is then needed.

## 2. Updated diagnosis: what can make the bulb drop after a long, steady run

None of these is confirmed. They are ranked by how well they fit what you describe.

| # | Hypothesis | What it would look like in the monitor |
|---|---|---|
| L1 | **Windows powers down or re-initialises the Wi-Fi adapter / hotspot.** "Allow the computer to turn off this device to save power" is **Enabled** on the RTL8852CE (confirmed on your PC). | Wi-Fi power state leaves D0, the adapter re-enumerates, its traffic counters reset, a hotspot/ICS/WLAN service restarts, the hotspot interface is recreated, or driver/NDIS/PnP events appear, *at or just before* the failure |
| L2 | **The Wi-Fi link between the hotspot and the bulb degrades while both stay "on".** The bulb uses Wi-Fi power saving (its 6–158 ms answer times fit that). A soft-AP driver that mishandles sleeping clients, or a periodic Wi-Fi security-key renewal that the bulb fails, can leave it "associated" but unreachable, or get it disconnected. The Windows hotspot's key-renewal interval is **not documented**. A failure at a regular interval (for example every ~60 min) would point here. | Bulb **still in the client list**, but ping, ARP and UDP fail; **or** the bulb drops out of the client list with **no** Windows-side sign |
| L3 | **Bulb firmware stops responding** (firmware 1.38.0) | Bulb associated **and pingable**, but UDP 38899 no longer answers |
| L4 | **Cloud-only failure:** the bulb stays on the LAN but its link to the WiZ cloud (which Alexa uses) breaks | Everything local stays OK while Alexa fails. You press **M** and the snapshot shows ping and UDP OK. |
| L5 | **PC-side idle or power policy** (display off, idle, sleep) | The failure correlates with the **idle time** column, or a gap in checks (PC asleep) |
| L6 | DHCP | **Unlikely:** leases last ~7 days (update 1). The monitor still records every lease and IP change. |

## 3. The one test: leave everything running and let the monitor catch the failure

`audit/Watch-WizConnectivity.ps1` was rebuilt for this (version 2.0.0). It stays read-only.

### What it records, and how often

| Every 10 s (sends nothing to the bulb) | Every 30 s, and every 10 s once a failure starts | Continuously |
|---|---|---|
| PC internet (TCP 443) and DNS · hotspot state, client count, interface index · hotspot virtual adapter status and traffic counters · **RTL8852CE** status, PnP status, **device power state (D0…D3)**, **last re-enumeration time**, traffic counters · hotspot/ICS/WLAN services: state and **process IDs** · bulb in the hotspot **client list** · bulb **DHCP** entry and lease end · bulb **ARP** state on the hotspot interface · bulb IP (followed by MAC) · **user idle time** | ICMP ping · WiZ **getPilot** on UDP 38899 (answer time, RSSI) | **Windows events:** Wi-Fi driver, NDIS, PnP, power, TCP/IP, DHCP and ICS providers; start/stop of icssvc, SharedAccess, WlanSvc, WFDSConMgrSvc; WLAN-AutoConfig, NetworkProfile, NCSI, Kernel-PnP and tethering/Wi-Fi-Direct channels |

When the bulb misses **two answers in a row**, the monitor:
1. takes a **snapshot**: 3 extra probes, the hotspot client list, the ARP table, the DHCP table,
   adapters, services, `netsh wlan show interfaces`, and the last 20 minutes of events;
2. writes an **incident analysis** with the **first failing layer** and the answers to your questions
   A–K;
3. beeps and shows instructions on screen;
4. keeps checking every 10 s until the bulb answers again, and then logs **RECOVERED**.

Pressing **M** records the moment you noticed Alexa failing, and takes a snapshot. If the snapshot then
shows everything local still OK, that is the cloud-only case (L4).

### How the incident analysis answers A–K

| Question | Answered from |
|---|---|
| A. Hotspot stayed ON? | Hotspot state at the failure, plus any change in the previous 30 min |
| B. Wi-Fi adapter active? Powered down / re-initialised? | Status, PnP status, **power state**, **re-enumeration**, **counter resets** (−30 … +5 min) |
| C. PC internet? | Internet and DNS at the failure, plus changes in the previous 30 min |
| D. Bulb reachable locally? | Ping and ARP |
| E. UDP 38899 stopped? | getPilot result: TIMEOUT (no answer) vs PORT_UNREACHABLE (bulb up, service gone) |
| F. Bulb disappeared from the network? | Hotspot client list (Wi-Fi association) |
| G. DHCP lease disappeared or changed? | DHCP entry, IP, lease end, plus changes in the previous 30 min |
| H. Reachable but not answering WiZ? | Ping OK while UDP fails |
| I. Windows event at the same time? | All captured events from 5 min before to 5 min after |
| J. RTL8852CE event? | Driver / NDIS / PnP / WLAN / power events, plus the power and re-initialisation signs |
| K. Hotspot service event? | icssvc / SharedAccess / WlanSvc / WFDSConMgrSvc events and process-ID changes, hotspot interface recreation |

The **first failing layer** is the earliest layer that went bad *after* the bulb's last good answer.
Layers that were already failing before that are listed separately as "not the cause". When several
layers fail at the same check, they are reported together. The precision is 10 s for passive layers,
and up to 30 s for ping/UDP before the first miss.

### How to read the outcome

| First failing layer | Meaning | What would follow (each needs your approval) |
|---|---|---|
| Wi-Fi power state, re-enumeration, counter reset, service restart or hotspot interface change | **Windows is powering down or re-initialising the adapter/hotspot** (L1) | Propose turning off "Allow the computer to turn off this device" (C10), then re-measure |
| Bulb leaves the client list, with no Windows-side sign | The **bulb** drops off Wi-Fi by itself, or the link fails (L2/L3) | Check whether it repeats at a regular interval; compare with the bulb on a different access point |
| Bulb still in the client list, but ARP/ping/UDP fail | The **Wi-Fi link** fails while "associated" (L2) | Power-save or key handling; points towards a soft-AP/driver limitation |
| Ping OK, UDP TIMEOUT | The **bulb's firmware** stops answering (L3) | Firmware angle; the local "reboot" command as a candidate software recovery |
| Everything local OK when you press M | **Cloud-only** (L4) | Cloud path investigation |
| Internet or DNS first | Upstream problem | Test the internet path |
| Gap in checks just before | PC slept or froze (L5) | Power plan review |

### Observer effect
The monitor itself sends one small UDP query to the bulb every 30 s. If the failure is related to the
bulb idling, this traffic *could* delay it. If nothing fails within about 3–4× your usual time, run
again with `-ProbeSeconds 300`: the bulb is then contacted only every 5 min, while everything else is
still checked every 10 s.

## 4. Procedure (the short version is in the chat reply)

1. Get the latest `audit` folder from branch `nova/trusting-archimedes-0id8jy`.
2. Bulb on and working with Alexa; hotspot on; internet on.
3. Run: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Watch-WizConnectivity.ps1`
4. Leave it running (window open, don't click inside it, no changes to network/hotspot/bulb). Normal
   PC use is fine.
5. When Alexa can't control the bulb: **press M**, wait **5 minutes** untouched, then power-cycle the bulb
   as usual, and wait for **RECOVERED**. Then press **Ctrl+C**, or leave it running to catch a second
   failure.
6. Send `watch-report.txt`, `watch.csv` and `events.log` from `audit\output\longrun-<date-time>\`.

## 5. Verification done in the sandbox
Parse check and Windows PowerShell 5.1 syntax check: clean. PSScriptAnalyzer: no findings (apart from
deliberately empty catch blocks). An end-to-end rehearsal with Windows cmdlets replaced by stubs and a
simulated bulb produced the expected sequence and the A–K analysis. The rehearsal ran: healthy, then
the bulb left the client list and stopped answering, the adapter reported D3 and a driver event was
logged, then the bulb recovered. The Windows-only parts (WinRT hotspot state, PnP power data, event
logs, console key handling) could not execute in the sandbox; your PC is their first real run.
