# Audit update 1: results from the real PC (2026-09-26)

| | |
|---|---|
| Inputs | `audit-summary.txt` (collector v1.0, 21:04), `wiz-probe.txt` (21:04), `changes.log` (watch run, event at 21:10:36) |
| Not received yet | `audit-report.json` (full evidence behind the summary), `watch.csv` (every 30-s sample of the watch run) |
| Phase | Still **audit only**. Nothing was installed, changed or controlled on the PC. |
| Base report | [`AUDIT_REPORT.md`](AUDIT_REPORT.md) (research phase). Its conclusions that this data contradicts are listed in section 2.3. |

Every statement below is labelled:
**[PC]** = read directly from your PC's files · **[DOC]** = from documentation or source code ·
**[INFERENCE]** = my interpretation of [PC] data · **[HYPOTHESIS]** = not yet tested.

Times are the PC's local time as written in your files.

---

## 1. CONFIRMED FACTS

| # | Fact | Source |
|---|---|---|
| F1 | Windows 11 Pro **25H2**, build 26200.9457; the PC had been up **≈2 h** at 21:04 (booted ≈19:00) | [PC] summary |
| F2 | Board **Gigabyte B650 GAMING X AX V2**, BIOS **F34** (2025-05-23). The board does not report its PCB revision ("x.x"). | [PC] summary |
| F3 | Wi-Fi adapter **Realtek 8852CE WiFi 6E**, driver 6001.16.162.1 (2024-10-28). Its own client connection is "Disconnected" (it is not joined to any Wi-Fi network; it only hosts the hotspot). | [PC] summary |
| F4 | Wi-Fi adapter power management: **"Allow the computer to turn off this device to save power" = Enabled** | [PC] summary |
| F5 | Mobile Hotspot at 21:04: **On**, interface "Local Area Connection* 9" **192.168.137.1/24**, **2 of 8** clients, band **2.4 GHz** (explicitly set), security **WPA2**, **no-connections timeout: disabled**. The adapter supports 2.4 GHz and 5 GHz hotspots, not 6 GHz. | [PC] summary + probe |
| F6 | Hotspot clients (ICS DHCP table): an **iPhone** (192.168.137.243) and the **WiZ bulb** (192.168.137.77, hostname `wiz_xxxxxx`) | [PC] summary |
| F7 | **No PPP (PPPoE) interface existed** at 21:04 or at any moment of the watch run. The **default route was "Ethernet"**, and internet (TCP 443 to 1.1.1.1 / 8.8.8.8) and DNS were **OK** throughout. | [PC] summary + changes.log |
| F8 | RasClient (dial-up/PPPoE/VPN) history, 14 days: **three events**: 20222, 20221, **20227 (= a dial that failed)**. No successful dial is recorded. | [PC] summary; meaning of IDs [DOC] |
| F9 | The WiZ bulb answered the local UDP API (port 38899): module **ESP25_SHRGB_01**, firmware **1.38.0**, on, dimming 50 %, **RSSI −44 dBm** (strong), **0/10 lost**, latency min 6.4 / avg 133 / max 158 ms | [PC] probe |
| F10 | At **21:10:36** the Mobile Hotspot went **Off**. At that same check the internet and DNS were **still OK**, and the default route was still "Ethernet". | [PC] changes.log |
| F11 | Motherboard RGB controller **048D:5702** (ITE IT5702) present, with HID collections usage page **FF89** / usages 0010 and 00CC | [PC] summary |
| F12 | Mouse **1038:1832** (standard Sensei TEN): interface 0 = vendor page FFC0, interfaces 1–2 = mouse/keyboard/consumer, interface 3 = vendor page FFC1 | [PC] summary |
| F13 | Microphone RGB/HID function **0951:171F** (Kingston era), interface 0 = vendor page **FF90 / usage FF00**. Its audio function is a separate USB function, **0951:171D**. | [PC] summary |
| F14 | The only non-SteelSeries keyboard on the PC enumerates as **0C45:5004** (two "HID Keyboard Device" entries). The two 1038:1832 keyboard entries belong to the mouse. | [PC] summary |
| F15 | Software: **SignalRGB 2.5.74** (installed program + a Store package; service `SignalRgb.Service` Running/Auto; SignalRgb, Launcher and Service processes running); **SteelSeries GG 101.0.0** (GG, Engine and Prism running); **two HyperX NGENUITY Store packages** (`33C30B79.NGENUITY`, `33C30B79.HyperXNGenuity`) with **NGenuity2Helper.exe running**; **NZXT CAM 4.76.5** (CAMService Running/Auto, CAM and helper processes running) | [PC] summary |
| F16 | **No Gigabyte Control Center / RGB Fusion** among installed programs, services or processes. **No Redragon software** among installed programs. **OpenRGB** is not running. | [PC] summary |
| F17 | SignalRGB API port **16038 is listening**, but `GET /api/v1/lighting` returned **HTTP 403** | [PC] summary |
| F18 | SteelSeries GameSense: `coreProps.json` exists in both the Engine 3 location and the GG location. `address` 127.0.0.1:64921, `encryptedAddress` :64926 and `ggEncryptedAddress` :6327 **all accept connections** (connect test only; nothing was sent). | [PC] summary |
| F19 | Last 14 days of System events matched: WLAN-AutoConfig ×14, Dhcp-Client ×52, DHCPv6-Client ×20, Kernel-Power ×32, Kernel-PnP ×6, DNS-Client ×1. Hotspot/ICS/WLAN/RAS service state changes counted: 0 (see caveat in section 11). | [PC] summary |

---

## 2. WHAT THE REAL PC AUDIT REVEALED

### 2.1 The most important discovery: this PC is not using PPPoE
[PC] During the audit and the whole watch run there was **no PPPoE (PPP) interface**. The PC reached the
internet **directly through its Ethernet adapter** (default route "Ethernet"; F7). In 14 days there was
exactly **one** dial attempt, and it **failed** (F8).
[INFERENCE] Either a device upstream (ISP router or ONT in router mode) does the PPPoE login and hands
the PC an address, or the ISP gives the PC an address directly (IPoE/DHCP). The 52 Dhcp-Client events
(F19) fit an Ethernet link that gets its address by DHCP. Which of the two it is will be visible in
`audit-report.json` (`ipConfiguration`), or in the new `[INTERNET]` summary line of collector v1.1.

### 2.2 Other headline findings
* [PC] The hotspot is already configured the way the research recommended: **2.4 GHz, WPA2, no
  auto-off** (F5). Three of the ten hypotheses are therefore **eliminated** (section 3.3).
* [PC] The bulb's radio link is **excellent** (RSSI −44 dBm, no loss) and its **local API works**
  without any extra configuration (F9).
* [PC] **SignalRGB's API is not usable on this PC as it stands** (403; section 5).
* [PC] **GameSense is available** (section 6).
* [PC] The microphone is the best-supported variant (0951:171F) (section 7).
* [PC] The keyboard is **not** the ID the only K557 project claims (section 8).
* [PC] New item not in your list: **NZXT CAM** is installed and running (section 10).
* [PC] The Wi-Fi adapter may be powered down by Windows (F4). It is a plausible cause of hotspot
  interruptions, but not proven.
* [PC] The PC had been started ≈2 h before the audit, and there are 32 Kernel-Power events in 14 days.
  A restart or sleep stops the hotspot. The JSON will show how often that happens.

### 2.3 Research conclusions that the real data contradicts or changes

| Earlier conclusion (AUDIT_REPORT.md) | Real data | Updated conclusion |
|---|---|---|
| Topology: *"PC receives internet through PPPoE"*; H1 *"PPPoE redial on the PC breaks things"* | No PPP interface; default route Ethernet; 1 failed dial in 14 days (F7, F8) | **Contradicted for the audit period.** The PC does not run PPPoE. H1 in its "PPPoE on the PC" form cannot explain any drop in the last 14 days. Only a generalized version remains open: an interruption of the upstream internet (wherever PPPoE runs) breaks the bulb's cloud session. That is **untested**. |
| Kala: *"one community plugin claims 320F:5000 / 5055"* | Keyboard is **0C45:5004** (F14) | **Contradicted for this unit.** That plugin does not match your keyboard. |
| SignalRGB API: *"no authentication (plain HTTP)"* | 403 on a read-only GET (F17) | **Refined.** Access is gated by account: SignalRGB's docs say Pro endpoints return 403 when no user is signed in or the user has no Pro. The API is not usable here without Pro. |
| Wi-Fi chip: one of three (Realtek/MediaTek/Intel) depending on revision | Realtek 8852CE (F3) | **Resolved.** Per Gigabyte's spec this corresponds to board revision 1.0 [DOC, snippet]. |
| Microphone may be HP-era (03F0:xxxx) | 0951:171F (F13) | **Resolved:** Kingston-era, supported by OpenRGB, QuadcastRGB and SignalRGB. |
| Gigabyte RGB Fusion conflict possible | Not installed (F16) | **Resolved:** no Gigabyte software conflict today. |
| H3 no-connections timeout · H4 band Auto · H5 WPA3 | Timeout disabled, 2.4 GHz, WPA2 (F5) | **Eliminated.** |
| H6 DHCP lease expiry | `hosts.ics` lease end times are 7 days after issue (section 9) | **Weakened.** Leases last ~7 days, so expiry cannot cause frequent drops. |
| H8 weak signal | RSSI −44 dBm, 0 % loss (F9) | **Weakened** (true at 21:04; the watch keeps measuring it). |
| H7 Wi-Fi power saving | "Allow the computer to turn off this device" = Enabled (F4) | **Risk factor confirmed present**; not proven to cause drops. |

---

## 3. WiZ CONNECTIVITY RESULTS

### 3.1 Before your experiment (probe at 21:04 and every watch sample until ≈21:10:06)

| Layer | Result | Source |
|---|---|---|
| Bulb powered, on | on=True, dimming 50 % | [PC] probe |
| Wi-Fi association to the hotspot | Associated (in the hotspot client list: clients 2/8) | [PC] summary; changes.log "YES -> NO" at 21:10:36 implies YES before |
| DHCP | Lease 192.168.137.77 in `hosts.ics` | [PC] summary |
| Signal | −44 dBm (excellent) | [PC] probe |
| ICMP ping | OK until 21:10:06 | [PC] changes.log "OK -> TimedOut" |
| Local UDP 38899 / WiZ API | ONLINE; 10/10 answers | [PC] probe + changes.log |
| "Allow local communication" | Effectively **on**: the bulb answers unsigned local queries | [INFERENCE] from F9 (writes not tested, by design) |
| Internet on the PC | OK (TCP 443 + DNS) | [PC] changes.log (unchanged all run) |
| Alexa | Working, by your report | Your observation (not measurable by the tools) |

### 3.2 Latency note
[PC] The average is 133 ms but the minimum is 6.4 ms. [INFERENCE] This spread is typical of a Wi-Fi
client that uses **802.11 power saving**: it sleeps between beacons, and the access point holds packets
for it until it wakes. It is normal for ESP-based smart bulbs and is **not a fault**. It does mean the
bulb relies on the Windows soft-AP handling power-saving clients correctly. That is noted, not
concluded.

### 3.3 Hypothesis status after the real data

| Hypothesis | Status |
|---|---|
| H1 PPPoE redial on the PC | **Not applicable** in the last 14 days (no PPPoE on the PC) |
| H1' Upstream internet loss breaks the bulb's cloud session | **Open, untested** |
| H2 Hotspot interrupted (driver/power/restart/sleep) and the bulb does not rejoin | **Open**. Your run proves an interruption drops the bulb instantly; recovery was not observed. |
| H3 No-connections timeout | **Eliminated** (disabled) |
| H4 Band Auto → 5 GHz | **Eliminated** (2.4 GHz fixed) |
| H5 WPA3 / transition | **Eliminated** (WPA2) |
| H6 DHCP lease expiry | **Weakened** (7-day leases) |
| H7 Wi-Fi power saving | **Open; risk factor present** (F4) |
| H8 Weak signal | **Weakened** (−44 dBm) |
| H9 Bulb firmware (1.38.0) | **Open** |
| H10 PC sleep/restart | **Open.** PC booted ≈19:00 that day; 32 Kernel-Power events in 14 days |

---

## 4. WHAT HAPPENED DURING YOUR INTENTIONAL INTERNET-OFF TEST

### 4.1 Timeline (the only transition in changes.log)

| Time | What the monitor saw | Source |
|---|---|---|
| start … ≈21:10:06 | Hotspot On · bulb associated · DHCP entry present · ping OK · WiZ API ONLINE · **internet OK · DNS OK · default route Ethernet · no PPPoE** | [PC] implied by "old → new" values in changes.log |
| *between ≈21:10:06 and 21:10:36* | **Your action** | Your description |
| **21:10:36** | **Hotspot: On → Off** · hotspot interface 192.168.137.1 **disappeared** · bulb **left** the client list · bulb's `hosts.ics` entry **removed** · ping **TimedOut** · WiZ API **OFFLINE** | [PC] changes.log |
| **21:10:36** | **Internet: still OK · DNS: still OK · default route: still Ethernet · PPPoE: none (unchanged)** | [PC] changes.log (these fields never changed) |
| after 21:10:36 | **No further changes recorded** | [PC] changes.log |

### 4.2 What this means

**The data does not show an internet outage. It shows the Mobile Hotspot being switched off.**
At the exact check where the hotspot was found Off, the PC still reached 1.1.1.1/8.8.8.8 over TCP 443
and resolved DNS. No later check ever recorded an internet failure.

Three explanations are consistent with the log. I can't tell them apart without `watch.csv` and
your description of the exact action:

| Possibility | Fits the log? |
|---|---|
| **(a)** The action that "turned off internet" actually switched off Wi-Fi or the hotspot: Airplane mode, the Wi-Fi quick toggle, the Mobile-hotspot toggle, or disabling the connection the hotspot shares that is **not** the PC's Ethernet internet path. The PC's Ethernet internet kept working. | **Yes, fully** |
| **(b)** The internet was cut (Ethernet cable unplugged / adapter disabled) a second or two after that check had already tested the internet. Windows then stopped the hotspot, and the monitor was closed before the next check (≤30 s later) could record the internet failure. | Only if monitoring stopped within ~30 s |
| **(c)** The internet was cut upstream (modem/router) | **No.** The internet check would have failed. |

After 21:10:36 there is no "hotspot Off → On" and no "internet OK → FAIL". So either the monitor was
stopped soon after 21:10:36, or the hotspot stayed off and the internet stayed up until it was stopped.
`watch.csv` shows which. The new watch version (v1.1) also writes `START`, `INITIAL STATE` and `STOP`
lines, so this is visible directly in `changes.log` next time.

### 4.3 Your eleven questions, answered layer by layer

| # | Question | Answer | Basis |
|---|---|---|---|
| 1 | What changed immediately? | The **hotspot** turned off and took the whole local network with it. The internet did **not** change. | [PC] |
| 2 | Did the bulb stay reachable on the LAN? | **No**, after 21:10:36. The LAN itself (192.168.137.x) no longer existed. | [PC] |
| 3 | Did UDP 38899 stay reachable? | **No**, after 21:10:36. There was no network path. Before that: yes. | [PC] |
| 4 | Did the local WiZ API keep responding? | **No** (OFFLINE), for the same reason. | [PC] |
| 5 | Did only cloud/internet fail? | **No. The opposite:** the PC's internet stayed up; the local Wi-Fi went down. | [PC] |
| 6 | Did Alexa lose the bulb? | **Not measured** by the tools. With the hotspot off the bulb has no network at all, so Alexa losing it is **expected**. Please tell me what you saw. | [INFERENCE] |
| 7 | Did the hotspot stay active? | **No**: On → Off at 21:10:36 | [PC] |
| 8 | Did the PC's Wi-Fi adapter stay active? | **Cannot be determined.** Its client-mode status was "Disconnected" before and after, which is normal for a hotspot-only adapter and says nothing about whether the radio was switched off. The hotspot's virtual interface disappeared. | [PC] + [INFERENCE] |
| 9 | Did DHCP / local networking stay functional? | Until 21:10:06: yes. At 21:10:36 the hotspot subnet was gone and the bulb's lease was removed from `hosts.ics`. That is a **consequence of the hotspot stopping**, not a DHCP fault. | [PC] |
| 10 | Support or weaken "PPPoE drops cause my WiZ problem"? | **Weakens it strongly**, but not because of the experiment: the PC has **no PPPoE connection** (F7, F8). The experiment itself did not cut the internet, so it neither supports nor refutes an "internet-loss" cause. | [PC] |
| 11 | Does the bulb leave the hotspot, or stay connected but lose the cloud? | **In this run the bulb left because the hotspot itself went away.** That was triggered by your action, so it says nothing yet about the original spontaneous problem. Both mechanisms are still possible: "hotspot interrupted and the bulb doesn't come back" (H2/H7/H10) and "bulb stays on the LAN but loses the cloud" (H1'). | [PC] + [HYPOTHESIS] |

### 4.4 Was the test sufficient?
**No.** It did not produce the state it aimed for (internet down while the hotspot stays up), and it did
not observe the most important thing for your real problem: **what the bulb does when the network comes
back**. Section 12 gives the one test that closes that gap.

---

## 5. SIGNALRGB FINDINGS

| Item | Finding | Label |
|---|---|---|
| Version | SignalRGB **2.5.74**, installed program plus a Store package of the same name | [PC] |
| Running | `SignalRgb.Service` (Running, Auto), `SignalRgbService.exe`, `SignalRgbLauncher.exe`, `SignalRgb.exe` | [PC] |
| Motherboard controller | 048D:5702 with the exact HID collection (usage page FF89, usage CC) that OpenRGB's detector and SignalRGB's Gigabyte plugin target | [PC] + [DOC] |
| Local API | Listening on 127.0.0.1:16038, **GET /lighting → 403** | [PC] |
| Meaning of 403 | *"Endpoints requiring a Pro user account will return a 403 Forbidden error if the running application doesn't have a signed in user, or the signed in user doesn't have a SignalRGB Pro account."* | [DOC, snippet of docs.signalrgb.com] |
| Conclusion | **No programmatic control of SignalRGB on this PC without Pro.** The API server itself is up. | [INFERENCE] |
| Gigabyte software conflict | None: no GCC or RGB Fusion present | [PC] |
| Is SignalRGB also driving the mouse, mic or keyboard? | **Unknown.** It has plugins for the Sensei Ten and QuadCast S; whether they are enabled is only visible in SignalRGB's *Devices* page (a look, not a change) or in the JSON registry section. | open |

---

## 6. SENSEI TEN FINDINGS

| Item | Finding | Label |
|---|---|---|
| Identity | **1038:1832** Sensei TEN (not the Neon Rider edition) | [PC] |
| HID layout | Interface 0 = vendor page FFC0 (the interface rivalcfg configures), 1–2 = mouse/keyboard/consumer, 3 = vendor page FFC1 | [PC] + [DOC] |
| SteelSeries GG | **101.0.0**, running with Engine and **Prism** (GG's lighting engine) | [PC] |
| GameSense | **Available**: both `coreProps.json` locations exist; the plain-HTTP `address` port 64921 accepts connections | [PC] |
| Zone mapping (logo/wheel) | Still to confirm with one approved GameSense test (it registers an app in GG) | open |
| Other SteelSeries device | Arctis 1 Wireless headset (1038:12B3) and Sonar virtual audio are present; no RGB, not relevant for lighting | [PC] |
| Status | **POSSIBLE → high confidence** | |

---

## 7. QUADCAST S FINDINGS

| Item | Finding | Label |
|---|---|---|
| Identity | RGB/HID function **0951:171F**; audio function **0951:171D** (separate USB function) | [PC] |
| RGB interface | Interface 0, usage page **FF90**, usage **FF00**, exactly the collection OpenRGB targets | [PC] + [DOC] |
| Protocol support | Supported by OpenRGB, QuadcastRGB and SignalRGB (all list 171F) | [DOC] |
| NGENUITY | **Two** Store packages installed; **NGenuity2Helper.exe running** | [PC] |
| Current owner of the mic lighting | [INFERENCE] Most likely NGENUITY, via its helper. SignalRGB may also be driving it (unknown). Two streamers on the same mic cause flicker. | open |
| Status | **POSSIBLE → high confidence** for direct HID, provided NGENUITY (and SignalRGB) stop driving its lighting (decision Q3) | |

---

## 8. REDRAGON KALA FINDINGS

| Item | Finding | Label |
|---|---|---|
| Identity | **0C45:5004** (Sonix VID; EVision-family firmware per OpenRGB's notes) | [PC] + [DOC] |
| Earlier lead | The community K557 plugin (320F:5000/5055) **does not match**. It is dropped. | [PC] |
| New lead | OpenRGB's EVision driver lists **"EVision Keyboard 0C45:5004"**, which it looks for on **interface 1, usage page FF1C**. Modes include per-key Custom, hardware effects and brightness 0–4; changes are saved to the keyboard. | [DOC] |
| Caution | 0C45:5004 is a **generic ID shared by several Redragon models** (a K582 with the same ID is reported). This is exactly the ID-reuse situation OpenRGB warns about (a bricking report in the Sinowealth driver). The ID alone does not prove the protocol. | [DOC] |
| Redragon software | Not found among installed programs (folders and shortcuts are in the JSON) | [PC] |
| Next evidence | Interface list and usage pages for 0C45:5004 (in `audit-report.json` → `usbHidDevices`). If interface 1 with FF1C exists, the EVision path becomes a concrete candidate. | open |
| Status | **REQUIRES RESEARCH**, now with a concrete candidate | |

---

## 9. NETWORK / HOTSPOT FINDINGS

| Item | Finding | Label |
|---|---|---|
| Internet path | **Ethernet**, no PPPoE on the PC (section 2.1) | [PC] |
| Hotspot | On · 2.4 GHz · WPA2 · auto-off disabled · max 8 clients · 192.168.137.1/24 on "Local Area Connection* 9" | [PC] |
| Hotspot hardware | Realtek RTL8852CE; supports 2.4/5 GHz hotspot, not 6 GHz | [PC] |
| Power management | "Allow the computer to turn off this device" **Enabled** | [PC] |
| DHCP (ICS) | Scope 192.168.137.0/24 confirmed. In `hosts.ics` the iPhone's lease ends **exactly 7 days** after the instant ICS last rewrote the file (the PC's own entry carries the same time-of-day, to the millisecond). So **ICS leases last ~7 days**. The bulb's current lease runs until 2026-10-03 16:02:16 (file time base, probably UTC). | [PC] + [INFERENCE] |
| DHCP host name | `wiz_` + 6 hex digits, which appear to be the end of the bulb's MAC address. The v1.0 summary therefore exposed more of the MAC than intended (low sensitivity, LAN-only). **Fixed** in tools v1.1. | [PC] |
| Neighbour (ARP) entry for the bulb | Reported "**Permanent**" before *and after* the hotspot interface disappeared, so it sits on some interface other than the live hotspot interface. [INFERENCE] Probably created by Windows' hotspot/ICS stack, not by you; unconfirmed. Watch v1.1 now reads the hotspot interface only, and logs every entry (interface and store) at start. | [PC] |
| Which connection the hotspot shares (ICS roles) | Not in the summary (collector v1.0 printed only enabled roles). In the JSON; v1.1 always prints it. | open |
| Upstream of Ethernet | Private address → a router exists; public address → direct ISP link. In the JSON; v1.1 prints it as `[INTERNET]`. | open |
| Restarts / sleep | Uptime ≈2 h at 21:04; 32 Kernel-Power events in 14 days (details in the JSON) | [PC] |

---

## 10. IDENTIFIED CONFLICTS

| Conflict | Status | Label |
|---|---|---|
| NGENUITY (helper running) ↔ any other controller of the **QuadCast S** | **Active risk.** NGENUITY is running; SignalRGB has a plugin for 171F. | [PC] + [DOC] |
| SignalRGB ↔ SteelSeries GG on the **Sensei Ten** | **Possible.** GG + Prism are running; SignalRGB lists GG as conflicting and has a Sensei Ten plugin. Whether the plugin is enabled is unknown. | [PC] + [DOC] |
| SignalRGB ↔ Gigabyte RGB Fusion / GCC | **None.** Not installed. | [PC] |
| **NZXT CAM** (running, auto-start) | **New.** SignalRGB lists NZXT CAM as conflicting *for NZXT hardware*. No NZXT device is visible in the summary. Probably harmless; confirm with the JSON (VID 1E71). | [PC] + [DOC] |
| Redragon software ↔ keyboard | **None today.** No Redragon software found. | [PC] |
| Audit-tool false positive | "NgcCtnrSvc" is Windows' *Microsoft Passport Container*, not vendor software. It matched the pattern "gcc"; fixed in v1.1. | [PC] |
| Unattributed processes | `service.exe` (pid 5740), `crashpad_handler.exe`, `QtWebEngineProcess.exe` ×2: vendor unknown from the summary; their paths are in the JSON | open |

---

## 11. REMAINING UNKNOWN ITEMS

| # | Unknown | How it gets resolved |
|---|---|---|
| U1 | **What exactly you did to "turn off the internet"**, whether Alexa lost the bulb, and whether the bulb came back by itself afterwards or needed a power cycle | Your answer |
| U2 | How long the first watch ran after 21:10:36; whether the internet ever failed | `watch.csv` from that run |
| U3 | What is upstream of the Ethernet port (router or direct ISP); which connection the hotspot shares | `audit-report.json` (or collector v1.1 summary) |
| U4 | What the single failed dial (20227) was (PPPoE or VPN) and its error code | `audit-report.json` → `eventLogs.rasClientEvents` |
| U5 | How often the PC restarts or sleeps (hotspot interruptions) | `audit-report.json` → Kernel-Power events |
| U6 | Whether the hotspot/ICS services restarted in 14 days. The v1.0 count of 0 may be an artifact of a name filter that depends on the UI language (fixed in v1.1). | Collector v1.1 |
| U7 | Keyboard 0C45:5004 interfaces and usage pages | `audit-report.json` → `usbHidDevices` |
| U8 | The text of SignalRGB's 403 answer; whether SignalRGB drives the mouse, mic or keyboard | JSON `localApiProbes.signalRgb.lightingBody`; a look at SignalRGB → Devices |
| U9 | NZXT hardware present? | JSON (`usbHidDevices`, VID 1E71) |
| U10 | Origin of the "Permanent" neighbour entry | Watch v1.1 START line |
| U11 | Sensei Ten GameSense zone mapping; QuadCast S mute-LED behaviour; WiZ write path | Approved tests in the implementation phase |

---

## 12. RECOMMENDED NEXT DIAGNOSTIC TEST (one test)

### Test C: "hotspot restart recovery", with the internet untouched

**Why this one, and not the others**

| Candidate | Value now |
|---|---|
| B / F: PPPoE or Ethernet interruption | **Not applicable / low.** The PC has no PPPoE. Cutting Ethernet stops the hotspot too, which is what your run already showed. |
| A: internet off while the hotspot stays on | Valuable, but it has to be done **upstream** (at the modem/router), and we first need to know what is upstream (U3). It is second in line. |
| D: bulb power cycle with internet on | Low value. We already know a power cycle always brings the bulb back. |
| E: Wi-Fi adapter restart | A harsher version of C (it can also change the channel). Do C first. |
| **C: hotspot Off → On, nothing else touched** | **Highest value.** Your run already did the "Off" half. The missing half, *does the bulb come back by itself when the hotspot returns?*, decides between the two remaining mechanisms. It is reversible in one click and touches nothing else. |

**Procedure** (uses watch v1.1 from this update; read-only)

1. Bulb on and working in Alexa. Start the watch:
   `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Watch-WizConnectivity.ps1 -WizIp 192.168.137.77 -IntervalSeconds 15`
   Wait for 4 normal lines (≈1 min).
2. **T0**: Settings → Network & internet → **Mobile hotspot → Off**. Nothing else: no Airplane mode,
   no Wi-Fi toggle, no cable, no bulb switch. Write down the time.
3. Wait **10 minutes**. That is long enough to get past a bulb's quick-retry period.
4. **T1**: **Mobile hotspot → On**. Write down the time. Do not touch the bulb.
5. At **T1+2, +5, +10 and +15 min**: ask Alexa to change the bulb's colour; write down whether it
   worked. Optionally also note whether the WiZ app shows it.
6. At T1+15 min stop the watch (Ctrl+C). Send `changes.log`, `watch.csv` and your notes.
7. **Only if** the bulb did not come back: power-cycle it now and let the watch show it rejoining.
   That is the final confirmation.

**How to read the result**

| What the watch shows after T1 | Meaning | Next step |
|---|---|---|
| `bulbAssociated` YES → `bulbInHostsIcs` YES → `bulbApi` ONLINE within a few minutes, **and Alexa works** | A hotspot interruption alone does **not** strand the bulb | Test A (internet off upstream), and a long-running watch to catch a real drop |
| Bulb comes back **locally** (API ONLINE) but **Alexa fails** for a long time | The bulb rejoins the Wi-Fi but its **cloud** session does not recover | Focus on the cloud layer; the bulb's local "reboot" command becomes a candidate *software* recovery (needs approval) |
| `bulbAssociated` stays **NO** while the hotspot is On; a power cycle fixes it | **Your original symptom, reproduced**: the bulb does not rejoin after the hotspot drops out | Root-cause class = hotspot interruptions. Next: why the hotspot drops (power management F4, restarts/sleep U5, driver) and hardening options |

After the test, leave the watch running for a day or two so that a *spontaneous* drop is also recorded.

---

## 13. UPDATED ARCHITECTURE RECOMMENDATION

| Device | Control path (updated) | What changed | Status |
|---|---|---|---|
| Motherboard + fans (IT5702, 048D:5702) | **Decision needed.** (a) SignalRGB API: requires **Pro** (403 today), or (b) **OpenRGB** SDK for the motherboard only (supports this exact controller; full colour, brightness and zones). SignalRGB must then stop driving the IT5702. | SignalRGB without Pro is confirmed non-programmable | POSSIBLE |
| Sensei Ten (1038:1832) | **GameSense** via GG 101 | GameSense confirmed available | POSSIBLE (high confidence) |
| QuadCast S (0951:171F) | **Direct HID**, interface 0 (FF90/FF00). NGENUITY must stop driving its lighting. | Best-supported variant confirmed; NGENUITY helper confirmed running | POSSIBLE (high confidence) |
| Kala (0C45:5004) | Candidate: **EVision protocol** (OpenRGB), only after an interface check and an approved, reversible verification | Old lead dropped; new, concrete lead | REQUIRES RESEARCH |
| WiZ bulb | **Local UDP 38899** (pywizlight) | Local API confirmed working on your bulb | **READY** (read path verified; write path untested by design) |
| Network | Currently **"hotspot + Ethernet"** (architecture B in the report), not PPPoE | PPPoE removed from the picture | — |

Architecture principles from the report (one owner per device, drivers by protocol, declared
capabilities, isolation, localhost-only API) are **unchanged**.

Network: no hardware recommendation yet. If the device upstream of the PC turns out to be a router with
Wi-Fi (U3), the bulb could join it directly and stop depending on the PC hotspot altogether. That would
be a zero-cost option, to evaluate after test C.

---

## Plain-language summary

* **Your PC is not using PPPoE right now.** It gets its internet straight over the Ethernet cable. So
  "PPPoE dropping" cannot be what is knocking the bulb off, at least not in the last two weeks.
* **The bulb itself is healthy on the network:** strong signal, no lost packets, and its local control
  works without the cloud. That local control is exactly what the Setup Controller will use.
* **Your experiment switched off the hotspot, not the internet.** The monitor shows the PC's internet
  still working at the moment the hotspot went off. The bulb disappeared instantly because its Wi-Fi
  network disappeared. That is expected, and it doesn't yet explain your real problem.
* **The key unanswered question** is whether the bulb comes back by itself when the hotspot comes
  back. One 25-minute test (section 12) answers it. If it doesn't come back, we have reproduced your
  problem, and the cause is "anything that briefly interrupts the hotspot", for example Windows
  powering down the Wi-Fi adapter (currently allowed) or a restart.
* The other devices look good: the mouse (GameSense) and microphone (direct control) paths are
  confirmed; the motherboard needs either SignalRGB Pro or OpenRGB; the keyboard needs one more look.

## Sources added in this update
* **S25** docs.signalrgb.com: SignalRGB API introduction: *"Endpoints requiring a Pro user account will return a 403 Forbidden error if the running application doesn't have a signed in user, or the signed in user doesn't have a SignalRGB Pro account."* (search snippet; site blocked from the audit sandbox)
* **S26** RasClient event IDs: 20227 = *"dialed a connection … which has failed"* (error code in the message); 20221/20222 = link establishment events (Microsoft Q&A / TechNet / eventid.net, via search)
* **S4 (re-checked)** OpenRGB @0f8f2dc: Gigabyte Fusion2 USB detector usage page `0xFF89` / usage `0xCC`; EVision detector `"EVision Keyboard 0C45:5004"` on interface 1, usage page `0xFF1C`; HyperX microphone detector usage page `0xFF90` / `0xFF00`
