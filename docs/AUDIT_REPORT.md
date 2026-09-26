# Setup Controller – Phase 1 Technical Audit Report

| | |
|---|---|
| Date | 2026-09-26 |
| Phase | 1: audit only. **Nothing has been implemented, installed or changed on the PC.** |
| Status | Research complete. **First on-PC results received**: see **[AUDIT_UPDATE_01_PC_RESULTS.md](AUDIT_UPDATE_01_PC_RESULTS.md)**. Where the two documents disagree, the update wins. |
| Next step | Test C ("hotspot restart recovery"), described in the update, section 12 |

> **Corrections from real PC data (2026-09-26)** – details in the update document:
> * The PC is **not using PPPoE**: no PPP interface, default route via Ethernet, one failed dial in 14 days.
>   Topology descriptions below that put PPPoE on the PC are superseded.
> * The keyboard is **0C45:5004**, not the 320F:5000/5055 claimed by the community plugin.
> * The SignalRGB API returns **403** (Pro / sign-in required) on this PC.
> * The hotspot is 2.4 GHz, WPA2, auto-off disabled, so **H3, H4 and H5 are eliminated**. H6 and H8 are
>   weakened; H7 is present as a risk factor.
> * The Wi-Fi chip is a **Realtek RTL8852CE**. Mic is **0951:171F**, mouse **1038:1832**,
>   RGB controller **048D:5702** (all confirmed). No Gigabyte RGB software is installed. NZXT CAM is.
> * The WiZ local API is **confirmed working** (module ESP25_SHRGB_01, firmware 1.38.0, RSSI −44 dBm).

## Audit method and limitation (read first)

This audit was produced by an agent running in a **cloud Linux container**, not on your Windows PC. It
had no access to your PC's registry, devices, USB bus, event logs, Wi-Fi adapter, hotspot or LAN. So:

* **Research findings** (protocols, APIs, device IDs, capabilities, conflicts) come from primary
  sources: official SDK repositories, the source code of established open-source projects (checked at a
  specific commit), and official documentation. Each has a source tag `[S#]` (see the Sources list at
  the end).
* **Machine-specific findings** (what is installed, versions, which USB IDs your devices actually use,
  hotspot band and security, driver versions, event history) are marked **PENDING**. Three read-only
  PowerShell tools were written to collect them: `audit/Collect-SetupAudit.ps1`,
  `audit/Probe-WizBulb.ps1`, `audit/Watch-WizConnectivity.ps1`. They were syntax-checked, linted for
  Windows PowerShell 5.1 compatibility and tested in the sandbox against simulated devices. That test
  confirmed that only GET requests and WiZ `get*` queries are ever sent. They have **not** been run on
  your PC yet.
* Several official sites were **blocked by the sandbox network policy**: steelseries.com,
  docs.signalrgb.com, forum.signalrgb.com, learn.microsoft.com, gigabyte.com, faq.wizconnected.com,
  home-assistant.io and the IEEE OUI registry. Where possible the same official content was read from
  the vendor's GitHub repositories. Otherwise, only search-engine snippets of the official page were
  available. Those conclusions are marked *(snippet)* and treated as lower confidence.

Labels used below: **VERIFIED** (confirmed in a primary source), **PENDING** (needs on-PC evidence),
**UNCERTAIN** (sources incomplete or conflicting), **HYPOTHESIS** (to be tested with evidence).

---

## 1. SYSTEM OVERVIEW

| Component | What you reported | Expected hardware identity (from sources) | Actual on your PC |
|---|---|---|---|
| Motherboard RGB + fans | Gigabyte B650 GAMING X AX V2, detected by SignalRGB | ITE **IT5702** USB RGB controller, **VID 048D / PID 5702**, OpenRGB "layout 24" [S4] | **048D:5702 confirmed** (usage page FF89) |
| Mouse | SteelSeries Sensei Ten | **1038:1832** (Sensei TEN) or **1038:1834** (CS:GO Neon Rider Ed.), HID interface 0 [S2][S4][S6] | **1038:1832 confirmed** |
| Microphone | HyperX QuadCast S | **0951:171F** (Kingston-era) or HP-era **03F0:0F8B / 068C / 0294 / 028C / 048C / 0D8B** [S4][S5][S6] | **0951:171F confirmed** (audio function 0951:171D) |
| Keyboard | Redragon Kala Black (K557 KALA) | **Not established.** One community plugin claims **320F:5000 / 320F:5055** (EVision controller) [S12] | **0C45:5004**: contradicts the plugin; OpenRGB EVision lists this ID |
| Smart bulb | Philips "PHI WFB 100W A60 E27" (WiZ) | WiZ Wi-Fi module; RGB + tunable white; local UDP API on port 38899 [S13][S14] | **ESP25_SHRGB_01, fw 1.38.0, local API answers** |
| Network | PPPoE on the PC → Windows Mobile Hotspot (2.4 GHz) → bulb | Wi-Fi chip depends on **board revision**: Rev 1.0 Realtek RTL8852CE, Rev 1.1 AMD RZ616 (MediaTek MT7922), Rev 1.2/1.3 Intel AX210 [S19 *(snippet)*] | **No PPPoE on the PC (Ethernet default route)**; Realtek RTL8852CE |

The Wi-Fi chip matters because Windows Mobile Hotspot behaviour (supported bands, power saving,
stability) is driver-specific. The collector reads the board revision (`Win32_BaseBoard.Version`) and the
adapter/driver.

---

## 2. WINDOWS ENVIRONMENT

All items are **PENDING**; the collector gathers them:

| Item | Collected by `Collect-SetupAudit.ps1` section |
|---|---|
| Windows edition, version (e.g. 23H2/24H2), build.UBR, locale | `windows` |
| Board model, **PCB revision**, BIOS version/date | `hardware` |
| Power plan, sleep policy, "Wireless Adapter Settings → Power Saving Mode", available sleep states (Modern Standby) | `power` |
| Installed RGB/vendor software incl. Microsoft Store apps (NGENUITY is a Store app) | `installedSoftware` |
| Vendor + Windows network services (ICS `SharedAccess`, hotspot `icssvc`, `WlanSvc`, `RasMan`, …) | `services` |
| Vendor processes, versions, listening ports | `processes`, `listeningPorts` |
| USB/HID devices: VID, PID, interface (MI), collection, HID usage page, driver | `usbHidDevices`, `inputAndAudioDevices` |

Note: the tools need **Windows PowerShell 5.1** (`powershell.exe`). The Mobile Hotspot API is WinRT,
which PowerShell 7 cannot load.

---

## 3. NETWORK ARCHITECTURE

### 3.1 Topology as reported

```
Internet ── ISP ── (ONT/modem, bridge) ══Ethernet══ PC [PPPoE client (RasMan)]
                                                     │  ICS / NAT / DHCP / DNS proxy (SharedAccess)
                                                     │  Mobile Hotspot (icssvc) on Wi-Fi Direct virtual adapter
                                                     └── Wi-Fi 2.4 GHz ── WiZ bulb ──(cloud: MQTT)── WiZ cloud ── Alexa
```

### 3.2 How the Windows pieces fit (VERIFIED unless marked)

* **Mobile Hotspot** is driven by `NetworkOperatorTetheringManager`. It shares a chosen *public*
  connection profile over Wi-Fi [S18]. Configurable: **band** = Auto / 2.4 GHz / 5 GHz / 6 GHz [S18];
  **security** = WPA2 / WPA3 transition / WPA3 (on hardware that supports WPA3) [S18].
* **No-connections timeout** (official): *"If enabled, tethering turns off automatically in 5 minutes
  after the last peer of the tethering connection goes away."* [S18]. In Windows Settings this is the
  Mobile Hotspot *power saving* option.
* **ICS** provides NAT, a DHCP allocator and a DNS proxy on the private side. Its default scope is
  `192.168.137.0/24` (well known; the collector confirms `ScopeAddress`). Leases appear in `hosts.ics`.
  **UNCERTAIN:** no documented way to reserve a DHCP address in ICS was found, and the lease duration is
  not documented.
* **PPPoE** is a RAS connection (`WAN Miniport (PPPOE)`). When it drops, its interface and
  connection profile disappear and come back when it redials.
* **PPPoE as the hotspot's shared connection – UNCERTAIN.** Community sources state that PPPoE
  connections cannot be selected in Mobile Hotspot and must be shared with classic ICS instead [S20].
  You report a working setup, so the exact mechanism on your PC (hotspot sharing PPPoE directly, ICS
  configured separately, or sharing from the Ethernet adapter) must be read from the machine. The
  collector enumerates every connection's ICS role (PUBLIC or PRIVATE) and every profile's tethering
  capability and state.
* **Community-documented, not official:** `HKLM\SYSTEM\CurrentControlSet\Services\icssvc\Settings`
  values `PeerlessTimeoutEnabled`, `PeerlessTimeout` and `PublicConnectionTimeout` control when the
  hotspot turns itself off (no peers, or no public connection) [S20]. The collector *reads* this key
  and changes nothing.

### 3.3 Audit items (all PENDING, collected)

Adapters and drivers; Wi-Fi adapter model, driver and advanced properties (roaming, band preference,
MIMO power save, and so on); adapter power management ("allow the computer to turn off this device");
the current Wi-Fi station connection; `netsh wlan show drivers / wirelesscapabilities`; hotspot state,
band, security, maximum and current clients, client list; ICS roles; `hosts.ics` (bulb lease); routes,
metrics and MTU (PPPoE MTU); DNS; firewall profile on/off state; PPPoE redial settings; scheduled
`rasdial` tasks (name only); 14 days of events: PPPoE dial and disconnect (RasClient), hotspot and ICS
service restarts, WLAN, NDIS, Wi-Fi driver resets, sleep and wake.

Network isolation: Windows Mobile Hotspot has no client-isolation setting. Unicast between the PC and
hotspot clients works (it is how local WiZ control works). Broadcast to `192.168.137.255` reaches
clients. Multicast (mDNS) behaviour on the hotspot is **UNCERTAIN**. It only matters if the bulb is
paired with Alexa through Matter (see Q6).

---

## 4. SIGNALRGB AUDIT

### 4.1 Findings

| Question | Finding | Status |
|---|---|---|
| Motherboard as seen by Windows | Collector: `Win32_BaseBoard` product and version | PENDING |
| RGB controller hardware | ITE IT5702, USB **048D:5702**. OpenRGB maps "B650 GAMING X AX V2" to IT5702 layout 24 [S4] | VERIFIED (source) / PENDING (on PC) |
| Headers and zones | One USB controller with 5 zones: **D_LED1**, **D_LED2** (addressable 5 V ARGB, per-LED), **LED_C1**, **LED_C2** (12 V RGB, one colour per header), **LED_CPU** (onboard) [S4] | VERIFIED (source) |
| Fans as one or many devices | Fans are **not** separate USB devices. They are LEDs on a header zone of the single IT5702 controller. Fans daisy-chained on one ARGB header share that zone. | VERIFIED (architecture) |
| SignalRGB support | Official plugin "GIGABYTE Motherboard LED Controller", VID 048D, PIDs 5702/8297 [S6] | VERIFIED |
| SignalRGB version / services / processes | Collector | PENDING |
| Local API | REST at **`http://127.0.0.1:16038/api/v1`** [S7][S8][S9 *(snippet)*] | VERIFIED |
| API must be switched on | *Settings → General → Enable HTTP API* [S8] | VERIFIED (community integration docs) |
| **Pro required** | *"The SignalRGB REST API is only available in SignalRGB Pro"* [S9 *(snippet)*][S7][S8] | VERIFIED |
| Authentication | None in the reference client (plain HTTP, no auth header) [S7]. Bound to localhost by default [S9 *(snippet)*]. | VERIFIED (client code) |
| Endpoints (from reference client) | `GET /lighting` (current effect, `enabled`, `global_brightness`); `PATCH /lighting/global_brightness`; `PATCH /lighting/enabled`; `GET /lighting/effects`; `GET /lighting/effects/{id}`; `POST /lighting/effects/{id}/apply`; `GET/PATCH /lighting/effects/{id}/presets`; `GET/POST /lighting/next`, `/previous`; `POST /lighting/shuffle`; `GET/PATCH /scenes/current_layout`; `GET /scenes/layouts` [S7] | VERIFIED |
| Colour control | **No endpoint to set an arbitrary solid colour.** Options: (a) apply a solid-colour effect preset (presets must be created in the UI first, so a fixed palette); (b) the application URL `signalrgb://effect/apply/<Effect>?<param>=<value>&-silentlaunch-` [S11 *(snippet)*], where the parameter names for a solid-colour effect are **not verified**; (c) a custom SignalRGB effect | **UNCERTAIN: needs research and test** |
| Brightness | `global_brightness` 0–100, applies to every device SignalRGB drives [S7] | VERIFIED |
| On/off | `enabled` flag of the canvas, global [S7]. What the LEDs show when it is disabled (dark, or the plugin's "shutdown colour") is **UNCERTAIN** | VERIFIED / UNCERTAIN |
| Effects | Apply any installed effect by id or name; next, previous, shuffle; presets [S7] | VERIFIED |
| Per-zone control via API | Not exposed. Per-device "Forced colour" exists only as plugin parameters in the UI [S6] | VERIFIED (absence in reference client) |
| Gigabyte Control Center / RGB Fusion installed or running | Collector | PENDING |
| Conflict with Gigabyte software | SignalRGB docs list **RGB Fusion 2.0**: *"runs a background service that can interfere even when the app is closed"* [S10 *(snippet)*] | VERIFIED *(snippet)* |
| Exclusive access | Vendor HID collections on Windows can generally be opened by several processes at once. Conflicts show as the apps **overwriting each other** (flicker, resets), not as a clean lock-out. | Technical reasoning, medium confidence |
| Other local API via Gigabyte | Gigabyte publishes an "RGB Fusion SDK" page [S24]. Its content, licence and current availability were not verifiable (site blocked) | UNCERTAIN |
| SignalRGB also claims your other devices | SignalRGB ships plugins for **Sensei Ten (1038:1832)** and **QuadCast S (0951:171F, 03F0:048C/0F8B/068C/028C)** [S6], and SignalRGB docs list **SteelSeries GG** as a conflicting program [S10 *(snippet)*]. Unless disabled in SignalRGB, it will fight GG and NGENUITY | VERIFIED (plugins exist) / PENDING (whether enabled on your PC) |

### 4.2 Is SignalRGB the right tool for the motherboard?

* **With SignalRGB Pro:** yes. It is already detecting the controller, and brightness, on/off and
  effects are available locally through a documented API. Colour is the weak point (see 4.1).
* **Without Pro:** SignalRGB offers no documented programmatic API. The alternative is **OpenRGB**
  (open-source; supports this board's IT5702 [S4]; local SDK server on TCP 6742 with a documented
  protocol, so arbitrary colour, brightness and per-zone control are possible). It must then be the
  *only* program driving the IT5702, so SignalRGB would have to stop driving the motherboard.
  Decision **Q2**.

---

## 5. STEELSERIES SENSEI TEN AUDIT

| Question | Finding | Status |
|---|---|---|
| GG installed / version / services / processes | Collector | PENDING |
| Sensei Ten detected; IDs, HID interfaces | Expected **1038:1832** (or 1038:1834), HID **interface 0** [S2][S4][S6] | VERIFIED (sources) / PENDING (on PC) |
| RGB zones | **Two LEDs: logo (led_id 0) and wheel (led_id 1)** [S2] | VERIFIED |
| Hardware brightness command | None in rivalcfg's Sensei TEN definition (colours and gradients only) [S2] | VERIFIED (absence) |
| Official API | **GameSense SDK** (official): local HTTP JSON API of SteelSeries Engine / GG [S1] | VERIFIED |
| Discovery / port | `coreProps.json` → `"address": "127.0.0.1:<port>"`. The port is random at each start [S1]. Official path: `%PROGRAMDATA%\SteelSeries\SteelSeries Engine 3\coreProps.json` [S1]. GG uses `C:\ProgramData\SteelSeries\GG\coreProps.json`, which also carries `encryptedAddress` and `ggEncryptedAddress` [S3, community]. The collector checks both. | VERIFIED / community |
| Authentication | None documented for the plain-HTTP `address` [S1] | VERIFIED |
| Endpoints | `POST /game_metadata`, `/register_game_event`, `/bind_game_event`, `/game_event`, `/game_heartbeat`, `/stop_game`, `/remove_game_event`, `/remove_game`, `/supports_multiple_game_events` [S1] | VERIFIED |
| Zones addressable via GameSense | Device type `mouse` with zones `wheel`, `logo`, `base`; or `rgb-2-zone` with `one`, `two` [S1]. The docs predate the Sensei Ten and don't list it by name. The zone mapping is **PROBABLE, to be confirmed by a test** after approval. | UNCERTAIN (mapping) |
| Static colour | Yes: static colour, or `context-color` (arbitrary RGB sent with each event) [S1] | VERIFIED |
| Brightness | No native brightness in GameSense. Achieved by **scaling the RGB value**. That is a legitimate way to dim an RGB LED, but it is not a native brightness control. | VERIFIED |
| On/off | "Off" = send black. **GameSense only overrides lighting while the app is active**: it deactivates after 15 s without events (configurable 1–60 s via `deinitialize_timer_length_ms`), or on `stop_game`, and GG then returns to the profile's lighting [S1]. The controller must therefore **heartbeat continuously** to hold any state, "off" included. This is also a safe fail-safe: if the controller dies, the mouse returns to your GG profile. | VERIFIED |
| Effects | Flash (`frequency`, `repeat_limit`), value-driven gradients and ranges [S1]. No named hardware effects such as "rainbow". Those would have to be animated by the client. | VERIFIED |
| Third-party app needed | No. GG itself is the service. | VERIFIED |
| Works without SignalRGB | Yes, provided SignalRGB's Sensei Ten plugin is **disabled** (it exists [S6], and SignalRGB lists GG as conflicting [S10]) | VERIFIED / PENDING |
| Side effect on GG | Registering a GameSense app creates an entry in GG's app list. That is a (small) GG configuration change, so it is **not done during the audit** (Q4) | VERIFIED |
| Alternative: direct HID | `rivalcfg` (supports Windows) writes colours to interface 0 and can save to onboard memory [S2]. It would fight GG, which re-applies profiles. **Not recommended while GG is installed.** | VERIFIED |

**Verdict:** GameSense is the correct native method. Status **POSSIBLE**: IDs and GameSense availability
still need PC evidence, and the zone mapping needs one approved test.

---

## 6. HYPERX QUADCAST S AUDIT

| Question | Finding | Status |
|---|---|---|
| Detected; IDs; HID interfaces | Kingston-era **0951:171F**. HP-era (after HP bought HyperX) **03F0:0F8B, 068C, 0294, 028C, 048C, 0D8B** [S4]; QuadcastRGB lists 0F8B, 028C, 048C, 068C [S5]. RGB is on **HID interface 0** [S4][S5]. **Not to be confused with** 03F0:098C (DuoCast) or 03F0:02B5 (QuadCast **2 S**, a different protocol) [S4][S5]. | VERIFIED (sources) / PENDING (on PC) |
| NGENUITY installed / version / running | Microsoft Store app. Collector checks Store packages and processes. | PENDING |
| Official HyperX API | **None found.** No public NGENUITY SDK was found in official HyperX/HP material (searched 2026-09-26) [S23] | VERIFIED (absence, medium confidence) |
| Protocol | HID **feature report** (SET_REPORT), 64-byte packets, on interface 0. Colour packet: `[0x81, R, G, B]` for the **top** LED and `[0x81, R, G, B]` for the **bottom** LED [S4]. | VERIFIED (2 independent projects) |
| Zones | **Two: top (upper/capsule) and bottom (lower/base)** [S4][S5] | VERIFIED |
| Persistence | **Direct colours must be streamed continuously.** OpenRGB re-sends whenever 50 ms pass without an update [S4]; QuadcastRGB runs as a daemon looping its packets [S5]. When streaming stops, the microphone falls back to its stored behaviour. There is also an onboard **save** transaction (`0x53 …`) [S4], which writes to device memory. | VERIFIED |
| Colour | Yes (per zone) | VERIFIED |
| Brightness | No native brightness. QuadcastRGB's `-b` option **scales the RGB values** [S5]. | VERIFIED |
| On/off | Black colour (streamed) | VERIFIED |
| Effects | Solid, blink, cycle, wave, lightning, pulse are **generated by the host** and streamed [S5]; no hardware effect engine is used | VERIFIED |
| Works without SignalRGB | Yes. OpenRGB and QuadcastRGB do not use SignalRGB. But **only one program may stream to it**: NGENUITY, SignalRGB (it has plugins [S6]) and a Setup Controller would overwrite each other. | VERIFIED |
| Mute indicator | **UNCERTAIN (product behaviour):** the QuadCast S LEDs go dark when tap-to-mute is active. "Lighting off" and "muted" may therefore look the same, and the mute state may override the controller's colour. To be observed. | UNCERTAIN |

**Verdict:** direct HID control is **POSSIBLE** and well documented by two independent open-source
projects. It requires a resident process in the Setup Controller that streams frames, and it requires
NGENUITY and SignalRGB to stop driving the microphone's lighting (Q3). Through NGENUITY, programmatic
control is **NOT FEASIBLE** (no API).

---

## 7. REDRAGON KALA BLACK AUDIT

| Question | Finding | Status |
|---|---|---|
| Exact Windows name, VID/PID, HID interfaces, usage pages | Collector (`usbHidDevices`, `inputAndAudioDevices`, including `HID_DEVICE_UP` usage pages) | **PENDING (blocking)** |
| Redragon software, version, config | Redragon ships per-model Windows apps that are often not registered as installed programs. The collector searches installed programs, Program Files folders and shortcuts. | PENDING |
| Official API | None found | VERIFIED (absence, medium confidence) |
| Projects naming the K557 | Only **vinemelo/SignalRGB-Redragon-K557-Kala-V2** (community SignalRGB plugin, one maintainer, last commit 2026-07-02) [S12]: **VID 320F**, **PID 5000 / 5055**, interface 1, usage page **0xFF1C**, usage 0x0092; 64-byte packets with checksum; "software mode" on `04 8C 00 0B 30 50 01`, off `… 00`. **The author's own comment says the exit command must be confirmed on first test.** | Low confidence |
| OpenRGB | No K557 entry by name. Its generic **EVision** keyboard driver accepts **320F:5000** (and other 320F / 0C45 IDs) on usage page 0xFF1C [S4]. Modes: Custom (per-key), Colour Wave, Spectrum Cycle, Breathing, and others; **brightness 0–4 (5 levels, 0 = off)**; every mode is saved automatically to the keyboard [S4]. | VERIFIED (source) / unverified for your unit |
| **Safety warning** | OpenRGB **disabled** its Sinowealth keyboard detection *"due to VID/PID pairs being reused from Redragon keyboards, which ended up in bricking the latter"* [S4]. Redragon keyboards share IDs with other products, and sending the wrong protocol has bricked real units. | VERIFIED |
| Colour / brightness / on-off / effects / profiles | **If** your keyboard is 320F:5000 or 5055 and matches EVision: per-key colour yes; brightness 5 steps; off = brightness 0; hardware effects yes; profiles possibly. **Otherwise unknown.** | REQUIRES RESEARCH |

**If your IDs don't match anything verified, this is what reverse engineering would require (only with
your approval):**
1. Install a USB capture tool (USBPcap + Wireshark). This is a software installation, so it needs your approval.
2. Capture the official Redragon app while changing colour, brightness, effect and profile, one change at a time.
3. Map the observed packets. Then replay **only** byte-identical packets that the official app itself sent,
   never guessed commands, and never anything touching firmware, bootloader or flash-update modes.
4. Check that the keyboard returns to its normal hardware mode after each test.

**Verdict:** **REQUIRES RESEARCH.** It becomes **POSSIBLE** if the collector shows 320F:5000 or
320F:5055 with usage page 0xFF1C, and one approved, reversible test confirms the protocol.

---

## 8. PHILIPS WIZ AUDIT

| Question | Finding | Status |
|---|---|---|
| Exact device info (module, firmware, MAC OUI, RSSI) | `Probe-WizBulb.ps1` (`getSystemConfig`, `getModelConfig`, `getPilot`, `getUserConfig`) | PENDING |
| Product | Philips-branded WiZ full-colour A60 E27 "100 W equivalent" (WiZ lists a 100 W A60 E27 full-colour bulb, 1,521 lm) [S22 *(snippet)*]. Home Assistant lists "Philips Smart LED lights with WiZ Connected" as supported [S14]. | VERIFIED |
| Protocol | JSON over **UDP port 38899** on the bulb; push updates to the client on **UDP 38900** [S13] | VERIFIED |
| Methods | Read: `getPilot`, `getSystemConfig`, `getModelConfig`, `getUserConfig`. Write: `setPilot` (`state`, `r`/`g`/`b`, `c`/`w`, `dimming`, `sceneId`, `speed`, `temp`), `setState`, and also `reboot` and `reset` (**`reset` is dangerous and must never be used**) [S13] | VERIFIED |
| TCP | Not used for local control | VERIFIED |
| Authentication | None on the UDP API by default. WiZ app setting **"Allow local communication"** gates it; *"should be enabled by default"* [S14]. The official FAQ also describes a mode **"Only verified controls"** that accepts only messages signed with the home security key [S15 *(snippet)*]. If that is enabled, unsigned local control will be rejected. One user could not find the setting in WiZ app 1.27.4 [S16]. | VERIFIED / UNCERTAIN (your setting) |
| Colour / brightness / power / effects | RGB bulbs (module name contains "RGB"): colour, colour temperature, brightness, effects [S13]. Brightness is `dimming` in percent; pywizlight sends `max(1, %)` [S13]. **UNCERTAIN:** the lowest level the bulb accepts (older firmware used 10 %). About 35 built-in dynamic scenes (Ocean, Party, Fireplace, …) [S13]. | VERIFIED / UNCERTAIN |
| Library | **pywizlight**: active, used by Home Assistant's official WiZ integration [S13][S14] | VERIFIED |
| Local discovery | UDP **broadcast** of a `registration` message with `register:false` [S13]. **Not needed** once the IP or MAC is known. The probe avoids it and uses `hosts.ics` plus the neighbour table. | VERIFIED |
| Local control without cloud or Alexa | Works. Users and the maintainer report bulbs blocked from the internet keep working locally; cloud endpoints are MQTT (`*.wiz.world`) [S17] | VERIFIED (community, consistent) |
| Alexa needs cloud | Yes, for the WiZ Alexa skill: Alexa → WiZ cloud → bulb (MQTT). **UNCERTAIN** whether your bulb was added through Matter instead (Q6). | VERIFIED (skill) / UNCERTAIN (Matter) |
| Static IP | No option to set a static IP on the bulb was found. Stability depends on ICS DHCP, which has no documented reservations. **The controller should track the bulb by MAC**, and the watch tool already does. | UNCERTAIN |
| Needs internet after setup | Not for local control [S17]. Yes for the app's remote control and for Alexa. | VERIFIED |

**Verdict:** **POSSIBLE**, and it becomes **READY** as soon as `Probe-WizBulb.ps1` gets an answer from
the bulb.

---

## 9. WIZ NETWORK DISCONNECTION INVESTIGATION

### 9.1 What the symptom tells us

* The bulb works after joining, then becomes unavailable; **it does not recover by itself**; a
  **power cycle fixes it**.
* A power cycle forces the bulb to re-scan, re-associate, redo DHCP and reconnect to the cloud. So after
  the failure, **the AP must still be joinable** (otherwise the power cycle would not help), and **the
  bulb's own recovery logic is not re-trying successfully**.
* "Disconnected" currently means *"Alexa/WiZ says offline"*. That is compatible with two very
  different failures, and the first job is to tell them apart:
  1. **Wi-Fi/LAN loss**: the bulb is really gone from the hotspot (no ping, no local UDP).
  2. **Cloud loss**: the bulb is still on the hotspot and answers locally, but its cloud session is
     broken, so Alexa and the WiZ app show it offline.

### 9.2 Hypotheses (ranked by plausibility; none confirmed yet)

| # | Hypothesis | Mechanism | Evidence that decides it | Tool |
|---|---|---|---|---|
| H1 | **PPPoE redial breaks the bulb's cloud session** (cloud loss, not Wi-Fi loss) | ISP drops or renews PPPoE (often daily) → public IP changes → the bulb's MQTT session to the WiZ cloud breaks → the bulb reconnects slowly or not at all → Alexa shows offline. A power cycle forces an immediate fresh cloud connect. | RasClient disconnect events and `pppUp` DOWN→UP shortly before `Alexa offline`, **while `bulbApi` stays ONLINE** | Collector events + Watch |
| H2 | **The hotspot restarts internally** | `icssvc`/`SharedAccess` restart, a public-connection timeout during a PPPoE outage, a driver reset or power management → all clients are dropped → the bulb fails to rejoin (possibly because the channel changed) | Service 7036 events, `hotspotState` or `hotspotAdapter` transitions, NDIS/driver events at the outage time | Collector + Watch |
| H3 | **No-connections timeout** | If the bulb briefly drops, and no other device is connected, the hotspot switches **off after 5 min** [S18] | `noConnectionsTimeoutEnabled = True`; `hotspotState` goes Off | Collector + Watch |
| H4 | **Band = Auto** | After a restart the hotspot comes up on 5 GHz; the bulb cannot see it until the next restart on 2.4 GHz. (Partly contradicted: a power cycle would not fix a 5 GHz AP.) | Hotspot `band` value | Collector |
| H5 | **WPA3 / transition mode** | IoT Wi-Fi stacks can fail on group-key rekeys or PMF under WPA3 transition mode | `authenticationKind` | Collector |
| H6 | **DHCP / ICS allocator** | The lease renewal fails, or ICS state is lost on restart, so the bulb has no valid address | `bulbInHostsIcs` goes NO; `bulbNeighbor` Unreachable while `bulbAssociated` = YES | Watch |
| H7 | **Wi-Fi power saving** | Adapter or driver power saving (the Device Manager flag, "Wireless Adapter Settings", MIMO power save) disturbs soft-AP clients | Adapter power properties; WLAN and driver events | Collector |
| H8 | **Weak signal / interference** | Low RSSI or a congested channel | `bulbRssi` trend before the outages | Watch |
| H9 | **Bulb firmware** | A known class of IoT behaviour: the official WiZ FAQ recommends a power cycle for "offline" lights [S21] | The fault persists after H1–H8 are excluded; firmware version | Probe |
| H10 | **PC sleep / Modern Standby** | Wi-Fi is suspended while the display is off | `powercfg /a`, Kernel-Power events | Collector |

PPPoE itself is not assumed to be the cause. H1 is ranked first only because it explains *every*
reported symptom (Alexa offline, no self-recovery, power cycle fixes it) without any Wi-Fi fault. It is
still a hypothesis.

### 9.3 Answers to the specific questions

| Question | Answer |
|---|---|
| Does the bulb get a stable IP / does it change? | PENDING. Watch logs `bulbIp` and follows the bulb by MAC. |
| Does the hotspot restart internally / does the adapter reset? | PENDING. Service events, driver events and state transitions are logged. |
| Does PPPoE stay stable? | PENDING. RasClient events (14 days) plus the live `pppUp` column. |
| Does the PC keep internet when the bulb drops? | PENDING. The `internet` and `dns` columns at the moment of the drop. |
| Does the hotspot stay available when the bulb drops? | PENDING. `hotspotState`, `hotspotClients`, `hotspotAdapter`. |
| Does the bulb lose Wi-Fi when the hotspot changes state? | By 802.11 design **yes**: all clients are disassociated when the AP stops. The open question is whether it *rejoins*. PENDING. |
| Does DHCP lease expiry affect it? | UNCERTAIN (ICS lease time undocumented). Watch shows whether the `hosts.ics` entry disappears. |
| Does the bulb depend on broadcast/multicast? | Local control: **no** (unicast to a known IP). Discovery: broadcast. Alexa through the WiZ skill: **no** (cloud). Matter (if used): **yes**, mDNS multicast. |
| Does the bulb need internet after setup? | Not for local control; **yes for Alexa and the WiZ app's remote control** [S17]. |

### 9.4 Feasibility of the diagnostic program you described

**Feasible**, and a read-only prototype of its data collection already exists (`Watch-WizConnectivity.ps1`).
How each failure category you listed maps to observable signals:

| Failure category | Observable signature |
|---|---|
| 1 Internet failure (upstream of PPPoE) | `pppUp`=UP, `internet`=FAIL |
| 2 PPPoE failure | `pppUp`=DOWN / NO_PPP_INTERFACE, default route missing |
| 3 Hotspot failure | `hotspotState`≠On or `hotspotAdapter`≠Up, with `wifiAdapter`=Up |
| 4 Wi-Fi adapter failure | `wifiAdapter`≠Up (usually with the hotspot down too) |
| 5 DHCP problem | Bulb associated (`bulbAssociated`=YES) but no `hosts.ics` entry or ARP entry; ping fails |
| 6 WiZ Wi-Fi association problem | Hotspot On, bulb MAC **not** in the hotspot client list |
| 7 WiZ local API failure | Ping OK, UDP `getPilot` fails (or "local communication" disabled) |
| 8 WiZ cloud failure | Local API ONLINE, internet OK, but the WiZ app / Alexa show offline. **Not directly observable from the PC**; needs a manual note or a later cloud check |
| 9 Alexa cloud failure | WiZ app (remote, off-hotspot) shows the bulb online but Alexa fails. Manual observation. |

The `[NETWORK] … [HOTSPOT] … [WIZ] …` console format you asked for is what the watch tool prints.
The final diagnostic module (classification, history, UI) is future work that needs your approval.

---

## 10. SOFTWARE CONFLICT ANALYSIS

| | Motherboard (IT5702) | Sensei Ten | QuadCast S | Kala | WiZ |
|---|---|---|---|---|---|
| **SignalRGB** | Intended owner | **Conflict**: SignalRGB plugin exists [S6]; GG listed as conflicting [S10] | **Conflict**: SignalRGB plugin exists [S6] | Conflict **if** a Kala/EVision plugin is loaded [S12] | – |
| **Gigabyte GCC / RGB Fusion** | **Conflict** [S10] | – | – | – | – |
| **SteelSeries GG** | – | Intended owner (GameSense) | – | – | – |
| **HyperX NGENUITY** | – | – | **Conflict** with any direct controller (both stream) | – | – |
| **Redragon app** | – | – | – | Writes onboard settings; would conflict with a live controller | – |
| **OpenRGB** (if chosen) | Conflicts with SignalRGB on the same device | Can conflict with GG | Can conflict with NGENUITY | Can conflict with the Redragon app | – |
| **WiZ app / Alexa** | – | – | – | – | No conflict; last writer wins |

Required separation (to be applied only after approval): in **SignalRGB**, disable the Sensei Ten,
QuadCast S and any Kala device so it only drives the motherboard. Make sure **RGB Fusion** is not
running or installed alongside SignalRGB. Choose **one** owner for the QuadCast S (NGENUITY *or* the
Setup Controller).

---

## 11. DEVICE CAPABILITY MATRIX

| Device | Control method | Colour | Brightness | On/Off | Effects | Local control | External dependency | Status | Confidence |
|---|---|---|---|---|---|---|---|---|---|
| Gigabyte B650 GAMING X AX V2 RGB + fans (IT5702) | SignalRGB REST API | **Indirect** (effect/preset; no solid-colour endpoint) | Yes (global 0–100) | Yes (canvas enabled, global) | Yes (effect library) | Yes (127.0.0.1:16038) | SignalRGB **Pro**, app running, HTTP API enabled. **On the PC: 403 = no Pro/sign-in** | POSSIBLE (only with Pro) | Medium |
| ↳ alternative | OpenRGB SDK (TCP 6742) | Yes (per zone / per LED) | Via colour scaling | Via black / off mode | Yes (hardware modes) | Yes | OpenRGB running; SignalRGB must release the device | POSSIBLE | Medium |
| SteelSeries Sensei Ten | GameSense (GG) | Yes (logo + wheel, mapping to confirm) | Via colour scaling | Black + continuous heartbeat; reverts to GG profile when released | Limited (flash; client-side animation) | Yes (127.0.0.1:random port) | SteelSeries GG running; app registered in GG | POSSIBLE | Medium-High |
| HyperX QuadCast S | Direct HID feature reports (interface 0) | Yes (top + bottom) | Via colour scaling | Black (streamed) | Host-generated only | Yes (USB) | Resident streaming process; NGENUITY and SignalRGB must not drive it | POSSIBLE | Medium-High |
| ↳ via NGENUITY | – | – | – | – | – | – | No API | NOT FEASIBLE | High |
| Redragon Kala (K557) | Unknown. **On the PC: 0C45:5004**, an EVision candidate per OpenRGB | Unknown | EVision: 5 levels | EVision: brightness 0 | EVision: hardware modes | Yes (USB) | None | REQUIRES RESEARCH | Low |
| Philips WiZ A60 | WiZ local UDP 38899 (pywizlight) | Yes (RGB + white temperature) | Yes (native %, lower limit uncertain) | Yes | Yes (~35 scenes) | Yes | None locally; cloud for Alexa/app; "Allow local communication" on | **READY** (probe answered) | High |

"Via colour scaling" means dimming is done by multiplying the RGB values (for example 50 % red =
`#800000`). It is reliable and safe on these LEDs, but it is labelled as such rather than presented
as a native brightness control.

---

## 12. RECOMMENDED ARCHITECTURE

Proposed, **not implemented**. It needs your approval of the decisions in section 19.

### 12.1 Principles
1. **One owner per device.** Each device has exactly one controlling program. Setup Controller only
   talks to that owner's API (SignalRGB, GG), or owns the device itself (QuadCast S, maybe Kala, WiZ).
2. **Drivers by protocol, devices by configuration.** Drivers are `signalrgb_api`, `gamesense`,
   `hid_quadcast_s`, `hid_evision`, `wiz_udp`. Devices in `devices.json` bind a name ("mouse") to a
   driver plus identifiers (VID/PID, MAC). A new device of a supported kind needs only a config entry.
   A new kind of device needs only a new driver.
3. **Declared capabilities.** Each driver declares `color`, `brightness` (`native` / `scaled` /
   `none`), `power`, `effects[]`, `zones[]`. Setup-level commands degrade per device and return
   `UNSUPPORTED` instead of faking a feature.
4. **Isolation.** Every device call runs concurrently with its own timeout. One failing device never
   blocks the others; results are aggregated (`[HYPERX] ERROR: DEVICE_UNAVAILABLE`).
5. **State store.** The last "on" state per device is kept on disk (under `%LOCALAPPDATA%`), so
   `turn_on()` restores it.
6. **Keepers.** GameSense needs a heartbeat and the QuadCast S needs a frame stream. Both run as
   supervised background tasks inside the service.
7. **Local only.** The API binds to `127.0.0.1`. No firewall rule and no exposure. Secrets live in the
   Windows Credential Manager (Python `keyring`) or environment variables, never in files or source.

### 12.2 Proposed layout (refines your draft)
```
setup-controller/
├─ pyproject.toml
├─ config/        devices.json · presets.json          (no secrets)
├─ src/setup_controller/
│  ├─ core/       models.py (Color, Status, Result) · capabilities.py · registry.py
│  │              setup_group.py (fan-out + aggregation) · state_store.py · presets.py
│  ├─ drivers/    base.py · signalrgb_api.py · gamesense.py · hid_quadcast_s.py
│  │              hid_evision.py (only if approved) · wiz_udp.py · openrgb_sdk.py (optional)
│  ├─ network/    hotspot.py (WinRT read-only) · diagnostics.py · watchdog.py
│  ├─ api/        server.py (localhost HTTP) · cli.py
│  └─ alexa/      (empty until the Alexa architecture is chosen)
├─ tests/         fake devices (UDP / HTTP / HID) + contract tests per driver
└─ audit/         the Phase-1 tools (already present)
```
Logs go to `%LOCALAPPDATA%\SetupController\logs` with one logger per controller. Status values:
`ONLINE, OFFLINE, UNAVAILABLE, UNSUPPORTED, ERROR, NOT_CONFIGURED`.

### 12.3 How Setup-level commands map to each device

| Setup command | SignalRGB | GameSense (mouse) | QuadCast S | Kala (if EVision) | WiZ |
|---|---|---|---|---|---|
| `set_color(#FF0000)` | apply solid-colour preset or effect (see 4.1) | context-color event | stream colour | Custom mode | `setPilot r,g,b` |
| `set_brightness(50)` | `global_brightness=50` | scale RGB ×0.5 | scale RGB ×0.5 | level 2 of 4 | `dimming=50` |
| `turn_off()` | `enabled=false` | black + heartbeat | stream black | brightness 0 | `state=false` |
| `turn_on()` | `enabled=true` | restore last colour | restore last colour | restore level | `state=true` |
| `set_effect("rainbow")` | apply effect | UNSUPPORTED (or client-side) | host animation | Spectrum Cycle | a matching scene |

### 12.4 Alexa (deferred, as instructed)
Constraints for later: an Alexa Smart Home skill needs a cloud endpoint, and the PC must not accept
inbound connections. That points towards an **outbound-only** bridge (the PC keeps an outbound TLS
connection to a cloud relay or queue), or a local hub with an existing Alexa integration. To be
decided only after the local controller is validated.

---

## 13. NETWORK RECOMMENDATION

### 13.1 Architecture comparison

| | A. Hotspot + PPPoE (current) | B. Hotspot + Ethernet (ISP device routes) | C. Hotspot on a dedicated USB Wi-Fi adapter | D. Dedicated access point behind the PC | E. Dedicated router does PPPoE | F. PC as full router/NAT (RRAS/manual) |
|---|---|---|---|---|---|---|
| Stability | Unknown, suspect: many moving parts (RAS + ICS + icssvc + soft-AP) | Better: no RAS on the PC | Only helps if the onboard driver is at fault | Good radio; still ICS/PPPoE on the PC | **Best**: purpose-built | Poor/complex on Windows client |
| Cost | 0 | 0 if the ISP device can route | ~€15–35 (estimate) | ~€25–60 plus a 2nd NIC (estimate) | ~€30–80 (estimate) | 0 |
| Complexity | Medium | Low | Medium | Medium–High | Low (after setup) | High |
| WiZ compatibility | OK if 2.4 GHz + WPA2 | OK | Driver-dependent | Good | Good | – |
| Alexa compatibility | Only while the PC and PPPoE are up | Only while the PC is up | Only while the PC is up | Only while the PC is up | **Independent of the PC** | Only while the PC is up |
| Local API compatibility | Yes | Yes | Yes | Yes | Yes (PC and bulb on the same LAN) | Yes |
| Latency | Low | Low | Low | Low | Low | Low |
| PC must stay on | Yes | Yes | Yes | Yes | **No** | Yes |
| DHCP stability | ICS, no reservations | ICS, no reservations | ICS | ICS | **Router, reservations** | Needs a 3rd-party DHCP server |
| Wi-Fi stability | Consumer soft-AP | Consumer soft-AP | Consumer soft-AP | AP-grade | AP-grade | – |
| Maintenance | Windows updates can reset hotspot settings | Same | Same + extra driver | Medium | Low | High |

### 13.2 Recommendation (evidence-gated; no hardware recommended now)

1. **Keep A** (your preference) and **collect evidence first**: collector + probe + ≥48–72 h of the watch log
   including at least one outage.
2. If the evidence points to **H1 (PPPoE / cloud)**: the Wi-Fi is fine. Candidate actions are to align the
   PPPoE redial settings and to consider a software-only nudge (14.2).
3. If it points to **H2–H7 (hotspot / driver / power / security)**: apply the hardening in section 16
   (each change individually approved and reversible), then re-measure.
4. Consider **E (router doing PPPoE)** only if A still fails after hardening, *or* if you want Alexa to
   work while the PC is off. That is the only meaningful technical benefit of extra hardware here.
   **B** is a free variant if your ISP device can do PPPoE routing (Q8).

---

## 14. WIZ STABILITY RECOMMENDATION

### 14.1 Now
Run the three tools. When the bulb drops, write down the time and what the WiZ app and Alexa show.
That turns the investigation from hypotheses into a diagnosis.

### 14.2 Future watchdog (design only; no automatic power cycling)
```
every 30 s:  getPilot (UDP, 2 attempts, pywizlight-style backoff)
  ONLINE  → status ONLINE, record RSSI and latency
  no reply → retry; re-resolve the IP by MAC (neighbour table, hosts.ics)
           → still nothing → status OFFLINE, log a snapshot of every layer (section 9.4)
                           → no automatic action
```
Software-only recovery options, from least to most invasive. **None of them is automatic without your
approval.**

| Level | Action | Risk |
|---|---|---|
| 0 | Retry and back off; re-resolve the IP by MAC | None |
| 1 | If the bulb is **reachable locally but cloud-offline** (H1): send the bulb's local `reboot` method (exists in pywizlight [S13]). This is a *software* power cycle. | Light blinks or resets briefly; restored state after reboot is UNCERTAIN; test once manually first |
| 2 | Restart the Mobile Hotspot (WinRT stop/start) | **Drops every hotspot client**; the channel may change; may not fix a stuck bulb |
| 3 | Restart the `icssvc` / `SharedAccess` services or reset the Wi-Fi adapter | Admin rights; affects all networking; may not come back cleanly |
| – | `reset` UDP method, physical power cycling | **Never**: `reset` factory-resets the bulb |

---

## 15. REQUIRED SOFTWARE

| Phase | Software | Why | Status |
|---|---|---|---|
| Audit (now) | Windows PowerShell 5.1 (built into Windows) | Run the read-only tools | Nothing to install |
| Implementation (proposed) | Python 3.12+ | Controller runtime | To be approved |
| | `pywizlight` | WiZ UDP protocol [S13] | To be approved |
| | `hidapi` (Python binding) | QuadCast S (and Kala) HID feature reports | To be approved |
| | `httpx` / `aiohttp` | SignalRGB REST and GameSense HTTP | To be approved |
| | `keyring` | Secrets in Windows Credential Manager | To be approved |
| | `winrt`/`winsdk` bindings (or a PowerShell bridge) | Read-only hotspot state for diagnostics | To be approved |
| Option | SignalRGB **Pro** | Required for the SignalRGB REST API [S9] | Your decision (Q2) |
| Option | OpenRGB | Motherboard control without SignalRGB Pro | Your decision (Q2) |
| Option | USBPcap + Wireshark | Only if Kala reverse engineering is approved | Your decision (Q5) |

---

## 16. REQUIRED CONFIGURATION (proposed, **none applied**)

| # | Where | Change | Reason | Risk / rollback |
|---|---|---|---|---|
| C1 | SignalRGB | Enable HTTP API (Settings → General) | Needed for API control [S8] | Low / toggle back |
| C2 | SignalRGB | Disable Sensei Ten, QuadCast S (and any Kala) devices | One owner per device | Low / re-enable |
| C3 | Gigabyte | Make sure RGB Fusion is not running or installed alongside SignalRGB | Documented conflict [S10] | Medium: removing software / reinstall |
| C4 | SteelSeries GG | Allow the "Setup Controller" GameSense app once it registers | GameSense control | Low / remove app in GG |
| C5 | NGENUITY | Stop NGENUITY from driving the QuadCast S lighting (close it, or disable its lighting) | Single stream owner | Low / reopen |
| C6 | WiZ app | Confirm "Allow local communication" = on (and not "verified controls only") | Local UDP API [S14][S15] | Low |
| C7 | Mobile Hotspot | Band = **2.4 GHz** explicitly | WiZ is 2.4 GHz; removes H4 | Low / set back to Auto |
| C8 | Mobile Hotspot | Security = **WPA2** (if currently WPA3 or transition) | Removes H5 | Low / revert |
| C9 | Mobile Hotspot | Power saving (no-connections timeout) **off** | Removes H3 [S18] | Low / revert |
| C10 | Wi-Fi adapter | Untick "Allow the computer to turn off this device"; power plan wireless = Maximum Performance | Removes H7 | Low / revert |
| C11 | PPPoE entry | Review redial-on-link-failure and idle-disconnect settings | Shortens PPPoE outages (H1) | Low / revert |

C7–C11 are applied only if the evidence points to them, and one at a time, so the effect of each can be
measured.

---

## 17. FUTURE IMPLEMENTATION PLAN (each phase needs your go-ahead)

| Phase | Content | Exit criterion |
|---|---|---|
| 1b (now) | Run the audit tools; I update this report with real evidence | All PENDING items resolved or explained |
| 2 | Decisions (section 19); final architecture sign-off | Approved architecture |
| 3 | Core skeleton: models, capabilities, registry, config, state store, localhost API, fake devices and tests. **No device writes.** | Tests pass against fakes |
| 4 | WiZ driver + read-only diagnostics/watchdog | Colour, brightness, on/off, scene verified on the bulb |
| 5 | SignalRGB driver (read first, then write) | Brightness, on/off, effect, colour strategy verified |
| 6 | GameSense driver (register, heartbeat, zones) | Logo and wheel colour verified; clean release to the GG profile |
| 7 | QuadCast S HID driver (streamer) | Stable colour for 24 h; no conflict with NGENUITY off |
| 8 | Kala: only after ID match + approved protocol verification | Reversible test passed |
| 9 | Setup group, presets (Gaming/Study/Chill), restore-on | Per-device result logging |
| 10 | Alexa architecture decision + implementation | Voice commands end-to-end |

---

## 18. RISKS AND LIMITATIONS

1. **The audit has not run on the PC yet.** Every machine-specific conclusion is pending.
2. **Blocked official sources:** some official documentation was only seen as search snippets (marked).
   Conclusions based on them are lower confidence.
3. **SignalRGB:** the API needs Pro; there is no documented solid-colour endpoint; brightness and on/off
   are global. A future SignalRGB update could change the API.
4. **GameSense:** overrides are temporary by design (heartbeat required); the Sensei Ten zone mapping is
   unconfirmed; GG updates have moved `coreProps.json` before.
5. **QuadCast S:** needs a continuous stream from a resident process; conflicts with NGENUITY and
   SignalRGB; the mute indicator may override lighting; HP-era PIDs vary; onboard saves wear memory.
6. **Kala:** unverified protocol; **documented bricking risk** from ID reuse among Redragon keyboards [S4];
   EVision modes auto-save to the keyboard (memory wear for frequent changes).
7. **WiZ:** the local UDP API is unauthenticated, so anyone on the hotspot LAN can control the bulb;
   "verified controls only" would block it; firmware updates can change behaviour; `reset` must never be
   sent.
8. **Network:** the PC is a single point of failure for the bulb's internet (and so for Alexa) in
   architectures A–D and F. Windows feature updates can reset hotspot settings.
9. **Alexa:** needs the cloud. Architecture deferred.

---

## 19. QUESTIONS REQUIRING YOUR DECISION

1. **Run the audit tools?** Please run the three scripts (see `audit/README.md`) and share
   `audit-summary.txt`, `wiz-probe.txt` and, after an outage, `changes.log`.
2. **SignalRGB Pro:** do you have it (or want it) for API control of the motherboard? If not, is OpenRGB
   acceptable for the motherboard, with SignalRGB then no longer driving it?
3. **QuadCast S owner:** may the Setup Controller become the only program driving its lighting
   (NGENUITY lighting closed or disabled)?
4. **SteelSeries GG:** may the controller register a GameSense app in GG (one GG list entry)?
5. **Kala:** if its IDs don't match a verified project, may we install USBPcap + Wireshark to capture the
   official Redragon app (no firmware operations)?
6. **Alexa and the bulb:** was the bulb added to Alexa through the **WiZ skill** or through **Matter**?
   Where are your Echo devices connected (hotspot, mobile data, another network)?
7. **Other hotspot clients:** is anything else normally connected to the hotspot (phone, Echo)? This
   matters for the 5-minute no-connections timeout.
8. **ISP equipment:** can your ONT/modem do PPPoE routing itself (option B), or is it bridge-only?
9. **Implementation language:** Python (recommended: pywizlight, hidapi, signalrgb client) or C#/.NET?
10. **"Turn on setup" semantics:** restore each device's last state (recommended), or apply a default preset?
11. **Hardening:** after the evidence arrives, may I propose the specific C7–C11 changes one by one?

---

## 20. FINAL STATUS FOR EACH DEVICE

| Device / area | Status | Why |
|---|---|---|
| Gigabyte B650 GAMING X AX V2 RGB + fans via SignalRGB | **POSSIBLE** | API exists but needs Pro (**403 on the PC**); solid colour is indirect. OpenRGB is the no-Pro alternative. |
| SteelSeries Sensei Ten via GameSense | **POSSIBLE** | Official API; zone mapping and GG presence to be confirmed |
| HyperX QuadCast S via direct HID | **POSSIBLE** | Protocol documented by 2 independent projects; needs single-owner streaming. (Via NGENUITY: NOT FEASIBLE) |
| Redragon Kala Black | **REQUIRES RESEARCH** | IDs now known (**0C45:5004**); EVision candidate pending an interface check; bricking risk documented |
| Philips WiZ bulb (local control) | **READY** | The probe answered on the real bulb (read path) |
| WiZ disconnection problem | **REQUIRES RESEARCH** | H3/H4/H5 eliminated, PPPoE-on-PC ruled out; next: test C (update doc, section 12) |
| Alexa integration | **REQUIRES RESEARCH** | Deliberately deferred until the local controller is validated |

**Phase 1 stops here.** Nothing will be implemented until you answer the questions above and approve an
architecture.

---

## Sources

Commit hashes pin the exact revision that was read.

| Tag | Source | Type |
|---|---|---|
| S1 | SteelSeries **GameSense SDK**, github.com/SteelSeries/gamesense-sdk @5b69e24 (2024-02-12): `doc/api/sending-game-events.md`, `standard-zones.md`, `json-handlers-color.md` | Official |
| S2 | **rivalcfg**, github.com/flozz/rivalcfg @f16c521 (2026-08-16): `rivalcfg/devices/sensei_ten.py` | Established OSS |
| S3 | wex/sonar-rev README (GG `C:\ProgramData\SteelSeries\GG\coreProps.json`, encrypted addresses) | Community RE |
| S4 | **OpenRGB**, gitlab.com/CalcProgrammer1/OpenRGB @0f8f2dc (2026-09-25): `HyperXMicrophoneController/*`, `GigabyteRGBFusion2USBController/GigabyteFusion2USB_Devices.cpp`, `EVisionKeyboardController/*`, `SinowealthController/SinowealthControllerDetect.cpp`, `SteelSeriesController/*` | Established OSS |
| S5 | **QuadcastRGB**, github.com/Ors1mer/QuadcastRGB @e15a81c (2026-05-03): `modules/devio.c`, `rgbmodes.c`, README | OSS |
| S6 | **SignalRGB official plugins**, gitlab.com/signalrgb/signal-plugins @9503163 (2023-08-30): `Gigabyte_Motherboard_Controller.js`, `Steelseries_Sensi_Ten_Mouse.js`, `HyperX_Quadcast_S*.js` | Official (older snapshot) |
| S7 | **signalrgb-python**, github.com/hyperb1iss/signalrgb-python @e3d5850 (2026-04-05): `constants.py`, `async_client.py`, `model.py`, README ("SignalRGB Pro — required for API access") | OSS client of the official API |
| S8 | signalrgb-homeassistant README (Enable HTTP API; port 16038; Pro required) | OSS |
| S9 | docs.signalrgb.com: SignalRGB API introduction (base URL `http://127.0.0.1:16038/api/v1`; Pro only) | Official *(snippet)* |
| S10 | docs.signalrgb.com: Conflicting Programs (RGB Fusion 2.0 background service; SteelSeries GG) | Official *(snippet)* |
| S11 | docs.signalrgb.com / forum: Application URLs (`signalrgb://effect/apply/...`, `-silentlaunch-`) | Official *(snippet)* |
| S12 | github.com/vinemelo/SignalRGB-Redragon-K557-Kala-V2 @d2ea977 (2026-07-02) | Community, single maintainer |
| S13 | **pywizlight**, github.com/sbidy/pywizlight @c6ce9d9 (2026-08-05): `bulb.py`, `discovery.py`, `push_manager.py`, `bulblibrary.py`, `scenes.py` | Established OSS |
| S14 | Home Assistant WiZ docs source, github.com/home-assistant/home-assistant.io `source/_integrations/wiz.markdown` | Established OSS docs |
| S15 | WiZ FAQ "Secure or Disable local network communication" (faq.wizconnected.com …/548) | Official *(snippet)* |
| S16 | home-assistant/home-assistant.io issue #40835 (setting not found in WiZ app 1.27.4, 2025-09-12) | Community |
| S17 | sbidy/wiz_light discussion #85 (local operation without cloud; MQTT endpoints) | Maintainer + users |
| S18 | Microsoft WinRT API docs, github.com/MicrosoftDocs/winrt-api `windows.networking.networkoperators/*` (NetworkOperatorTetheringManager, TetheringWiFiBand, TetheringWiFiAuthenticationKind, TetheringCapability, IsNoConnectionsTimeoutEnabled) | Official |
| S19 | gigabyte.com B650 GAMING X AX V2 spec pages (Rev 1.0/1.1/1.2 and Rev 1.3): Wi-Fi module per revision | Official *(snippet)* |
| S20 | Community articles on Mobile Hotspot + PPPoE/ICS and `icssvc\Settings` timeouts (Microsoft Q&A volunteers, woshub, thewindowsclub) | Community (low authority) |
| S21 | WiZ FAQ "My light appears offline in the app" (power-cycle advice) | Official *(snippet)* |
| S22 | wizconnected.com product page, MODERN BULB 100 W A60 E27 | Official *(snippet)* |
| S23 | Search for an official HyperX/NGENUITY SDK or API (none found, 2026-09-26) | Absence of evidence |
| S24 | gigabyte.com/mb/rgb/sdk (RGB Fusion SDK page exists; content not fetched) | Official *(existence only)* |
