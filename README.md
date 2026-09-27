# setup_config

Groundwork for **Setup Controller**, a Windows application that will control every RGB and smart-lighting
device in the PC setup as one logical device ("Setup"), and later through Amazon Alexa.

**Current phase: 1 — technical audit (no implementation yet).**

| Path | Content |
|---|---|
| [`docs/AUDIT_REPORT.md`](docs/AUDIT_REPORT.md) | Audit report: findings, capability matrix, recommended architecture, open decisions |
| [`docs/AUDIT_UPDATE_01_PC_RESULTS.md`](docs/AUDIT_UPDATE_01_PC_RESULTS.md) | Results from the real PC, corrections to the report, next diagnostic test |
| [`docs/AUDIT_UPDATE_02_LONGRUN_TEST.md`](docs/AUDIT_UPDATE_02_LONGRUN_TEST.md) | Updated WiZ diagnosis (hotspot restart ruled out) and the long-run failure-capture test |
| [`audit/`](audit/README.md) | Read-only PowerShell tools that collect the on-PC evidence the report still needs |
