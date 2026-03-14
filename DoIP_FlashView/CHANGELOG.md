# Changelog — DoIP FlashView

All notable changes to DoIP FlashView will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2025-01-01

### Added
- Initial public release of DoIP FlashView
- PCAP/PCAPNG file loading via tshark
- Automatic UDS component segmentation based on `0x34` RequestDownload boundaries
- Per-component timing metrics: ReqDL Time, ReqDL Pending, Transfer Time, TD Pending, Exit Time, Other UDS Post Exit
- NRC `0x78` (RequestResponsePending) aware timing — pending time tracked per transaction without double-counting
- Multi-stream support — flash and non-flash UDS streams analyzed independently
- Dashboard tab with per-stream Treeview tables and auto-fitted columns
- UDS Timing tab with overall ECU vs. client gap totals and top-10 longest transactions
- Health Check tab with capture validation, stream inventory, and UDS service statistics
- Profile tab showing active analysis profile configuration
- Extensible profile system via `config.py` and `metrics_plugins.py`
- `verify_time_routine` plugin — measures RoutineControl verify timing
- `verify_time_did` plugin — measures RDBI (0x22) round-trip timing
- Native Windows DPI awareness via `SetProcessDpiAwareness` — crisp rendering on 4K displays
- Horizontal and vertical scrollbars on all Treeview tables
- Indeterminate progress bar during analysis
- Background threading — UI stays responsive during long analyses
