# DoIP FlashView

A desktop diagnostic tool for analyzing **DoIP (Diagnostics over Internet Protocol)** flash data captured in PCAP/PCAPNG files. DoIP FlashView parses UDS (Unified Diagnostic Services) traffic, segments ECU flash components, and produces detailed timing breakdowns — all through a clean GUI.

![DoIP FlashView Screenshot](docs/screenshot.png)

> Part of the [Automotive Embedded Engineering Tools](https://github.com/Rajkaran75/Automotive_Embedded_Engineering_Tools) collection.

---

## Features

- **Automatic component segmentation** — detects each ECU flash component by identifying `0x34` RequestDownload boundaries
- **Per-component timing metrics** — ReqDL time, Transfer time, TD Pending (NRC 0x78), Exit time, and post-exit UDS time
- **Multi-stream support** — handles captures with multiple TCP streams, correctly separating flash vs. non-flash UDS traffic
- **NRC 0x78 aware** — pending responses are tracked accurately; ECU busy time is never double-counted
- **UDS Timing tab** — overall ECU vs. client gap time, transfer phase breakdown, and top-10 longest transactions
- **Health Check** — pre-analysis validation of the capture file with stream inventory and service statistics
- **Profile system** — extensible metric profiles; custom verify routines can be added via `metrics_plugins.py`
- **4K / high-DPI ready** — native Windows DPI awareness, crisp rendering at any display scale

---

## Requirements

### Python
- Python 3.8 or newer

### External dependency — tshark
DoIP FlashView uses **tshark** (the command-line component of Wireshark) to dissect PCAP files. You must have it installed and accessible on your system PATH.

- **Windows**: Install [Wireshark](https://www.wireshark.org/download.html) and make sure to tick *"Add tshark to PATH"* during setup, or add it manually (default location: `C:\Program Files\Wireshark\`)
- **Linux**: `sudo apt install tshark` or `sudo dnf install wireshark-cli`
- **macOS**: `brew install wireshark`

Verify installation:
```bash
tshark --version
```

### Python packages
DoIP FlashView uses only Python standard library modules — no `pip install` is required.

| Module | Purpose |
|--------|---------|
| `tkinter` / `ttk` | GUI framework |
| `subprocess` | tshark process execution |
| `threading` | Background analysis worker |
| `collections` | Stream packet counting |
| `ctypes` | Windows DPI awareness |

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/Rajkaran75/Automotive_Embedded_Engineering_Tools.git
cd Automotive_Embedded_Engineering_Tools/DoIP_FlashView

# 2. No pip install needed — run directly
python main.py
```

---

## Usage

1. Launch the tool:
   ```bash
   python main.py
   ```

2. Click **Open PCAP** and select your `.pcap` or `.pcapng` capture file

3. Select an analysis **Profile** from the dropdown (default: `core_uds_only`)

4. Click **Analyze**

5. Results appear across four tabs:
   - **Dashboard** — per-stream component table with all timing metrics
   - **UDS Timing** — ECU vs. client timing totals and top-10 longest transactions
   - **Health Check** — capture file validation, stream inventory, service stats
   - **Profile** — description of the active analysis profile

---

## Project Structure

```
DoIP_FlashView/
├── main.py                 # Entry point
├── gui.py                  # Tkinter GUI — all tabs, rendering, DPI handling
├── config.py               # Column definitions and analysis profiles
├── event_extraction.py     # tshark calls, UDS event parsing, timing calculation
├── component_analysis.py   # Component segmentation and per-component metrics
├── health_check.py         # Pre-analysis PCAP validation
├── metrics_plugins.py      # Extensible metric plugin registry
├── tshark_utils.py         # tshark subprocess helpers and type converters
├── README.md
├── CHANGELOG.md
├── LICENSE
├── requirements.txt
└── docs/
    └── architecture.md
```

---

## Metrics Explained

| Column | Description |
|--------|-------------|
| **Component #** | Sequential flash component index (one per `0x34` RequestDownload) |
| **Start Frame** | PCAP frame number of the first `0x34` request |
| **End Frame** | PCAP frame number of the last event in this component |
| **Total Time (s)** | Wall-clock duration from component start to end |
| **ReqDL Time (s)** | ECU response time for the `0x34` RequestDownload service |
| **ReqDL Pending (s)** | Time spent in NRC `0x78` pending state during RequestDownload |
| **Transfer Time (s)** | Duration from first `0x34` positive response to last `0x37` positive response |
| **TD Pending (s)** | Total NRC `0x78` pending time across all `0x36` TransferData transactions |
| **Exit Time (s)** | ECU response time for the `0x37` TransferExit service |
| **Other UDS Post Exit** | Time spent on other UDS services after TransferExit before the next component |

---

## Profiles

Profiles define which metrics are computed. The active profile is selected from the GUI dropdown.

**Built-in profiles:**

| Profile ID | Description |
|------------|-------------|
| `core_uds_only` | Core flash metrics only — no custom verify routines |

**Adding a custom profile:**

Edit `config.py` and add an entry to `BUILTIN_PROFILES`. Custom metric functions are registered in `metrics_plugins.py` using the `@register_metric` decorator. Two plugin types are supported:

- `verify_time_routine` — measures time between RoutineControl start/end subfunction calls
- `verify_time_did` — measures RDBI (0x22) request/response round-trip time for a given DID

---

## How It Works

1. **tshark** dissects the PCAP and extracts UDS fields into tab-separated rows
2. **event_extraction.py** parses rows into structured event dicts, sorted by frame number
3. **component_analysis.py** segments events into components at each `0x34` request boundary, then computes timing metrics per component
4. NRC `0x78` (RequestResponsePending) responses are treated as ECU-busy signals — the pending flag is set on the active transaction, and the full request-to-final-response duration is counted as pending time only if at least one `0x78` was seen
5. Multiple TCP streams are processed independently — timing gaps between different streams are never counted as client time
6. **gui.py** renders results into Treeview tables with auto-fitted column widths

---

## Platform Support

| Platform | Status |
|----------|--------|
| Windows 10 / 11 (including 4K) | ✅ Fully supported |
| Linux | ✅ Supported |
| macOS | ✅ Supported (tkinter must be available) |

---

## Contributing

Pull requests are welcome. For significant changes please open an issue first to discuss what you'd like to change.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.
