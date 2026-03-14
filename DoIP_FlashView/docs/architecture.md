# DoIP FlashView — Architecture

This document describes how the application is structured and how data flows through it from a raw PCAP file to the final rendered results.

Repository: https://github.com/Rajkaran75/Automotive_Embedded_Engineering_Tools/tree/master/DoIP_FlashView

---

## Module Overview

```
main.py
  └── gui.py  (DoIPAnalysisTool)
        ├── config.py              (profiles, column definitions)
        ├── health_check.py        (pre-analysis validation)
        ├── event_extraction.py    (tshark calls, event parsing, timing)
        │     └── tshark_utils.py  (subprocess helpers, type converters)
        ├── component_analysis.py  (segmentation, per-component metrics)
        │     └── event_extraction.py
        └── metrics_plugins.py     (pluggable extended metric functions)
```

---

## Data Flow

### 1. File load
The user selects a `.pcap` or `.pcapng` file. The path is stored — no data is read yet.

### 2. Health check (`health_check.py`)
Before full analysis, a quick validation pass runs two tshark queries:
- Count UDS packets per TCP stream
- Collect UDS service statistics (0x34, 0x36, 0x37 request/success/pending/fail counts)

Streams are classified as **flash** (contain 0x34/0x36/0x37) or **non-flash UDS** (other UDS traffic). Warnings and errors are generated for missing services or unexpected stream counts. If errors are found, analysis halts.

### 3. Stream discovery (`event_extraction.get_uds_streams`)
tshark lists all TCP streams carrying UDS traffic, sorted by packet count descending. Streams with fewer than 5 packets are skipped.

### 4. Flash window detection (`event_extraction.find_flash_window`)
A single tshark query finds the first `0x34` request frame and last `0x37` positive response frame, tracked per stream. This defines the transfer phase window used later for timing calculations.

### 5. Event extraction (`event_extraction.extract_events`)
For each stream, tshark extracts 12 UDS fields per packet into tab-separated rows. Each row is parsed into a structured event dict:

```python
{
    "frame":       int,    # PCAP frame number
    "t_epoch":     float,  # Unix timestamp (microsecond precision)
    "tcp_stream":  int,
    "uds_reply":   int,    # 0x00 = request, 0x01 = response
    "uds_sid":     int,    # Service ID
    "uds_err_sid": int,    # Error response: original SID
    "uds_err_code":int,    # NRC code (e.g. 0x78 = pending)
    "td_bsc":      int,    # TransferData block sequence counter
    "rc_id":       int,    # RoutineControl routine ID
    "rc_subfn":    int,    # RoutineControl subfunction
    "rc_info":     int,    # RoutineControl info byte
    "rdbi_did":    int,    # ReadDataByIdentifier DID
}
```

Events are sorted by frame number.

### 6. Component segmentation (`component_analysis.segment_components`)
Components are identified by scanning for `0x34` request events (reply == 0x00). Each `0x34` request starts a new component. The component's frame range runs from that request up to (but not including) the next `0x34` request, or to the last event in the capture.

### 7. Per-component analysis (`component_analysis.analyze_components`)
For each component, events within its frame range are extracted and the following metrics are computed:

| Metric | Function | Logic |
|--------|----------|-------|
| ReqDL Time | `ecu_time_for_service(0x34)` | Time from 0x34 request to first positive response |
| ReqDL Pending | `pending_txn_time(0x34)` | Total duration of 0x34 transactions that had NRC 0x78 |
| Transfer Time | `find_transfer_window` | Time from 0x34 positive response to 0x37 positive response |
| TD Pending | `pending_txn_time(0x36)` | Total duration of 0x36 transactions that had NRC 0x78 |
| Exit Time | `ecu_time_for_service(0x37)` | Time from 0x37 request to positive response |
| Other UDS Post Exit | `post_exit_other_uds_time` | Time from 0x37 response to next 0x34 request (or component end) |

#### NRC 0x78 Pending Logic
`pending_txn_time()` walks events in order. When a request is seen, it sets `active = request_event` and `pending_seen = False`. If a NRC 0x78 response arrives for that service, `pending_seen` is flipped to `True` — no timer starts yet. When the final response arrives (positive or other NRC), `dt = final_time - request_time` is computed. This `dt` is only added to the running total if `pending_seen` is `True`. This means the clock always starts at the original request, not at the first 0x78.

### 8. Timing calculation (`event_extraction.calculate_timing_simple`, `uds_timing`)
Two timing calculations run after component analysis:

**Overall timing** — across all UDS traffic in the capture. Each TCP stream is processed independently. Within a stream, time between a response and the next request is client gap time. Time between a request and its final response (excluding 0x78 intermediates) is ECU time.

**Transfer phase timing** — same logic but scoped to the flash window frame range per stream. Returns top-20 ECU gaps and top-20 client gaps for display in the UDS Timing tab.

### 9. Rendering (`gui.py`)
Results are rendered into Tkinter Treeview tables. Column widths are auto-fitted on the `<Map>` event using the actual live Treeview font, ensuring accurate measurements at any DPI. A Canvas-based scroll frame keeps tables correctly sized to the window width.

---

## Profile System

Profiles are defined in `config.py` as dicts:

```python
{
    "id": "my_profile",
    "name": "My Profile",
    "extended_metrics": [
        {
            "id": "verify_time",
            "name": "Verify Time (s)",
            "width": 130,
            "compute_fn": "verify_time_routine",   # key in METRIC_REGISTRY
            "params": { ... }
        }
    ]
}
```

Each `compute_fn` string maps to a function registered in `metrics_plugins.py` via the `@register_metric` decorator. The function receives `(events_range, params)` and returns a float (seconds) or `None`.

---

## Multi-Stream Handling

Streams are analyzed independently throughout the pipeline:
- Component segmentation uses events from one stream at a time
- Timing calculations never pair a request from stream A with a response from stream B
- The gap between the last event on stream A and the first event on stream B is never counted as client time
- Flash streams (containing 0x34/0x36/0x37) and non-flash UDS streams are displayed in separate Dashboard sections

---

## DPI Handling (Windows)

`SetProcessDpiAwareness(2)` is called at module level in `gui.py` before the Tk window is created. This tells Windows to provide true physical pixel dimensions rather than bitmap-upscaling the process. As a result, Tkinter renders at native resolution (crisp on 4K displays) and font measurement functions return accurate pixel values.
