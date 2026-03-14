# event_extraction.py
from tshark_utils import run_tshark_fields, _to_int, _safe_float
from collections import Counter
import subprocess

def get_uds_streams(pcap):
    rows = run_tshark_fields(pcap, "uds", ["tcp.stream"])
    counts = Counter(_to_int(r[0]) for r in rows if r and r[0].strip())
    return sorted(counts.items(), key=lambda x: x[1], reverse=True)

def extract_events(pcap, tcp_stream=None):
    filter_ = f"tcp.stream == {tcp_stream} && uds" if tcp_stream is not None else "uds"
    fields = [
        "frame.number", "frame.time_epoch", "tcp.stream",
        "uds.reply", "uds.sid", "uds.err.sid", "uds.err.code",
        "uds.td.block_sequence_counter", "uds.rc.identifier", "uds.rc.subfunction",
        "uds.rc.info", "uds.rdbi.data_identifier"
    ]
    rows = run_tshark_fields(pcap, filter_, fields)

    events = []
    for r in rows:
        while len(r) < len(fields): r.append("")
        d = {
            "frame": _to_int(r[0]),
            "t_epoch": _safe_float(r[1]),
            "tcp_stream": _to_int(r[2]),
            "uds_reply": _to_int(r[3]),
            "uds_sid": _to_int(r[4]),
            "uds_err_sid": _to_int(r[5]),
            "uds_err_code": _to_int(r[6]),
            "td_bsc": _to_int(r[7]),
            "rc_id": _to_int(r[8]),
            "rc_subfn": _to_int(r[9]),
            "rc_info": _to_int(r[10]),
            "rdbi_did": _to_int(r[11]),
        }
        if d["frame"] is not None and d["t_epoch"] is not None:
            events.append(d)
    events.sort(key=lambda x: x["frame"])
    return events

def calculate_timing_simple(pcap, filter_str):
    """
    Calculate ECU and client timing, treating each TCP stream independently.
    Gaps between different streams are NOT counted as client time.
    Properly handles NRC 0x78 (pending) responses.
    """
    cmd = ["tshark", "-r", pcap, "-Y", filter_str,
           "-T", "fields", "-e", "tcp.stream", "-e", "frame.time_epoch", 
           "-e", "uds.reply", "-e", "uds.sid", "-e", "uds.err.code"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True)
    lines = [line.strip() for line in out.stdout.splitlines() if line.strip()]

    if not lines:
        return 0.0, 0.0  # ECU, Client

    # Group events by stream
    streams = {}
    for line in lines:
        parts = line.split("\t")
        if len(parts) < 5: 
            parts.extend([""] * (5 - len(parts)))
        
        stream = _to_int(parts[0])
        t = _safe_float(parts[1])
        reply = _to_int(parts[2])
        sid = _to_int(parts[3])
        err_code = _to_int(parts[4])
        
        if stream is None or t is None or reply is None: 
            continue
        streams.setdefault(stream, []).append((t, reply, sid, err_code))

    total_ecu = 0.0
    total_client = 0.0

    # Process each stream independently
    for stream_id, events in streams.items():
        events.sort(key=lambda x: x[0])  # sort by time
        
        active_req_time = None
        last_response_time = None
        
        for t, reply, sid, err_code in events:
            if reply == 0:  # Request
                if last_response_time is not None:
                    # Gap from last response to this request (client time)
                    gap = t - last_response_time
                    if gap > 0:
                        total_client += gap
                active_req_time = t
            else:  # Response (reply == 1)
                if active_req_time is None:
                    last_response_time = t
                    continue
                
                # NRC 0x78 means ECU is still busy, don't close the transaction
                if sid == 0x3F and err_code == 0x78:
                    last_response_time = t
                    continue
                
                # Final response (positive or other negative)
                ecu_time = t - active_req_time
                if ecu_time > 0:
                    total_ecu += ecu_time
                
                last_response_time = t
                active_req_time = None

    return total_ecu, total_client


def find_flash_window(pcap_path: str):
    """
    Find the first 0x34 request frame and the last 0x37 positive response frame.
    Returns a dict with per-stream windows and overall window.
    """
    display_filter = "uds.sid==0x34 or uds.sid==0x37"
    cmd = [
        "tshark", "-r", pcap_path, "-Y", display_filter, "-T", "fields",
        "-e", "frame.number", "-e", "tcp.stream", "-e", "uds.sid", "-e", "uds.reply",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)

    # Track per stream
    stream_windows = {}
    overall_first = None
    overall_last = None

    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 4: continue
        
        frame_str, stream_str, sid_str, reply_str = parts
        frame = int(frame_str)
        stream = int(stream_str)
        sid = int(sid_str, 16)
        reply_flag = int(reply_str, 16)

        if stream not in stream_windows:
            stream_windows[stream] = {"first_download": None, "last_exit": None}

        # Track first 0x34 request per stream
        if sid == 0x34 and reply_flag == 0 and stream_windows[stream]["first_download"] is None:
            stream_windows[stream]["first_download"] = frame
            if overall_first is None:
                overall_first = frame

        # Track last 0x37 response per stream
        if sid == 0x37 and reply_flag == 1:
            stream_windows[stream]["last_exit"] = frame
            overall_last = frame

    return {
        "per_stream": stream_windows,
        "overall_first": overall_first,
        "overall_last": overall_last
    }


def uds_timing(pcap_path: str, start_frame: int, end_frame: int):
    """
    Compute ECU and client timing within [start_frame, end_frame],
    correctly handling NRC 0x78 as ECU busy, and treating each stream independently.
    """
    display_filter = f"frame.number>={start_frame} and frame.number<={end_frame} and uds"
    cmd = [
        "tshark", "-r", pcap_path, "-Y", display_filter, "-T", "fields",
        "-e", "tcp.stream", "-e", "frame.time_epoch", "-e", "frame.number",
        "-e", "uds.reply", "-e", "uds.sid", "-e", "uds.err.code",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)

    # stream_id -> list of (time, frame_no, reply_flag, sid, err_code)
    events_by_stream = {}
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 6: continue
        
        stream_str, time_str, frame_str, reply_str, sid_str, err_str = [p or "0" for p in parts]
        stream_id = int(stream_str)
        timestamp = float(time_str)
        frame_no = int(frame_str)
        reply_flag = int(reply_str, 16)
        service_id = int(sid_str, 16)
        error_code = int(err_str, 16) if err_str != "0" else None
        
        events_by_stream.setdefault(stream_id, []).append(
            (timestamp, frame_no, reply_flag, service_id, error_code)
        )

    total_ecu_time = 0.0
    total_client_time = 0.0
    ecu_gaps = []
    client_gaps = []

    # Process each stream independently
    for stream_id, events in events_by_stream.items():
        events.sort(key=lambda e: e[0])

        active_req_time = None
        active_req_frame = None
        active_req_sid = None
        last_response_time = None
        last_response_frame = None

        for timestamp, frame_no, reply_flag, service_id, error_code in events:
            if reply_flag == 0:  # request
                if last_response_time is not None:
                    client_gap = timestamp - last_response_time
                    if client_gap > 0:
                        total_client_time += client_gap
                        client_gaps.append((client_gap, stream_id, last_response_frame, frame_no))
                active_req_time, active_req_frame, active_req_sid = timestamp, frame_no, service_id
            else:  # response
                if active_req_time is None:
                    last_response_time, last_response_frame = timestamp, frame_no
                    continue

                # NRC 0x78 means ECU is still busy, don't close the transaction
                if service_id == 0x3F and error_code == 0x78:
                    last_response_time, last_response_frame = timestamp, frame_no
                    continue

                ecu_gap = timestamp - active_req_time
                if ecu_gap > 0:
                    total_ecu_time += ecu_gap
                    ecu_gaps.append((ecu_gap, stream_id, active_req_frame, frame_no, active_req_sid))

                last_response_time, last_response_frame = timestamp, frame_no
                active_req_time = active_req_frame = active_req_sid = None

    top_ecu_gaps = sorted(ecu_gaps, reverse=True)[:20]
    top_client_gaps = sorted(client_gaps, reverse=True)[:20]
    
    return total_ecu_time, total_client_time, top_ecu_gaps, top_client_gaps