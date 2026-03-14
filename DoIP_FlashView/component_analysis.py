# component_analysis.py
from event_extraction import extract_events

def segment_components(events):
    """
    Segment components based on 0x34 requests.
    Works across all streams - components are identified regardless of stream.
    """
    starts = [e for e in events if e["uds_sid"] == 0x34 and e["uds_reply"] == 0x00]
    if not starts:
        return []
    last = events[-1]
    comps = []
    for i, s in enumerate(starts):
        sf = s["frame"]
        st = s["t_epoch"]
        ef = starts[i+1]["frame"] - 1 if i < len(starts)-1 else last["frame"]
        et = starts[i+1]["t_epoch"] if i < len(starts)-1 else last["t_epoch"]
        comps.append({
            "component": i+1,
            "start_frame": sf,
            "end_frame": ef,
            "start_ts": st,
            "end_ts": et,
            "total_time_s": et - st if et and st else None,
            "tcp_stream": s["tcp_stream"]
        })
    return comps

def _events_in_frame_range(events, start_frame, end_frame):
    return [e for e in events if start_frame <= e["frame"] <= end_frame]

def ecu_time_for_service(events_range, sid):
    """Calculate ECU processing time for a specific service."""
    req = next((e for e in events_range if e["uds_sid"] == sid and e["uds_reply"] == 0x00), None)
    if not req: 
        return None
    resp = next((e for e in events_range if e["frame"] > req["frame"] and
                 e["uds_sid"] == sid and e["uds_reply"] == 0x01 and e["uds_err_code"] is None), None)
    return resp["t_epoch"] - req["t_epoch"] if resp else None

def pending_txn_time(events_range, sid):
    """
    Calculate time spent in pending state (NRC 0x78) for a service.
    Returns total pending time and details of each transaction.
    """
    total = 0.0
    details = []
    active = None
    pending_seen = False
    
    for e in events_range:
        if e["uds_sid"] == sid and e["uds_reply"] == 0x00:
            active = e
            pending_seen = False
            continue
            
        if active is None: 
            continue
            
        if e["uds_err_sid"] == sid and e["uds_err_code"] == 0x78:
            pending_seen = True
            continue
            
        if e["uds_err_sid"] == sid and e["uds_err_code"] is not None and e["uds_err_code"] != 0x78:
            dt = e["t_epoch"] - active["t_epoch"]
            if pending_seen: 
                total += dt
            details.append((active["frame"], e["frame"], dt, pending_seen, "NRC"))
            active = None
            pending_seen = False
            continue
            
        if e["uds_sid"] == sid and e["uds_reply"] == 0x01 and e["uds_err_code"] is None:
            dt = e["t_epoch"] - active["t_epoch"]
            if pending_seen: 
                total += dt
            details.append((active["frame"], e["frame"], dt, pending_seen, "POS"))
            active = None
            pending_seen = False
            
    return total, details

def find_transfer_window(events_range):
    """
    Find the transfer window from first 0x34 positive response to last 0x37 positive response.
    """
    start = next((e for e in events_range if e["uds_sid"] == 0x34 and e["uds_reply"] == 0x01 
                  and e["uds_err_code"] is None), None)
    if not start: 
        return None, None, None
        
    end = next((e for e in events_range if e["frame"] > start["frame"] and
                e["uds_sid"] == 0x37 and e["uds_reply"] == 0x01 and e["uds_err_code"] is None), None)
    if not end: 
        return None, None, None
        
    return start["frame"], end["frame"], end["t_epoch"] - start["t_epoch"]

def post_exit_other_uds_time(events_range, component_end_ts):
    """
    Calculate time spent on other UDS services after transfer exit.
    """
    te = next((e for e in events_range if e["uds_sid"] == 0x37 and e["uds_reply"] == 0x01 
               and e["uds_err_code"] is None), None)
    if not te: 
        return None
        
    start_ts = te["t_epoch"]
    next_rd = next((e for e in events_range if e["frame"] > te["frame"] and 
                    e["uds_sid"] == 0x34 and e["uds_reply"] == 0x00), None)
    end_ts = next_rd["t_epoch"] if next_rd else component_end_ts
    dt = end_ts - start_ts
    return dt if dt >= 0 else None

def analyze_components(events, components, profile):
    """
    Analyze each component for timing metrics.
    Components may span different TCP streams.
    """
    rows = []
    td_details_all = {}
    
    for c in components:
        c_events = _events_in_frame_range(events, c["start_frame"], c["end_frame"])
        
        # Find transfer window for this component
        tw_start, tw_end, tw_time = find_transfer_window(c_events)
        transfer_events = _events_in_frame_range(events, tw_start, tw_end) if tw_start else c_events
        
        row = {
            "component": c["component"],
            "tcp_stream": c["tcp_stream"],
            "start_frame": c["start_frame"],
            "end_frame": c["end_frame"],
            "total_time": c["total_time_s"],
            "reqdl_time": ecu_time_for_service(c_events, 0x34),
            "reqdl_pending": pending_txn_time(c_events, 0x34)[0],
            "transfer_time": tw_time,
            "td_pending": pending_txn_time(transfer_events, 0x36)[0],
            "transfer_exit_time": ecu_time_for_service(c_events, 0x37),
            "other_uds_services_post_transfer_exit": post_exit_other_uds_time(c_events, c["end_ts"])
        }
        rows.append(row)
        
        _, details = pending_txn_time(c_events, 0x36)
        td_details_all[c["component"]] = details
        
    return rows, td_details_all

def analyze_non_flash_stream(events, stream_id):
    """
    Analyze a stream that contains only non-flash UDS traffic.
    """
    if not events: 
        return [], {}
        
    total_time = events[-1]["t_epoch"] - events[0]["t_epoch"] if events else None
    row = {
        "component": "UDS only",
        "tcp_stream": stream_id,
        "start_frame": events[0]["frame"] if events else None,
        "end_frame": events[-1]["frame"] if events else None,
        "total_time": total_time,
        "reqdl_time": None, 
        "reqdl_pending": None,
        "transfer_time": None, 
        "td_pending": None,
        "transfer_exit_time": None, 
        "other_uds_services_post_transfer_exit": None
    }
    return [row], {}

def group_components_by_stream(components):
    """
    Group components by their TCP stream.
    Returns dict: {stream_id: [component_list]}
    """
    by_stream = {}
    for comp in components:
        stream = comp.get("tcp_stream")
        if stream not in by_stream:
            by_stream[stream] = []
        by_stream[stream].append(comp)
    return by_stream
