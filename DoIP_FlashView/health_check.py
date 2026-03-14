# health_check.py
from collections import Counter
from tshark_utils import run_tshark_fields, _to_int

def health_check(pcap):
    """
    Perform health check on the PCAP file.
    Reports stream information and UDS service statistics.
    """
    health_data = {
        "tcp_streams": Counter(),
        "stream_details": {},  # Per-stream information
        "warnings": [],
        "errors": [],
        "uds_services": {
            0x34: {"req": 0, "succ": 0, "pend": 0, "fail": 0},
            0x36: {"req": 0, "succ": 0, "pend": 0, "fail": 0},
            0x37: {"req": 0, "succ": 0, "pend": 0, "fail": 0}
        },
    }

    # Count UDS packets per stream
    rows = run_tshark_fields(pcap, "uds", ["tcp.stream", "uds.sid"])
    for r in rows:
        if len(r) < 2:
            continue
        s = _to_int(r[0])
        sid = _to_int(r[1])
        if s is not None:
            health_data["tcp_streams"][s] += 1
            if s not in health_data["stream_details"]:
                health_data["stream_details"][s] = {
                    "has_flash": False,
                    "uds_count": 0,
                    "services": set()
                }
            health_data["stream_details"][s]["uds_count"] += 1
            if sid is not None:
                health_data["stream_details"][s]["services"].add(sid)
                if sid in [0x34, 0x36, 0x37]:
                    health_data["stream_details"][s]["has_flash"] = True

    # Collect UDS service statistics (global across all streams)
    rows = run_tshark_fields(pcap, "uds", ["uds.sid", "uds.reply", "uds.err.sid", "uds.err.code"])
    for r in rows:
        if len(r) < 4:
            continue
        sid = _to_int(r[0])
        reply = _to_int(r[1])
        err_sid = _to_int(r[2])
        err_code = _to_int(r[3])
        
        if sid in [0x34, 0x36, 0x37]:
            if reply == 0x00: 
                health_data["uds_services"][sid]["req"] += 1
            elif reply == 0x01 and err_code is None: 
                health_data["uds_services"][sid]["succ"] += 1
                
        if err_sid in [0x34, 0x36, 0x37]:
            if err_code == 0x78: 
                health_data["uds_services"][err_sid]["pend"] += 1
            elif err_code is not None: 
                health_data["uds_services"][err_sid]["fail"] += 1

    # Generate warnings and errors
    if not health_data["tcp_streams"]:
        health_data["errors"].append("No UDS packets found")
    
    if len(health_data["tcp_streams"]) > 1:
        flash_streams = [s for s, info in health_data["stream_details"].items() if info["has_flash"]]
        non_flash_streams = [s for s, info in health_data["stream_details"].items() if not info["has_flash"]]
        
        msg = f"Multiple TCP streams detected: {len(flash_streams)} with flash traffic"
        if non_flash_streams:
            msg += f", {len(non_flash_streams)} with non-flash UDS"
        health_data["warnings"].append(msg)

    # Check for missing services in flash streams
    flash_streams = [s for s, info in health_data["stream_details"].items() if info["has_flash"]]
    if flash_streams:
        for sid in [0x34, 0x36, 0x37]:
            stats = health_data["uds_services"][sid]
            if stats["req"] == 0:
                health_data["warnings"].append(f"No 0x{sid:02x} requests found")
            elif stats["succ"] == 0:
                health_data["errors"].append(f"No successful 0x{sid:02x} responses")

    health_data["status"] = "ERROR" if health_data["errors"] else "WARNING" if health_data["warnings"] else "OK"
    return health_data
