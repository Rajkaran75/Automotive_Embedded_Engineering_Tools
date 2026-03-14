# tshark_utils.py
import subprocess

def _to_int(v):
    if v is None: return None
    s = str(v).strip()
    if not s: return None
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return None

def _safe_float(x):
    try:
        return float(x) if x not in (None, "") else None
    except ValueError:
        return None

def _run(cmd):
    try:
        out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return out.stdout
    except FileNotFoundError:
        raise RuntimeError("tshark not found. Install Wireshark/tshark.")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"tshark error:\n{e.stderr}")

def run_tshark_fields(pcap, display_filter, fields):
    cmd = ["tshark", "-r", pcap, "-Y", display_filter, "-T", "fields", "-E", "separator=\t"]
    for f in fields:
        cmd += ["-e", f]
    stdout = _run(cmd)
    return [line.split("\t") for line in stdout.splitlines() if line.strip()]

def _fmt_seconds(x):
    return f"{x:.6f}" if x is not None else ""

# # tshark_utils.py
# import subprocess

# def _to_int(v):
#     if v is None: return None
#     s = str(v).strip()
#     if not s: return None
#     try:
#         return int(s, 16) if s.lower().startswith("0x") else int(s)
#     except ValueError:
#         return None

# def _safe_float(x):
#     try:
#         return float(x) if x not in (None, "") else None
#     except ValueError:
#         return None

# def _run(cmd):
#     try:
#         out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
#         return out.stdout
#     except FileNotFoundError:
#         raise RuntimeError("tshark not found. Install Wireshark/tshark.")
#     except subprocess.CalledProcessError as e:
#         raise RuntimeError(f"tshark error:\n{e.stderr}")

# def run_tshark_fields(pcap, display_filter, fields):
#     cmd = ["tshark", "-r", pcap, "-Y", display_filter, "-T", "fields", "-E", "separator=\t"]
#     for f in fields:
#         cmd += ["-e", f]
#     stdout = _run(cmd)
#     return [line.split("\t") for line in stdout.splitlines() if line.strip()]

# def _fmt_seconds(x):
#     return f"{x:.6f}" if x is not None else ""