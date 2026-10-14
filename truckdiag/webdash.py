"""Web dashboard: live J1939 values on your phone's browser.

Listen-only -- this server never transmits on the CAN bus.

Usage:
  .venv/bin/python webdash.py --demo
      # simulated truck, no hardware; open http://localhost:8080/
  .venv/bin/python webdash.py --socketcan can0 --bitrate 250000
      # real truck on the Pi; on your phone (same hotspot/Wi-Fi)
      # open http://<pi-ip>:8080/  (or http://raspberrypi.local:8080/)

One background thread reads CAN frames and maintains the live state;
the HTTP server only serves that state as JSON plus a single page.
"""

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from truckdiag.bus import open_bus
from truckdiag.decoder import decode_frame, format_value
from truckdiag.dtc import parse_dm1, format_dtc
from truckdiag.health import action_for, check_soot, fmi_guidance
from truckdiag.j1939 import (DM1, DM2, PGN_REQUEST, TP_CM, TP_DT,
                             decode_can_id, parse_acknowledgment)
from truckdiag.thresholds import (check as check_threshold, PROFILES,
                                  DEFAULT_PROFILE)
from truckdiag.transport import BamReassembler

# Big glanceable cards: (spn, short label). State SPNs show their state text.
CRITICAL_CARDS = [
    (100, "Oil pressure"),
    (110, "Coolant temp"),
    (111, "Coolant level"),
    (98, "Oil level"),
    (1761, "DEF level"),
    (5246, "SCR inducement"),
    (3719, "DPF soot"),
    (168, "Battery"),
]

STALE_AFTER_S = 3.0


class LiveState:
    """Thread-safe snapshot of everything the page needs."""

    def __init__(self, profile):
        self.profile = profile
        self.lock = threading.Lock()
        self.latest = {}        # spn -> decoded value dict
        self.dtc_state = {}     # source addr -> parsed DM1
        self.notices = []
        self.alerts = []        # list of dicts
        self.last_frame_ts = 0.0

    def snapshot(self):
        with self.lock:
            now = time.time()
            cards = []
            for spn, label in CRITICAL_CARDS:
                v = self.latest.get(spn)
                status = "ok"
                display = "--"
                if v is not None:
                    display = format_value(v).split(": ", 1)[-1]
                    for a in self.alerts:
                        if a["spn"] == spn and a["status"] in ("warn", "alert"):
                            if a["status"] == "alert":
                                status = "alert"
                            elif status == "ok":
                                status = "warn"
                cards.append({"spn": spn, "label": label,
                              "display": display, "status": status})
            ecus = []
            for esrc in sorted(self.dtc_state):
                st = self.dtc_state[esrc]
                if not (st.get("dtcs") or st.get("lamps") or st.get("flashing")):
                    continue
                ecus.append({
                    "src": esrc,
                    "lamps": st.get("lamps", []),
                    "flashing": st.get("flashing", []),
                    "dtcs": [{"text": format_dtc(d),
                              "guidance": fmi_guidance(d["fmi"])}
                             for d in st.get("dtcs", [])],
                })
            values = [{"spn": v["spn"], "display": format_value(v)}
                      for v in self.latest.values()]
            return {
                "ok": True,
                "ts": now,
                "stale": (now - self.last_frame_ts) > STALE_AFTER_S,
                "profile": PROFILES[self.profile]["label"],
                "cards": cards,
                "alerts": self.alerts,
                "ecus": ecus,
                "values": values,
                "notices": list(self.notices[-5:]),
            }

    def recompute_alerts(self):
        with self.lock:
            alerts = []
            for spn, v in self.latest.items():
                status, text = check_threshold(spn, v["value"], self.profile)
                if status != "ok":
                    alerts.append({"spn": spn, "status": status,
                                   "text": text, "action": action_for(spn)})
            soot = self.latest.get(3719)
            thr = self.latest.get(5466)
            if soot and thr:
                s_status, s_text = check_soot(soot["value"], thr["value"])
                if s_status != "ok":
                    alerts.append({"spn": 3719, "status": s_status,
                                   "text": s_text,
                                   "action": action_for(3719)})
            alerts.sort(key=lambda a: (0 if a["status"] == "alert" else 1,
                                       a["spn"]))
            self.alerts = alerts


def reader_thread(bus, state, stop):
    """Mirror of monitor.py's receive loop, feeding LiveState."""
    from truckdiag.j1939 import ACKM, encode_can_id
    reasm = BamReassembler()
    last_recompute = 0.0
    while not stop.is_set():
        msg = bus.recv(timeout=0.2)
        if msg is None or not msg.is_extended_id:
            continue
        if msg.arbitration_id is None:
            continue
        info = decode_can_id(msg.arbitration_id)
        src, pgn = info["source"], info["pgn"]
        with state.lock:
            state.last_frame_ts = time.time()
        if pgn == ACKM:
            ack = parse_acknowledgment(msg.data)
            if ack:
                with state.lock:
                    state.notices.append(
                        "ECU 0x%02X: %s (PGN %d)" %
                        (src, ack["control_name"], ack["pgn"]))
                    state.notices = state.notices[-5:]
            continue
        if pgn in (TP_CM, TP_DT):
            done = reasm.feed(msg.arbitration_id, msg.data)
            if done:
                rpgn, rsrc, payload = done
                if rpgn in (DM1, DM2):
                    parsed = parse_dm1(payload)
                    if parsed:
                        with state.lock:
                            state.dtc_state[rsrc] = parsed
                else:
                    dec = decode_frame(encode_can_id(6, rpgn, rsrc), payload)
                    with state.lock:
                        for v in dec["values"]:
                            state.latest[v["spn"]] = v
            continue
        if pgn in (DM1, DM2):
            parsed = parse_dm1(msg.data)
            if parsed:
                with state.lock:
                    state.dtc_state[src] = parsed
            continue
        if pgn == PGN_REQUEST:
            continue
        dec = decode_frame(msg.arbitration_id, msg.data)
        with state.lock:
            for v in dec["values"]:
                state.latest[v["spn"]] = v
        now = time.time()
        if now - last_recompute >= 0.5:
            last_recompute = now
            state.recompute_alerts()


# Filled in main() before threads start.
_live_state = [None]


PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TruckDiag live</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; margin: 0;
         padding: 12px; background: #111; color: #eee; }
  #statusbar { display: flex; justify-content: space-between; align-items: center;
               padding: 10px 12px; border-radius: 10px; margin-bottom: 12px;
               background: #1d3; color: #061; font-weight: 700; }
  #statusbar.stale { background: #a33; color: #fff; }
  #cards { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  .card { background: #222; border-radius: 10px; padding: 12px;
          border-left: 6px solid #444; }
  .card .label { font-size: 13px; color: #aaa; }
  .card .val { font-size: 30px; font-weight: 700; margin-top: 4px; }
  .card.warn { border-left-color: #da0; }
  .card.alert { border-left-color: #e33; background: #331616; }
  .card.warn .val { color: #fc3; } .card.alert .val { color: #f66; }
  h2 { font-size: 16px; margin: 18px 0 8px; color: #aaa; }
  .alertbox { border-radius: 10px; padding: 12px; margin-bottom: 8px; }
  .alertbox.alert { background: #3a1414; border: 1px solid #e33; }
  .alertbox.warn { background: #332a10; border: 1px solid #da0; }
  .alertbox .t { font-weight: 700; }
  .alertbox .a { color: #ccc; margin-top: 6px; font-size: 14px; }
  .ecu { background: #222; border-radius: 10px; padding: 12px; margin-bottom: 8px; }
  .ecu .lamps { color: #fc3; font-weight: 600; }
  .dtc { margin-top: 8px; font-size: 14px; }
  .dtc .g { color: #9c9; font-size: 13px; }
  #allvals { font-size: 13px; color: #bbb; }
  #allvals div { padding: 3px 0; border-bottom: 1px solid #222; }
  button { font-size: 16px; padding: 10px 16px; border-radius: 10px; border: 0;
           background: #2a6; color: #fff; font-weight: 700; }
  button.off { background: #555; }
  #soundrow { margin: 4px 0 0; display: flex; gap: 10px; align-items: center; }
  .none { color: #777; }
</style>
</head>
<body>
<div id="statusbar">connecting…</div>
<div id="soundrow">
  <button id="soundbtn" class="off">🔇 sound off</button>
  <span style="color:#888;font-size:13px">tap to allow alert beeps</span>
</div>

<h2>Critical readings</h2>
<div id="cards"></div>

<h2>Health alerts</h2>
<div id="alerts"><span class="none">none</span></div>

<h2>Fault codes</h2>
<div id="ecus"><span class="none">none</span></div>

<h2>All decoded values</h2>
<details><summary style="color:#888">show all</summary><div id="allvals"></div></details>

<script>
let soundOn = false, audioCtx = null, knownAlerts = new Set();
const btn = document.getElementById('soundbtn');
btn.onclick = () => {
  soundOn = !soundOn;
  btn.textContent = soundOn ? '🔔 sound on' : '🔇 sound off';
  btn.className = soundOn ? '' : 'off';
  if (soundOn && !audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
};
function beep() {
  if (!soundOn || !audioCtx) return;
  const o = audioCtx.createOscillator(), g = audioCtx.createGain();
  o.connect(g); g.connect(audioCtx.destination);
  o.frequency.value = 880; g.gain.value = 0.2;
  o.start(); o.stop(audioCtx.currentTime + 0.4);
}
function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;'); }
async function poll() {
  try {
    const r = await fetch('/api/state', {cache: 'no-store'});
    const s = await r.json();
    const bar = document.getElementById('statusbar');
    if (s.stale) { bar.className = 'stale'; bar.textContent = 'STALE — no frames for 3s+'; }
    else { bar.className = ''; bar.textContent = '● LIVE — ' + new Date(s.ts*1000).toLocaleTimeString(); }
    document.getElementById('cards').innerHTML = s.cards.map(c =>
      `<div class="card ${c.status}"><div class="label">${esc(c.label)}</div>` +
      `<div class="val">${esc(c.display)}</div></div>`).join('');
    const ab = document.getElementById('alerts');
    ab.innerHTML = s.alerts.length ? s.alerts.map(a =>
      `<div class="alertbox ${a.status}"><div class="t">[${a.status.toUpperCase()}] ${esc(a.text)}</div>` +
      (a.action ? `<div class="a">→ ${esc(a.action)}</div>` : '') + `</div>`).join('')
      : '<span class="none">none</span>';
    const fresh = s.alerts.map(a => a.text).filter(t => !knownAlerts.has(t));
    if (fresh.length && knownAlerts.size) beep();
    knownAlerts = new Set(s.alerts.map(a => a.text));
    const eb = document.getElementById('ecus');
    eb.innerHTML = s.ecus.length ? s.ecus.map(e =>
      `<div class="ecu"><div>ECU 0x${e.src.toString(16).toUpperCase().padStart(2,'0')}</div>` +
      `<div class="lamps">Lamps: ${esc(e.lamps.join(', ') || 'none')}</div>` +
      e.dtcs.map(d => `<div class="dtc">${esc(d.text)}` +
        (d.guidance ? `<div class="g">typically: ${esc(d.guidance)}</div>` : '') + `</div>`).join('') +
      `</div>`).join('') : '<span class="none">none</span>';
    document.getElementById('allvals').innerHTML =
      s.values.map(v => `<div>${esc(v.display)}</div>`).join('');
  } catch (e) {
    const bar = document.getElementById('statusbar');
    bar.className = 'stale'; bar.textContent = 'DISCONNECTED — retrying…';
  }
  setTimeout(poll, 1000);
}
poll();
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/":
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/state":
            body = json.dumps(_live_state[0].snapshot()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


def main():
    ap = argparse.ArgumentParser(description="TruckDiag web dashboard")
    ap.add_argument("--socketcan", metavar="IFACE",
                    help="real hardware on Linux, e.g. can0")
    ap.add_argument("--slcan", metavar="PORT",
                    help="real hardware over serial, e.g. COM3")
    ap.add_argument("--bitrate", type=int, default=250000)
    ap.add_argument("--demo", action="store_true",
                    help="run the simulated ECU in-process (no truck needed)")
    ap.add_argument("--profile", default=DEFAULT_PROFILE,
                    choices=sorted(PROFILES),
                    help="engine profile for health thresholds")
    ap.add_argument("--port", type=int, default=8080,
                    help="HTTP port (default 8080)")
    args = ap.parse_args()

    if args.socketcan:
        bus = open_bus("socketcan", channel=args.socketcan,
                       bitrate=args.bitrate)
    elif args.slcan:
        bus = open_bus("slcan", channel=args.slcan, bitrate=args.bitrate)
    else:
        bus = open_bus("virtual")

    state = LiveState(args.profile)
    _live_state[0] = state
    stop = threading.Event()

    if args.demo:
        import sim_ecu

        def run_sim():
            t = 0.0
            while not stop.is_set():
                for can_id, data in sim_ecu.build_frames(t):
                    import can
                    bus.send(can.Message(arbitration_id=can_id, data=data,
                                         is_extended_id=True))
                time.sleep(0.1)
                t += 0.1

        threading.Thread(target=run_sim, daemon=True).start()

    threading.Thread(target=reader_thread, args=(bus, state, stop),
                     daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    print("webdash on http://0.0.0.0:%d/  (profile %s, listen-only)" %
          (args.port, args.profile))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        bus.shutdown()


if __name__ == "__main__":
    main()
