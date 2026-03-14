# gui.py
import sys
import ctypes
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import tkinter.font as tk_font
import threading
import os

from event_extraction import find_flash_window, uds_timing
from config import CORE_METRICS, BUILTIN_PROFILES
from health_check import health_check
from event_extraction import get_uds_streams, extract_events, calculate_timing_simple
from component_analysis import (segment_components, analyze_components,
                                analyze_non_flash_stream, group_components_by_stream)
from tshark_utils import _fmt_seconds

# ── DPI awareness ────────────────────────────────────────────────────────────
# Tell Windows NOT to bitmap-upscale this process.  Must happen before the Tk
# window is created so the OS hands us true physical pixel dimensions and Tk's
# own scaling factor is correct.  Eliminates blurriness on 4K / high-DPI
# displays and also means we no longer need the manual "scaling * 1.5" hack
# that was causing column-width measurement errors.
if sys.platform == "win32":
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)   # PROCESS_PER_MONITOR_DPI_AWARE
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()    # fallback for older Windows
        except Exception:
            pass


class DoIPAnalysisTool(tk.Tk):
    def __init__(self):
        super().__init__()

        # ── Single unified style block ────────────────────────────────────────
        # All font sizes in one place — change F_BODY to rescale everything.
        F_BODY  = 13   # cell text, labels, buttons, tabs
        F_HEAD  = 13   # column headings (bold)
        F_KPI   = 14   # KPI value numbers (slightly larger for emphasis)
        F_TITLE = 15   # stream section titles on Dashboard
        F_MONO  = 13   # Health Check / Profile plain-text tabs
        ROW_H   = 38   # Treeview row height — keep ~2.9× F_BODY

        self._style = ttk.Style(self)
        self._style.configure("Treeview",          rowheight=ROW_H, font=("Helvetica", F_BODY))
        self._style.configure("Treeview.Heading",  font=("Helvetica", F_HEAD, "bold"))
        self._style.configure("TNotebook.Tab",     font=("Helvetica", F_BODY))
        self._style.configure("TLabel",            font=("Helvetica", F_BODY))
        self._style.configure("TButton",           font=("Helvetica", F_BODY))
        self._style.configure("TLabelframe.Label", font=("Helvetica", F_BODY, "bold"))
        self._style.configure("TCombobox",         font=("Helvetica", F_BODY))

        # Store for use in _build_timing_tab and _render_dashboard
        self._F_KPI   = F_KPI
        self._F_TITLE = F_TITLE
        self._F_MONO  = F_MONO

        self.title("DoIP FlashView")
        self.geometry("2050x1400")

        self.pcap_path = None
        self.profile = BUILTIN_PROFILES[0]
        self.all_results = {}
        self.all_timing = {}
        self.all_events = {}
        self.uds_streams = []
        self.health_data = None
        self.flash_windows = None

        self._build_ui()

    # ── helpers ──────────────────────────────────────────────────────────────

    def _treeview_font(self):
        """Return the actual Font object used by the Treeview style.
        Measuring with this gives accurate pixel widths at any DPI."""
        try:
            return tk_font.Font(font=self._style.lookup("Treeview", "font"))
        except Exception:
            return tk_font.nametofont("TkDefaultFont")

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        top = ttk.Frame(self)
        top.pack(fill="x", padx=12, pady=10)

        ttk.Button(top, text="Open PCAP", command=self.open_pcap).pack(side="left")
        self.file_lbl = ttk.Label(top, text="No file selected", width=50, anchor="w")
        self.file_lbl.pack(side="left", padx=10)

        ttk.Label(top, text="Profile:").pack(side="left", padx=(20, 4))
        self.profile_var = tk.StringVar(value=self.profile["id"])
        cb = ttk.Combobox(top, textvariable=self.profile_var, state="readonly", width=30)
        cb["values"] = [p["id"] for p in BUILTIN_PROFILES]
        cb.pack(side="left")
        cb.bind("<<ComboboxSelected>>", lambda e: self.on_profile_change())

        ttk.Button(top, text="Analyze", command=self.run_analysis).pack(side="left", padx=10)

        self.status = ttk.Label(self, text="Ready.", anchor="w")
        self.status.pack(fill="x", padx=12)

        self.pb = ttk.Progressbar(self, mode="indeterminate")
        self.pb.pack(fill="x", padx=12, pady=(0, 6))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)

        self.tab_dashboard = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_dashboard, text="Dashboard")

        self.tab_timing = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_timing, text="UDS Timing")
        self._build_timing_tab()

        self.tab_health = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_health, text="Health Check")
        self.health_text = tk.Text(self.tab_health, wrap="word",
                                   font=("Courier", self._F_MONO))
        self.health_text.pack(fill="both", expand=True)

        self.tab_profile = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_profile, text="Profile")
        self.profile_text = tk.Text(self.tab_profile, wrap="word",
                                    font=("Courier", self._F_MONO))
        self.profile_text.pack(fill="both", expand=True)
        self._render_profile()

    def _build_timing_tab(self):
        frame = ttk.Frame(self.tab_timing)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Overall Totals
        overall_kpi_frame = ttk.LabelFrame(
            frame, text="Overall Totals (All UDS in Capture)", padding=10)
        overall_kpi_frame.pack(fill="x", pady=(0, 10))

        self.overall_kpi = {}
        for label, default in [("ECU Total Time", "0.000000 s"),
                                ("Client Total Gap Time", "0.000000 s"),
                                ("Transactions", "ECU: 0 | Gaps: 0")]:
            subf = ttk.Frame(overall_kpi_frame)
            subf.pack(side="left", padx=25)
            ttk.Label(subf, text=label + ":",
                      font=("Helvetica", self._F_KPI, "bold")).pack(anchor="w")
            lbl = ttk.Label(subf, text=default,
                            font=("Helvetica", self._F_KPI))
            lbl.pack(anchor="w")
            self.overall_kpi[label] = lbl

        # Transfer Phase Totals
        transfer_kpi_frame = ttk.LabelFrame(
            frame, text="Transfer Phase Only (0x34/0x36/0x37 during flash)", padding=10)
        transfer_kpi_frame.pack(fill="x", pady=(0, 15))

        self.transfer_kpi = {}
        for label, default in [("ECU Transfer Time", "0.000000 s"),
                                ("Client Transfer Gap", "0.000000 s"),
                                ("Transfer Transactions", "ECU: 0 | Gaps: 0")]:
            subf = ttk.Frame(transfer_kpi_frame)
            subf.pack(side="left", padx=25)
            ttk.Label(subf, text=label + ":",
                      font=("Helvetica", self._F_KPI, "bold")).pack(anchor="w")
            lbl = ttk.Label(subf, text=default,
                            font=("Helvetica", self._F_KPI))
            lbl.pack(anchor="w")
            self.transfer_kpi[label] = lbl

        topf = ttk.Frame(frame)
        topf.pack(fill="x", pady=(0, 10))

        ttk.Label(topf, text="Top 10 longest:").pack(side="left", padx=(0, 8))
        self.timing_var = tk.StringVar(value="ECU Response Time")
        opts = ["ECU Response Time (req → pos resp)", "Client Gap Time (pos resp → next req)"]
        ttk.Combobox(topf, textvariable=self.timing_var, values=opts,
                     state="readonly", width=40).pack(side="left")
        self.timing_var.trace("w", lambda *args: self._render_timing())

        self.timing_tree = ttk.Treeview(frame, show="headings")
        self.timing_tree.pack(fill="both", expand=True)

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.timing_tree.yview)
        vsb.pack(side="right", fill="y")
        self.timing_tree.configure(yscrollcommand=vsb.set)

        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self.timing_tree.xview)
        hsb.pack(side="bottom", fill="x")
        self.timing_tree.configure(xscrollcommand=hsb.set)

    # ── file / profile ────────────────────────────────────────────────────────

    def open_pcap(self):
        path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap *.pcapng")])
        if path:
            self.pcap_path = path
            self.file_lbl.config(text=os.path.basename(path))
            self.status.config(text="File loaded. Ready to analyze.")

    def on_profile_change(self):
        pid = self.profile_var.get()
        for p in BUILTIN_PROFILES:
            if p["id"] == pid:
                self.profile = p
                break
        self._render_profile()
        self.status.config(text=f"Profile changed to {self.profile['name']}")
        if self.all_results:
            self._render_dashboard()

    # ── analysis ──────────────────────────────────────────────────────────────

    def run_analysis(self):
        if not self.pcap_path:
            messagebox.showwarning("No file", "Open a PCAP file first.")
            return

        def worker():
            try:
                self.pb.start(10)
                self.status.config(text="Health check...")
                self.health_data = health_check(self.pcap_path)
                self._render_health()

                if self.health_data["status"] == "ERROR":
                    self.pb.stop()
                    messagebox.showerror("Health Failed", "\n".join(self.health_data["errors"]))
                    return

                self.status.config(text="Finding streams...")
                self.uds_streams = get_uds_streams(self.pcap_path)

                self.flash_windows = find_flash_window(self.pcap_path)

                self.all_results.clear()
                self.all_events.clear()
                self.all_timing.clear()

                for stream, count in self.uds_streams:
                    if count < 5:
                        continue

                    self.status.config(text=f"Stream {stream} ({count} pkts)...")
                    events = extract_events(self.pcap_path, stream)
                    self.all_events[stream] = events

                    comps = segment_components(events)

                    if comps:
                        rows, details = analyze_components(events, comps, self.profile)
                        is_flash = True
                    else:
                        rows, details = analyze_non_flash_stream(events, stream)
                        is_flash = False

                    self.all_results[stream] = (rows, details, comps, is_flash)

                self.status.config(text="Calculating overall timing...")
                self._calculate_overall_timing()

                self.status.config(text="Calculating transfer timing...")
                self._calculate_transfer_timing()

                self.status.config(text=f"Done - {len(self.uds_streams)} streams analyzed")
                self.pb.stop()
                self._render_dashboard()
                self._render_timing()

            except Exception as e:
                self.pb.stop()
                messagebox.showerror("Error", str(e))
                import traceback
                traceback.print_exc()

        threading.Thread(target=worker, daemon=True).start()

    def _calculate_overall_timing(self):
        overall_ecu, overall_client = calculate_timing_simple(self.pcap_path, "uds")
        self.overall_timing = {
            "ecu_total":    overall_ecu,
            "client_total": overall_client,
        }

    def _calculate_transfer_timing(self):
        if not self.flash_windows or not self.flash_windows.get("per_stream"):
            self.transfer_timing = {
                "ecu_total": 0.0, "client_total": 0.0,
                "top_ecu": [],    "top_client": []
            }
            return

        total_ecu       = 0.0
        total_client    = 0.0
        all_ecu_gaps    = []
        all_client_gaps = []

        for stream_id, window in self.flash_windows["per_stream"].items():
            first_frame = window.get("first_download")
            last_frame  = window.get("last_exit")
            if first_frame is None or last_frame is None:
                continue

            ecu_time, client_time, ecu_gaps, client_gaps = uds_timing(
                self.pcap_path, first_frame, last_frame)

            total_ecu    += ecu_time
            total_client += client_time
            all_ecu_gaps.extend(ecu_gaps)
            all_client_gaps.extend(client_gaps)

        self.transfer_timing = {
            "ecu_total":    total_ecu,
            "client_total": total_client,
            "top_ecu":    sorted(all_ecu_gaps,    reverse=True)[:10],
            "top_client": sorted(all_client_gaps, reverse=True)[:10],
        }

    # ── rendering ─────────────────────────────────────────────────────────────

    def _render_health(self):
        self.health_text.delete("1.0", "end")
        hd = self.health_data
        if not hd:
            return

        lines = [
            "=" * 60,
            "HEALTH CHECK RESULTS",
            "=" * 60,
            f"Status: {hd['status']}",
            ""
        ]

        lines.append("TCP STREAMS:")
        if hd["tcp_streams"]:
            for stream, count in sorted(hd["tcp_streams"].items()):
                detail = hd["stream_details"].get(stream, {})
                stream_type = "Flash" if detail.get("has_flash") else "Non-flash UDS"
                lines.append(f"  Stream {stream}: {count} packets ({stream_type})")
                if detail.get("services"):
                    svc_list = ", ".join([f"0x{s:02x}" for s in sorted(detail["services"])])
                    lines.append(f"    Services: {svc_list}")
        else:
            lines.append("  None found")
        lines.append("")

        lines.append("UDS FLASH SERVICES (GLOBAL):")
        for sid in [0x34, 0x36, 0x37]:
            stats = hd["uds_services"][sid]
            name  = {0x34: "RequestDownload", 0x36: "TransferData", 0x37: "TransferExit"}[sid]
            lines.append(f"{name} (0x{sid:02x}):")
            lines.append(f"  Requests: {stats['req']}")
            lines.append(f"  Success:  {stats['succ']}")
            lines.append(f"  Pending:  {stats['pend']}")
            lines.append(f"  Failed:   {stats['fail']}")
            if stats['req'] > 0:
                rate = (stats['succ'] / stats['req']) * 100
                lines.append(f"  Success Rate: {rate:.1f}%")
            lines.append("")

        if hd["errors"]:
            lines.append("ERRORS:")
            for err in hd["errors"]:
                lines.append(f"  ✗ {err}")
            lines.append("")

        if hd["warnings"]:
            lines.append("WARNINGS:")
            for warn in hd["warnings"]:
                lines.append(f"  ⚠ {warn}")
            lines.append("")

        if not hd["errors"] and not hd["warnings"]:
            lines.append("✓ All checks passed")

        self.health_text.insert("1.0", "\n".join(lines))

    def _render_dashboard(self):
        for w in self.tab_dashboard.winfo_children():
            w.destroy()

        container = ttk.Frame(self.tab_dashboard)
        container.pack(fill="both", expand=True)

        canvas = tk.Canvas(container, highlightthickness=0)
        vsb = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        scroll_frame = ttk.Frame(canvas)

        scroll_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        win_id = canvas.create_window((0, 0), window=scroll_frame, anchor="nw")

        # Keep scroll_frame width locked to canvas viewport so fill="x" works
        def _on_canvas_resize(event, cid=win_id):
            canvas.itemconfig(cid, width=event.width)

        canvas.bind("<Configure>", _on_canvas_resize)

        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        for stream, (rows, td_details, comps, is_flash) in sorted(self.all_results.items()):
            lbl = f"TCP Stream {stream} - {'Flash' if is_flash else 'Non-flash UDS'} ({len(rows)} entries)"
            ttk.Label(scroll_frame, text=lbl,
                      font=("Helvetica", self._F_TITLE, "bold")).pack(
                          anchor="w", pady=(20, 5), padx=10)

            tree = ttk.Treeview(scroll_frame, show="headings")
            tree.pack(fill="x", padx=10, pady=5)

            cols = [m["name"] for m in CORE_METRICS]
            tree["columns"] = cols
            for m in CORE_METRICS:
                tree.heading(m["name"], text=m["name"], anchor="center")
                tree.column(m["name"], width=m["width"], minwidth=60,
                            anchor="center", stretch=True)

            hsb = ttk.Scrollbar(scroll_frame, orient="horizontal", command=tree.xview)
            hsb.pack(fill="x", padx=10, pady=(0, 5))
            tree.configure(xscrollcommand=hsb.set)

            for r in rows:
                values = []
                for m in CORE_METRICS:
                    cid = m["id"]
                    val = r.get(cid)
                    if cid in ["component", "start_frame", "end_frame"]:
                        values.append(str(val) if val is not None else "")
                    else:
                        values.append(_fmt_seconds(val))
                tree.insert("", "end", values=values)

            # Autofit: fires once when widget is first drawn, using the live
            # Treeview font so measurements are correct at any DPI.
            def _autofit(event, t=tree, c=cols):
                t.unbind("<Map>")
                fnt = self._treeview_font()
                for col in c:
                    max_w = fnt.measure(col) + 30
                    for iid in t.get_children():
                        cell_w = fnt.measure(str(t.set(iid, col))) + 30
                        if cell_w > max_w:
                            max_w = cell_w
                    t.column(col, width=max_w)

            tree.bind("<Map>", _autofit)

    def _render_timing(self):
        self.timing_tree.delete(*self.timing_tree.get_children())

        if hasattr(self, 'overall_timing'):
            ot = self.overall_timing
            self.overall_kpi["ECU Total Time"].config(
                text=f"{_fmt_seconds(ot['ecu_total'])} s")
            self.overall_kpi["Client Total Gap Time"].config(
                text=f"{_fmt_seconds(ot['client_total'])} s")
            if hasattr(self, 'transfer_timing'):
                tt = self.transfer_timing
                self.overall_kpi["Transactions"].config(
                    text=f"ECU: {len(tt['top_ecu'])}+ | Gaps: {len(tt['top_client'])}+")

        if hasattr(self, 'transfer_timing'):
            tt = self.transfer_timing
            self.transfer_kpi["ECU Transfer Time"].config(
                text=f"{_fmt_seconds(tt['ecu_total'])} s")
            self.transfer_kpi["Client Transfer Gap"].config(
                text=f"{_fmt_seconds(tt['client_total'])} s")
            self.transfer_kpi["Transfer Transactions"].config(
                text=f"ECU: {len(tt['top_ecu'])} | Gaps: {len(tt['top_client'])}")

            metric = self.timing_var.get()
            is_ecu = "ECU" in metric

            if is_ecu:
                cols = ["Rank", "Stream", "SID", "Req Frame", "Resp Frame", "Duration (s)"]
                data = tt['top_ecu']
            else:
                cols = ["Rank", "Stream", "From Frame", "To Frame", "Gap (s)"]
                data = tt['top_client']

            self.timing_tree["columns"] = cols
            for col in cols:
                self.timing_tree.heading(col, text=col)
                self.timing_tree.column(col, width=120, anchor="center")

            rank = 1
            for item in data:
                if is_ecu:
                    gap, stream_id, req_frame, resp_frame, sid = item
                    vals = [rank, stream_id, f"0x{sid:02x}", req_frame, resp_frame,
                            _fmt_seconds(gap)]
                else:
                    gap, stream_id, from_frame, to_frame = item
                    vals = [rank, stream_id, from_frame, to_frame, _fmt_seconds(gap)]

                self.timing_tree.insert("", "end", values=vals)
                rank += 1

    def _render_profile(self):
        self.profile_text.delete("1.0", "end")
        p = self.profile
        lines = [
            f"Profile ID: {p['id']}",
            f"Name: {p['name']}",
            "",
            "Component segmentation:",
            "  Start: uds.sid==0x34 AND uds.reply==0x00",
            "  End: next start or end of capture",
            "",
            "Core metrics:",
            "  - Component #, Start/End Frame, Total Time",
            "  - ReqDL Time & Pending",
            "  - Transfer Time & TD Pending",
            "  - Exit Time",
            "  - Other UDS Services Post Exit",
            "",
            "Extended metrics:"
        ]
        if not p.get("extended_metrics"):
            lines.append("  None")
        else:
            for m in p["extended_metrics"]:
                lines.append(f"  - {m['name']}")

        lines.append("")
        lines.append("Multi-stream handling:")
        lines.append("  - Each TCP stream analyzed independently")
        lines.append("  - Timing calculations treat streams separately")
        lines.append("  - No cross-stream request/response pairing")
        lines.append("  - Components can span different streams")

        self.profile_text.insert("1.0", "\n".join(lines))


if __name__ == "__main__":
    app = DoIPAnalysisTool()
    app.mainloop()
