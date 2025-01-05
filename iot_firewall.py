#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import pickle
import re
from collections import defaultdict

import tkinter as tk
from tkinter import ttk, messagebox

###############################################################################
# Load Classifier (Random Forest) - optional if you want real classification
###############################################################################

def load_classifier(model_path="rf_classifier.pkl"):
    try:
        with open(model_path, "rb") as f:
            classifier = pickle.load(f)
        print(f"[INFO] Loaded classifier from", model_path)
        return classifier
    except Exception as e:
        print(f"[WARN] Could not load classifier from {model_path}: {e}")
        return None

###############################################################################
# Run tcpdump & Save Output
###############################################################################

def run_tcpdump(duration=10, interface="any", output_file="tcpdump_capture.log"):
    """
    Runs tcpdump for 'duration' seconds on the given interface (default 'any').
    Writes lines to output_file. If no lines, writes 'No packets collected'.
    Returns a list of the captured lines.
    """
    # Removed '-v' to try to get single-line output
    cmd = ["tcpdump", "-i", interface, "-n", "-l", "-q", "-t"]
    print(f"[DEBUG] Running: {' '.join(cmd)} for {duration} seconds")
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    start_time = time.time()
    captured_lines = []

    while True:
        if (time.time() - start_time) > duration:
            process.terminate()
            break
        line = process.stdout.readline()
        if line:
            captured_lines.append(line.strip())
        else:
            time.sleep(0.01)

    # Wait for process to exit (up to 5 seconds)
    process.wait(timeout=5)

    # Read leftover lines (if any)
    while True:
        leftover = process.stdout.readline()
        if not leftover:
            break
        captured_lines.append(leftover.strip())

    # Write to file
    if not captured_lines:
        with open(output_file, "w") as f:
            f.write("No packets collected\n")
    else:
        with open(output_file, "w") as f:
            for cl in captured_lines:
                f.write(cl + "\n")

    return captured_lines

###############################################################################
# Parse tcpdump lines into flows
###############################################################################

def parse_tcpdump_to_flows(tcpdump_lines):
    """
    Uses a broader regex that accounts for possible timestamps, interface info, etc.
    We capture:
      src_ip, src_port, dst_ip, dst_port, proto
    Then aggregate packets by (src_ip, dst_ip, src_port, dst_port, proto).
    We'll store 'packets' count, but skip or ignore 'bytes'.
    """

    # This regex tries to match lines like:
    # IP 192.168.1.42.35572 > 192.168.1.42.554: tcp ...
    # Possibly with timestamps, interface, etc. up front.
    line_regex = re.compile(
        r".*\bIP\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+)\.(\d+)\s*:\s*(tcp|udp)",
        re.IGNORECASE
    )

    flow_dict = defaultdict(lambda: {"packets": 0, "bytes": 0})

    for line in tcpdump_lines:
        match = line_regex.search(line)
        if match:
            src_ip, src_port, dst_ip, dst_port, proto = match.groups()
            proto = proto.upper()  # "TCP" or "UDP"

            key = (src_ip, dst_ip, int(src_port), int(dst_port), proto)
            flow_dict[key]["packets"] += 1
            # We won't parse packet length, so let's keep it at 0
            flow_dict[key]["bytes"] += 0

    flows = []
    for (sip, dip, sport, dport, proto), stats in flow_dict.items():
        flows.append({
            "src_ip": sip,
            "dst_ip": dip,
            "src_port": sport,
            "dst_port": dport,
            "proto": proto,
            "packets": stats["packets"],
            "bytes": stats["bytes"]
        })
    print(f"[DEBUG] Parsed {len(flows)} flow(s)")
    return flows

###############################################################################
# Classification (with forced label for port 554, minus 'bytes' in the vector)
###############################################################################

def classify_flows(flows, classifier):
    """
    If classifier is loaded, predict device types using a 5-feature vector:
      [packets, src_port, dst_port, proto_tcp, proto_udp]

    We skip f["bytes"] because the old model expects only 5 features.
    We still do forced-labelling if dst_port=554 => "IP Camera".
    """
    labeled_flows = []

    for f in flows:
        # Force label if dst_port=554
        if f["dst_port"] == 554:
            forced_label = "IP Camera"
            labeled_flows.append((f, forced_label))
            continue

        # If we have a loaded classifier, use it
        if classifier:
            proto_tcp = 1 if f["proto"] == "TCP" else 0
            proto_udp = 1 if f["proto"] == "UDP" else 0
            feature_vector = [
                f["packets"],   # 1
                f["src_port"],  # 2
                f["dst_port"],  # 3
                proto_tcp,      # 4
                proto_udp       # 5
            ]
            predicted = classifier.predict([feature_vector])[0]
            labeled_flows.append((f, predicted))
        else:
            labeled_flows.append((f, "Unknown"))

    # Print debug info
    for flow, label in labeled_flows:
        print("[DEBUG] Flow:", flow, "=> Label:", label)

    return labeled_flows

###############################################################################
# IPTABLES Blocking
###############################################################################

def block_flows_for_device(labeled_flows, selected_device_type):
    """
    If (flow, dev_label) matches 'selected_device_type', we block inbound
    traffic to that device's IP:port using iptables:
      iptables -A INPUT -p <proto> -d <dst_ip> --dport <dst_port> -j DROP
    """
    matching = [(f, dev) for (f, dev) in labeled_flows
                if dev.lower() == selected_device_type.lower()]
    if not matching:
        print(f"[DEBUG] No flows matched device = {selected_device_type}")
        return

    for flow, dev_type in matching:
        proto = flow["proto"].lower()  # "tcp" or "udp"
        dst_ip = flow["dst_ip"]
        dst_port = flow["dst_port"]

        cmd = [
            "iptables",
            "-A", "INPUT",
            "-p", proto,
            "-d", dst_ip,
            "--dport", str(dst_port),
            "-j", "DROP"
        ]
        print("[DEBUG] IPTABLES CMD:", cmd)
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] iptables failed: {cmd}\n{e}")

###############################################################################
# Tkinter UI
###############################################################################

class FirewallApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IoT Firewall v6 (5-feature fix)")
        self.geometry("600x280")

        lbl = tk.Label(self, text="Select IoT device type to block, then capture traffic.")
        lbl.pack(pady=5)

        self.device_types = ["IP Camera", "Smart Speaker", "Smart TV", "Unknown"]
        self.selected_device_var = tk.StringVar(value=self.device_types[0])

        self.combo = ttk.Combobox(
            self,
            textvariable=self.selected_device_var,
            values=self.device_types,
            state="readonly",
            width=30
        )
        self.combo.pack(pady=5)

        dur_label = tk.Label(self, text="Capture Duration (seconds):")
        dur_label.pack()

        self.duration_var = tk.StringVar(value="10")
        self.duration_entry = tk.Entry(self, textvariable=self.duration_var, width=5)
        self.duration_entry.pack(pady=2)

        self.start_btn = tk.Button(self, text="Start Capture & Block",
                                   command=self.start_capture_and_block)
        self.start_btn.pack(pady=5)

        self.exit_btn = tk.Button(self, text="Exit", command=self.exit_app)
        self.exit_btn.pack(pady=5)

        # Attempt to load a real classifier
        self.classifier = load_classifier("rf_classifier.pkl")

    def start_capture_and_block(self):
        if os.geteuid() != 0:
            messagebox.showerror("Error", "Please run as root/sudo for tcpdump & iptables.")
            return

        try:
            duration = int(self.duration_var.get())
        except ValueError:
            messagebox.showerror("Invalid Input", "Capture duration must be an integer.")
            return

        messagebox.showinfo(
            "Info",
            f"Capturing {duration} seconds. Output in tcpdump_capture.log"
        )

        lines = run_tcpdump(
            duration=duration,
            interface="any",
            output_file="tcpdump_capture.log"
        )

        flows = parse_tcpdump_to_flows(lines)
        labeled = classify_flows(flows, self.classifier)
        dev_type = self.selected_device_var.get()
        block_flows_for_device(labeled, dev_type)

        messagebox.showinfo(
            "Done",
            f"Capture finished. Attempted to block flows for {dev_type}.\nCheck iptables -L -n and tcpdump_capture.log."
        )

    def exit_app(self):
        self.destroy()

def main():
    if os.geteuid() != 0:
        print("[WARNING] Not running as root. iptables/tcpdump may fail.")
    app = FirewallApp()
    app.mainloop()

if __name__ == "__main__":
    main()

