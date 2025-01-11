#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import pickle
import re
import threading
import queue
import numpy as np
from collections import defaultdict
from scapy.all import PacketList, rdpcap, TCP, IP, UDP
import tkinter as tk
from tkinter import ttk, messagebox

###############################################################################
# Load Classifier (Random Forest)
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

def run_tcpdump(duration=10, interface="any", output_file="tcpdump_capture.pcap"):
    try:
        process = subprocess.Popen(
            ["tcpdump", "-i", interface, "-w", output_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        time.sleep(duration)
        process.terminate()
        return output_file

    except Exception as e:
        print(f"An error occurred: {e}")
        return None

###############################################################################
# Parse tcpdump into flows
###############################################################################

def parse_tcpdump_to_flows(directory):
    packets = rdpcap(directory)
    flows = defaultdict(list)

    for pkt in packets:
        if IP in pkt and (TCP in pkt or UDP in pkt):
            flow_key = (
                pkt[IP].src,
                pkt[IP].dst,
                pkt.sport,
                pkt.dport,
                pkt[IP].proto
            )
            flows[flow_key].append(pkt)
    return flows

###############################################################################
# Classification
###############################################################################

def classify_flows(flows, classifier):
    input = np.zeros((1, 5))
    for flow, pkts in flows.items():
        input = np.vstack([input, (flow[2], flow[3], flow[4], len(pkts), sum([pkt.len for pkt in pkts]))])

    input = np.delete(input, 0, axis=0)
    probabilities = classifier.predict_proba(input)
    threshold = 0.5
    max_probs = np.max(probabilities, axis=1)
    predictions = classifier.predict(input)

    for i, prob in enumerate(max_probs):
        if prob < threshold:
            predictions[i] = 'other'

    return list(zip(flows, predictions))

###############################################################################
# IPTABLES Blocking
###############################################################################

def block_flows_for_device(labeled_flows, selected_device_type):
    matching = [(f, dev) for (f, dev) in labeled_flows
                if dev.lower() == selected_device_type.lower()]
    if not matching:
        print(f"[DEBUG] No flows matched device = {selected_device_type}")
        return
    else: 
        print(f"[DEBUG] Blocking flows for device = {selected_device_type}")

    for flow, dev_type in matching:
        dst_ip = flow[1]
        dst_port = flow[3]

        cmd = [
            "iptables",
            "-A", "INPUT",
            "-p", "tcp",
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
        self.rules_window = None
        self.tcpdump_thread = None
        self.tcpdump_process = None
        self.device_block_list = set()
        self.capture_queue = queue.Queue()
        self.process_traffic_thread = None
        self.running = False

        self.title("IoT Firewall")
        self.geometry("600x280")

        lbl = tk.Label(self, text="Select IoT device type to block, then capture traffic.")
        lbl.pack(pady=5)

        self.device_types = ["IP Camera", "Smart Speaker", "Smart TV", "alarm", "Unknown"]
        self.selected_device_var = tk.StringVar(value=self.device_types[0])

        self.combo = ttk.Combobox(
            self,
            textvariable=self.selected_device_var,
            values=self.device_types,
            state="readonly",
            width=30
        )
        self.combo.pack(pady=5)

        frame1 = tk.Frame(self)
        frame1.pack(anchor='center')

        dur_label = tk.Label(frame1, text="Capture Duration (seconds):")
        dur_label.pack(side=tk.LEFT)

        self.duration_var = tk.StringVar(value="10")
        self.duration_entry = tk.Entry(frame1, textvariable=self.duration_var, width=5)
        self.duration_entry.pack(pady=2, side=tk.RIGHT)

        self.start_btn = tk.Button(self, text="Start Capture & Block",
                                   command=self.add_device_to_block)
        self.start_btn.pack(pady=5)

        frame2 = tk.Frame(self)
        frame2.pack(anchor='center')
        self.show_rules_btn = tk.Button(frame2, text="Show rules", command=self.show_rules, width=6)
        self.show_rules_btn.pack(pady=5, side=tk.LEFT, padx=5)

        self.exit_btn = tk.Button(frame2, text="Exit", command=self.exit_app, width=6)
        self.exit_btn.pack(pady=5, side=tk.RIGHT, padx=5)

        self.classifier = load_classifier("rf_classifier.pkl")
        self.start_tcpdump()

    def start_tcpdump(self):
        if os.geteuid() != 0:
            messagebox.showerror("Error", "Please run as root/sudo for tcpdump & iptables.")
            return

        def tcpdump_capture():
            try:
                self.tcpdump_process = subprocess.Popen(
                    ["tcpdump", "-i", "any", "-w", "tcpdump_capture.pcap"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                self.tcpdump_process.wait()
            except Exception as e:
                print(f"Error starting tcpdump: {e}")

        self.tcpdump_thread = threading.Thread(target=tcpdump_capture, daemon=True)
        self.tcpdump_thread.start()

    def add_device_to_block(self):
        dev_type = self.selected_device_var.get()
        if dev_type in self.device_block_list:
            messagebox.showinfo("Info", f"{dev_type} is already being blocked.")
            return

        self.device_block_list.add(dev_type)
        messagebox.showinfo("Info", f"Added {dev_type} to block list.")

        if not self.running:
            self.running = True
            self.process_traffic_thread = threading.Thread(target=self.process_captured_traffic_loop, daemon=True)
            self.process_traffic_thread.start()

    def process_captured_traffic_loop(self):
        while self.running:
            self.process_captured_traffic()
            time.sleep(1)

    def process_captured_traffic(self):
        try:
            flows = parse_tcpdump_to_flows("tcpdump_capture.pcap")
            labeled = classify_flows(flows, self.classifier)

            for dev_type in self.device_block_list:
                block_flows_for_device(labeled, dev_type)

        except Exception as e:
            print(f"Error processing captured traffic: {e}")

    def exit_app(self):
        if self.tcpdump_process:
            self.tcpdump_process.terminate()
        self.running = False
        if self.process_traffic_thread:
            self.process_traffic_thread.join()
        self.destroy()

    def show_rules(self):
        if self.rules_window and tk.Toplevel.winfo_exists(self.rules_window):
            self.rules_window.lift()
            self.rules_window.focus_force()
            return

        self.rules_window = tk.Toplevel(self)
        self.rules_window.title("Iptables Rules")

        listbox = tk.Listbox(self.rules_window, selectmode=tk.SINGLE, width=100, height=20, font=("Courier", 10))
        listbox.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        try:
            result = subprocess.run(["iptables", "-L", "-n", "--line-numbers", "-v"], capture_output=True, text=True, check=True)
            rules = result.stdout.splitlines()

            for rule in rules:
                listbox.insert(tk.END, rule)
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Error fetching iptables rules: {e}")

        def delete_rule():
            selected_index = listbox.curselection()
            if not selected_index:
                messagebox.showwarning("Warning", "Please select a rule to delete.")
                return

            selected_rule = listbox.get(selected_index)
            parts = selected_rule.split()

            if len(parts) < 2 or not parts[0].isdigit():
                messagebox.showwarning("Warning", "Invalid rule selected.")
                return

            rule_number = parts[0]
            chain = "INPUT"

            try:
                subprocess.run(["iptables", "-D", chain, rule_number], check=True)
                listbox.delete(selected_index)
                messagebox.showinfo("Success", f"Rule {rule_number} deleted successfully.")
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Error", f"Error deleting rule {rule_number}: {e}")

        frame3 = tk.Frame(self.rules_window)
        frame3.pack(anchor='center')

        delete_button = tk.Button(frame3, text="Delete Rule", command=delete_rule)
        delete_button.pack(pady=5, side=tk.LEFT, padx=5)

        def close_rules_window():
            self.rules_window.destroy()
            self.rules_window = None

        close_button = tk.Button(frame3, text="Close Rules", command=close_rules_window)
        close_button.pack(pady=5, side=tk.RIGHT, padx=5)

def main():
    if os.geteuid() != 0:
        print("[WARNING] Not running as root. iptables/tcpdump may fail.")
    app = FirewallApp()
    app.mainloop()

if __name__ == "__main__":
    main()
