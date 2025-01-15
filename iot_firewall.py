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
def run_tcpdump(duration=10, interface="any", output_file="tcpdump_capture.pcap"):
    try:
        cmd = [
            "tcpdump",
            "-i", interface,
            "-y", "EN10MB",  # Force Ethernet link-layer
            "-w", output_file
        ]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(duration)
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()

        with open(output_file, "rb") as file:
            file_contents = file.read()
        return file_contents
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

###############################################################################
# Parse .pcap into flows
###############################################################################
def parse_tcpdump_to_flows(directory):
    packets = rdpcap(directory)
    # For demonstration, just filter TCP
    packets = packets.filter(lambda x: x.haslayer(TCP))

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
    # Build input array from flows
    input_data = []
    flow_keys = list(flows.keys())

    for flow_key in flow_keys:
        pkts = flows[flow_key]
        sport = flow_key[2]
        dport = flow_key[3]
        proto = flow_key[4]  # numeric (6 for TCP, 17 for UDP, etc.)
        num_pkts = len(pkts)
        total_len = sum([pkt.len for pkt in pkts])
        input_data.append((sport, dport, proto, num_pkts, total_len))

    if not len(input_data):
        return []

    input_data = np.array(input_data)
    probabilities = classifier.predict_proba(input_data)
    threshold = 0.5
    max_probs = np.max(probabilities, axis=1)
    predictions = classifier.predict(input_data)

    for i, prob in enumerate(max_probs):
        if prob < threshold:
            predictions[i] = 'other'

    labeled = list(zip(flow_keys, predictions))
    return labeled

###############################################################################
# IPTABLES Blocking
###############################################################################
def block_flows_for_device(labeled_flows, selected_device_type):
    matching = [(f, dev) for (f, dev) in labeled_flows
                if dev.lower() == selected_device_type.lower()]
    if not matching:
        print(f"[DEBUG] No flows matched device = {selected_device_type}")
        return

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

        self.tcpdump_thread = None
        self.tcpdump_process = None
        self.device_block_list = set()  
        self.capture_queue = queue.Queue()

        self.process_traffic_thread = None
        self.running = False

        self.rules_window = None
        self.rules_listbox = None
        self.rules_data = []  # Will store tuples (chain, line_number, rule_line)

        # ------------------------------------------------------
        # Window Configuration & Style
        # ------------------------------------------------------
        self.title("IoT Firewall v7 (Enhanced Rules Deletion)")
        self.geometry("600x300")
        self.configure(bg="#2C2F33")  # Dark background

        # Create and configure a custom style for TTK widgets
        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.style.configure("TLabel", background="#2C2F33", foreground="white", font=("Arial", 10))
        self.style.configure("TFrame", background="#2C2F33")
        self.style.configure("TCombobox", fieldbackground="#FFFFFF", background="#99AAB5", foreground="black")
        self.style.configure("TButton", background="#7289DA", foreground="white", padding=6, font=("Arial", 9, "bold"))
        self.style.map(
            "TButton",
            background=[("active", "#5B6EAE"), ("disabled", "#464A4D")],
            foreground=[("active", "white"), ("disabled", "#cccccc")]
        )

        # ------------------------------------------------------
        # Main Frame
        # ------------------------------------------------------
        main_frame = ttk.Frame(self)
        main_frame.pack(expand=True, fill=tk.BOTH)

        lbl = ttk.Label(main_frame, text="Select IoT device type to block, then capture traffic.")
        lbl.pack(pady=5)

        self.device_types = ["IP Camera", "Sensor", "Hub", "Alarm", "Plug", "Switch", "Gateway", "other"]
        self.selected_device_var = tk.StringVar(value=self.device_types[0])

        self.combo = ttk.Combobox(
            main_frame,
            textvariable=self.selected_device_var,
            values=self.device_types,
            state="readonly",
            width=30
        )
        self.combo.pack(pady=5)

        # Frame for capture duration
        frame1 = ttk.Frame(main_frame)
        frame1.pack(anchor='center')

        dur_label = ttk.Label(frame1, text="Capture Duration (seconds):")
        dur_label.pack(side=tk.LEFT, padx=5)

        self.duration_var = tk.StringVar(value="10")
        self.duration_entry = ttk.Entry(frame1, textvariable=self.duration_var, width=5)
        self.duration_entry.pack(side=tk.RIGHT, padx=5)

        # Start capture & block button
        self.start_btn = ttk.Button(
            main_frame,
            text="Start Capture & Block",
            command=self.add_device_to_block
        )
        self.start_btn.pack(pady=5)

        # Frame for show rules / exit
        frame2 = ttk.Frame(main_frame)
        frame2.pack(anchor='center')

        self.clear_devices_btn = ttk.Button(frame2, text="Stop IoT scanning", command=self.clear_devices, width=16)
        self.clear_devices_btn.pack(pady=5, side = tk.TOP, padx=10)

        self.show_rules_btn = ttk.Button(frame2, text="Show Rules", command=self.show_rules, width=12)
        self.show_rules_btn.pack(pady=5, side=tk.LEFT, padx=10)

        self.exit_btn = ttk.Button(frame2, text="Exit", command=self.exit_app, width=12)
        self.exit_btn.pack(pady=5, side=tk.RIGHT, padx=10)

        # Attempt to load a classifier
        self.classifier = load_classifier("rf_classifier.pkl")
        self.start_tcpdump()

    def start_tcpdump(self):
        if os.geteuid() != 0:
            messagebox.showerror("Error", "Please run as root/sudo for tcpdump & iptables.")
            return

        try:
            duration = int(self.duration_var.get())
        except ValueError:
            messagebox.showerror("Invalid Input", "Capture duration must be an integer.")
        def tcpdump_capture():
            try:
                self.tcpdump_process = subprocess.Popen(
                    ["tcpdump", "-i", "any", "-w", "tcpdump_capture.pcap"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                self.tcpdump_process.wait()  # Keep process alive
            except Exception as e:
                print(f"Error starting tcpdump: {e}")
        self.tcpdump_thread = threading.Thread(target=tcpdump_capture, daemon=True)
        self.tcpdump_thread.start()
    def add_device_to_block(self):
        """Add the selected IoT device to the block list and trigger classification."""
        dev_type = self.selected_device_var.get()
        if dev_type in self.device_block_list:
            messagebox.showinfo("Info", f"{dev_type} is already being blocked.")

        self.device_block_list.add(dev_type)
        messagebox.showinfo("Info", f"Added {dev_type} to block list.")
        self.process_captured_traffic()

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

    def clear_devices(self):
        self.device_block_list.clear()
        messagebox.showinfo("Info", "Cleared device block list.")

    def show_rules(self):
        # If already open, bring it to the front
        if self.rules_window and tk.Toplevel.winfo_exists(self.rules_window):
            self.rules_window.lift()
            self.rules_window.focus_force()
            return

        self.rules_window = tk.Toplevel(self)
        self.rules_window.title("Iptables Rules")
        self.rules_window.configure(bg="#2C2F33")
        self.rules_window.geometry("800x400")

        frame_rules = ttk.Frame(self.rules_window)
        frame_rules.pack(expand=True, fill=tk.BOTH)

        # Create the Listbox
        self.rules_listbox = tk.Listbox(
            frame_rules,
            selectmode=tk.SINGLE,
            width=100,
            height=15,
            font=("Courier", 10),
            bg="#23272A",  # dark background
            fg="white",
            highlightbackground="#2C2F33"
        )
        self.rules_listbox.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        frame_buttons = ttk.Frame(frame_rules)
        frame_buttons.pack(anchor='center', pady=5)

        add_button = ttk.Button(frame_buttons, text="Add Rule", command=self.add_rule_popup)
        add_button.pack(side=tk.LEFT, padx=5)

        delete_button = ttk.Button(frame_buttons, text="Delete Rule", command=self.delete_rule)
        delete_button.pack(side=tk.LEFT, padx=5)

        delete_all_button = ttk.Button(frame_buttons, text="Delete All Rules", command=self.delete_all_rules)
        delete_all_button.pack(side=tk.LEFT, padx=5)

        close_button = ttk.Button(frame_buttons, text="Close Window", command=self.close_rules_window)
        close_button.pack(side=tk.RIGHT, padx=5)

        # Finally, fetch & display iptables rules
        self.refresh_rules_list()

    def refresh_rules_list(self):
        """
        Clears and re-populates the Listbox with *only* actual iptables rules
        (skipping "Chain INPUT (policy ...)" lines).
        This ensures the Listbox index matches the iptables rule line numbers.
        """
        if not self.rules_listbox:
            return

        self.rules_listbox.delete(0, tk.END)
        self.rules_data.clear()

        try:
            result = subprocess.run(
                ["iptables", "-L", "-n", "--line-numbers", "-v"],
                capture_output=True,
                text=True,
                check=True
            )
            lines = result.stdout.splitlines()

            current_chain = None
            for line in lines:
                # Detect chain heading lines
                # Example: "Chain INPUT (policy ACCEPT 0 packets, 0 bytes)"
                if line.startswith("Chain "):
                    parts = line.split()
                    if len(parts) >= 2:
                        current_chain = parts[1]  # e.g. "INPUT"
                    else:
                        current_chain = None
                    # We skip adding these heading lines to the Listbox
                else:
                    # Potential rule lines typically start with a digit
                    tokens = line.split()
                    if tokens and tokens[0].isdigit() and current_chain is not None:
                        line_number = tokens[0]
                        # We'll keep the entire line for display
                        display_line = f"{current_chain} {line}"
                        # Insert for user display
                        self.rules_listbox.insert(tk.END, display_line)
                        # Store for deletion
                        self.rules_data.append((current_chain, line_number, line))

        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Error fetching iptables rules: {e}")

    def add_rule_popup(self):
        """
        Opens a popup to add a new rule, and refreshes the list on success.
        """
        add_rule_window = tk.Toplevel(self.rules_window)
        add_rule_window.title("Add New Rule")
        add_rule_window.geometry("400x600")
        add_rule_window.configure(bg="#2C2F33")

        style_label = ttk.Label(add_rule_window, text="Add a New Rule", style="TLabel")
        style_label.pack(pady=10)

        main_frame = ttk.Frame(add_rule_window)
        main_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        main_frame.grid_columnconfigure(0, weight=1, uniform="colgroup")
        main_frame.grid_columnconfigure(1, weight=2, uniform="colgroup")

        # Chain
        chain_label = ttk.Label(main_frame, text="Chain:")
        chain_label.grid(row=0, column=0, pady=5, sticky="e")

        chain_entry_var = tk.StringVar(value="INPUT")
        chain_entry = ttk.Combobox(
            main_frame,
            textvariable=chain_entry_var,
            values=["INPUT", "FORWARD", "OUTPUT"],
            state="readonly"
        )
        chain_entry.grid(row=0, column=1, sticky="w", padx=5, pady=5)

        # Target
        target_label = ttk.Label(main_frame, text="Target:")
        target_label.grid(row=1, column=0, pady=5, sticky="e")

        target_entry_var = tk.StringVar(value="ACCEPT")
        target_entry = ttk.Combobox(
            main_frame,
            textvariable=target_entry_var,
            values=["ACCEPT", "DROP", "REJECT"],
            state="readonly"
        )
        target_entry.grid(row=1, column=1, sticky="w", padx=5, pady=5)

        # State
        state_label = ttk.Label(main_frame, text="State:")
        state_label.grid(row=2, column=0, pady=5, sticky="e")

        state_entry_var = tk.StringVar(value="Any")
        state_entry = ttk.Combobox(
            main_frame,
            textvariable=state_entry_var,
            values=["Any", "NEW", "ESTABLISHED", "RELATED", "INVALID"],
            state="readonly"
        )
        state_entry.grid(row=2, column=1, sticky="w", padx=5, pady=5)

        # Source IP
        source_ip_label = ttk.Label(main_frame, text="Source IP:")
        source_ip_label.grid(row=3, column=0, pady=5, sticky="e")

        source_ip_entry = ttk.Entry(main_frame)
        source_ip_entry.grid(row=3, column=1, sticky="w", padx=5, pady=5)

        # Destination IP
        destination_ip_label = ttk.Label(main_frame, text="Destination IP:")
        destination_ip_label.grid(row=4, column=0, pady=5, sticky="e")

        destination_ip_entry = ttk.Entry(main_frame)
        destination_ip_entry.grid(row=4, column=1, sticky="w", padx=5, pady=5)

        # Source Port
        src_port_label = ttk.Label(main_frame, text="Source Port:")
        src_port_label.grid(row=5, column=0, pady=5, sticky="e")

        src_port_entry = ttk.Entry(main_frame, width=10)
        src_port_entry.grid(row=5, column=1, sticky="w", padx=5, pady=5)

        # Destination Port
        dst_port_label = ttk.Label(main_frame, text="Destination Port:")
        dst_port_label.grid(row=6, column=0, pady=5, sticky="e")

        dst_port_entry = ttk.Entry(main_frame, width=10)
        dst_port_entry.grid(row=6, column=1, sticky="w", padx=5, pady=5)

        # Protocol
        protocol_label = ttk.Label(main_frame, text="Protocol:")
        protocol_label.grid(row=7, column=0, pady=5, sticky="e")

        protocol_entry_var = tk.StringVar(value="TCP")
        protocol_entry = ttk.Combobox(
            main_frame,
            textvariable=protocol_entry_var,
            values=["TCP", "UDP", "ICMP", "ALL"],
            state="readonly"
        )
        protocol_entry.grid(row=7, column=1, sticky="w", padx=5, pady=5)

        frame9 = ttk.Frame(add_rule_window)
        frame9.pack(anchor='center')

        def save_rule():
            """
            Saves the new rule to iptables, then refreshes the list.
            """
            chain = chain_entry_var.get().strip()
            target = target_entry_var.get().strip()
            state_val = state_entry_var.get().strip()
            source_ip = source_ip_entry.get().strip()
            dest_ip = destination_ip_entry.get().strip()
            src_port = src_port_entry.get().strip()
            dst_port = dst_port_entry.get().strip()
            protocol = protocol_entry_var.get().strip()

            if not chain or not target or not protocol:
                messagebox.showerror("Error", "Chain, Target, and Protocol are required.")
                return

            cmd = ["iptables", "-A", chain]
            if protocol != "ALL":
                cmd.extend(["-p", protocol.lower()])
            if source_ip:
                cmd.extend(["-s", source_ip])
            if dest_ip:
                cmd.extend(["-d", dest_ip])

            if state_val and state_val != "Any":
                cmd.extend(["-m", "state", "--state", state_val])

            # Only add --sport/--dport if it's TCP or UDP
            proto_lower = protocol.lower()
            if proto_lower in ("tcp", "udp"):
                if src_port:
                    cmd.extend(["--sport", src_port])
                if dst_port:
                    cmd.extend(["--dport", dst_port])

            cmd.extend(["-j", target])
            print(cmd)
            try:
                subprocess.run(cmd, check=True)
                messagebox.showinfo("Success", f"Rule added successfully:\n{' '.join(cmd)}")
                add_rule_window.destroy()
                self.refresh_rules_list()
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Error", f"Failed to add rule:\n{e}")

        save_button = ttk.Button(frame9, text="Save Rule", command=save_rule)
        save_button.pack(side=tk.LEFT, padx=5, pady=5)

        cancel_button = ttk.Button(frame9, text="Cancel", command=add_rule_window.destroy)
        cancel_button.pack(side=tk.RIGHT, padx=5, pady=5)

    def delete_rule(self):
        """
        Deletes the selected rule from the correct chain.
        Because we skip chain headings, the index lines up exactly with our rules_data.
        """
        if not self.rules_listbox:
            return

        selected_index = self.rules_listbox.curselection()
        if not selected_index:
            messagebox.showwarning("Warning", "Please select a rule to delete.")
            return

        # The same index in self.rules_data
        chain, line_number, rule_line = self.rules_data[selected_index[0]]

        try:
            subprocess.run(["iptables", "-D", chain, line_number], check=True)
            messagebox.showinfo("Success", f"Deleted rule #{line_number} from chain {chain}")
            self.refresh_rules_list()
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Error deleting rule {line_number} from chain {chain}:\n{e}")

    def delete_all_rules(self):
        """
        Flush all iptables rules (INPUT, FORWARD, OUTPUT, etc.).
        """
        try:
            subprocess.run(["iptables", "-F"], check=True)
            subprocess.run(["iptables", "-t", "nat", "-F"], check=True)
            messagebox.showinfo("Success", "All iptables rules have been deleted.")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to delete all rules:\n{e}")

        self.refresh_rules_list()

    def close_rules_window(self):
        if self.rules_window:
            self.rules_window.destroy()
            self.rules_window = None

    def exit_app(self):
        
        if self.tcpdump_process:
            self.tcpdump_process.terminate()
        self.running = False
        if self.process_traffic_thread:
            self.process_traffic_thread.join()
        self.destroy()

###############################################################################
# Main
###############################################################################
def main():
    if os.geteuid() != 0:
        print("[WARNING] Not running as root. iptables/tcpdump may fail.")
    app = FirewallApp()
    app.mainloop()

if __name__ == "__main__":
    main()

