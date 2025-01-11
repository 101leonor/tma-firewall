#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import pickle
import re
import numpy as np
from collections import defaultdict
from scapy.all import PacketList,rdpcap, TCP,IP,UDP


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


def run_tcpdump_updated(duration=10, interface="any", output_file="tcpdump_capture.pcap"):
    try:
        process = subprocess.Popen(
            ["tcpdump", "-i", interface, "-w", output_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        time.sleep(duration)

        process.terminate()

        with open(output_file, "rb") as file:
            file_contents = file.readlines()
        return file_contents
        

    except Exception as e:
        print(f"An error occurred: {e}")
        return None

    

###############################################################################
# Parse tcpdump lines into flows
###############################################################################

'''def parse_tcpdump_to_flows(tcpdump_lines):
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
'''

def parse_tcpdump_to_flows(directory):

    packets = rdpcap(directory)

    packets = packets.filter(lambda x: x.haslayer(TCP)) # filter only TCP packets Not sure if we should use this or not

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
# Classification (with forced label for port 554, minus 'bytes' in the vector)
###############################################################################

'''def classify_flows(flows, classifier):
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
'''

def classify_flows(flows, classifier):
    input = np.zeros((1,5))
    for flow,pkts in flows.items():
    #print(flow[2], flow[3], flow[4], len(pkts), sum([pkt.len for pkt in pkts]), pkts[0].device)
        input = np.vstack([input,(flow[2], flow[3], flow[4], len(pkts), sum([pkt.len for pkt in pkts]))])

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
    
    # TODO: decide which IP we are going to use - source or destination
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
        self.rules_window = None  # Variable para controlar la ventana de reglas


        self.title("IoT Firewall v6 (5-feature fix)")
        self.geometry("400x200")

        lbl = tk.Label(self, text="Select IoT device type to block, then capture traffic.")
        lbl.pack(pady=5)
        
        # TODO: make sure the naming is the same as the classifier
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
        self.duration_entry.pack(pady=2,side=tk.RIGHT)
        



        self.start_btn = tk.Button(self, text="Start Capture & Block",
                                   command=self.start_capture_and_block)
        self.start_btn.pack(pady=5)

        frame2 = tk.Frame(self)
        frame2.pack(anchor='center')
        self.show_rules_btn = tk.Button(frame2, text="Show rules", command=self.show_rules, width=6)
        self.show_rules_btn.pack(pady=5, side=tk.LEFT, padx=5)

        self.exit_btn = tk.Button(frame2, text="Exit", command=self.exit_app, width=6)
        self.exit_btn.pack(pady=5, side=tk.RIGHT, padx=5)

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
            f"Capturing {duration} seconds. Output in tcpdump_capture.pcap"
        )

        lines = run_tcpdump_updated(
            duration=duration,
            interface="any",
            output_file="tcpdump_capture.pcap"
        )

        flows = parse_tcpdump_to_flows("tcpdump_capture.pcap")
        labeled = classify_flows(flows, self.classifier)
        dev_type = self.selected_device_var.get()
        print(labeled, dev_type)
        block_flows_for_device(labeled, dev_type)

        messagebox.showinfo(
            "Done",
            f"Capture finished. Attempted to block flows for {dev_type}.\nCheck iptables -L -n and tcpdump_capture.pcap."
        )

    def exit_app(self):
        self.destroy()




    def show_rules(self):
        
        # Check if a window is already open
        if self.rules_window and tk.Toplevel.winfo_exists(self.rules_window):
            self.rules_window.lift()  # Bring the window to the front
            self.rules_window.focus_force()  # Give it focus
            return

        # Create a new window
        self.rules_window = tk.Toplevel(self)
        self.rules_window.title("Iptables Rules")
        #self.rules_window.geometry("800x400")

        # Create a Listbox to display the rules with monospaced font
        listbox = tk.Listbox(self.rules_window, selectmode=tk.SINGLE, width=100, height=20, font=("Courier", 10))
        listbox.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Get iptables rules and add them to the Listbox
        try:
            result = subprocess.run(["iptables", "-L", "-n", "--line-numbers", "-v"], capture_output=True, text=True, check=True)
            rules = result.stdout.splitlines()

            for rule in rules:
                listbox.insert(tk.END, rule)
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Error fetching iptables rules: {e}")

        def add_rule():
            """Abre una ventana emergente para añadir una nueva regla."""
            # Crear una nueva ventana emergente
            add_rule_window = tk.Toplevel(self.rules_window)
            add_rule_window.title("Add New Rule")
            add_rule_window.geometry("400x600")
            
            
            # Etiqueta de título
            title_label = tk.Label(add_rule_window, text="Add a New Rule", font=("Helvetica", 16, "bold"))
            title_label.pack(pady=10)
            
            main_frame = tk.Frame(add_rule_window)
            main_frame.pack(fill=tk.BOTH, expand=True, pady=10)

            # Configurar columnas para que sean iguales
            main_frame.grid_columnconfigure(0, weight=1, uniform="group1")  # Columna de etiquetas
            main_frame.grid_columnconfigure(1, weight=2, uniform="group1")  # Columna de campos
            

          
            # Campos para la nueva regla

            # Chain
            chain_label = tk.Label(main_frame, text="Chain:")
            chain_label.grid(row=0, column=0, pady=5, sticky="e")

            chain_entry_var = tk.StringVar(value="INPUT")
            chain_entry = ttk.Combobox(main_frame, textvariable=chain_entry_var, values=["INPUT", "FORWARD", "OUTPUT"], state="readonly")
            chain_entry.grid(row=0, column=1, sticky="w", padx=5, pady=5)

         
            # Target
            target_label = tk.Label(main_frame, text="Target:")
            target_label.grid(row=1, column=0, pady=5, sticky="e")
            
            target_entry_var = tk.StringVar(value="ACCEPT")
            target_entry = ttk.Combobox(main_frame, textvariable=target_entry_var, values=["ACCEPT", "DROP", "REJECT"], state="readonly")
            target_entry.grid(row=1, column=1, sticky="w", padx=5, pady=5)

            # State
            state_label = tk.Label(main_frame, text="State:")
            state_label.grid(row=2, column=0, pady=5, sticky="e")
            
            state_entry_var = tk.StringVar(value="Any")
            state_entry = ttk.Combobox(main_frame, textvariable=state_entry_var, values=["Any", "NEW", "ESTABLISHED", "RELATED", "INVALID"], state="readonly")
            state_entry.grid(row=2, column=1, sticky="w", padx=5, pady=5)

            # Source IP
            source_ip_label = tk.Label(main_frame, text="Source IP:")
            source_ip_label.grid(row=3, column=0, pady=5, sticky="e")
           
            source_ip_entry = tk.Entry(main_frame)
            source_ip_entry.grid(row=3, column=1, sticky="w", padx=5, pady=5)
        

            # Destination IP
            destination_ip_label = tk.Label(main_frame, text="Destination IP:")
            destination_ip_label.grid(row=4, column=0, pady=5, sticky="e")
            
            destination_ip_entry = tk.Entry(main_frame)
            destination_ip_entry.grid(row=4, column=1, sticky="w", padx=5, pady=5)

            # Source Port
            src_port_label = tk.Label(main_frame, text="Source Port:")
            src_port_label.grid(row=5, column=0, pady=5, sticky="e")
            
            src_port_entry = tk.Entry(main_frame, width=10)
            src_port_entry.grid(row=5, column=1, sticky="w", padx=5, pady=5)


            # Source Port
            dst_port_label = tk.Label(main_frame, text="Destination Port:")
            dst_port_label.grid(row=6, column=0, pady=5, sticky="e")
            
            dst_port_entry = tk.Entry(main_frame, width=10)
            dst_port_entry.grid(row=6, column=1, sticky="w", padx=5, pady=5)

            # Protocol
            protocol_label = tk.Label(main_frame, text="Protocol:")
            protocol_label.grid(row=7, column=0, pady=5, sticky="e")
            
            protocol_entry_var = tk.StringVar(value="TCP")
            protocol_entry = ttk.Combobox(main_frame, textvariable=protocol_entry_var , values=["TCP", "UDP", "ICMP", "ALL"], state="readonly")
            protocol_entry.grid(row=7, column=1, sticky="w", padx=5, pady=5)




            # Botón para guardar la regla
            def save_rule():
                """Guarda la nueva regla."""
                
                # Obtener los valores del formulario
                chain = chain_entry_var.get().strip()
                target = target_entry_var.get().strip()
                state = state_entry_var.get().strip()
                source_ip = source_ip_entry.get().strip()
                src_port = src_port_entry.get().strip()
                destination_ip = destination_ip_entry.get().strip()
                dst_port = dst_port_entry.get().strip()
                protocol = protocol_entry_var.get().strip()


                # Validar campos requeridos
                if not chain or not target or not protocol:
                    messagebox.showerror("Error", "Chain, Target, and Protocol are required.")
                    return

                # Lógica para añadir la regla al sistema
                
                # Construir el comando base de iptables
                cmd = ["iptables", "-A", chain]

                if protocol != "ALL":  # Si no es "ALL", especificar el protocolo
                    cmd.extend(["-p", protocol.lower()])
                if source_ip:
                    cmd.extend(["-s", source_ip])
                if destination_ip:
                    cmd.extend(["-d", destination_ip])
                
                # Añadir condiciones opcionales según los campos llenados
                if state and state != "Any":
                    cmd.extend(["-m", "state", "--state", state])
                
                if protocol in ("tcp", "udp"):
                    if src_port:
                        cmd.extend(["--sport", src_port])

                    if dst_port:
                        cmd.extend(["--dport", dst_port])
               

                
                cmd.extend(["-j", target])
                print(cmd)
            
                # Intentar ejecutar el comando
                try:
                    subprocess.run(cmd, check=True)
                    messagebox.showinfo("Success", f"Rule added successfully:\n{' '.join(cmd)}")
                    add_rule_window.destroy()  # Cerrar la ventana emergente
                except subprocess.CalledProcessError as e:
                    messagebox.showerror("Error", f"Failed to add rule:\n{e}")



            frame9 = tk.Frame(add_rule_window)
            frame9.pack(anchor='center')

            save_button = tk.Button(frame9, text="Save Rule", command=save_rule)
            save_button.pack(side=tk.LEFT, pady=10)

            # Botón para cerrar la ventana sin guardar
            close_button = tk.Button(frame9, text="Cancel", command=add_rule_window.destroy)
            close_button.pack(side=tk.RIGHT, pady=5)




        # Function to delete a selected rule
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
            chain = "INPUT"  # We assume we are working on the default INPUT chain

            try:
                subprocess.run(["iptables", "-D", chain, rule_number], check=True)
                listbox.delete(selected_index)
                messagebox.showinfo("Success", f"Rule {rule_number} deleted successfully.")
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Error", f"Error deleting rule {rule_number}: {e}")

        def delete_all_rules():
            """Elimina todas las reglas definidas en iptables."""
            try:
                # Ejecutar el comando para borrar todas las reglas
                subprocess.run(["iptables", "-F"], check=True)

                # Opcional: borrar reglas específicas de NAT si es necesario
                subprocess.run(["iptables", "-t", "nat", "-F"], check=True)

                # Mensaje de confirmación
                messagebox.showinfo("Success", "All iptables rules have been deleted.")
            except subprocess.CalledProcessError as e:
                # Mensaje de error si el comando falla
                messagebox.showerror("Error", f"Failed to delete all rules:\n{e}")
            close_rules_window()




        frame3 = tk.Frame(self.rules_window)
        frame3.pack(anchor='center')

        # Add Rules Button
        add_button = tk.Button(frame3, text="Add Rule", command=add_rule)
        add_button.pack(pady=5, side=tk.LEFT, padx=5)


        # Delete Rules Button
        delete_button = tk.Button(frame3, text="Delete Rule", command=delete_rule)
        delete_button.pack(pady=5, side=tk.LEFT, padx=5)


        delete_all_rules_button = tk.Button(frame3, text="Delete All Rules", command=delete_all_rules)
        delete_all_rules_button.pack(side=tk.LEFT, padx=5)


        def close_rules_window():
            self.rules_window.destroy()
            self.rules_window = None  # Reiniciar el control de la ventana


        # Close Rules window Button
        close_button = tk.Button(frame3, text="Close Rules", command=close_rules_window)
        close_button.pack(pady=5, side=tk.RIGHT, padx=5)


def main():
    if os.geteuid() != 0:
        print("[WARNING] Not running as root. iptables/tcpdump may fail.")
    app = FirewallApp()
    app.mainloop()

if __name__ == "__main__":
    main()

