import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import json
import os

class FirewallApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IoT Firewall")
        
        # Where we'll store/read the rules JSON
        self.rules_file = "firewall_rules.json"
        
        # List to hold all rules. Each rule is a dict of form data.
        self.rules = []
        # If modifying an existing rule, store its index here; None for new rules.
        self.edit_index = None
        
        # Load any existing rules from file
        self.load_rules_from_file()
        
        # Create the two frames (pages)
        self.main_frame = MainPage(self)
        self.rule_frame = RulePage(self)
        
        # Use grid so both frames occupy the same location;
        # we'll raise one or the other as needed.
        for frame in (self.main_frame, self.rule_frame):
            frame.grid(row=0, column=0, sticky="nsew")
        
        # Show the main page
        self.show_frame(self.main_frame)
        
        # After loading from file, refresh the list to display them
        self.main_frame.refresh_rules_list(self.rules)

    def show_frame(self, frame):
        """Bring the given frame to the front."""
        frame.tkraise()
    
    def create_rule(self):
        """Called when user clicks 'Create Rule' on the main page."""
        self.edit_index = None  # We are creating a brand-new rule
        self.rule_frame.load_rule_data({  # Empty/default data
            "chain": "INPUT",
            "target": "ACCEPT",
            # Default to "Any" (meaning no state restriction)
            "state": "Any",
            "proto_all": False,
            "proto_tcp": True,
            "proto_udp": True,
            "proto_icmp": False,
            "filter_all": False,
            "filter_ipcam": False,
            "filter_mic": False,
            "src_ip": "",
            "src_port": "",
            "dst_ip": "",
            "dst_port": ""
        })
        self.show_frame(self.rule_frame)
    
    def modify_rule(self):
        """Called when user clicks 'Modify rule' on the main page."""
        selection = self.main_frame.rules_listbox.curselection()
        if not selection:
            messagebox.showwarning("No selection", "Please select a rule to modify.")
            return
        
        idx = selection[0]
        rule_data = self.rules[idx]
        self.edit_index = idx
        self.rule_frame.load_rule_data(rule_data)
        self.show_frame(self.rule_frame)
    
    def delete_rule(self):
        """Called when user clicks 'Delete rule' on the main page."""
        selection = self.main_frame.rules_listbox.curselection()
        if not selection:
            messagebox.showwarning("No selection", "Please select a rule to delete.")
            return
        
        idx = selection[0]
        # Remove rule from self.rules
        self.rules.pop(idx)
        # Refresh the listbox
        self.main_frame.refresh_rules_list(self.rules)
        # Apply changes to iptables
        self.apply_iptables_rules()
        # Persist changes to disk
        self.save_rules_to_file()

    def save_rule(self, rule_data):
        """
        Called by the RulePage when 'Create rule' or 'Save Changes' is clicked.
        `rule_data` is a dict of all fields.
        """
        if self.edit_index is None:
            self.rules.append(rule_data)
        else:
            self.rules[self.edit_index] = rule_data
        
        # Refresh list and re-apply firewall changes
        self.main_frame.refresh_rules_list(self.rules)
        self.apply_iptables_rules()
        # Persist changes
        self.save_rules_to_file()
        
        # Return to the main frame
        self.show_frame(self.main_frame)

    def apply_iptables_rules(self):
        """
        Flush existing rules (in the relevant chains) and apply
        our Python-managed list of rules to the system's iptables.
        
        NOTE: Must be run with privileges (root/sudo).
        """
        try:
            for chain in ["INPUT", "FORWARD", "OUTPUT"]:
                subprocess.run(["iptables", "-F", chain], check=True)
            
            for rule in self.rules:
                commands = self._build_iptables_command(rule)
                if commands:
                    for cmd in commands:
                        subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            messagebox.showerror("iptables Error", f"Error applying iptables rules:\n{e}")
    
    def _build_iptables_command(self, rule):
        """
        Build a list-of-lists for iptables commands. For multiple protocols,
        we create multiple commands (e.g., TCP + UDP).
        """
        chain   = rule["chain"]
        target  = rule["target"]
        state   = rule["state"]       
        src_ip  = rule["src_ip"]
        src_prt = rule["src_port"]
        dst_ip  = rule["dst_ip"]
        dst_prt = rule["dst_port"]
        
        # Protocol(s)
        if rule["proto_all"]:
            protos = ["all"]
        else:
            protos = []
            if rule["proto_tcp"]:
                protos.append("tcp")
            if rule["proto_udp"]:
                protos.append("udp")
            if rule["proto_icmp"]:
                protos.append("icmp")
            if not protos:
                protos = ["all"]
        
        commands = []
        for proto in protos:
            cmd = ["iptables", "-A", chain]
            
            if proto != "all":
                cmd += ["-p", proto]
            
            if src_ip:
                cmd += ["-s", src_ip]
            if dst_ip:
                cmd += ["-d", dst_ip]
            
            # If state != "Any", restrict by state
            if state and state != "Any":
                cmd += ["-m", "state", "--state", state]
            
            # Ports (only if tcp/udp)
            if proto in ("tcp", "udp"):
                if src_prt:
                    cmd += ["--sport", src_prt]
                if dst_prt:
                    cmd += ["--dport", dst_prt]
            
            cmd += ["-j", target]
            commands.append(cmd)
        
        return commands

    def load_rules_from_file(self):
        """
        Load rules from a JSON file if it exists.
        """
        if os.path.isfile(self.rules_file):
            try:
                with open(self.rules_file, "r") as f:
                    self.rules = json.load(f)
            except Exception as e:
                messagebox.showerror("Error loading rules", f"Could not load rules: {e}")
                self.rules = []
        else:
            self.rules = []

    def save_rules_to_file(self):
        """
        Save rules to a JSON file.
        """
        try:
            with open(self.rules_file, "w") as f:
                json.dump(self.rules, f, indent=2)
        except Exception as e:
            messagebox.showerror("Error saving rules", f"Could not save rules: {e}")

    def close_app(self):
        """Close the application gracefully."""
        self.destroy()

class MainPage(tk.Frame):
    """
    The main page that displays the list of added rules
    and has buttons to create, modify, delete, and exit.
    """
    def __init__(self, parent):
        super().__init__(parent)
        
        title_label = tk.Label(self, text="IoT Firewall", font=("Helvetica", 18, "bold"))
        title_label.pack(pady=10)
        
        list_frame = tk.Frame(self, bd=1, relief="solid", padx=10, pady=10)
        list_frame.pack(padx=10, pady=5, fill="both", expand=True)
        
        lbl = tk.Label(list_frame, text="Added rules:")
        lbl.pack(anchor="w")
        
        self.rules_listbox = tk.Listbox(list_frame, width=80, height=10)
        self.rules_listbox.pack(pady=5)
        
        btn_frame = tk.Frame(list_frame)
        btn_frame.pack(fill="x")
        
        create_btn = tk.Button(btn_frame, text="Create Rule", 
                               width=15, command=parent.create_rule)
        create_btn.pack(side="left", expand=True, fill="x", padx=2)
        
        modify_btn = tk.Button(btn_frame, text="Modify rule", 
                               width=15, command=parent.modify_rule)
        modify_btn.pack(side="left", expand=True, fill="x", padx=2)
        
        delete_btn = tk.Button(btn_frame, text="Delete rule", 
                               width=15, command=parent.delete_rule)
        delete_btn.pack(side="left", expand=True, fill="x", padx=2)
        
        exit_btn = tk.Button(btn_frame, text="Exit",
                             width=15, command=parent.close_app)
        exit_btn.pack(side="left", expand=True, fill="x", padx=2)
        
    def refresh_rules_list(self, rules):
        self.rules_listbox.delete(0, tk.END)
        for rule in rules:
            display_str = self.format_rule(rule)
            self.rules_listbox.insert(tk.END, display_str)
        
    @staticmethod
    def format_rule(rule):
        s_ip = rule.get("src_ip") or "any"
        s_port = rule.get("src_port") or "any"
        d_ip = rule.get("dst_ip") or "any"
        d_port = rule.get("dst_port") or "any"
        chain = rule.get("chain", "INPUT")
        target = rule.get("target", "ACCEPT")
        
        # Protocol summary
        protos = []
        if rule.get("proto_all"):
            protos.append("ALL")
        else:
            if rule.get("proto_tcp"):
                protos.append("TCP")
            if rule.get("proto_udp"):
                protos.append("UDP")
            if rule.get("proto_icmp"):
                protos.append("ICMP")
        if not protos:
            protos.append("No protocols")
        
        iot_filters = []
        if rule.get("filter_all"):
            iot_filters.append("All devices")
        else:
            if rule.get("filter_ipcam"):
                iot_filters.append("IP Cameras")
            if rule.get("filter_mic"):
                iot_filters.append("Microphone")
        if not iot_filters:
            iot_filters.append("No IoT filter")
        
        state = rule.get("state")
        if not state or state == "Any":
            state_str = "Any state"
        else:
            state_str = state
        
        proto_str = ",".join(protos)
        iot_str   = ", ".join(iot_filters)
        
        return (
            f"{s_ip}:{s_port} --> {d_ip}:{d_port} | "
            f"{chain} {target} {proto_str} "
            f"({iot_str}, state={state_str})"
        )

class RulePage(tk.Frame):
    """
    The 'Add a new Rule' page (or Modify a rule).
    Adjusted layout so ports don't overlap ICMP.
    Now also includes a 'Back' button.
    """
    def __init__(self, parent):
        super().__init__(parent)
        
        self.parent = parent
        
        # Title
        title_label = tk.Label(self, text="Add a new Rule", font=("Helvetica", 18, "bold"))
        title_label.grid(row=0, column=0, columnspan=8, pady=(10, 20))
        
        # ---- Left columns (0..3): Chain, Target, State, IP, Ports ----
        
        # Chain
        chain_label = tk.Label(self, text="Chain:")
        chain_label.grid(row=1, column=0, sticky="e", padx=(10,5), pady=5)
        self.chain_var = tk.StringVar()
        self.chain_combo = ttk.Combobox(
            self, textvariable=self.chain_var, 
            values=["INPUT", "FORWARD", "OUTPUT"], 
            state="readonly"
        )
        self.chain_combo.grid(row=1, column=1, sticky="w", pady=5)
        
        # Target
        target_label = tk.Label(self, text="Target:")
        target_label.grid(row=2, column=0, sticky="e", padx=(10,5), pady=5)
        self.target_var = tk.StringVar()
        self.target_combo = ttk.Combobox(
            self, textvariable=self.target_var, 
            values=["ACCEPT", "DROP", "REJECT"], 
            state="readonly"
        )
        self.target_combo.grid(row=2, column=1, sticky="w", pady=5)
        
        # State
        state_label = tk.Label(self, text="State:")
        state_label.grid(row=3, column=0, sticky="e", padx=(10,5), pady=5)
        self.state_var = tk.StringVar()
        self.state_combo = ttk.Combobox(
            self, textvariable=self.state_var,
            values=["Any", "NEW", "ESTABLISHED", "RELATED", "INVALID"],
            state="readonly"
        )
        self.state_combo.grid(row=3, column=1, sticky="w", pady=5)
        
        # Source IP + Port
        src_ip_label = tk.Label(self, text="Source IP address:")
        src_ip_label.grid(row=4, column=0, sticky="e", padx=(10,5), pady=5)
        self.src_ip_entry = tk.Entry(self)
        self.src_ip_entry.grid(row=4, column=1, sticky="w", pady=5)
        
        src_port_label = tk.Label(self, text="Port:")
        src_port_label.grid(row=4, column=2, sticky="e", padx=5, pady=5)
        self.src_port_entry = tk.Entry(self, width=10)
        self.src_port_entry.grid(row=4, column=3, sticky="w", pady=5)
        
        # Destination IP + Port
        dst_ip_label = tk.Label(self, text="Destination IP address:")
        dst_ip_label.grid(row=5, column=0, sticky="e", padx=(10,5), pady=5)
        self.dst_ip_entry = tk.Entry(self)
        self.dst_ip_entry.grid(row=5, column=1, sticky="w", pady=5)
        
        dst_port_label = tk.Label(self, text="Port:")
        dst_port_label.grid(row=5, column=2, sticky="e", padx=5, pady=5)
        self.dst_port_entry = tk.Entry(self, width=10)
        self.dst_port_entry.grid(row=5, column=3, sticky="w", pady=5)
        
        # ---- Right columns (4..7): Protocol & Filter checkboxes ----
        
        # Protocol label
        proto_label = tk.Label(self, text="Protocol:")
        proto_label.grid(row=1, column=4, sticky="w", padx=(20,5), pady=5)
        
        self.proto_all_var = tk.BooleanVar()
        self.proto_tcp_var = tk.BooleanVar(value=True)
        self.proto_udp_var = tk.BooleanVar(value=True)
        self.proto_icmp_var = tk.BooleanVar()
        
        tk.Checkbutton(self, text="ALL", variable=self.proto_all_var).grid(
            row=1, column=5, sticky="w"
        )
        tk.Checkbutton(self, text="TCP", variable=self.proto_tcp_var).grid(
            row=2, column=5, sticky="w"
        )
        tk.Checkbutton(self, text="UDP", variable=self.proto_udp_var).grid(
            row=3, column=5, sticky="w"
        )
        tk.Checkbutton(self, text="ICMP", variable=self.proto_icmp_var).grid(
            row=4, column=5, sticky="w"
        )
        
        # Filter label
        filter_label = tk.Label(self, text="Filter by:")
        filter_label.grid(row=1, column=6, sticky="w", padx=(20,5), pady=5)
        
        self.filter_all_var = tk.BooleanVar()
        self.filter_ipcam_var = tk.BooleanVar()
        self.filter_mic_var = tk.BooleanVar()
        
        tk.Checkbutton(self, text="All", variable=self.filter_all_var).grid(
            row=1, column=7, sticky="w"
        )
        tk.Checkbutton(self, text="IP Cameras", variable=self.filter_ipcam_var).grid(
            row=2, column=7, sticky="w"
        )
        tk.Checkbutton(self, text="Microphone", variable=self.filter_mic_var).grid(
            row=3, column=7, sticky="w"
        )
        
        # ---- Buttons at the bottom ----
        
        # Create/Save Rule button
        self.create_rule_btn = tk.Button(self, text="Create rule", width=15, command=self.on_submit)
        self.create_rule_btn.grid(row=6, column=0, columnspan=8, pady=(15, 5))
        
        # Back button to return to main page
        self.back_btn = tk.Button(self, text="Back", width=15, command=self.go_back)
        self.back_btn.grid(row=7, column=0, columnspan=8, pady=(0, 10))
        
    def load_rule_data(self, rule_data):
        """Pre-populate fields with the given rule_data (new or existing)."""
        self.chain_var.set(rule_data["chain"])
        self.target_var.set(rule_data["target"])
        
        # If no state, treat as 'Any'
        if not rule_data.get("state"):
            rule_data["state"] = "Any"
        self.state_var.set(rule_data["state"])
        
        self.proto_all_var.set(rule_data["proto_all"])
        self.proto_tcp_var.set(rule_data["proto_tcp"])
        self.proto_udp_var.set(rule_data["proto_udp"])
        self.proto_icmp_var.set(rule_data["proto_icmp"])
        
        self.filter_all_var.set(rule_data["filter_all"])
        self.filter_ipcam_var.set(rule_data["filter_ipcam"])
        self.filter_mic_var.set(rule_data["filter_mic"])
        
        self.src_ip_entry.delete(0, tk.END)
        self.src_ip_entry.insert(0, rule_data["src_ip"])
        
        self.src_port_entry.delete(0, tk.END)
        self.src_port_entry.insert(0, rule_data["src_port"])
        
        self.dst_ip_entry.delete(0, tk.END)
        self.dst_ip_entry.insert(0, rule_data["dst_ip"])
        
        self.dst_port_entry.delete(0, tk.END)
        self.dst_port_entry.insert(0, rule_data["dst_port"])
        
        # If editing, show "Save changes"; if new, show "Create rule"
        if self.parent.edit_index is None:
            self.create_rule_btn.config(text="Create rule")
        else:
            self.create_rule_btn.config(text="Save changes")
        
    def on_submit(self):
        """Collect all form fields and pass them back to the app."""
        updated_data = {
            "chain": self.chain_var.get(),
            "target": self.target_var.get(),
            "state": self.state_var.get(),  
            "proto_all": self.proto_all_var.get(),
            "proto_tcp": self.proto_tcp_var.get(),
            "proto_udp": self.proto_udp_var.get(),
            "proto_icmp": self.proto_icmp_var.get(),
            "filter_all": self.filter_all_var.get(),
            "filter_ipcam": self.filter_ipcam_var.get(),
            "filter_mic": self.filter_mic_var.get(),
            "src_ip": self.src_ip_entry.get().strip(),
            "src_port": self.src_port_entry.get().strip(),
            "dst_ip": self.dst_ip_entry.get().strip(),
            "dst_port": self.dst_port_entry.get().strip()
        }
        
        self.parent.save_rule(updated_data)
    
    def go_back(self):
        """
        Return to the main page without saving changes.
        """
        self.parent.show_frame(self.parent.main_frame)

# ---- Run the application ----
if __name__ == "__main__":
    app = FirewallApp()
    app.mainloop()

