import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import sniff, IP, TCP, UDP
import threading

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Mini Wireshark (Lite)")
        self.root.geometry("800x500")

        # === Top Control Panel ===
        control_frame = ttk.Frame(root)
        control_frame.pack(pady=10)

        # Protocol Filter Dropdown
        ttk.Label(control_frame, text="Protocol:").grid(row=0, column=0, padx=5)
        self.protocol_var = tk.StringVar(value="All")
        ttk.Combobox(
            control_frame,
            textvariable=self.protocol_var,
            values=["All", "TCP", "UDP"],
            width=10
        ).grid(row=0, column=1, padx=5)

        # IP Filter Entry
        ttk.Label(control_frame, text="IP Filter:").grid(row=0, column=2, padx=5)
        self.ip_filter = tk.Entry(control_frame, width=15)
        self.ip_filter.grid(row=0, column=3, padx=5)

        # Start and Stop Buttons
        self.start_button = ttk.Button(control_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.grid(row=0, column=4, padx=5)

        self.stop_button = ttk.Button(control_frame, text="Stop", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=5, padx=5)

        # Clear Output Button
        self.clear_button = ttk.Button(control_frame, text="Clear Output", command=self.clear_output)
        self.clear_button.grid(row=0, column=6, padx=5)

        # === Output Display (Scrolled Text) ===
        self.output = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=25)
        self.output.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.sniffing = False  # State to control sniffing

    def start_sniffing(self):
        """Start the packet sniffing in a separate thread."""
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.output.insert(tk.END, "🚀 Sniffing started...\n")
        self.output.see(tk.END)
        thread = threading.Thread(target=self.sniff_packets)
        thread.daemon = True  # Daemon thread will close with the app
        thread.start()

    def stop_sniffing(self):
        """Stop the packet sniffing."""
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.output.insert(tk.END, "🛑 Sniffing stopped.\n")
        self.output.see(tk.END)

    def clear_output(self):
        """Clear the packet log output."""
        self.output.delete('1.0', tk.END)

    def sniff_packets(self):
        """Capture and process packets based on selected filters."""

        def process_packet(packet):
            """Filter and display packets based on IP and protocol."""
            if IP in packet:
                proto = None
                # Determine the protocol
                if TCP in packet:
                    proto = "TCP"
                elif UDP in packet:
                    proto = "UDP"
                else:
                    return  # Ignore other protocols

                # Filter by selected protocol if not "All"
                if self.protocol_var.get() != "All" and proto != self.protocol_var.get():
                    return

                src = packet[IP].src
                dst = packet[IP].dst

                # Filter by IP if filter is specified
                ip_filter_val = self.ip_filter.get().strip()
                if ip_filter_val and ip_filter_val not in [src, dst]:
                    return

                # Display formatted message in the text box
                msg = f"[{proto}] {src} → {dst}\n"
                self.output.insert(tk.END, msg)
                self.output.see(tk.END)

        # Start sniffing packets until self.sniffing becomes False
        sniff(prn=process_packet, store=0, stop_filter=lambda x: not self.sniffing)

# === Main Execution ===
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
