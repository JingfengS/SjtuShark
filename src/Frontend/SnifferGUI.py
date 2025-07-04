import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from ..Backend.SnifferBackend import SnifferBackend
class SnifferGUI(tk.Tk):
    """
    Manages the Graphical User Interface using Tkinter.
    """

    def __init__(self, title):
        super().__init__()
        self.title(title)
        self.geometry("1200x800")

        # Initialize the backend
        self.backend = SnifferBackend(self.add_packet_to_gui)

        # Create and layout the widgets
        self._create_widgets()
        self._layout_widgets()

        # Populate the interface dropdown
        self._populate_interfaces()


    def _create_widgets(self):
        """Creates all the GUI widgets."""
        # --- Controls ---
        self.controls_frame = ttk.LabelFrame(self, text="Controls")
        self.iface_label = ttk.Label(self.controls_frame, text="Network Interface:")
        self.iface_combo = ttk.Combobox(self.controls_frame, state="readonly", width=40)
        self.start_button = ttk.Button(
            self.controls_frame, text="Start Capture", command=self.start_capture
        )
        self.stop_button = ttk.Button(
            self.controls_frame,
            text="Stop Capture",
            command=self.stop_capture,
            state="disabled",
        )
        self.save_button = ttk.Button(
            self.controls_frame, text="Save to TXT", command=self.save_to_txt
        )
        self.exit_button = ttk.Button(
            self.controls_frame, text="Exit", command=self.quit
        )

        # --- Packet List Display ---
        self.packets_frame = ttk.LabelFrame(self, text="Captured Packets")
        columns = ("#", "Time", "Source", "Destination", "Protocol", "Info")
        self.tree = ttk.Treeview(self.packets_frame, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
        self.tree.column("#", width=60)
        self.tree.column("Time", width=100)
        self.tree.column("Source", width=150)
        self.tree.column("Destination", width=150)
        self.tree.column("Protocol", width=80)
        self.tree.column("Info", width=400)
        self.tree.bind("<<TreeviewSelect>>", self.show_packet_details)

        # The tag name must match the protocol string from the backend
        self.tree.tag_configure("TCP", background="#e0f0ff")  # Light Blue
        self.tree.tag_configure("UDP", background="#e0ffe0")  # Light Green
        self.tree.tag_configure("ICMP", background="#ffe0e0") # Light Red/Pink
        self.tree.tag_configure("ARP", background="#fffde0")   # Light Yellow
        self.tree.tag_configure("HTTP", background="#d0ffff")  # Light Cyan
        self.tree.tag_configure("HTTPS", background="#e0d0ff") # Light Purple

        # --- Packet Details Display ---
        self.details_frame = ttk.LabelFrame(self, text="Packet Details")
        self.details_text = scrolledtext.ScrolledText(
            self.details_frame, wrap=tk.WORD, state="disabled", height=15
        )

    def _layout_widgets(self):
        """Lays out the widgets in the main window."""
        self.controls_frame.pack(side="top", fill="x", padx=10, pady=5)
        self.iface_label.pack(side="left", padx=5, pady=5)
        self.iface_combo.pack(side="left", padx=5, pady=5)
        self.start_button.pack(side="left", padx=5, pady=5)
        self.stop_button.pack(side="left", padx=5, pady=5)
        self.save_button.pack(side="left", padx=5, pady=5)
        self.exit_button.pack(side="right", padx=5, pady=5)

        self.packets_frame.pack(expand=True, fill="both", padx=10, pady=5)
        self.tree.pack(expand=True, fill="both")

        self.details_frame.pack(expand=True, fill="both", padx=10, pady=10)
        self.details_text.pack(expand=True, fill="both")

    def _populate_interfaces(self):
        """Gets and displays network interfaces in the dropdown."""
        interfaces = self.backend.get_network_interfaces()
        self.iface_combo["values"] = interfaces
        if interfaces:
            self.iface_combo.current(0)

    def start_capture(self):
        """Handler for the 'Start Capture' button."""
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.iface_combo.config(state="disabled")
        self.tree.delete(*self.tree.get_children())  # Clear previous results
        self.backend.clear_captured_packets() # Clear backend data

        selected_iface = self.iface_combo.get()
        self.backend.start_sniffing(selected_iface)
        print(f"Sniffing started on {selected_iface}")

    def stop_capture(self):
        """Handler for the 'Stop Capture' button."""
        self.backend.stop_sniffing()
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.iface_combo.config(state="normal")
        print("Sniffing stopped.")

    def add_packet_to_gui(self, packet_summary, packet_details):
        """
        Thread-safe method to add a new packet to the GUI.
        This is called by the backend sniffer thread.
        """
        # The `after` method schedules a function to be called in the main GUI thread
        self.after(0, self._insert_packet_data) # 不再传递具体信息

    def _insert_packet_data(self):
        """Inserts packet data into the Treeview and stores details."""
        idx = len(self.backend.captured_packets)
        if idx == 0:
            return
        
        # Get the latest packet's summary and protocol
        summary = self.backend.captured_packets[-1][0]
        protocol_tag = summary[3]  # The protocol string (e.g., "TCP", "UDP") is the tag

        # Insert into treeview with the corresponding tag
        self.tree.insert("", "end", values=(idx,) + summary, tags=(protocol_tag,))

    def show_packet_details(self, event):
        """Displays detailed info for the selected packet."""
        selected_item = self.tree.selection()
        if not selected_item:
            return

        item_id = selected_item[0]
        values = self.tree.item(item_id)["values"]
        if not values:
            details = "No details available."
        else:
            # values[0] 是 packet_id，从 1 开始
            idx = int(values[0]) - 1
            if 0 <= idx < len(self.backend.captured_packets):
                details = self.backend.captured_packets[idx][1]
            else:
                details = "No details available."

        self.details_text.config(state="normal")
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, details)
        self.details_text.config(state="disabled")

    def save_to_txt(self):
        """Saves the captured packet summaries to a text file."""
        if not self.backend.captured_packets:
            messagebox.showinfo("Info", "There are no packets to save.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Captured Packets As",
        )
        if not file_path:
            return

        # 建议调用后端方法
        self.backend.save_captured_packets(file_path)
        messagebox.showinfo("Success", f"Data saved to {file_path}")
