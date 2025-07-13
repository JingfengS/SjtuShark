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
        
        # New buttons for additional functionality
        self.filter_button = ttk.Button(
            self.controls_frame, 
            text="Filter", 
            command=self.show_filter_dialog
        )
        self.search_button = ttk.Button(
            self.controls_frame, 
            text="Search", 
            command=self.show_search_dialog
        )
        self.logs_button = ttk.Button(
            self.controls_frame, 
            text="View Logs", 
            command=self.show_logs
        )
        self.reassemble_button = ttk.Button(
            self.controls_frame, 
            text="Reassemble", 
            command=self.packet_reassembly
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
        
        # Pack the new buttons
        self.filter_button.pack(side="left", padx=5, pady=5)
        self.search_button.pack(side="left", padx=5, pady=5)
        self.logs_button.pack(side="left", padx=5, pady=5)
        self.reassemble_button.pack(side="left", padx=5, pady=5)
        
        self.save_button.pack(side="left", padx=5, pady=5)
        self.exit_button.pack(side="right", padx=5, pady=5)

        self.packets_frame.pack(expand=True, fill="both", padx=10, pady=5)
        self.tree.pack(expand=True, fill="both")

        self.details_frame.pack(expand=True, fill="both", padx=10, pady=10)
        self.details_text.pack(expand=True, fill="both")

    # New methods for the additional functionality
    def show_filter_dialog(self):
        """Show dialog for packet filtering."""
        filter_dialog = tk.Toplevel(self)
        filter_dialog.title("Packet Filter")
        filter_dialog.geometry("450x150")
        filter_dialog.transient(self)
        filter_dialog.grab_set()

        ttk.Label(filter_dialog, text="Enter filter expression (e.g., 'proto=TCP and src=192.168.1.1'):").pack(pady=10)
        self.filter_entry = ttk.Entry(filter_dialog, width=55)
        self.filter_entry.pack(pady=5)
        self.filter_entry.focus()

        def _apply():
            expr = self.filter_entry.get().strip()
            try:
                self.apply_filter(expr)
                filter_dialog.destroy()
            except ValueError as e:
                messagebox.showerror("Filter Error", str(e), parent=filter_dialog)

        ttk.Button(filter_dialog, text="Apply Filter", command=_apply).pack(side="left", padx=20, pady=10)
        ttk.Button(filter_dialog, text="Clear Filter", command=self.clear_filter).pack(side="right", padx=20, pady=10)

    def apply_filter(self, filter_expr):
        """Apply the filter to captured packets."""
        if not filter_expr:
            self.clear_filter()
            return

        filtered_packets = self.backend.query_packets(filter_expr)
        self.tree.delete(*self.tree.get_children())
        for idx, (summary, _) in enumerate(filtered_packets):
            self.tree.insert("", "end", values=(idx + 1,) + summary, tags=(summary[3],))
        if not filtered_packets:
            messagebox.showinfo("Filter Results", "No packets match the filter criteria")
            return

    def clear_filter(self):
        """Clear any applied filters."""
        self.tree.delete(*self.tree.get_children())
        for idx, (summary, _) in enumerate(self.backend.captured_packets):
            self.tree.insert("", "end", values=(idx + 1,) + summary, tags=(summary[3],))

    def show_search_dialog(self):
        """Show dialog for searching packets."""
        search_dialog = tk.Toplevel(self)
        search_dialog.title("Packet Search")
        search_dialog.geometry("400x130")
        search_dialog.transient(self)
        search_dialog.grab_set()

        ttk.Label(search_dialog, text="Search for:").pack(pady=10)
        self.search_entry = ttk.Entry(search_dialog, width=50)
        self.search_entry.pack(pady=5)
        self.search_entry.focus()

        def _do_search():
            keyword = self.search_entry.get().strip()
            if not keyword:
                return
            self.search_packets(keyword)
            search_dialog.destroy()

        ttk.Button(search_dialog, text="Search", command=_do_search).pack(pady=10)

    def search_packets(self, search_term):
        """Search through captured packets."""
        found_items = []
        search_term = search_term.lower()
        for item in self.tree.get_children():
            values = self.tree.item(item)["values"]
            if any(search_term in str(value).lower() for value in values):
                found_items.append(item)

        if not found_items:
            messagebox.showinfo("Search Results", "No matching packets found")
            return

        # Highlight found items
        self.tree.selection_set(found_items)
        self.tree.focus(found_items[0])
        self.tree.see(found_items[0])
        messagebox.showinfo("Search Results", f"Found {len(found_items)} matching packets")

    def show_logs(self):
        """Display capture logs in a new window."""
        log_window = tk.Toplevel(self)
        log_window.title("Capture Logs")
        log_window.geometry("600x400")
        
        log_text = scrolledtext.ScrolledText(log_window, wrap=tk.WORD)
        log_text.pack(expand=True, fill="both", padx=10, pady=10)
        
        # Add some sample log data - in a real app this would come from actual logging
        log_text.insert(tk.END, "=== Capture Log ===\n\n")
        log_text.insert(tk.END, f"Interface: {self.iface_combo.get()}\n")
        log_text.insert(tk.END, f"Total packets: {len(self.backend.captured_packets)}\n")
        log_text.insert(tk.END, "\nPacket Statistics:\n")
        stats = self.backend.get_stats()
        for proto, count in stats.items():
            log_text.insert(tk.END, f"{proto}: {count}\n")
        
        log_text.config(state="disabled")

    def packet_reassembly(self):
        """Show dialog for packet reassembly options."""
        reassembly_dialog = tk.Toplevel(self)
        reassembly_dialog.title("Packet Reassembly")
        reassembly_dialog.geometry("400x300")
        
        ttk.Label(reassembly_dialog, text="Select reassembly options:").pack(pady=10)
        
        self.reassembly_var = tk.StringVar(value="tcp")
        ttk.Radiobutton(reassembly_dialog, text="TCP Stream", 
                       variable=self.reassembly_var, value="tcp").pack(anchor="w", padx=20)
        ttk.Radiobutton(reassembly_dialog, text="UDP Stream", 
                       variable=self.reassembly_var, value="udp").pack(anchor="w", padx=20)
        ttk.Radiobutton(reassembly_dialog, text="HTTP Session", 
                       variable=self.reassembly_var, value="http").pack(anchor="w", padx=20)
        
        ttk.Button(reassembly_dialog, text="Reassemble", 
                  command=self.perform_reassembly).pack(pady=20)

    def perform_reassembly(self):
        """Perform the selected packet reassembly."""
        method = self.reassembly_var.get()
        if method == "tcp":
            # Perform TCP stream reassembly
           
            summary = self.backend.get_tcp_stream_summary()
            if not summary:
                messagebox.showinfo("Reassembly", "No TCP streams found for reassembly")
                return

            # Display the reassembled streams
            reassembly_window = tk.Toplevel(self)
            reassembly_window.title("TCP Stream Reassembly")
            reassembly_window.geometry("800x600")

            text = scrolledtext.ScrolledText(reassembly_window, wrap=tk.WORD)
            text.pack(expand=True, fill="both", padx=10, pady=10)

            text.insert(tk.END, "=== TCP Stream Reassembly ===\n\n")
            for stream in summary:
                text.insert(tk.END, f"Stream: {stream['src']}:{stream['sport']} -> {stream['dst']}:{stream['dport']}\n")
                text.insert(tk.END, f"Length: {stream['length']} bytes\n")
                text.insert(tk.END, "-" * 50 + "\n")
            text.config(state="disabled")
        else:
            messagebox.showinfo("Reassembly", f"Packet reassembly for {method.upper()} would be performed here.\n"
                              "This is a placeholder - actual implementation would require\n"
                              "processing the raw packets in the backend.")

    # Rest of the existing methods remain unchanged...
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
