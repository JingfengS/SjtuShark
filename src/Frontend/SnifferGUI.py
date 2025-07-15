import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from ..Backend.SnifferBackend import SnifferBackend
from .HTTP_Viewer import HTTPContentViewer
import json


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
        self.http_viewer = HTTPContentViewer()

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
            self.controls_frame, text="Filter", command=self.show_filter_dialog
        )
        self.search_button = ttk.Button(
            self.controls_frame, text="Search", command=self.show_search_dialog
        )
        self.logs_button = ttk.Button(
            self.controls_frame, text="View Logs", command=self.show_logs
        )
        self.reassemble_button = ttk.Button(
            self.controls_frame, text="Reassemble", command=self.packet_reassembly
        )

        self.save_button = ttk.Button(
            self.controls_frame, text="Save to TXT", command=self.save_to_txt
        )
        self.export_button = ttk.Button(
            self.controls_frame, text="Export to PCAP", command=self.export_to_pcap
        )
        self.import_button = ttk.Button(
            self.controls_frame, text="Import from PCAP", command=self.import_from_pcap
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
        self.tree.tag_configure("ICMP", background="#ffe0e0")  # Light Red/Pink
        self.tree.tag_configure("ARP", background="#fffde0")  # Light Yellow
        self.tree.tag_configure("HTTP", background="#d0ffff")  # Light Cyan
        self.tree.tag_configure("HTTPS", background="#e0d0ff")  # Light Purple

        # --- Packet Details Display ---
        # Replace the single ScrolledText with a Notebook (tabbed view)
        self.details_notebook = ttk.Notebook(self)

        # Tab 1: For raw packet details from Scapy
        self.details_frame = ttk.Frame(self.details_notebook)
        self.details_text = scrolledtext.ScrolledText(
            self.details_frame, wrap=tk.WORD, height=15
        )
        self.details_text.pack(expand=True, fill="both")
        self.details_notebook.add(self.details_frame, text="Packet Details")

        # Tab 2: For reassembled TCP and HTTP content
        self.data_frame = ttk.Frame(self.details_notebook)

        # 添加一个工具栏用于HTTP内容
        self.http_toolbar = ttk.Frame(self.data_frame)
        self.open_browser_button = ttk.Button(
            self.http_toolbar,
            text="Open in Browser",
            command=self._open_http_in_browser,
            state="disabled",
        )
        self.open_browser_button.pack(side="left", padx=5)

        self.open_raw_html_button = ttk.Button(
            self.http_toolbar,
            text="Open Raw HTML",
            command=self._open_raw_html,
            state="disabled",
        )
        self.open_raw_html_button.pack(side="left", padx=5)

        self.export_http_button = ttk.Button(
            self.http_toolbar,
            text="Export HTTP Session",
            command=self._export_http_session,
            state="disabled",
        )
        self.export_http_button.pack(side="left", padx=5)

        # HTTP内容显示区域
        self.data_text = scrolledtext.ScrolledText(
            self.data_frame, wrap=tk.WORD, height=15
        )

        self.http_toolbar.pack(side="top", fill="x", pady=5)
        self.data_text.pack(expand=True, fill="both")

        self.details_notebook.add(self.data_frame, text="Reassembled Data")

        # Tab 3: HTTP美化视图
        self.http_view_frame = ttk.Frame(self.details_notebook)
        self.http_view_text = scrolledtext.ScrolledText(
            self.http_view_frame, wrap=tk.WORD, height=15
        )
        self.http_view_text.pack(expand=True, fill="both")
        self.details_notebook.add(self.http_view_frame, text="HTTP View")
        # 存储当前选中的包信息
        self.current_packet_id = None
        self.current_http_messages = None

    def _layout_widgets(self):
        """Lays out the widgets in the main window with responsive layout."""
        self.controls_frame.pack(side="top", fill="x", padx=10, pady=5)

        # 使用 grid 布局，让按钮自适应窗口大小
        for i in range(12):
            self.controls_frame.columnconfigure(i, weight=1, uniform="btn")

        # 第0行：接口选择
        self.iface_label.grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.iface_combo.grid(row=0, column=1, columnspan=3, sticky="ew", padx=5, pady=5)

        # 第1行：所有按钮
        buttons = [
            self.start_button, self.stop_button, self.filter_button,
            self.search_button, self.logs_button, self.reassemble_button,
            self.save_button, self.export_button, self.import_button
        ]
        for idx, btn in enumerate(buttons):
            btn.grid(row=1, column=idx, sticky="ew", padx=2, pady=2)

        # 退出按钮靠右
        self.exit_button.grid(row=1, column=10, sticky="e", padx=5, pady=2)

        # 下方区域保持不变
        self.packets_frame.pack(expand=True, fill="both", padx=10, pady=5)
        self.tree.pack(expand=True, fill="both")
        self.details_notebook.pack(expand=True, fill="both", padx=10, pady=10)
    # New methods for the additional functionality
    def show_filter_dialog(self):
        """Show dialog for packet filtering."""
        if self.backend.is_sniffing:
            messagebox.showwarning(
                "Warning", "Please stop capturing before applying a filter."
            )
            return
        filter_dialog = tk.Toplevel(self)
        filter_dialog.title("Packet Filter")
        filter_dialog.geometry("450x150")
        filter_dialog.transient(self)
        filter_dialog.grab_set()

        ttk.Label(
            filter_dialog,
            text="Enter filter expression (e.g., 'proto=TCP and src=192.168.1.1'):",
        ).pack(pady=10)
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

        ttk.Button(filter_dialog, text="Apply Filter", command=_apply).pack(
            side="left", padx=20, pady=10
        )
        ttk.Button(filter_dialog, text="Clear Filter", command=self.clear_filter).pack(
            side="right", padx=20, pady=10
        )

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
            messagebox.showinfo(
                "Filter Results", "No packets match the filter criteria"
            )
            return

    def clear_filter(self):
        """Clear any applied filters."""
        self.tree.delete(*self.tree.get_children())
        for idx, (summary, _) in enumerate(self.backend.captured_packets):
            self.tree.insert("", "end", values=(idx + 1,) + summary, tags=(summary[3],))

    def show_search_dialog(self):
        """Show dialog for searching packets."""
        if self.backend.is_sniffing:
            messagebox.showwarning(
                "Warning", "Please stop capturing before searching packets."
            )
            return
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
        messagebox.showinfo(
            "Search Results", f"Found {len(found_items)} matching packets"
        )

    def show_logs(self):
        """Display capture logs in a new window."""
        if self.backend.is_sniffing:
            messagebox.showwarning(
                "Warning", "Please stop capturing before viewing logs."
            )
            return
        log_window = tk.Toplevel(self)
        log_window.title("Capture Logs")
        log_window.geometry("600x400")

        log_text = scrolledtext.ScrolledText(log_window, wrap=tk.WORD)
        log_text.pack(expand=True, fill="both", padx=10, pady=10)

        # Add some sample log data - in a real app this would come from actual logging
        log_text.insert(tk.END, "=== Capture Log ===\n\n")
        log_text.insert(tk.END, f"Interface: {self.iface_combo.get()}\n")
        log_text.insert(
            tk.END, f"Total packets: {len(self.backend.captured_packets)}\n"
        )
        log_text.insert(tk.END, "\nPacket Statistics:\n")
        stats = self.backend.get_stats()
        for proto, count in stats.items():
            log_text.insert(tk.END, f"{proto}: {count}\n")

        log_text.config(state="disabled")

    def packet_reassembly(self):
        """Show dialog for packet reassembly options."""
        if self.backend.is_sniffing:
            messagebox.showwarning(
                "Warning", "Please stop capturing before reassembling packets."
            )
            return
        reassembly_dialog = tk.Toplevel(self)
        reassembly_dialog.title("Packet Reassembly")
        reassembly_dialog.geometry("400x300")

        ttk.Label(reassembly_dialog, text="Select reassembly options:").pack(pady=10)

        self.reassembly_var = tk.StringVar(value="tcp")
        ttk.Radiobutton(
            reassembly_dialog,
            text="TCP Stream",
            variable=self.reassembly_var,
            value="tcp",
        ).pack(anchor="w", padx=20)
        ttk.Radiobutton(
            reassembly_dialog,
            text="UDP Stream",
            variable=self.reassembly_var,
            value="udp",
        ).pack(anchor="w", padx=20)
        ttk.Radiobutton(
            reassembly_dialog,
            text="HTTP Session",
            variable=self.reassembly_var,
            value="http",
        ).pack(anchor="w", padx=20)

        ttk.Button(
            reassembly_dialog, text="Reassemble", command=self.perform_reassembly
        ).pack(pady=20)

    def perform_reassembly(self):
        """
        FINAL VERSION: 执行所选的重组操作。
        此函数现在与基于序列号的后台重组引擎完全兼容。
        """
        method = self.reassembly_var.get()

        if method == "tcp":
            # 调用更新后的后台函数获取TCP会话摘要
            summary = self.backend.get_tcp_stream_summary()
            if not summary:
                messagebox.showinfo("Reassembly", "没有找到可以重组的TCP会话。")
                return

            # 创建新窗口以显示摘要
            reassembly_window = tk.Toplevel(self)
            reassembly_window.title("TCP会话摘要")
            reassembly_window.geometry("900x600")

            # 创建一个带滚动条的Treeview来显示会话
            tree_frame = ttk.Frame(reassembly_window)
            tree_frame.pack(expand=True, fill="both", padx=10, pady=10)
            
            # 创建Treeview
            columns = ("Session", "Protocol", "Size", "Client→Server", "Server→Client")
            session_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=15)
            
            # 设置列标题
            session_tree.heading("Session", text="会话")
            session_tree.heading("Protocol", text="协议")
            session_tree.heading("Size", text="总大小")
            session_tree.heading("Client→Server", text="客户端→服务器")
            session_tree.heading("Server→Client", text="服务器→客户端")
            
            # 设置列宽
            session_tree.column("Session", width=300)
            session_tree.column("Protocol", width=80)
            session_tree.column("Size", width=100)
            session_tree.column("Client→Server", width=120)
            session_tree.column("Server→Client", width=120)
            
            # 添加滚动条
            scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=session_tree.yview)
            session_tree.configure(yscrollcommand=scrollbar.set)
            
            # 填充数据
            for stream in summary:
                session = f"{stream['src']}:{stream['sport']} ↔ {stream['dst']}:{stream['dport']}"
                protocol = stream.get('protocol', 'TCP')
                size = f"{stream['length']} bytes"
                
                # 获取详细的流统计信息
                session_key = stream.get('session_key')
                if session_key:
                    stats = self.backend.tcp_reassembler.get_stream_statistics(session_key)
                    if stats:
                        c2s = f"{stats['client_to_server_bytes']} bytes"
                        s2c = f"{stats['server_to_client_bytes']} bytes"
                    else:
                        c2s = s2c = "N/A"
                else:
                    c2s = s2c = "N/A"
                
                session_tree.insert("", "end", values=(session, protocol, size, c2s, s2c))
            
            # 布局
            session_tree.pack(side="left", expand=True, fill="both")
            scrollbar.pack(side="right", fill="y")
            
            # 添加按钮框架
            button_frame = ttk.Frame(reassembly_window)
            button_frame.pack(fill="x", padx=10, pady=5)
            
            def view_selected_session():
                selected = session_tree.selection()
                if selected:
                    item = session_tree.item(selected[0])
                    values = item['values']
                    messagebox.showinfo("Session Details", f"Selected session: {values[0]}")
            
            ttk.Button(button_frame, text="View Details", command=view_selected_session).pack(side="left", padx=5)
            ttk.Button(button_frame, text="Close", command=reassembly_window.destroy).pack(side="right", padx=5)

        elif method == "http":
            # HTTP重组对话框（增强版）
            conversations = self.backend.get_all_http_conversations()
            if not conversations:
                messagebox.showinfo(
                    "HTTP Reassembly", "没有找到可以重组的完整HTTP会话。"
                )
                return

            # 创建新窗口以显示重组后的HTTP内容
            http_window = tk.Toplevel(self)
            http_window.title("HTTP会话分析器")
            http_window.geometry("1000x700")

            # 创建一个PanedWindow来分割界面
            paned = ttk.PanedWindow(http_window, orient="horizontal")
            paned.pack(expand=True, fill="both", padx=10, pady=10)
            
            # 左侧：会话列表
            left_frame = ttk.Frame(paned)
            paned.add(left_frame, weight=1)
            
            ttk.Label(left_frame, text="HTTP会话列表", font=("Arial", 10, "bold")).pack(pady=5)
            
            # 会话列表
            session_listbox = tk.Listbox(left_frame, width=40)
            session_listbox.pack(expand=True, fill="both", padx=5)
            
            # 解析所有会话并提取摘要信息
            all_parsed_sessions = []
            for i, conv_text in enumerate(conversations):
                # 从会话文本中提取基本信息
                lines = conv_text.split('\n')
                session_info = lines[0] if lines else f"Session #{i+1}"
                session_listbox.insert(tk.END, session_info)
                
                # 解析会话内容
                # 这里需要从原始TCP流重新获取数据
                all_parsed_sessions.append(conv_text)
            
            # 右侧：详细内容显示
            right_frame = ttk.Frame(paned)
            paned.add(right_frame, weight=3)
            
            # 创建Notebook来显示不同视图
            detail_notebook = ttk.Notebook(right_frame)
            detail_notebook.pack(expand=True, fill="both")
            
            # Raw视图
            raw_frame = ttk.Frame(detail_notebook)
            raw_text = scrolledtext.ScrolledText(raw_frame, wrap=tk.WORD)
            raw_text.pack(expand=True, fill="both")
            detail_notebook.add(raw_frame, text="Raw Data")
            
            # Formatted视图
            formatted_frame = ttk.Frame(detail_notebook)
            formatted_text = scrolledtext.ScrolledText(formatted_frame, wrap=tk.WORD)
            formatted_text.pack(expand=True, fill="both")
            detail_notebook.add(formatted_frame, text="Formatted")
            
            # 按钮框架
            button_frame = ttk.Frame(right_frame)
            button_frame.pack(fill="x", pady=5)
            
            open_browser_btn = ttk.Button(
                button_frame, 
                text="在浏览器中打开",
                state="disabled"
            )
            open_browser_btn.pack(side="left", padx=5)
            
            export_btn = ttk.Button(
                button_frame,
                text="导出会话",
                state="disabled"
            )
            export_btn.pack(side="left", padx=5)
            
            # 选择事件处理
            def on_session_select(event):
                selection = session_listbox.curselection()
                if selection:
                    idx = selection[0]
                    # 显示原始数据
                    raw_text.config(state="normal")
                    raw_text.delete(1.0, tk.END)
                    raw_text.insert(tk.END, all_parsed_sessions[idx])
                    raw_text.config(state="disabled")
                    
                    # TODO: 这里可以添加更多格式化显示
                    formatted_text.config(state="normal")
                    formatted_text.delete(1.0, tk.END)
                    formatted_text.insert(tk.END, "Formatted view coming soon...")
                    formatted_text.config(state="disabled")
            
            session_listbox.bind("<<ListboxSelect>>", on_session_select)
            
            # 关闭按钮
            ttk.Button(http_window, text="关闭", command=http_window.destroy).pack(pady=10)

        else:
            # 其他协议的占位符
            messagebox.showinfo(
                "Reassembly", f"对 {method.upper()} 协议的重组功能尚未实现。"
            )

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
        self.backend.clear_captured_packets()  # Clear backend data

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
        self.after_idle(self._insert_packet_data)  # 不再传递具体信息

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

        # --- Clear previous content in text widgets ---
        for widget in [self.details_text, self.data_text]:
            widget.config(state="normal")
            widget.delete(1.0, tk.END)

        # 重置HTTP相关按钮状态
        self.open_browser_button.config(state="disabled")
        self.open_raw_html_button.config(state="disabled")
        self.export_http_button.config(state="disabled")
        self.current_http_messages = None

        item_id = selected_item[0]
        values = self.tree.item(item_id)["values"]
        if not values:
            self.details_text.insert(tk.END, "No details available.")
            self.details_text.config(state="disabled")
            self.data_text.config(state="disabled")
            return

        packet_id = int(values[0]) - 1  # Get the packet index
        if not (0 <= packet_id < len(self.backend.captured_packets)):
            self.details_text.insert(tk.END, "Packet data not found.")
            self.details_text.config(state="disabled")
            self.data_text.config(state="disabled")
            return

        # --- Tab 1: Populate Packet Details (Raw Scapy Output) ---
        raw_details = self.backend.captured_packets[packet_id][1]
        self.details_text.insert(tk.END, raw_details)

        # --- Tab 2: Populate Reassembled Data (TCP/HTTP) ---
        packet_summary = self.backend.captured_packets[packet_id][0]
        proto = packet_summary[3]

        if proto in ("TCP", "HTTP", "HTTPS"):
            # Get the full data stream associated with this packet
            stream_data, stream_key = self.backend.get_tcp_stream_content(packet_id)

            if stream_data:
                # If it's an HTTP packet, try to parse the content
                if proto == "HTTP":
                    # 解析HTTP消息
                    self.current_http_messages = self.http_viewer.parse_http_message(
                        stream_data
                    )

                    if self.current_http_messages:
                        # Tab 2: 显示原始重组数据
                        header = f"--- HTTP Session (Stream: {stream_key}) ---\n\n"
                        raw_display = self.backend._parse_http_data(stream_data)
                        self.data_text.insert(tk.END, header + raw_display)

                        # Tab 3: 显示美化的HTTP内容
                        formatted_text = self.http_viewer.create_formatted_text_view(
                            self.current_http_messages
                        )
                        self.http_view_text.insert(tk.END, formatted_text)

                        # 启用HTTP相关按钮
                        self.open_browser_button.config(state="normal")
                        self.export_http_button.config(state="normal")

                        # 检查是否有HTML响应
                        for msg in self.current_http_messages:
                            if msg.get("type") == "response" and msg.get("is_html"):
                                self.open_raw_html_button.config(state="normal")
                                break
                else:
                    header = f"--- Showing Reassembled TCP Stream (Stream: {stream_key}) ---\n\n"
                    # Displaying raw bytes can be messy, so we decode with 'latin-1'
                    # which can represent any byte value without error.
                    self.data_text.insert(
                        tk.END, header + stream_data.decode("latin-1", errors="ignore")
                    )
            else:
                self.data_text.insert(
                    tk.END, "No TCP stream data available for this packet."
                )
        else:
            self.data_text.insert(
                tk.END, "Data reassembly is only available for TCP-based protocols."
            )

        # --- Set text widgets to disabled after populating ---
        self.details_text.config(state="disabled")
        self.data_text.config(state="disabled")

    def save_to_txt(self):
        """Saves the captured packet summaries to a text file."""
        if self.backend.is_sniffing:
            messagebox.showwarning(
                "Warning", "Please stop capturing before saving packets."
            )
            return
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

    def _open_http_in_browser(self):
        """在浏览器中打开HTTP会话的HTML预览"""
        if not self.current_http_messages:
            messagebox.showwarning("Warning", "No HTTP content to display")
            return

        success, result = self.http_viewer.save_and_open_in_browser(
            self.current_http_messages
        )
        if success:
            messagebox.showinfo(
                "Success", f"HTTP session opened in browser.\nTemp file: {result}"
            )
        else:
            messagebox.showerror("Error", f"Failed to open in browser: {result}")

    def _open_raw_html(self):
        """在浏览器中打开原始HTML响应"""
        if not self.current_http_messages:
            messagebox.showwarning("Warning", "No HTTP content available")
            return

        success, result = self.http_viewer.save_raw_html_response(
            self.current_http_messages
        )
        if success:
            messagebox.showinfo(
                "Success", f"Raw HTML opened in browser.\nTemp file: {result}"
            )
        else:
            messagebox.showerror("Error", f"Failed to open HTML: {result}")

    def _export_http_session(self):
        """导出HTTP会话"""
        if not self.current_http_messages:
            messagebox.showwarning("Warning", "No HTTP content to export")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[
                ("HTML files", "*.html"),
                ("JSON files", "*.json"),
                ("All files", "*.*"),
            ],
            title="Export HTTP Session As",
        )

        if not file_path:
            return

        try:
            if file_path.endswith(".json"):
                # 导出为JSON格式
                with open(file_path, "w", encoding="utf-8") as f:
                    json_data = []
                    for msg in self.current_http_messages:
                        # 移除一些不适合JSON序列化的字段
                        clean_msg = {
                            k: v
                            for k, v in msg.items()
                            if k not in ["parsed_body"]
                            or not isinstance(v, str)
                            or len(v) < 10000
                        }
                        json_data.append(clean_msg)
                    json.dump(json_data, f, indent=2, ensure_ascii=False)
            else:
                # 导出为HTML格式
                html_content = self.http_viewer.create_html_preview(
                    self.current_http_messages
                )
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(html_content)

            messagebox.showinfo("Success", f"HTTP session exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {str(e)}")

    def export_to_pcap(self):
        """Exports captured packets to a PCAP file."""
        if self.backend.is_sniffing:
            messagebox.showwarning(
                "Warning", "Please stop capturing before exporting packets."
            )
            return
        if not self.backend.captured_packets:
            messagebox.showinfo("Info", "There are no packets to export.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
            title="Export Packets To PCAP",
        )
        if not file_path:
            return

        # Call the backend method to save packets in PCAP format
        self.backend.export_to_pcap(file_path)
        messagebox.showinfo("Success", f"Packets exported to {file_path}")

    def import_from_pcap(self):
        """Imports packets from a PCAP file."""
        if self.backend.is_sniffing:
            messagebox.showwarning(
                "Warning", "Please stop capturing before importing packets."
            )
            return
        file_path = filedialog.askopenfilename(
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
            title="Import Packets From PCAP",
        )
        if not file_path:
            return

        try:
            self.backend.import_from_pcap(file_path)
            messagebox.showinfo("Success", f"Packets imported from {file_path}")
            # Refresh the Treeview with the newly imported packets
            self.tree.delete(*self.tree.get_children())
            for idx, (summary, _) in enumerate(self.backend.captured_packets):
                self.tree.insert("", "end", values=(idx + 1,) + summary, tags=(summary[3],))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import packets: {str(e)}")