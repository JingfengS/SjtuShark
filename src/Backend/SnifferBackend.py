import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import scapy.all as scapy
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
import threading
import datetime
import platform
from pyparsing import (
    Word,
    alphas,
    alphanums,
    oneOf,
    infixNotation,
    opAssoc,
    ParserElement,
    Literal,
    ParseException,
    Group,
)
import zlib
from bs4 import BeautifulSoup
from .TCP_Assembler import ImprovedTCPReassembler

# --- Backend Logic ---

# <<< ADDED: Dictionaries for human-readable descriptions >>>
TCP_FLAGS = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}

ICMP_TYPES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded",
}
# <<< END ADDED SECTION >>>


class SnifferBackend:
    """
    Handles all the packet sniffing and processing logic.
    """

    def __init__(self, gui_callback):
        self.is_sniffing = False
        self.sniffer_thread = None
        self.gui_callback = gui_callback
        self.captured_packets = []  # List to store captured packets
        self.captured_packets_raw = []  # List to store raw captured packets
        self.tcp_reassembler = ImprovedTCPReassembler()

        self.stats = {  # Dictionary to store statistics
            "ip_total": 0,
            "tcp_total": 0,
            "udp_total": 0,
            "icmp_total": 0,
            "http_total": 0,
            "https_total": 0,
            "arp_total": 0,
            "ethernet_total": 0,
        }

    def get_network_interfaces(self):
        """
        Returns a list of available network interfaces.
        """
        # Using a set to avoid duplicate interface names
        interfaces = set()
        # scapy.get_if_list() returns a list of interface names
        # We also check the main route table for more human-friendly names
        for iface in scapy.get_if_list():
            interfaces.add(iface)

        # On Windows, names can be complex, let's try to get descriptions
        if platform.system() == "Windows":
            try:
                # This provides more descriptive names on Windows
                from scapy.arch.windows import get_windows_if_list

                win_ifaces = get_windows_if_list()
                return [iface["name"] for iface in win_ifaces if "name" in iface]
            except ImportError:
                return list(interfaces)  # Fallback for other systems
        return list(interfaces)

    def start_sniffing(self, interface, capture_filter=""):
        """
        Starts the sniffing process on a separate thread.
        """
        if not interface:
            # Using messagebox to show error in GUI context
            messagebox.showerror("Error", "Please select a network interface first.")
            return

        self.is_sniffing = True
        # The sniff function is blocking, so we run it in a thread
        self.sniffer_thread = threading.Thread(
            target=lambda: scapy.sniff(
                iface=interface,
                prn=self._process_packet,
                stop_filter=self._stop_sniffing_filter,
                filter=(
                    capture_filter if capture_filter else None
                ),  # Sniff with filter if provided, to be implemented in SnifferGUI
            ),
            daemon=True,
        )
        self.sniffer_thread.start()

    def stop_sniffing(self):
        """
        Signals the sniffing thread to stop.
        """
        self.is_sniffing = False

    def _stop_sniffing_filter(self, packet):
        """
        A filter function for scapy's sniff to check if sniffing should stop.
        """
        return not self.is_sniffing

    def _process_packet(self, packet):
        """
        This function is called for each packet captured by Scapy.
        It parses the packet and sends the data to the GUI.
        """
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

        # Default values
        src_addr, dst_addr, proto, info = "N/A", "N/A", "N/A", ""

        # --- Packet Parsing ---
        if ARP in packet:
            proto = "ARP"
            src_addr = packet[ARP].psrc
            dst_addr = packet[ARP].pdst
            if packet[ARP].op == 1:  # who-has
                info = f"Who has {dst_addr}? Tell {src_addr}"
            else:  # is-at
                info = f"At {src_addr} is-at {packet[ARP].hwsrc}"
            self.stats["arp_total"] += 1

        elif IP in packet:
            src_addr = packet[IP].src
            dst_addr = packet[IP].dst
            self.stats["ip_total"] += 1
            if TCP in packet:
                # --- REVISED TCP & HTTP HANDLING BLOCK ---
                result = self.tcp_reassembler.process_packet(packet)

                if result:
                    stream = result["stream"]
                    proto = stream["protocol"]  # TCP, HTTP, 或 HTTPS

                    # 生成显示信息
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    tcp_flags = self._get_tcp_flags_string(packet[TCP].flags)

                    if proto == "HTTPS":
                        info = f"{sport} -> {dport} Encrypted TLS/SSL [{tcp_flags}]"
                    elif proto == "HTTP":
                        # 可以添加更多HTTP特定信息
                        info = f"{sport} -> {dport} HTTP Traffic [{tcp_flags}]"
                    else:
                        info = f"{sport} -> {dport} [{tcp_flags}] Seq:{packet[TCP].seq}"

                    # 更新统计
                    self.stats["tcp_total"] += 1
                    if proto == "HTTP":
                        self.stats["http_total"] += 1
                    elif proto == "HTTPS":
                        self.stats["https_total"] += 1
                else:
                    # 如果处理失败，使用基本信息
                    proto = "TCP"
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    tcp_flags = self._get_tcp_flags_string(packet[TCP].flags)
                    info = f"{sport} -> {dport} [{tcp_flags}]"
                    self.stats["tcp_total"] += 1

            elif UDP in packet:
                proto = "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                if sport == 53 or dport == 53:
                    info = f"DNS Query/Response: {sport} -> {dport}"
                else:
                    info = f"Src Port: {sport} -> Dst Port: {dport} Length: {packet[UDP].len}"
                self.stats["udp_total"] += 1

            elif ICMP in packet:
                proto = "ICMP"
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                type_desc = ICMP_TYPES.get(icmp_type, f"Type {icmp_type}")
                if icmp_type == 8:  # Echo Request
                    info = f"{type_desc} (ping)"
                elif icmp_type == 0:  # Echo Reply
                    info = f"{type_desc} (pong)"
                else:
                    info = f"{type_desc} (Code: {icmp_code})"
                self.stats["icmp_total"] += 1

            else:
                proto = "IP"
                info = f"Protocol: {packet[IP].proto}"

        elif Ether in packet:
            proto = "Ethernet"
            src_addr = packet[Ether].src
            dst_addr = packet[Ether].dst
            info = f"EtherType: {hex(packet[Ether].type)}"
            self.stats["ethernet_total"] += 1

        # Prepare data for GUI
        packet_summary = (timestamp, src_addr, dst_addr, proto, info)
        packet_details = packet.show(dump=True)  # Full packet details for the text view
        self.captured_packets_raw.append(packet)
        self.captured_packets.append(
            (packet_summary, packet_details)
        )  # Save captured packets
        # Use the callback to update the GUI safely from this thread
        self.gui_callback(packet_summary, packet_details)

    def _get_tcp_flags_string(self, flags):
        """获取TCP标志位的字符串表示"""
        flag_list = []
        if flags & 0x01:
            flag_list.append("FIN")
        if flags & 0x02:
            flag_list.append("SYN")
        if flags & 0x04:
            flag_list.append("RST")
        if flags & 0x08:
            flag_list.append("PSH")
        if flags & 0x10:
            flag_list.append("ACK")
        if flags & 0x20:
            flag_list.append("URG")
        if flags & 0x40:
            flag_list.append("ECE")
        if flags & 0x80:
            flag_list.append("CWR")
        return ",".join(flag_list) if flag_list else "NONE"

    def match(self, summary, expr=""):
        """
        Matches a packet summary against a filter expression and raise ValueError if the expression is invalid.
        Format: key=value, with logical operators: and, or, not, and parentheses
        Keys can be "proto", "src", "dst".
        Example: "not (proto=TCP or src=192.168.1.1) and dst=8.8.8.8"
        """
        if not expr or not expr.strip():
            return True

        ParserElement.enablePackrat()

        # Define the grammar for the filter expression
        key = oneOf("proto src dst")
        value = Word(alphanums + ".:")
        cond = key + Literal("=").suppress() + value

        def cond_action(tokens):
            k, v = tokens[0], tokens[1]
            v = v.lower()
            if k == "proto":
                return summary[0][3].lower() == v  # summary[0] 是 5 元组
            elif k == "src":
                return v in summary[0][1].lower()
            elif k == "dst":
                return v in summary[0][2].lower()
            else:
                raise ValueError(f"Invalid key in filter expression: {k}")

        cond.setParseAction(cond_action)

        # Define logical operators
        and_op = Literal("and") | "&&"
        or_op = Literal("or") | "||"
        not_op = Literal("not") | "!"

        expr_parser = infixNotation(
            cond,
            [
                (not_op, 1, opAssoc.RIGHT, lambda t: not t[0][1]),
                (and_op, 2, opAssoc.LEFT, lambda t: t[0][0] and t[0][2]),
                (or_op, 2, opAssoc.LEFT, lambda t: t[0][0] or t[0][2]),
            ],
        )

        try:
            result = expr_parser.parseString(expr, parseAll=True)[0]
            return bool(result)
        except ParseException as e:
            raise ValueError(f"Invalid filter expression: {e}\nExpression: {expr}")

    def query_packets(self, expr=""):
        """
        Query filter
        """
        results = []
        for summary in self.captured_packets:
            if self.match(summary, expr):
                results.append(summary)
        return results

    def delete_packet(self, packet_id):
        """
        Deletes a packet by its ID.
        """
        if 0 <= packet_id < len(self.captured_packets):
            summary = self.captured_packets[packet_id][0]
            proto = summary[3]
            if proto == "HTTP":
                self.stats["http_total"] -= 1
                self.stats["tcp_total"] -= 1
                self.stats["ip_total"] -= 1
            elif proto == "HTTPS":
                self.stats["https_total"] -= 1
                self.stats["tcp_total"] -= 1
                self.stats["ip_total"] -= 1
            elif proto == "TCP":
                self.stats["tcp_total"] -= 1
                self.stats["ip_total"] -= 1
            elif proto == "UDP":
                self.stats["udp_total"] -= 1
                self.stats["ip_total"] -= 1
            elif proto == "ICMP":
                self.stats["icmp_total"] -= 1
                self.stats["ip_total"] -= 1
            elif proto == "IP":
                self.stats["ip_total"] -= 1
            elif proto == "ARP":
                self.stats["arp_total"] -= 1
            elif proto == "Ethernet":
                self.stats["ethernet_total"] -= 1
            del self.captured_packets[packet_id]
            del self.captured_packets_raw[packet_id]
            return True
        return False

    def clear_captured_packets(self):
        """
        Clears the captured packets list.
        """
        self.captured_packets.clear()
        self.captured_packets_raw.clear()
        self.tcp_reassembler.tcp_streams.clear()
        for k in self.stats:
            self.stats[k] = 0
        return True

    def save_captured_packets(self, file_path):
        """
        Saves all captured packet summaries to a text file.
        """
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("--- Captured Packets ---\n\n")
            for idx, (summary, details) in enumerate(self.captured_packets):
                f.write(
                    f"Packet #{idx+1}: Time={summary[0]}, Src={summary[1]}, Dst={summary[2]}, Proto={summary[3]}, Info={summary[4]}\n"
                )
                f.write("-" * 20 + " Details " + "-" * 20 + "\n")
                f.write(details)
                f.write("\n\n")

    def get_stats(self):
        return dict(self.stats)

    def export_to_pcap(self, file_path):
        """
        Exports captured packets to a pcap file.
        """
        if self.captured_packets_raw:
            scapy.wrpcap(file_path, self.captured_packets_raw)

    def import_from_pcap(self, file_path):
        """
        Imports packets from a pcap file and processes them.
        """
        self.clear_captured_packets()
        pkts = scapy.rdpcap(file_path)
        for packet in pkts:
            self._process_packet(packet)

    def get_tcp_stream_summary(self):
        """
        modified: 从新的、真正的重组引擎中返回tcp会话的摘要。
        这个函数会把双向流合并为一个会话进行统计。
        """
        raw = self.tcp_reassembler.get_all_streams()
        summary = []
        for item in raw:
            stats = item["summary"]
            summary.append({
                "session_key": item["session_key"],
                "src":   stats["client"][0],
                "sport": stats["client"][1],
                "dst":   stats["server"][0],
                "dport": stats["server"][1],
                "length": stats["client_to_server_bytes"]
                        + stats["server_to_client_bytes"],
                "protocol": stats["protocol"],
            })
        return summary

    # --- ADDED: New methods for data reassembly and parsing ---
    def get_tcp_stream_content(self, packet_id):
        """
        MODIFIED: 查找一个数据包所属会话的双向数据流。
        """
        if not (0 <= packet_id < len(self.captured_packets_raw)):
            return None, None

        packet = self.captured_packets_raw[packet_id]
        if not packet.haslayer(TCP):
            return None, None
        # 获取流标识符
        stream_key = self.tcp_reassembler.get_stream_key(packet)
        session_key = self.tcp_reassembler.get_bidirectional_key(stream_key)

        if not session_key:
            return None, None

        # 获取双向数据
        stream_data = self.tcp_reassembler.get_stream_data(session_key, "both")

        if stream_data:
            # 合并双向数据用于显示
            combined_data = (
                stream_data["client_to_server"]
                + b"\n=== Server Response ===\n"
                + stream_data["server_to_client"]
            )
            return combined_data, session_key

        return None, None

    def get_all_http_conversations(self):
        """获取所有HTTP会话"""
        http_conversations = []

        # 获取所有TCP流
        all_streams = self.tcp_reassembler.get_all_streams()

        for stream_info in all_streams:
            session_key = stream_info["session_key"]
            summary = stream_info["summary"]

            # 只处理HTTP流
            if summary["protocol"] != "HTTP":
                continue

            # 获取流数据
            stream_data = self.tcp_reassembler.get_stream_data(session_key, "both")

            if stream_data:
                # 解析HTTP内容
                client_data = stream_data["client_to_server"]
                server_data = stream_data["server_to_client"]

                # 创建会话摘要
                client_str = f"{summary['client'][0]}:{summary['client'][1]}"
                server_str = f"{summary['server'][0]}:{summary['server'][1]}"

                conversation = (
                    f"=== HTTP Conversation: {client_str} <-> {server_str} ===\n\n"
                    f"--- Client Request ---\n"
                    f"{self._parse_http_data(client_data, 'request')}\n\n"
                    f"--- Server Response ---\n"
                    f"{self._parse_http_data(server_data, 'response')}\n\n"
                    f"{'='*70}\n\n"
                )

                http_conversations.append(conversation)

        return http_conversations

    def _parse_http_data(self, data, direction="request"):
        """解析HTTP数据"""
        if not data:
            return "No data"

        try:
            # 解码为字符串
            text = data.decode("utf-8", errors="ignore")

            # 分离头部和正文
            parts = text.split("\r\n\r\n", 1)
            headers = parts[0]
            body = parts[1] if len(parts) > 1 else ""

            # 格式化输出
            result = headers

            if body:
                # 检查是否是HTML
                if "<html" in body.lower() or "<!doctype" in body.lower():
                    result += "\n\n[HTML Content - {} bytes]".format(len(body))
                else:
                    # 显示前500个字符
                    if len(body) > 500:
                        result += f"\n\n{body[:500]}...\n[Truncated - Total {len(body)} bytes]"
                    else:
                        result += f"\n\n{body}"

            return result

        except Exception as e:
            return f"Error parsing HTTP data: {str(e)}"
