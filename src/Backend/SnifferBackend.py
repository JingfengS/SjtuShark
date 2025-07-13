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
        self.tcp_streams = {}  # Dictionary to store TCP streams
        # Key 现在是单向的 (src_ip, src_port, dst_ip, dport)
        # Value 是一个字典，包含重组所需的状态

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
                # --- THIS ENTIRE BLOCK IS REWRITTEN FOR TRUE REASSEMBLY ---
                proto = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                payload = bytes(packet[TCP].payload)

                # TCP重组需要为每个方向的流维护独立的状态
                stream_key = (src_addr, sport, dst_addr, dport)

                # 如果是新流，初始化其状态
                if stream_key not in self.tcp_streams:
                    self.tcp_streams[stream_key] = {
                        "expected_seq": packet[TCP].seq,  # 初始期望值
                        "buffer": {},  # 乱序包的缓存
                        "data": b"",  # 重组后的数据
                    }

                stream = self.tcp_streams[stream_key]

                # 如果是期望的包，或流刚刚初始化
                if packet[TCP].seq == stream["expected_seq"]:
                    # 1. 将当前包的载荷附加到数据中
                    stream["data"] += payload
                    stream["expected_seq"] += len(payload)

                    # 2. 检查缓存中是否有可以“解锁”的、紧随其后的包
                    while stream["expected_seq"] in stream["buffer"]:
                        buffered_payload = stream["buffer"].pop(stream["expected_seq"])
                        stream["data"] += buffered_payload
                        stream["expected_seq"] += len(buffered_payload)

                # 如果是乱序（未来）的包，并且有载荷，则放入缓存
                elif payload and packet[TCP].seq > stream["expected_seq"]:
                    # 只有当这个包我们没有收到过时才缓存
                    if packet[TCP].seq not in stream["buffer"]:
                        stream["buffer"][packet[TCP].seq] = payload

                # --- 更新GUI显示信息 (info) ---
                flag_str = "".join(
                    [TCP_FLAGS.get(f, f) for f in str(packet[TCP].flags)]
                )
                info = f"{sport} -> {dport} [{flag_str}] Seq: {packet[TCP].seq} Ack: {packet[TCP].ack}"
                self.stats["tcp_total"] += 1

                # --- 更新协议判断逻辑 (HTTP/HTTPS) ---
                # 这个判断逻辑本身可以保持不变
                combined_data = stream["data"]  # 使用重组后的数据来判断
                raw_payload_str = combined_data.decode(errors="ignore").upper()
                if sport == 80 or dport == 80:
                    if "HTTP" in raw_payload_str:  # 检查整个重组流
                        proto = "HTTP"
                elif sport == 443 or dport == 443:
                    # TLS握手通常在流的开始
                    if combined_data.startswith(b"\x16\x03"):
                        proto = "HTTPS"

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
        self.tcp_streams.clear()
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
        summary = []
        processed_streams = set()  # 用来存放已处理过的反向流key，避免重复计算

        for stream_key, stream_obj in self.tcp_streams.items():
            # 如果这个key是作为反向流被处理过的，就跳过
            if stream_key in processed_streams:
                continue

            (src, sport, dst, dport) = stream_key
            reverse_key = (dst, dport, src, sport)

            # 计算会话双向的总数据长度
            total_length = len(stream_obj["data"])
            if reverse_key in self.tcp_streams:
                total_length += len(self.tcp_streams[reverse_key]["data"])
                # 将反向key加入已处理集合
                processed_streams.add(reverse_key)

            summary.append(
                {
                    "src": src,
                    "sport": sport,
                    "dst": dst,
                    "dport": dport,
                    "length": total_length,
                }
            )
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

        # 定义会话的双向流key
        key_forward = (
            packet[IP].src,
            packet[TCP].sport,
            packet[IP].dst,
            packet[TCP].dport,
        )
        key_reverse = (
            packet[IP].dst,
            packet[TCP].dport,
            packet[IP].src,
            packet[TCP].sport,
        )

        # 从两个方向收集数据
        conversation_data = b""
        if key_forward in self.tcp_streams:
            conversation_data += self.tcp_streams[key_forward]["data"]
        if key_reverse in self.tcp_streams:
            # 在实际的HTTP解析中，将两个方向的数据混合可能不理想
            # 但为了显示，我们这里将它们拼接
            conversation_data += self.tcp_streams[key_reverse]["data"]

        return conversation_data, (key_forward, key_reverse)

    def get_http_content(self, raw_data):
        """
        Parses raw byte data, checks for HTTP, and returns decoded/decompressed content.
        """
        if not raw_data:
            return "No data in stream."

        try:
            # Try to decode as HTTP response
            headers_part, body = raw_data.split(b"\r\n\r\n", 1)
            headers_str = headers_part.decode("utf-8", errors="ignore")
            headers = dict(
                line.split(": ", 1)
                for line in headers_str.split("\r\n")[1:]
                if ": " in line
            )

            content = body
            # Handle Gzip decompression
            if headers.get("Content-Encoding") == "gzip":
                try:
                    content = zlib.decompress(body, 16 + zlib.MAX_WBITS)
                except zlib.error:
                    return "[Gzip Decompression Failed]\n\n" + body.decode("latin-1")

            # Check for HTML and pretty-print it
            if "text/html" in headers.get("Content-Type", ""):
                try:
                    soup = BeautifulSoup(content, "html.parser")
                    return soup.prettify()
                except Exception:
                    return content.decode("utf-8", errors="ignore")

            # Return plain text or other content types
            return content.decode("utf-8", errors="ignore")

        except (ValueError, UnicodeDecodeError):
            # If splitting or decoding fails, it might be a request or not HTTP at all.
            # Return the raw data representation.
            return raw_data.decode("latin-1", errors="ignore")

    def get_all_http_conversations(self):
        """
        MODIFIED: 遍历所有流来寻找和重组HTTP会话。
        """
        http_conversations = []
        processed_streams = set()  # 防止双向流被处理两次

        for stream_key, stream_obj in self.tcp_streams.items():
            if stream_key in processed_streams:
                continue

            # 找到反向流的key
            (src, sport, dst, dport) = stream_key
            reverse_key = (dst, dport, src, sport)

            # 将双向流的数据合并
            full_data = stream_obj["data"]
            if reverse_key in self.tcp_streams:
                full_data += self.tcp_streams[reverse_key]["data"]
                processed_streams.add(reverse_key)

            # 检查合并后的数据是否包含HTTP
            stream_start = full_data[:1024]
            if (
                b"HTTP" in stream_start
                or b"GET" in stream_start
                or b"POST" in stream_start
            ):
                # 后续逻辑与之前类似...
                parsed_content = self.get_http_content(full_data)
                try:
                    first_line = full_data.decode("latin-1").splitlines()[0]
                except IndexError:
                    first_line = "Unknown HTTP Message"

                conversation_summary = (
                    f"--- Conversation between {src}:{sport} and {dst}:{dport} ---\n"
                    f"--- Reassembled Content ---\n"
                    f"{parsed_content}\n\n{'='*70}\n\n"
                )
                http_conversations.append(conversation_summary)

        return http_conversations
