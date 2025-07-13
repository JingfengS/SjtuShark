import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import scapy.all as scapy
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
import threading
import datetime
import platform
from pyparsing import Word, alphas, alphanums, oneOf, infixNotation, opAssoc, ParserElement, Literal, ParseException, Group
import zlib
from bs4 import BeautifulSoup

# --- Backend Logic ---

# <<< ADDED: Dictionaries for human-readable descriptions >>>
TCP_FLAGS = {
    "F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
    "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR",
}

ICMP_TYPES = {
    0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench",
    5: "Redirect", 8: "Echo Request", 11: "Time Exceeded",
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
                filter=capture_filter if capture_filter else None,  # Sniff with filter if provided, to be implemented in SnifferGUI
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
                proto = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                flag_str = "".join([TCP_FLAGS[f] for f in str(packet[TCP].flags)])
                info = f"{sport} -> {dport} [{flag_str}]"
                self.stats["tcp_total"] += 1

                 # --- MODIFIED: Handle TCP Stream Reassembly ---
                payload = bytes(packet[TCP].payload)
                if payload:
                    # Create a key for the stream, ensuring client->server and server->client packets
                    # map to the same stream. We sort the (IP, port) tuples to make the key consistent.
                    stream_key = tuple(sorted(((src_addr, sport), (dst_addr, dport))))
                    if stream_key not in self.tcp_streams:
                        self.tcp_streams[stream_key] = b''
                    self.tcp_streams[stream_key] += payload

                # Check for HTTP/HTTPS
                raw_payload_str = payload.decode(errors='ignore').upper()
                if sport == 80 or dport == 80:
                    if "HTTP" in raw_payload_str or any(verb in raw_payload_str for verb in ["GET", "POST", "PUT"]):
                        proto = "HTTP"
                        try:
                            first_line = payload.decode(errors='ignore').split("\r\n")[0]
                            info = f"HTTP Packet: {first_line}"
                            self.stats["http_total"] += 1
                        except:
                            info = "HTTP Packet (undecoded)"
                elif sport == 443 or dport == 443 or payload.startswith(b"\x16\x03"):
                    proto = "HTTPS"
                    info = "Encrypted TLS/SSL Data"
                    self.stats["https_total"] += 1

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
        self.captured_packets.append((packet_summary, packet_details))  # Save captured packets 
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
            ]
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
        Returns a summary of TCP streams.
        """
        summary = []
        # self.tcp_streams 的键是排序后的元组：((ip1, port1), (ip2, port2))
        for stream_key, data in self.tcp_streams.items():
            # 解包 stream_key 来获取源和目标信息
            (addr1, port1), (addr2, port2) = stream_key
            summary.append({
                "src": addr1,
                "sport": port1,
                "dst": addr2,
                "dport": port2,
                "length": len(data)
            })
        return summary

    # --- ADDED: New methods for data reassembly and parsing ---

    def get_tcp_stream_content(self, packet_id):
        """
        Finds the full TCP stream for a given packet and returns the raw bytes.
        """
        if not (0 <= packet_id < len(self.captured_packets_raw)):
            return None, None

        packet = self.captured_packets_raw[packet_id]
        if not packet.haslayer(TCP):
            return None, None

        sport = packet[TCP].sport
        dport = packet[TCP].dport
        src_addr = packet[IP].src
        dst_addr = packet[IP].dst

        # Find the corresponding stream key
        stream_key = tuple(sorted(((src_addr, sport), (dst_addr, dport))))
        
        if stream_key in self.tcp_streams:
            return self.tcp_streams[stream_key], stream_key
        return None, None

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
            headers = dict(line.split(": ", 1) for line in headers_str.split("\r\n")[1:] if ": " in line)

            content = body
            # Handle Gzip decompression
            if headers.get("Content-Encoding") == "gzip":
                try:
                    content = zlib.decompress(body, 16 + zlib.MAX_WBITS)
                except zlib.error:
                    return "[Gzip Decompression Failed]\n\n" + body.decode('latin-1')
            
            # Check for HTML and pretty-print it
            if "text/html" in headers.get("Content-Type", ""):
                try:
                    soup = BeautifulSoup(content, "html.parser")
                    return soup.prettify()
                except Exception:
                    return content.decode('utf-8', errors='ignore')

            # Return plain text or other content types
            return content.decode('utf-8', errors='ignore')

        except (ValueError, UnicodeDecodeError):
            # If splitting or decoding fails, it might be a request or not HTTP at all.
            # Return the raw data representation.
            return raw_data.decode('latin-1', errors='ignore')