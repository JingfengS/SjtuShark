import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import scapy.all as scapy
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
import threading
import datetime
import platform
import re

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
        self.stats = { # Dictionary to store statistics
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

                # HTTP/HTTPS
                raw = bytes(packet[TCP].payload)
                if raw:
                    if sport == 80 or dport == 80:
                         if raw.startswith((b"GET", b"POST", b"HTTP", b"PUT", b"DELETE", b"HEAD")):
                            proto = "HTTP"
                            try:
                                http_text = raw.decode(errors="ignore")
                                first_line = http_text.split("\r\n")[0]
                                info = f"HTTP Request: {first_line}"
                            except:
                                info = "HTTP Packet (undecoded)"
                    elif sport == 443 or dport == 443 or raw.startswith(b"\x16\x03"):
                        proto = "HTTPS"
                        info = "Encrypted TLS/SSL Data"

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
                if icmp_type == 8: # Echo Request
                    info = f"{type_desc} (ping)"
                elif icmp_type == 0: # Echo Reply
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
        self.captured_packets.append((packet_summary, packet_details))  # Save captured packets 
        # Use the callback to update the GUI safely from this thread
        self.gui_callback(packet_summary, packet_details)

    
    def match(self, summary, expr=""):
        """
        Under development
        """
        return True
        
    # To be implemented in SnifferGUI
    def query_packets(self, expr=""):
        """
        Query filter
        """
        results = []
        for summary in self.captured_packets:
            if self.match(summary, expr):
                results.append(summary)
        return results

    # To be implemented in SnifferGUI
    def delete_packet(self, packet_id):
        """
        Deletes a packet by its ID.
        """
        if 0 <= packet_id < len(self.captured_packets):
            summary = self.captured_packets[packet_id][0]
            proto = summary[3]
            # 分层递减
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
            return True
        return False
    
    # To be implemented in SnifferGUI
    def clear_captured_packets(self):
        """
        Clears the captured packets list.
        """
        self.captured_packets.clear()
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