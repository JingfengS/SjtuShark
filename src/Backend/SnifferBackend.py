import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import scapy.all as scapy
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.arch.windows import get_windows_if_list
import threading
import datetime
import platform
import re

# --- Backend Logic ---


class SnifferBackend:
    """
    Handles all the packet sniffing and processing logic.
    """

    def __init__(self, gui_callback):
        self.is_sniffing = False
        self.sniffer_thread = None
        self.gui_callback = gui_callback
        self.captured_packets = []  # List to store captured packets

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

        elif IP in packet:
            src_addr = packet[IP].src
            dst_addr = packet[IP].dst

            if TCP in packet:
                proto = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                info = (
                    f"Src Port: {sport} -> Dst Port: {dport} Flags: {packet[TCP].flags}"
                )

                # HTTP/HTTPS
                raw = bytes(packet[TCP].payload)
                if raw:
                    try:
                        http_text = raw.decode(errors="ignore")
                        if http_text.startswith(
                            ("GET", "POST", "HTTP", "PUT", "DELETE", "HEAD", "OPTIONS")
                        ):
                            proto = "HTTP"
                            first_line = http_text.split("\r\n")[0]
                            info = f"HTTP: {first_line}"
                    except Exception:
                        pass

                if raw and (
                    sport == 443
                    or dport == 443
                    or raw.startswith(b"\x16\x03")
                ):
                    proto = "HTTPS"
                    info = "Ciphered text"

            elif UDP in packet:
                proto = "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                info = (
                    f"Src Port: {sport} -> Dst Port: {dport} Length: {packet[UDP].len}"
                )

            elif ICMP in packet:
                proto = "ICMP"
                info = f"Type: {packet[ICMP].type} Code: {packet[ICMP].code}"

            else:
                proto = "IP"
                info = f"Protocol: {packet[IP].proto}"

        elif Ether in packet:
            proto = "Ethernet"
            src_addr = packet[Ether].src
            dst_addr = packet[Ether].dst
            info = f"EtherType: {hex(packet[Ether].type)}"

        # Prepare data for GUI
        packet_summary = (timestamp, src_addr, dst_addr, proto, info)
        packet_details = packet.show(dump=True)  # Full packet details for the text view
        self.captured_packets.append((packet_summary, packet_details))  # Save captured packets 
        # Use the callback to update the GUI safely from this thread
        self.gui_callback(packet_summary, packet_details)

    
    def match(summary, expr=None):
        """
        Under development
        """
        
    # To be implemented in SnifferGUI
    def query_packets(self, expr=None):
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
            del self.captured_packets[packet_id]
            return True
        return False
    
    # To be implemented in SnifferGUI
    def clear_captured_packets(self):
        """
        Clears the captured packets list.
        """
        self.captured_packets.clear()
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