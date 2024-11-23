import scapy.all as scapy


def packet_callback(packet):
    """
    Callback function to analyze each packet captured.
    """
    if packet.haslayer(scapy.IP):  # Ensure the packet has an IP layer
        ip_src = packet[scapy.IP].src  # Source IP address
        ip_dst = packet[scapy.IP].dst  # Destination IP address
        protocol = packet[scapy.IP].proto  # Protocol (e.g., TCP, UDP)

        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")

        if packet.haslayer(scapy.TCP):  # Check for TCP layer
            print(f"TCP Payload: {packet[scapy.TCP].payload}")

        elif packet.haslayer(scapy.UDP):  # Check for UDP layer
            print(f"UDP Payload: {packet[scapy.UDP].payload}")

        print("=" * 50)


def start_sniffing():
    """
    Starts sniffing the network to capture packets.
    """
    print("Starting packet capture. Press Ctrl+C to stop.")
    scapy.sniff(prn=packet_callback, store=False)


if __name__ == "__main__":
    start_sniffing()
