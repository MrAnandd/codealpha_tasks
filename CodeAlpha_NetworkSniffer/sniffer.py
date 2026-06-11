from scapy.all import sniff, IP, TCP, UDP, Raw

total_packets = 0
tcp_count = 0
udp_count = 0
icmp_count = 0

def packet_callback(packet):
    global total_packets, tcp_count, udp_count, icmp_count

    total_packets += 1

    print("\n" + "=" * 50)
    if IP in packet:    # this is for IP info.
        protocols = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }

        proto = packet[IP].proto

        print(f"Source IP       : {packet[IP].src}")
        print(f"Destination IP  : {packet[IP].dst}")
        print(f"Protocol        : {protocols.get(proto, proto)}")
        print(f"Packet Size     : {len(packet)} bytes")

        if proto == 1:
            icmp_count += 1

    if TCP in packet:  # For TCP
        tcp_count += 1

        print("Layer 4         : TCP")
        print(f"Source Port     : {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")

    elif UDP in packet:  # For UDP
        udp_count += 1

        print("Layer 4         : UDP")
        print(f"Source Port     : {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")

    if Raw in packet:  # Payload
        try:
            payload = packet[Raw].load.decode(errors="ignore")
            print("\nPayload:")
            print(payload[:500])  # Limit output
        except:
            print("\nPayload: <binary data>")
    else:
        print("\nPayload: None")

print("Capturing packets for 5 seconds...\n")

sniff(
    prn=packet_callback,
    store=False,
    timeout=5
)

# Analysis Report
print("\n" + "=" * 50)
print("NETWORK TRAFFIC ANALYSIS REPORT")
print("=" * 50)

print(f"Total Packets Captured : {total_packets}")
print(f"TCP Packets            : {tcp_count}")
print(f"UDP Packets            : {udp_count}")
print(f"ICMP Packets           : {icmp_count}")

other_packets = total_packets - (tcp_count + udp_count + icmp_count)
print(f"Other Packets          : {other_packets}")

print("\nCapture finished.")