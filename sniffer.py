import argparse
import sys
from scapy.all import sniff, IP, TCP, UDP, Raw

# 1. Packet Processing Function

def process_packet(packet):
    """
    Callback function executed every time a packet is captured.
    This function is where we perform our analysis.
    """

    if IP in packet:
        ip_layer = packet[IP]
        protocol = ""
        transport_layer = None

        if TCP in packet:
            protocol="TCP"
            transport_layer = packet[TCP]
        elif UDP in packet:
            protocol="UDP"
            transport_layer = packet[UDP]
        else:
            # Ignore the packets that are neither TCP nor UDP
            return

        # Extract Key Information
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        src_port = transport_layer.sport
        dst_port = transport_layer.dport

        payload_data = ""
        if Raw in packet:
            try:
                payload_data = packet[Raw].load.decode('utf-8', errors='ignore')
            except:
                payload_data = "[Binary Data]"
        
        # Print Analysis
        print("-"*60)
        print(f"[{protocol} Packet] Source: {src_ip}:{src_port} -> Destination: {dst_ip}:{dst_port}")

        if payload_data:
            print(f"  Payload Data ({len(payload_data)} bytes):")
            print(f"     {payload_data.strip().replace('\n', ' ')}")
        
def main():
    parser = argparse.ArgumentParser(
        description="Basic Network Packet Sniffer"
    )
    parser.add_argument(
        '-i', '--interface0,'
        help= 'Network interface to sniff on (e.g., "eth0", "Wi-Fi"). Leave blank to use default.'
    )
    parser.add_argument(
        '-c', '--count',
        type=int,
        default=0
        help='Number of packets to capture. Use 0 for infinite capture (default).'    
    )
    parser.add_argument(
        '-f', '--filter',
        default="",
        help='Byp (Berkeley Packet Filter) syntax for filtering (e.g., "tcp port 80" or "host 192.168.1.1").'
    )

    args = parser.parse_args()

    print("-" * 60)
    print("Starting packet sniffer...")
    print(f"Interface: {args.interface if args.interface else 'Default'}")
    print(f"Filter: '{args.filter if args.filter else 'None'}'")
    print("Press Ctrl+C to stop the capture.")
    print("-" * 60)

    # Start sniffing with Scapy
    try:
        # We use the sniff function:
        # prn=process_packet: The callback function for each packet
        # iface=args.interface: The network adapter to listen on
        # count=args.count: The number of packets to capture
        # filter=args.filter: The BPF filter string
        sniff(
            prn=process_packet,
            iface=args.interface,
            count=args.count,
            filter=args.filter,
            store=0 # Do not store packets in memory for efficiency
        )
    except PermissionError:
        print("\n[ERROR] Permission denied. Try running with administrator/root privileges (sudo).")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[STOPPED] Capture stopped by user.")
    except Exception as e:
        print(f"\n[ERROR] An unexpected error occurred: {e}")