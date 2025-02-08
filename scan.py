import dpkt
import os
from collections import defaultdict
from datetime import datetime

def detect_ddos(pcap_file):
    packet_count = 0 
    ip_count = defaultdict(int)

    # Open the pcap file
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        
        # Loop through each packet in the pcap file
        for timestamp, buf in pcap:
            packet_count += 1
            eth = dpkt.ethernet.Ethernet(buf)
            
            # Check if the packet is an IP packet
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                ip_count[ip.src] += 1

    # Set threshold for detecting DDoS attack
    threshold = 100
    ddos_detected = False
    for ip, count in ip_count.items():
        if count > threshold:
            ddos_detected = True
            break

    return ddos_detected, packet_count

def main():
    folder_path = r"C:\Users\Admin\Desktop\ddos_detect"
    for file_name in os.listdir(folder_path):
        if file_name.endswith(".pcap"):
            pcap_file = os.path.join(folder_path, file_name)
            ddos_detected, packet_count = detect_ddos(pcap_file)
            print(f"PCAP File: {file_name}")
            print(f"Packet Count: {packet_count}")
            if ddos_detected:
                print("DDoS attack detected!")
            else:
                print("No DDoS attack detected.")
            print("=" * 50)

if __name__ == "__main__":
    main()
