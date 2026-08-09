from scapy.all import IP, TCP, ICMP, send, UDP
from collections import defaultdict

from packet_sender import send_packets
from nmap_type import PortInfo, TCPFlag

# TCP SYN scan
def tcp_syn_scan(hosts: list[str], port_count=100) -> dict[str, PortInfo]:
    scan_result = defaultdict(list)
    
    # Take top common ports for TCP
    ports = []
    with open("assets/top_tcp_ports.txt", "r") as f:
        for _ in range(port_count):
            port = int(f.readline())
            ports.append(port)
    
    for host in hosts:
        # Build packets for all common ports
        packets = []
        for port in ports:
            packets.append(IP(dst=host)/TCP(dport=port, flags="S"))

        # send packets
        answered_packets, unanswered_packets = send_packets(packets, is_tcp=True)

        # Handle answered packets 
        for sent, recv in answered_packets:
            ip = recv[IP].src
            if ip != host:
                continue

            # Handle TCP response
            if TCP in recv and recv[TCP] and ICMP not in recv:
                # Recieved TCP RST flags which mean the port is closed
                if recv[TCP].flags & TCPFlag.RST:
                    scan_result[ip].append(
                        PortInfo(
                            port_number=sent[TCP].dport,
                            protocol="TCP",
                            state=["closed"]
                        )
                    )
                # Recieved TCP SYN-ACK flags which mean the port is open
                elif recv[TCP].flags & TCPFlag.SYN and recv[TCP].flags & TCPFlag.ACK :
                    scan_result[ip].append(
                        PortInfo(
                            port_number=sent[TCP].dport,
                            protocol="TCP",
                            state=["open"]
                        )
                    )

                    # Send RST packet to close connection
                    rst_packet = IP(dst=recv[IP].src)/TCP(sport=sent[TCP].sport, dport=sent[TCP].dport, flags="R")
                    send(rst_packet, verbose=False)

            # Handle ICMP response which mean the port is filtered
            # https://nmap.org/book/synscan.html#scan-methods-tbl-syn-scan-responses
            elif ICMP in recv and recv[ICMP] and recv[ICMP].type == 3 and recv[ICMP].code in [1, 2, 3, 9, 10, 13]:
                scan_result[ip].append(
                    PortInfo(
                        port_number=sent[TCP].dport,
                        protocol="TCP",
                        state=["filtered"]
                    )
                )
        
        # Handle unanswered packets
        for sent in unanswered_packets:
            scan_result[host].append(
                PortInfo(
                    port_number=sent[TCP].dport,
                    protocol="TCP",
                    state=["filtered"],
                )
            )
                    
    return dict(scan_result)


# UDP scan
def udp_scan(hosts: list[str], port_count=100) -> dict[str, PortInfo]:
    scan_result = defaultdict(list)
    
    # Take top common ports for UDP
    ports = []
    with open("assets/top_udp_ports.txt", "r") as f:
        for _ in range(port_count):
            port = int(f.readline())
            ports.append(port)

    for host in hosts:
        # Build packets for all common ports
        packets = []
        for port in ports:
            packets.append(IP(dst=host)/UDP(dport=port))

        # send packets
        answered_packets, unanswered_packets = send_packets(packets, is_tcp=False)
        
        # Handle answered packets 
        for sent, recv in answered_packets:
            ip = recv[IP].src
            if ip != host:
                continue

            # Handle UDP response
            if UDP in recv and recv[UDP] and ICMP not in recv:
                scan_result[ip].append(
                    PortInfo(
                        port_number=sent[UDP].dport,
                        protocol="UDP",
                        state=["open"]
                    )
                )

            # Handle ICMP response which mean the port is filtered
            # https://nmap.org/book/scan-methods-udp-scan.html#scan-methods-tbl-udp-scan-responses
            elif ICMP in recv and recv[ICMP] and recv[ICMP].type == 3:
                if recv[ICMP].code in [1, 2, 9, 10, 13]:
                    scan_result[ip].append(
                        PortInfo(
                            port_number=sent[UDP].dport,
                            protocol="UDP",
                            state=["filtered"]
                        )
                    )
                elif recv[ICMP].code == 3:
                    scan_result[ip].append(
                        PortInfo(
                            port_number=sent[UDP].dport,
                            protocol="UDP",
                            state=["closed"]
                        )
                    )

        # Handle unanswered packets
        for sent in unanswered_packets:
            scan_result[host].append(
                PortInfo(
                    port_number=sent[UDP].dport,
                    protocol="UDP",
                    state=["filtered", "open"]
                )
            )

    return dict(scan_result)


print(tcp_syn_scan(["103.143.12.117"]))
print(udp_scan(["103.143.12.117"], 20)) 