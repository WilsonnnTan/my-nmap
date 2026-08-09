from scapy.all import IP, TCP, ICMP, sr, send, Ether, srp, ARP
import ipaddress
import time
from nmap_type import TCPFlag

# Discover live host
def discover_live_host(network_address: str):
    # Convert into IPv4/IPv6 Object
    network = ipaddress.ip_network(network_address, strict=False)

    start_time = time.time()
    
    # Use ARP for private network
    if network.is_private:
        result = arp(network_address)
        print(f"Discovered live hosts in {time.time() - start_time:.2f} seconds")
        return result
    
    alive_hosts = set()
    
    # Convert into IP addresses
    hosts = [str(ip) for ip in network.hosts()]
    
    # Call discover host method for public network
    icmp_ping_alive_hosts = icmp_ping(hosts)
    tcp_syn_alive_hosts = tcp_syn(hosts)
    
    alive_hosts.update(icmp_ping_alive_hosts)
    alive_hosts.update(tcp_syn_alive_hosts)
    
    print(f"Discovered live hosts in {time.time() - start_time:.2f} seconds")
    
    return list(alive_hosts)


# ICMP Type 8, 13, and 17
def icmp_ping(hosts: list[str]) -> list[str]:
    alive_hosts = []

    # Build ICMP packets for all IP addresses
    packets = []
    for host in hosts:
        packets.append(IP(dst=host)/ICMP(type=8))
        packets.append(IP(dst=host)/ICMP(type=13))
        packets.append(IP(dst=host)/ICMP(type=17))

    # Send packets and collect answered packets
    answered_packets, _ = sr(
                            packets, 
                            timeout=2,
                            retry=1,
                            verbose=False, 
                          )

    # ICMP type: https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
    for sent, recv in answered_packets:
        if ICMP in recv and recv[ICMP].type in [0, 14, 18]:
            alive_hosts.append(recv[IP].src)

    return alive_hosts


# TCP SYN Request
def tcp_syn(hosts: list[str]) -> list[str]:
    alive_hosts = []
    
    # Take top common ports for TCP
    ports = []
    with open("assets/top_tcp_ports.txt", "r") as f:
        for line in f:
            ports.append(int(line.strip()))

    for host in hosts:
        # Build packets for all common ports
        packets = []
        for port in ports:
            packets.append(IP(dst=host)/TCP(dport=port, flags="S"))
        
        # logic for sr() early stop
        def is_packet_answered(recv):
            if IP in recv and TCP in recv and host == recv[IP].src:
                is_syn_ack_flag = recv[TCP].flags & TCPFlag.SYN and recv[TCP].flags & TCPFlag.ACK
                is_rst_flag = recv[TCP].flags & TCPFlag.RST
                
                if is_syn_ack_flag: 
                    # Send RST to close connection
                    rst_recv = IP(dst=recv[IP].src)/TCP(sport=recv[TCP].dport, dport=recv[TCP].sport, flags="R")
                    send(rst_recv, verbose=False)
                    
                if is_syn_ack_flag or is_rst_flag:
                    alive_hosts.append(recv[IP].src)
                    return True
                  
            return False
        
        # Send packets
        sr(
            packets, 
            timeout=3,
            retry=2,
            inter=0.01,
            verbose=False, 
            stop_filter=is_packet_answered  # Stop after recieving response from host
        )
        
    return alive_hosts


# ARP based host discovery for local network
def arp(network_address: str):
    alive_hosts = []
    packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=network_address)
    answered_packets, _ = srp(
                            packet,
                            timeout=3,
                            retry=2,
                            verbose=False, 
                          )
    
    for sent, recv in answered_packets:
        alive_hosts.append({
            "ip": recv[ARP].psrc,
            "mac": recv[ARP].hwsrc,
        })
    
    return alive_hosts
