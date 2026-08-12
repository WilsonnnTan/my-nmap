import click
import texttable
import time
from utils.host_discoverer import discover_live_host
from utils.port_scanner import tcp_syn_scan, udp_scan
from utils.nmap_type import PortInfo
from utils.service_scan import ServiceScan


@click.command()
@click.argument('target')
@click.option("-sT", "sT", is_flag=True, help="Port Scan with TCP SYN")
@click.option("-sU", "sU", is_flag=True, help="Port Scan with UDP")
@click.option("--top-ports", "top_ports", help="Scan <number> most common ports", default=100)
def my_nmap(target, sT, sU, top_ports):
    """
    TARGET is the target IP/Network (Hostname not supported)
    """
    print("Initializing Service Probes Database...")
    service_scan = ServiceScan()
    print("Starting network scan...")
    start_time = time.time()
    
    # --- Discover Host ---
    live_hosts = discover_live_host(target)
    
    if not live_hosts:
        print(f"Scan report for {target}")
        print("No live host found.")
        return
    
    
    # --- Port Scan ---
    tcp_scan_result = None
    udp_scan_result = None
    
    # No scan technique provided
    if not sT and not sU:
        tcp_scan_result = tcp_syn_scan(live_hosts, port_count=top_ports)
        udp_scan_result = udp_scan(live_hosts, port_count=top_ports)
    elif sT:
        tcp_scan_result = tcp_syn_scan(live_hosts, port_count=top_ports)
    elif sU:
        udp_scan_result = udp_scan(live_hosts, port_count=top_ports)

    # --- Merge scan result ---
    scan_result = tcp_scan_result
    for key, val in udp_scan_result.items():
        scan_result[key].extend(val)
    
    # --- Service scan ---
    for host, ports in scan_result.items():
        scan_result[key] = service_scan.scan(host, ports)
    
    # --- Print output ---
    output(scan_result) if scan_result else None
    print(f"Scan done: {len(live_hosts)} host up scanned in {time.time() - start_time:.2f} seconds")
    

def output(scan_result: dict[str, list[PortInfo]]):
    for host, result in scan_result.items():
        print(f"Scan report for {host}")
        
        # initiate table and header
        table = texttable.Texttable()
        table.add_row(["PORT", "STATE", "SERVICE", "VERSION"])
        
        # --- count each port state ---
        counter = {
            "filtered": 0,
            "open": 0,
            "open | filtered": 0,
            "closed": 0,
        }
        for port_info in result:
            if port_info.is_open_filtered():
                counter["open | filtered"] += 1
            elif port_info.is_filtered():
                counter["filtered"] += 1
            elif port_info.is_open():
                counter["open"] += 1
            elif port_info.is_closed():
                counter["closed"] += 1

        # --- Determine which port to print ---
        should_print = []
        should_not_print = []
        for key, val in counter.items():
            if val <= 7:
                should_print.append(key)
            else:
                should_not_print.append(key)
        
        # --- print the not shown port ---
        print("Not shown: ", end="")
        for state in should_not_print:
            print(f"{counter[state]} {state} ports", end=", ")
        
        # --- print the port table ---
        for port_info in result:
            if port_info.state in should_print:
                table.add_row([
                    f"{port_info.port_number}/{port_info.protocol}", 
                    port_info.state,
                    port_info.service if port_info.service else "",
                    port_info.version if port_info.version else ""
                ])
        
        print("")
        print(table.draw())
            

if __name__ == "__main__":
    my_nmap()