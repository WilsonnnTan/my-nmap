from scapy.all import sr
import time
from utils.nmap_type import PortInfo, Port, TCPFlag
from scapy.all import IP, TCP, ICMP, sr1, send, UDP, sndrcv, conf, AsyncSniffer
import asyncio

def send_packets(packets, is_tcp=True):
    # UDP params
    inter = 1
    
    # TCP params
    if is_tcp:
        inter = 0.01
    
    start_time = time.time()
    
    answered, unanswered = sr(packets, verbose=False, timeout=3, retry=2, inter=inter)
    
    print(f"Sent in {time.time() - start_time:.2f} seconds")
    
    return answered, unanswered


async def open_tcp_connection(host:str, port: PortInfo):
    try:
        # Open TCP connection
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host=host, port=port.port_number),
            timeout=1   # second
        )
        return (reader, writer)
    except:
        # Failed to open TCP connection
        return None
    
    
async def read_packets(reader) -> bytes | None:
    # Wait for welcome banner (NULL Probe) (6s timeout)
    chunks = []
    while True:
        try:
            chunk = await asyncio.wait_for(
                reader.read(1024),
                timeout=6    # seconds 
            )
        except:
            break
        
        if not chunk:
            break
        chunks.append(chunk)

    if not chunks:
        return None

    return b"".join(chunks)