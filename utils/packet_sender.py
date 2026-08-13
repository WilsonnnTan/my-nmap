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


async def open_tcp_connection(host:str, port: PortInfo) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
    try:
        # Open TCP connection
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host=host, port=port.port_number),
            timeout=5   # second
        )
        return (reader, writer)
    except Exception as e:
        # Failed to open TCP connection
        return None
    
    
async def read_welcome_banner(reader: asyncio.StreamReader) -> str:
    """
    Wait and read welcome banner from TCP StreamReader (NULL Probe) (7s timeout)
    and return decoded banner (string)
    """
    chunks = []
    while True:
        try:
            chunk = await asyncio.wait_for(
                reader.read(1024),
                timeout=7    # seconds 
            )
        except:
            break
        
        if not chunk:
            break
        chunks.append(chunk)

    if not chunks:
        return ""

    return (b"".join(chunks)).decode("utf-8")
        

async def read_tcp_response(reader: asyncio.StreamReader) -> str:
    """
    Read response from TCP StreamReader and decode the response
    """
    
    chunks = []
    while True:
        try:
            chunk = await reader.read(1024)
        except:
            break
        
        if not chunk:
            break
        chunks.append(chunk)

    if not chunks:
        return ""

    return (b"".join(chunks)).decode("utf-8")