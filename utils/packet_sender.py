from scapy.all import sr
import time

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