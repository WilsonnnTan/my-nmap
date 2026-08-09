from scapy.all import IP, TCP, ICMP, sr, send, UDP, sndrcv, conf, AsyncSniffer
from nmap_type import Port
from typing import Literal
from dataclasses import dataclass, field
import re


# Probes Database File Format:
# https://nmap.org/book/vscan-fileformat.html
@dataclass
class Probe:
    protocol: Literal["UDP", "TCP"]
    probe_name: str
    probe_string: str
    no_payload: Literal["no-payload"] | None = None


@dataclass
class Match:
    service: str
    pattern: str
    version_info: str


@dataclass
class ServiceProbe:
    probe: Probe
    match: list[Match] = field(default_factory=list)
    soft_match: list[Match] = field(default_factory=list)
    ports: list[Port] = field(default_factory=list)
    sslports: list[Port] = field(default_factory=list)
    totalwaitms: int | None = None                          # miliseconds
    tcpwrappedms: int | None = None                         # miliseconds
    rarity: Literal[1, 2, 3, 4, 5, 6, 7, 8] | None = None   # higher = more rare
    fallback: list[str] | None = None                       # probe_name fallback


class ServiceScan:
    def __init__(self, probes_database:str = "assets/nmap_service_probes.txt"):
        self.probes_database = probes_database
        
        self.excluded_port: list[Port] = []
        self.probes: list[ServiceProbe] = []
        self.probes_counter = -1     # counter to track self.probes index
        self.parse_probes_database()
        
    def parse_probes_database(self):
        with open(self.probes_database, "r") as f:
            for line in f:
                # Ignore comments
                if line.startswith("#"):
                    continue
                elif line.startswith("Exclude"):
                    self.exclude_parser(line)
                elif line.startswith("Probe"):
                    self.probe_parser(line)
                # continue if no probes exist in self.probes
                elif self.probes_counter < 0:
                    continue
                elif line.startswith("match"):
                    self.match_parser(line)
                elif line.startswith("softmatch"):
                    self.softmatch_parser(line)
                elif line.startswith("ports"):
                    self.ports_parser(line)
                elif line.startswith("sslports"):
                    self.sslports_parser(line)
                elif line.startswith("totalwaitms"):
                    self.totalwaitms_parser(line)
                elif line.startswith("tcpwrappedms"):
                    self.tcpwrappedms_parser(line)
                elif line.startswith("rarity"):
                    self.rarity_parser(line)
                elif line.startswith("fallback"):
                    self.fallback_parser(line)
    
    
    def exclude_parser(self, line:str):
        line = re.sub(r'^\s*Exclude\s+', '', line.strip(), flags=re.IGNORECASE)
        tokens = [t.strip() for t in line.split(',') if t.strip()]

        result: list[Port] = []
        for tok in tokens:
            m = re.search(r'^(?:([TU]):)?(\d+)(?:-(\d+))?$', tok)
            if not m:
                raise ValueError(f"Invalid token: {tok}")

            proto, start, end = m.groups()
            start = int(start)
            end = int(end) if end else start

            if proto is None:
                for p in range(start, end + 1):
                    result.append(Port(port_number=p, protocol="TCP"))
                    result.append(Port(port_number=p, protocol="UDP"))
            else:
                protocol = "TCP" if proto == "T" else "UDP"
                for p in range(start, end + 1):
                    result.append(Port(port_number=p, protocol=protocol))

        self.excluded_port = result
    
    def probe_parser(self, line:str):
        pass
    
    def match_parser(self, line:str):
        pass
    
    def softmatch_parser(self, line:str):
        pass
    
    def ports_parser(self, line:str):
        # Extract portlist after "ports "
        match = re.search(r'ports\s+([\d,\-]+)', line)
        port_string = match.group(1)
        
        ports: list[Port] = []
        for part in port_string.split(','):
            # Construct list of ports from the portlist
            m = re.match(r'^(\d+)-(\d+)$', part)
            if m:
                start, end = int(m.group(1)), int(m.group(2))
                for p in range(start, end + 1):
                    ports.append(Port(port_number=p, protocol="TCP"))
                    ports.append(Port(port_number=p, protocol="UDP"))
            else:
                ports.append(Port(port_number=int(part), protocol="TCP"))
                ports.append(Port(port_number=int(part), protocol="UDP"))

        self.probes[self.probes_counter].ports = ports
    
    def sslports_parser(self, line:str):
        # Extract portlist after "sslports "
        match = re.search(r'sslports\s+([\d,\-]+)', line)
        port_string = match.group(1)
        
        ports: list[Port] = []
        for part in port_string.split(','):
            # Construct list of ports from the portlist
            m = re.match(r'^(\d+)-(\d+)$', part)
            if m:
                start, end = int(m.group(1)), int(m.group(2))
                for p in range(start, end + 1):
                    ports.append(Port(port_number=p, protocol="TCP"))
                    ports.append(Port(port_number=p, protocol="UDP"))
            else:
                ports.append(Port(port_number=int(part), protocol="TCP"))
                ports.append(Port(port_number=int(part), protocol="UDP"))

        self.probes[self.probes_counter].sslports = ports
    
    def totalwaitms_parser(self, line:str):
        # Extract time after "totalwaitms "
        match = re.search(r'totalwaitms\s+(\d+)(?![,\-])', line)
        self.probes[self.probes_counter].totalwaitms = int(match.group(1))
    
    def tcpwrappedms_parser(self, line:str):
        # Extract time after "tcpwrappedms "
        match = re.search(r'tcpwrappedms\s+(\d+)(?![,\-])', line)
        self.probes[self.probes_counter].tcpwrappedms = int(match.group(1))
    
    def rarity_parser(self, line:str):
        # Extract rarity after "rarity "
        match = re.search(r'rarity\s+(\d+)(?![,\-])', line)
        self.probes[self.probes_counter].rarity = int(match.group(1))
    
    def fallback_parser(self, line:str):
        # Extract fallback probes after "fallback "
        match = re.search(r'fallback\s+([\w,\-]+)', line)
        self.probes[self.probes_counter].fallback = match.group(1).split(",")


scanner=ServiceScan()
print(scanner.exclude_parser("Exclude 53,T:9100,U:30000-30002"))