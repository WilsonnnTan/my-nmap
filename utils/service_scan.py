from scapy.all import IP, TCP, ICMP, sr, send, UDP, sndrcv, conf, AsyncSniffer
from .nmap_type import Port, PortInfo
from typing import Literal
from dataclasses import dataclass, field
import re


# Probes Database File Format:
# https://nmap.org/book/vscan-fileformat.html
@dataclass
class Probe:
    protocol: Literal["UDP", "TCP"]
    probe_string: bytearray    # converted to byte during parsing
    no_payload: Literal["no-payload"] | None = None
    source_port: Port | None = None


@dataclass
class VersionInfo:
    product_name: str | None = None  # p/
    version: str | None = None       # v/
    info: str | None = None          # i/
    hostname: str | None = None      # h/
    os: str | None = None            # o/
    device_type: str | None = None   # d/
    cpe: list[dict[str, str]] = field(default_factory=list)  # cpe:/.../[class]


@dataclass
class Match:
    service: str
    pattern: str     # regex pattern
    option: str     # example: "i" (match case-insensitive), "s" (includes newlines in the '.' specifier)
    version_info: VersionInfo


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
        
        self.excluded_ports: list[Port] = []
        self.probes: dict[str, ServiceProbe] = {}   # example: {"probe_name": ServiceProbe, ....}
        self.probes_tracker = None     # track self.probes by key index
        self.parse_probes_database()
    
    def scanner(self, ports: list[PortInfo]):
        """
        Implementation of https://nmap.org/book/vscan-technique.html
        Version and App scanner will blow all the stealth
        
        Algorithm:
        1. Pass all open or open | filtered port to this scanner
        2. Exclude port that is mentioned on self.excluded_ports
        3. For TCP port, we start by:
            - TCP Three way handshake
            - if the connection succeeds, we change the port state to "open"
            - once connection is made wait for 6 seconds to receive welcome banner from some services
            - if response is received, we compare it with `NULL Probe` match and softmatch signatures
            - if signature is matched then we are done with that port
            - if signature is soft matched then we send other probes that are known to recognize the soft matched service type
            - if no direct match is found, compare the response against fallback signatures from related probes. If the response looks like a delayed welcome banner, check it against the NULL probe signatures (the "NULL probe cheat").
        4. This point is where we start for UDP port probes (and continue for TCP connections if the NULL probe failed or soft matched).
        5. Send probe to probeable ports by: 
            - identify probes that explicitly list the target port number as highly effective.
            - send these probes sequentially in the order they appear in the nmap-service-probes file.
        6. For each probe sent, wait for a response according to totalwaitms or default to 2s and compare it against signature regular expressions:
            - if scanning UDP and a response is received, we change its port state to "open".
            - if signature is matched then we are done with that port
            - if signature is soft matched then we send other probes that are known to recognize the soft matched service type
            - if no direct match is found, compare the response against fallback signatures from related probes. If the response looks like a delayed welcome banner, check it against the NULL probe signatures (the "NULL probe cheat").
        7. If Probable Port Probes fail, sequentially test remaining existing probes:
            - for TCP scans, establish a brand new connection for each probe to prevent previous probes from corrupting the service's state.
            - evaluate responses using the same Full Match / Soft Match / Fallback logic from Step 6.
        8. Handle Special Service Triggers:
            - SSL/TLS: If a probe detects the port is running SSL, reconnect using SSL/TLS and completely restart the version scan algorithm through the encrypted tunnel to identify what is hiding behind it.
        9. Handle Unrecognized Services:
            - if one or more probes elicited a response but Nmap failed to fully recognize the service, print the response content as a "fingerprint" so the user can identify it manually
        """
        
        
        pass
        
    def parse_probes_database(self):
        """
        Parse probes database into a list of ServiceProbe
        """
        
        with open(self.probes_database, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                # Ignore comments
                if line.startswith("#"):
                    continue
                elif line.startswith("Exclude"):
                    self.exclude_parser(line)
                elif line.startswith("Probe"):
                    self.probe_parser(line)
                # continue if no probes exist in self.probes
                elif not self.probes_tracker:
                    continue
                elif line.startswith("match") or line.startswith("softmatch"):
                    self.match_parser(line)
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
        """
        Exclude Directive
        See: https://nmap.org/book/vscan-fileformat.html#vscan-db-exclude
        
        Syntax: Exclude <port specification>
        Example: Exclude 53,T:9100,U:30000-40000
        """
        
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

        self.excluded_ports = result
    
    def probe_parser(self, line:str):
        """
        Probe Directive
        See: https://nmap.org/book/vscan-fileformat.html#vscan-db-probe
        
        Syntax: Probe <protocol> <probename> <probestring> [no-payload]
        Example: Probe UDP Sqlping q|\x02| no-payload
        """
        
        # https://en.wikipedia.org/wiki/Escape_sequences_in_C
        escape_map = {
            '\\': b'\x5c',  # Backslash
            '0':  b'\x00',  # Null
            'a':  b'\x07',  # Alert / Bell
            'b':  b'\x08',  # Backspace
            'f':  b'\x0c',  # Formfeed
            'n':  b'\x0a',  # Newline
            'r':  b'\x0d',  # Carriage Return
            't':  b'\x09',  # Horizontal Tab
            'v':  b'\x0b',  # Vertical Tab
        }

        regex = re.compile(
                    r'^Probe\s+(TCP|UDP)\s+(\S+)\s+q(.)((?:(?!\3).)*)\3(?:\s+(no-payload))?(?:\s+source=(\d+))?\s*$'
                )

        match = regex.match(line)
        if not match:
            print(line)
        protocol, probe_name, delimeter, raw_probe_string, no_payload_flag, source_port = match.groups()
        
        # Decoded raw probe string into byte
        probe_string = bytearray()
        i = 0
        
        while i < len(raw_probe_string):
            char = raw_probe_string[i]
            if char == '\\' and i + 1 < len(raw_probe_string):
                next_char = raw_probe_string[i + 1]
                # \xHH -> (H is any hex digit)
                if next_char == 'x' and i + 3 < len(raw_probe_string):
                    hex_digits = raw_probe_string[(i + 2):(i + 4)]
                    probe_string.append(int(hex_digits, base=16))
                    i += 4
                elif next_char in escape_map:
                    probe_string += escape_map[next_char]
                    i += 2
            else:
                probe_string.append(ord(char))
                i += 1
        
        # construct source port object
        source_port_obj = Port(port_number=int(source_port), protocol=protocol) if source_port else None
        
        result = ServiceProbe(
                    probe=Probe(
                        protocol=protocol,
                        probe_string=probe_string,
                        no_payload=(True if no_payload_flag else False),
                        source_port=source_port_obj
                    )
                )
        
        self.probes[probe_name] = result
        self.probes_tracker = probe_name

    def match_parser(self, line:str):
        """
        Match Directive
        See: https://nmap.org/book/vscan-fileformat.html#vscan-db-match
        
        Syntax: match <service> <pattern> [<versioninfo>]
        
        ----
        
        Softmatch Directive
        See: https://nmap.org/book/vscan-fileformat.html#vscan-db-softmatch
        
        Syntax: softmatch <service> <pattern>
        """
        
        # --- Parse match line ---
        match_pattern = re.compile(
            r'^\s*(?P<is_soft>soft)?match\s+'     # "match" or "softmatch"
            r'(?P<service>\S+)\s+'                # service name (may be prefixed ssl/)
            r'm(?P<delim>\S)'                     # 'm' + one-char delimiter
            r'(?P<pattern>.*?)(?P=delim)'         # pattern body up to the matching delim
            r'(?P<option>[a-zA-Z]*)'              # pattern options: i, s
            r'(?:\s+(?P<versioninfo>.*))?\s*$',   # everything else is version info
            re.DOTALL,
        )
        
        match = match_pattern.match(line)
        is_soft = True if match.group("is_soft") else False
        service = match.group("service")
        pattern = match.group("pattern")
        option = match.group("option")
        version_info_raw = match.group("versioninfo") or ""
        
        # --- Parse version info ---
        version_info = VersionInfo()
        version_info_pattern = re.compile(
            r'(?P<simple>(?P<tag>[pvihod])(?P<sdelim>\S)(?P<svalue>.*?)(?P=sdelim))'
            r'|'
            r'(?P<cpe>cpe:(?P<cdelim>\S)(?P<cvalue>.*?)(?P=cdelim)(?P<cclass>[aho]?))'
        )
        
        for info in version_info_pattern.finditer(version_info_raw):
            # for non cpe
            if info.group('simple'):
                tag, value = info.group('tag'), info.group('svalue')
                if tag == 'p':
                    version_info.product_name = value
                elif tag == 'v':
                    version_info.version = value
                elif tag == 'i':
                    version_info.info = value
                elif tag == 'h':
                    version_info.hostname = value
                elif tag == 'o':
                    version_info.os = value
                elif tag == 'd':
                    version_info.device_type = value
            # for cpe
            # https://nmap.org/book/output-formats-cpe.html
            else:
                version_info.cpe.append({
                    'name': info.group('cvalue'),
                    'class': info.group('cclass') or 'a',
                })
        
        
        result = Match(
                    service=service,
                    pattern=pattern,
                    option=option,
                    version_info=version_info
                )

        if is_soft:
            self.probes[self.probes_tracker].soft_match.append(result)
        else:
            self.probes[self.probes_tracker].match.append(result)
    
    def ports_parser(self, line:str):
        """
        Ports Directive
        See: https://nmap.org/book/vscan-fileformat.html#vscan-db-ports
        
        Syntax: ports <portlist>
        Example: ports 111,4045,32750-32810,38978
        """
        
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

        self.probes[self.probes_tracker].ports = ports
    
    def sslports_parser(self, line:str):
        """
        Sslports Directive
        See: https://nmap.org/book/vscan-fileformat.html#vscan-db-ports
        
        Syntax: sslports <portlist>
        Example: sslports 443-445,80
        """
        
        match = re.match(r'sslports\s+([\d,\-]+)', line)
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

        self.probes[self.probes_tracker].sslports = ports
    
    def totalwaitms_parser(self, line:str):
        """
        Totalwaitms Directive
        See: https://nmap.org/book/vscan-fileformat.html#vscan-db-totalwaitms
        
        Syntax: totalwaitms <milliseconds>
        Example: totalwaitms 6000
        """
        
        match = re.match(r'totalwaitms\s+(\d+)(?![,\-])', line)
        self.probes[self.probes_tracker].totalwaitms = int(match.group(1))
    
    def tcpwrappedms_parser(self, line:str):
        """
        Tcpwrappedms Directive
        See: https://nmap.org/book/vscan-fileformat.html#vscan-db-tcpwrappedms
        
        Syntax: tcpwrappedms <milliseconds>
        Example: tcpwrappedms 3000
        """
        match = re.match(r'tcpwrappedms\s+(\d+)(?![,\-])', line)
        self.probes[self.probes_tracker].tcpwrappedms = int(match.group(1))
    
    def rarity_parser(self, line:str):
        """
        Rarity Directive
        See: https://nmap.org/book/vscan-fileformat.html#vscan-db-rarity
        
        Syntax: rarity <value between 1 and 9>
        Example: rarity 6
        """
        
        match = re.match(r'rarity\s+(\d+)(?![,\-])', line)
        self.probes[self.probes_tracker].rarity = int(match.group(1))
    
    def fallback_parser(self, line:str):
        """
        Fallback Directive
        See: https://nmap.org/book/vscan-fileformat.html#vscan-db-fallback
        
        Syntax: fallback <Comma separated list of probes>
        Example: fallback GetRequest,GenericLines
        """
        
        match = re.match(r'fallback\s+([\w,\-]+)', line)
        self.probes[self.probes_tracker].fallback = match.group(1).split(",")

