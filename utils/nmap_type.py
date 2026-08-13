from dataclasses import dataclass, field
from typing import Literal


# Bit map for TCP flags
class TCPFlag:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

# ---------- Port Type -----------
@dataclass
class Port:
    port_number: int
    protocol: Literal["UDP", "TCP"]
    
    def is_tcp(self):
        return self.protocol == "TCP"

    def is_udp(self):
        return self.protocol == "UDP"

    # to support eq operation between Port and PortInfo
    def __eq__(self, other):
        if not isinstance(other, Port):
            return NotImplemented
        return self.port_number == other.port_number and self.protocol == other.protocol

    def __hash__(self):
        return hash((self.port_number, self.protocol))

@dataclass(eq=False)
class PortInfo(Port):
    state: Literal["open", "closed", "filtered", "open | filtered"]
    service: str | None = None
    version_info: VersionInfo | None = None

    def is_open(self):
        return "open" == self.state
    
    def is_closed(self):
        return "closed" == self.state
    
    def is_filtered(self):
        return "filtered" == self.state
    
    def is_open_filtered(self):
        return "open | filtered" == self.state


# ---------- Probes Type -----------
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
