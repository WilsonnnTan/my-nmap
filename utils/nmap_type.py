from dataclasses import dataclass
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
    version: str | None = None

    def is_open(self):
        return "open" == self.state
    
    def is_closed(self):
        return "closed" == self.state
    
    def is_filtered(self):
        return "filtered" == self.state
    
    def is_open_filtered(self):
        return "open | filtered" == self.state
