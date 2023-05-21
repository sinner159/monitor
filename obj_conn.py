from scapy.all import sniff
from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.fields import FlagsField
from enum import Enum
class Machine():

    def __init__(self, ip, interface, mac, name):
        self.ip = ip
        self.interface = interface
        self.mac = mac
        self.name = name
        
class Client(Machine):

    def __init__(self, ip, name, is_suspicious=False, is_attacker=False):
        super().__init__(ip,None, None, name)
        self.is_suspicious = is_suspicious
        self.is_attacker = is_attacker
        self.host_connections = {}
        self.packets_sent = 0
        self.ports_connected_from = set()
        self.avg_pkt_count = 0 # totalPacketCount/numberofhosts
        self.avg_num_connections = 0
        self.partial_requests_sent = 0

class TCPHandshake():
    #shows the stages of the handshake, used to determine if a client has partial connections open

    def __init__(self):
        self.most_recent_client_pkt = None
        self.most_recent_host_pkt = None

class ClientHostConnection():
    #Represents the tcp ports open on the client machine that are connecting to the host machine
    #In this case it's just connecting to port 80 of the host machine
    def __init__(self):
        self.tcp_ports = {}

    def tcp_conn_open(self, client_port):
        return client_port in self.tcp_ports
    
    def update_tcp_conn(self, port, is_client_side, tcp_flags):

        if not self.tcp_conn_open(port):
            self.tcp_ports[port] = TCPHandshake()
    
        if is_client_side :
            self.tcp_ports[port].most_recent_client_pkt = tcp_flags
        else:
            self.tcp_ports[port].most_recent_host_pkt = tcp_flags

    def get_partially_open_ports(self):
        for port in self.tcp_ports:
            if port.most_recent_client_pkt == TCPFLAG.SYN and 



class Host(Machine):
    
    def __init__(self, ip, interface, mac,name, is_target=False):
        super().__init__(ip, interface, mac, name)
        self.is_target = is_target

class PacketWrapper():

    def __init__(self,pkt: Packet):

        self.mac_src = pkt.src
        self.mac_dst = pkt.dst
        ip = pkt.payload
        self.ip_src = ip.src
        self.ip_dst = ip.dst
        tcp = ip.payload
        self.tcp_src = tcp.sport
        self.tcp_dst = tcp.dport
        self.tcp_seq = tcp.seq
        self.tcp_ack = tcp.ack
        self.tcp_reserved = tcp.reserved
        self.tcp_flags = tcp.flags.value
        self.interface_sniffed_on = pkt.sniffed_on
    
    def getFlagStr(self):
        
        if self.tcp_flags == TCPFLAG.SYNACK.value:
            return "SYNACK"
        if self.tcp_flags == TCPFLAG.ACK.value:
            return "ACK"
        if self.tcp_flags == TCPFLAG.SYN.value:
            return "SYN"
        if self.tcp_flags == TCPFLAG.FIN.value:
            return "FIN"
        if self.tcp_flags == TCPFLAG.PUSHACK.value:
            return "PUSHACK"
        if self.tcp_flags == TCPFLAG.PSH.value:
            return "PSH"
        if self.tcp_flags == TCPFLAG.RST.value:
            return "RST"
        if self.tcp_flags == TCPFLAG.FINACK.value:
            return "FINACK"
    
    def __str__(self) -> str:
        return f"mac_src: {self.mac_src} tcp_flag: {self.getFlagStr()} ip_src: {self.ip_src} ip_dst: {self.ip_dst} tcp_src: {self.tcp_src} tcp_dst: {self.tcp_dst} sniffed_on: {self.interface_sniffed_on} mac_dst: {self.mac_dst}"


    def __repr__(self) -> str:
        return f"mac_src: {self.mac_src} tcp_flag: {self.getFlagStr()} ip_src: {self.ip_src} ip_dst: {self.ip_dst} tcp_src: {self.tcp_src} tcp_dst: {self.tcp_dst} sniffed_on: {self.interface_sniffed_on} mac_dst: {self.mac_dst}"
    

class TCPFLAG(Enum):
    SYNACK = 18
    ACK = 16
    SYN = 2
    FIN = 1
    PSH = 8 
    RST = 4
    PUSHACK = 24
    FINACK = 17
