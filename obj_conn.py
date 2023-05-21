from scapy.all import sniff
from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.fields import FlagsField
from enum import Enum
import time

def getFlagStr(tcp_flags):
    
    if tcp_flags == TCPFLAG.SYNACK.value:
        return "SYNACK"
    if tcp_flags == TCPFLAG.ACK.value:
        return "ACK"
    if tcp_flags == TCPFLAG.SYN.value:
        return "SYN"
    if tcp_flags == TCPFLAG.FIN.value:
        return "FIN"
    if tcp_flags == TCPFLAG.PUSHACK.value:
        return "PUSHACK"
    if tcp_flags == TCPFLAG.PSH.value:
        return "PSH"
    if tcp_flags == TCPFLAG.RST.value:
        return "RST"
    if tcp_flags == TCPFLAG.FINACK.value:
        return "FINACK"
    
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
        self.client_time = None
        self.most_recent_host_pkt = None
        self.host_time = None
    
    def __str__(self) -> str:
        return f"client_side: {getFlagStr(self.most_recent_client_pkt)} host_side: {getFlagStr(self.most_recent_host_pkt)}"


    def __repr__(self) -> str:
        return f"client_side: {getFlagStr(self.most_recent_client_pkt)} host_side: {getFlagStr(self.most_recent_host_pkt)}"

    


class ClientHostConnection():
    #Represents the tcp ports open on the client machine that are connecting to the host machine
    #In this case it's just connecting to port 80 of the host machine
    def __init__(self):
        self.tcp_ports = {}

    def tcp_conn_open(self, client_port):
        return client_port in self.tcp_ports
    
    def update_tcp_conn(self, port, is_client_side, tcp_flags, time_in):

        if not self.tcp_conn_open(port):
            self.tcp_ports[port] = TCPHandshake()
        
        tcp_handshake:TCPHandshake = self.tcp_ports[port]
        
        if is_client_side :
            tcp_handshake.most_recent_client_pkt = tcp_flags
            tcp_handshake.client_time = time_in
        else:
            tcp_handshake.most_recent_host_pkt = tcp_flags
            tcp_handshake.host_time = time_in
        
        self.tcp_ports[port] = tcp_handshake

    def is_partially_open(self,tcp_conn):
        return tcp_conn.most_recent_client_pkt == TCPFLAG.SYN.value
    
    def num_partially_open_ports(self):
        count = 0
        for port in self.tcp_ports.values():
            if self.is_partially_open(port):
                count = count + 1
        return count

    def clean_up_old_ports(self):
        ports_to_remove = []
        curr_time = time.time()
        for port, tcpH in self.tcp_ports.items():
             if tcpH.most_recent_client_pkt == TCPFLAG.FIN.value or \
                tcpH.most_recent_client_pkt == TCPFLAG.FINACK.value or \
                tcpH.most_recent_host_pkt == TCPFLAG.FIN.value or \
                tcpH.most_recent_host_pkt == TCPFLAG.FINACK.value:
                
                # (curr_time -(tcpH.client_time if tcpH.client_time is not None else curr_time)) > 2000 or \
                # (curr_time - (tcpH.host_time if tcpH.host_time is not None else curr_time)) > 2000:
                 ports_to_remove.append(port)
        
        for port in ports_to_remove:
            self.tcp_ports.pop(port)

            
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
        self.time_created = time.time()
    

    
    def __str__(self) -> str:
        return f"mac_src: {self.mac_src} tcp_flag: {getFlagStr(self.tcp_flags)} ip_src: {self.ip_src} ip_dst: {self.ip_dst} tcp_src: {self.tcp_src} tcp_dst: {self.tcp_dst} sniffed_on: {self.interface_sniffed_on} mac_dst: {self.mac_dst}"


    def __repr__(self) -> str:
        return f"mac_src: {self.mac_src} tcp_flag: {getFlagStr(self.tcp_flags)} ip_src: {self.ip_src} ip_dst: {self.ip_dst} tcp_src: {self.tcp_src} tcp_dst: {self.tcp_dst} sniffed_on: {self.interface_sniffed_on} mac_dst: {self.mac_dst}"
    

class TCPFLAG(Enum):
    SYNACK = 18
    ACK = 16
    SYN = 2
    FIN = 1
    PSH = 8 
    RST = 4
    PUSHACK = 24
    FINACK = 17
