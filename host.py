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
        

    # def process_pkt(self,pkt):
    #     print(pkt)

    # def monitor(self):
    #     print(f"monitor started for {self.name} {self.ip} {self.interface}")
    #     sniff(prn=self.process_pkt, iface=self.interface, filter=f"tcp and ip", store=0)



class Client(Machine):

    def __init__(self, ip, mac, name, is_suspicious=False, is_attacker=False):
        super().__init__(ip,None, mac, name)
        self.is_suspicious = is_suspicious
        self.is_attacker = is_attacker
        self.connections = {}
        self.packets_sent = 0
        self.ports_connected_from = set()
        self.avg_pkt_count = 0 # totalPacketCount/numberofhosts
        self.avg_num_connections = 0
        self.partial_requests_sent = 0


        

class Host(Machine):
    
    def __init__(self, ip, interface, mac,name, is_target=False):
        super().__init__(ip, interface, mac, name)
        self.is_target = is_target
        

    # def process_pkt(self,pkt: Packet):
        
    #     pw = PacketWrapper(pkt)
    #     if pw.ip_src not in self.clients_connected:
    #         self.clients_connected[pw.ip_src] = Client(pw.ip_src,"",pw.mac_src,"")
        
    #     print("Host process_pkt Called")
        



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
            return "SYNACK"
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
