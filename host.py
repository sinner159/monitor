import asyncio
from pyshark.packet.packet import Packet
import time

class Machine():

    def __init__(self, ip, interface, mac, name, capture=None):
        self.ip = ip
        self.interface = interface
        self.mac = mac
        self.name = name
        self.capture = capture
        

    def process_pkt(self,pkt: Packet):
        print(pkt)

    async def readPackets(self):
        print("readPacketsCalled")
        await self.capture.packets_from_tshark(self.process_pkt)

    def monitor(self):
        print(f"monitor started for {self.name} {self.ip} {self.interface}")
        while True:
            asyncio.run(self.readPackets())
            time.sleep(1)

class Client(Machine):

    def __init__(self, ip, interface, mac,name, capture=None, is_suspicious=False,is_attacker=False):
        super().__init__(ip, interface, mac, name, capture)
        self.is_suspicious = is_suspicious
        self.is_attacker = is_attacker
    
    def process_pkt(self,pkt: Packet):
        print("Client process_pkt Called")
        

class Host(Machine):
    
    def __init__(self, ip, interface, mac,name, capture=None,is_target=False):
        super().__init__(ip, interface, mac, name, capture)
        self.is_target = is_target

    def process_pkt(self,pkt: Packet):
        print("Host process_pkt Called")
        