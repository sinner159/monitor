import asyncio

class Machine():

    def __init__(self, ip, interface, mac, name, capture=None):
        self.ip = ip
        self.interface = interface, 
        self.mac = mac
        self.name = name
        self.capture = capture
        

    def process_pkt(self,pkt):
        print(pkt)

    async def readPackets(self):
        await self.capture.packets_from_tshark(self.process_pkt)

    def monitor(self):
        print(f"monitor started for {self.name} {self.ip} {self.interface}")
        while True:
            asyncio.run(self.readPackets())

class Client(Machine):

    def __init__(self, ip, interface, mac,name, capture=None, is_suspicious=False,is_attacker=False):
        super().__init__(ip, interface, mac, name, capture)
        self.is_suspicious = is_suspicious
        self.is_attacker = is_attacker
    
    def process_pkt(self,pkt):
        pkt
        

class Host(Machine):
    
    def __init__(self, ip, interface, mac,name, capture=None,is_target=False):
        super().__init__(ip, interface, mac, name, capture)
        self.is_target = is_target

    def process_pkt(self,pkt):
        pkt
        a=0