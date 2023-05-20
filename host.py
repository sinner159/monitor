class Machine():

    def __init__(self, ip, interface, mac, name, capture=None):
        self.ip = ip
        self.interface = interface, 
        self.mac = mac
        self.name = name
        self.capture = capture
        
class Client(Machine):

    def __init__(self, ip, interface, mac,name, capture=None, is_suspicious=False,is_attacker=False):
        super().__init__(ip, interface, mac, name, capture)
        self.is_suspicious = is_suspicious
        self.is_attacker = is_attacker

class Host(Machine):
    
    def __init__(self, ip, interface, mac,name, capture=None,is_target=False):
        super().__init__(ip, interface, mac, name, capture)
        self.is_target = is_target