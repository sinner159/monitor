import pyshark
import requests
from host import Host,Client
from threading import Thread
import json
import time

def process_pkt(pkt):
    print(pkt)

class Monitor():
    def __init__(self):
        self.suspicious_hosts = {}
        self.threads = []
        self.host_vms = []
        self.clients = []
        self.read_mapping("mapping.json")


    def read_mapping(self,filename):
        file = open(filename,"r")
        obj = json.load(file)
        for h in obj['hosts']:
            ip = h['ip']
            interface= h['interface']
            mac = h['mac']
            name = h['name']
            self.host_vms.append(Host(ip, interface ,mac, name))

        for c in obj['clients']:
            ip = c['ip']
            interface = c['interface']
            mac = c['mac']
            name = c['name']
            self.clients.append(Client(ip, interface, mac, name))

    def main(self):
        
        #cap = pyshark.LiveCapture("eth1")
        cap = pyshark.RemoteCapture("10.10.1.1","eth1")
        
        # for host in self.host_vms:
        #     cap.interfaces.append(host.interface)
            # host.capture = pyshark.LiveCapture(host.interface)
            # self.threads.append(Thread(target=host.monitor))

        # for client in self.clients:
        #     cap.interfaces.append(client.interface)
            # client.capture = pyshark.LiveCapture(client.interface)
            # self.threads.append(Thread(target=client.monitor))
            

        # for thread in self.threads:
        #     thread.start()

        while True:
            #for host in self.host_vms:
            #cap.sniff(timeout=5)
            cap.apply_on_packets(process_pkt)

            for client in self.clients:
                if client.is_suspicious:
                    print(f"client: {client.name} is suspicious!!")
                time.sleep(0)
                   


     
monitor = Monitor()
monitor.main()