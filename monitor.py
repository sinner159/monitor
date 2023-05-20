import pyshark
import requests
from host import Host,Client
from threading import Thread
import json


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
            interface = h['interface']
            mac = h['mac']
            name = h['name']
            self.host_vms.append(Host(ip,interface,mac,name))

        for c in obj['clients']:
            ip = c['ip']
            interface = c['interface']
            mac = c['mac']
            name = c['name']
            self.clients.append(Client(ip,interface,mac,name))

    def main(self):
        
        for i , host in self.host_vms.items():
            host.capture = pyshark.LiveCapture(host.interface)
            self.threads.append(Thread(target=host.monitor()))

        for i , client in self.clients.items():
            client.capture = pyshark.LiveCapture(client.interface)
            self.threads.append(Thread(target=client.monitor()))
            

        for thread in self.threads:
            thread.start()


     
monitor = Monitor()
monitor.main()