import pyshark
import requests
from host import Host,Client
from threading import Thread
import json


class Monitor():
    def __init__(self):
        self.suspicious_hosts = {}
        self.host_vms = []
        self.clients = []
        self.read_mapping()


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


for i , host in host_vms.items():
    host.capture = pyshark.LiveCapture(host.interface)
    host_vms.append

for i , client in clients.items():
    client.capture = pyshark.LiveCapture(client.interface)
    

while True:

    for index, capture in captures.items():
        capture.sniff(timeout=5)

        for packet in capture:
            print(packet)

     
