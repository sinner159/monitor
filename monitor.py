from host import Host,Client,PacketWrapper,TCPFLAG
from threading import Thread
import json
import time
from scapy.all import sniff
from scapy.fields import FlagsField
import requests


class Monitor():
    def __init__(self):
        self.suspicious_hosts = {}
        self.threads = []
        self.host_vms = []
        self.clients = []
        self.read_mapping("mapping.json")
        self.clients_connected = dict()
        self.host_ips = [h.ip for h in self.host_vms]


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

    def monitor(self):
        sniff(prn=self.process_pkt, iface=[h.interface for h in self.host_vms], filter=f"tcp and ip", store=0)
        a=0

    def main(self):
        
        thread = Thread(target=self.monitor)
        thread.start()

        
        while True:

            for client_ip, client in self.clients_connected.items():
                for host_ip, tcp_conns in client.connections.items():
                    conn_count = len(tcp_conns.keys())
                    if  conn_count > 50:
                        print(f"client: {client.ip} has {conn_count} connections with host {host_ip} !!!")
                        requests.get(f"http://192.86.139.96:8080/falsereality/{client_ip}")

                if client.is_suspicious:
                    print(f"client: {client.name} is suspicious!!")
                time.sleep(0)
                   
    def process_pkt(self,pkt):
        pw = PacketWrapper(pkt)
        print(pw)
        
        if pw.ip_src not in self.host_ips:
            host_ip = pw.ip_dst
            host_tcp = pw.tcp_dst
            client_ip = pw.ip_src
            client_tcp = pw.tcp_src
            if client_ip not in self.clients_connected:
                self.clients_connected[client_ip] = Client(client_ip,pw.mac_src,"")

            client:Client = self.clients_connected[client_ip]
            if host_ip not in client.connections:
                client.connections[host_ip] = {}
            ports_open_from_client = client.connections[host_ip]
            if client_tcp not in ports_open_from_client:
                ports_open_from_client[client_tcp] = False
            else:
                
                if pw.tcp_flags == TCPFLAG.SYN.value:
                    print("second SYN on port already in use!!!!")
                if pw.tcp_flags == TCPFLAG.ACK.value:
                    ports_open_from_client[client_tcp] = True
                if pw.tcp_flags == TCPFLAG.FINACK.value or pw.tcp_flags == TCPFLAG.FIN.value: 
                    ports_open_from_client.pop(client_tcp)
        else:
            host_ip = pw.ip_src
            host_tcp = pw.tcp_src
            client_ip = pw.ip_dst
            client_tcp = pw.tcp_dst

            if pw.tcp_flags == TCPFLAG.FINACK.value and client_ip in self.clients_connected:
                client = self.clients_connected[client_ip]
                ports_open_from_client = client.connections[host_ip]
                if client_tcp in ports_open_from_client:
                    ports_open_from_client.pop(client_tcp)

                

     
monitor = Monitor()
monitor.main()

