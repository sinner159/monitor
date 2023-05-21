from obj_conn import Host,Client,PacketWrapper,TCPFLAG,ClientHostConnection, TCPHandshake
from threading import Thread, Lock
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
        self.lock = Lock()


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
        #[h.interface for h in self.host_vms]
        sniff(prn=self.process_pkt, iface="eth4", filter=f"tcp and ip", store=0)
        a=0

    def main(self):
        
        thread = Thread(target=self.monitor)
        thread.start()
        
        while True:
            with self.lock:
                for client_ip, client in self.clients_connected.items():
                    for host_ip, chc in client.host_connections.items():
                        chc.clean_up_old_ports()
                        conn_count = chc.num_partially_open_ports()
                        print(f"conn_count: {conn_count}")
                        if  conn_count > 50:
                            print(f"client: {client.ip} has {conn_count} connections with host {host_ip} !!!")
                            requests.get(f"http://192.86.139.96:8080/falsereality/{client_ip}")

                    if client.is_suspicious:
                        print(f"client: {client.name} is suspicious!!")
            time.sleep(5)
                   
    def process_pkt(self,pkt):
        pw = PacketWrapper(pkt)
        #print(pw)
        
        if pw.ip_src not in self.host_ips:
           self.handle_client_packet(pw.ip_dst, pw.ip_src, pw.tcp_src, pw.tcp_flags,pw.time_created)
        else:
           self.handle_host_packet(pw.ip_src, pw.ip_dst, pw.tcp_dst, pw.tcp_flags,pw.time_created)

    def handle_client_packet(self, host_ip, client_ip, client_tcp, tcp_flags,time_in):
        with self.lock:
        
            if client_ip not in self.clients_connected:
                    self.clients_connected[client_ip] = Client(client_ip, None)

            client:Client = self.clients_connected[client_ip]

            if host_ip not in client.host_connections:
                    client.host_connections[host_ip] = ClientHostConnection()

            chc: ClientHostConnection = client.host_connections[host_ip]
            
            chc.update_tcp_conn(client_tcp,True,tcp_flags,time_in)

    def handle_host_packet(self, host_ip, client_ip, client_tcp, tcp_flags,time_in):
        with self.lock:

            if  client_ip in self.clients_connected:
                client: Client = self.clients_connected[client_ip]
                chc: ClientHostConnection = client.host_connections[host_ip]

                chc.update_tcp_conn(client_tcp, False, tcp_flags,time_in)

     
monitor = Monitor()
monitor.main()

