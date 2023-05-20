import requests



class Notifier():

    def __init__(self):
        a=0

    def notify_controller(self,attacker_ip):
        requests.get("192.86.139.96:80/falsereality/",params={'attacker_ip':attacker_ip})

