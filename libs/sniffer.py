import time
from threading import Thread, Event
import scapy.all as scapy
from libs import injector, packet as lpkt,logger as _

# Get the logger instance from logger
log = _.log
plist = None
pcapname = None

# Sniff connection and execute conditions (Is multi-threaded)
class sniffer:
    #Function to handle each packet that is sniffed
    def sniff(self, pkt):
        #Access the global settings object
#        pkt.show()
#        print("packet received")
        # Add the sniffed packet to the event queue for processing by injector
        self.proto.events.add_queue(pkt);
#        if (pkt[scapy.IP].src) == self.src:
#            log.print("client send packet. ("+self.src+")")
#        if (pkt[scapy.IP].src) == self.dst:
#            log.print("server send packet. ("+self.dst+")")
#-------------------------------------------------------------------------------------
#        if pkt[IP].src == settings.dst:
#            print("Server: " +str(pkt[TCP].flags))
#        if pkt[IP].src == sniff_settings.src:
#            print("Client: " +str(pkt[TCP].flags))
#        if pkt[TCP].flags == "S":
#            sniff_settings.syn = sniff_settings.syn + 1
#        if pkt[TCP].flags == "A" and sniff_settings.syn >= 1:
#            sniff_settings.ack = sniff_settings.ack + 1
#            print("ACK detected. "+str(sniff_settings.ack))
#        if pkt[TCP].flags == "PA" and sniff_settings.ack == 1:
#            sniff_settings.psh = sniff_settings.psh + 1
#            print("Psh true mode")
#        if sniff_settings.ack >= 1 and pkt[IP].src == sniff_settings.dst and sniff_settings.psh >= 0 and sniff_settings.packet_sent != True:
#            # send payload (reponse error) to client
#            print("conditions have been meet.")
#            inject_packet = pkt
#            inject_packet.flags = "PA"
#            inject_packet.load ="\x48\x00\x00\x02\xff\x15\x04\x23\x32\x38\x30\x30\x30\x41\x63\x63\x65\x73\x73\x20\x64\x65\x6e\x69\x65\x64\x20\x66\x6f\x72\x20\x75\x73\x65\x72\x20\x27\x72\x6f\x6f\x74\x27\x40\x27\x31\x37\x32\x2e\x31\x38\x2e\x30\x2e"+hex(ord(pkt[IP].dst.split(".")[3]))+"\x27\x20\x28\x75\x73\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x3a\x20\x4e\x4f\x29"
#            inject_packetload ="\x48\x00\x00\x02\xff\x15\x04\x23\x32\x38\x30\x30\x30\x41\x63\x63\x65\x73\x73\x20\x64\x65\x6e\x69\x65\x64\x20\x66\x6f\x72\x20\x75\x73\x65\x72\x20\x27\x72\x6f\x6f\x74\x27\x40\x27\x31\x37\x32\x2e\x31\x38\x2e\x30\x2e\x33\x27\x20\x28\x75\x73\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x3a\x20\x4e\x4f\x29"
#            inject_packet.show()
#            settings.ack = 0
#            settings.psh = 0
#            settings.packet_sent = True
            # send request query to server
#--------------------------------------------------------------------------------------
    def stop(self):
        self.exit.set()

    # Sniffer class that starts packet sniffing
    def __init__(self, src, dst, port, iface, protocol, mac, pcap):
        global pcapname, plist
        log.print("sniffer is starting!")
        self.exit   = Event()
        # Access global settings
        self.src    = src
        self.dst    = dst
        self.port   = port
        self.iface  = iface
        # boolean for writing into a pcap
        pcapname    = pcap
        self.mac    = mac
        self.proto  = protocol
        #Inform the user that sniffing has started
        print("sniffing on iface {} port {}...".format(self.iface, self.port))
        
        #Scapy sniff function to start capturing packet
        sniffplist = scapy.sniff(prn=self.sniff,# Function that call for each packet captured 
                      iface=self.iface, 
                      filter=f"tcp port {self.port} and (host {self.dst} and host {self.src})", 
                      stop_filter=lambda p: self.exit.is_set(),
                      store=False)
        #Set running to false when sniffing is done
        self.running = False
        if self.pcap == True:
            if len(plist) != 0:
                lpkt.dump_data(plist)
            else:
                lpkt.dump_data(sniffplist)
