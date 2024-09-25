from scapy.all import *
import time
import threading
from libs import packet as lpkt

class settings:
    stop    = threading.Event()
    plist   = scapy.PacketList()
    running = True
    pcap    = False
    src     = ""
    dst     = ""
    port    = ""
    psh     = 0
    ack     = 0
    syn     = 0
    data    = []

class sniffer:
    def sniff(pkt):
        global settings
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
            #inject_packet.flags = "PA"
            #inject_packet.load ="\x48\x00\x00\x02\xff\x15\x04\x23\x32\x38\x30\x30\x30\x41\x63\x63\x65\x73\x73\x20\x64\x65\x6e\x69\x65\x64\x20\x66\x6f\x72\x20\x75\x73\x65\x72\x20\x27\x72\x6f\x6f\x74\x27\x40\x27\x31\x37\x32\x2e\x31\x38\x2e\x30\x2e"+hex(ord(pkt[IP].dst.split(".")[3]))+"\x27\x20\x28\x75\x73\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x3a\x20\x4e\x4f\x29"
            inject_packet.load ="\x48\x00\x00\x02\xff\x15\x04\x23\x32\x38\x30\x30\x30\x41\x63\x63\x65\x73\x73\x20\x64\x65\x6e\x69\x65\x64\x20\x66\x6f\x72\x20\x75\x73\x65\x72\x20\x27\x72\x6f\x6f\x74\x27\x40\x27\x31\x37\x32\x2e\x31\x38\x2e\x30\x2e\x33\x27\x20\x28\x75\x73\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x3a\x20\x4e\x4f\x29"
            inject_packet.show()
            sniff_settings.ack = 0
            sniff_settings.psh = 0
            sniff_settings.packet_sent = True
            # send request query to server

    def __init__(self):
        global settings
        print("sniffing...")
        plist = sniff(prn=sniffer.sniff, filter=f"tcp port {settings.port} and (host {settings.dst} and host {settings.src})", stop_filter=lambda p: sniff_settings.stop.is_set())
        settings.running = False
        if settings.pcap == True:
            if len(settings.plist) != 0:
                lpkt.dump_data(settings.plist)
            else
                lpkt.dump_data(plist)

def stop():
    global settings
    settings.stop.set()

def start(src, dst, port, pcap = False):
    global settings

    settings.src    = src
    settings.dst    = dst
    settings.port   = port
    settings.pcap   = pcap
    
    print("sniffer is starting!")
    threading.Thread(target=sniffer).start()
