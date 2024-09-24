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
    scapy.hexdump(pkt)

inject_packet = None
current_response = None

class sniffer:
    def sniff(pkt):
        global sniff_settings, inject_packet, current_response
        if pkt[IP].dst == sniff_settings.dst or pkt[IP].src == sniff_settings.src:
            print_pkt(pkt)

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
