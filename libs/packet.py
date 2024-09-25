from scapy.all import *
from libs import sniffer

def append_packet(pkt = None):
    global settings
    if pkt is None:
        return;
    settings.plist.append(pkt)

def dump_data(pkts = None):
    global settings
    if pcap == False:
        return;
    if pkts is None:
        scapy.wrpcap("dyndump.pcap", settings.plist)
    else
        scapy.wrpcap("dyndump.pcap", pkts)

def psh(pkt = None, payload = h""):
    if len(payload) == 0 or pkt is None:
        return;
    forge = pkt
    forge.load = payload
    del forge.len
    del forge.options
    del forge.chksum
    del forge[TCP].chksum
    return forge;

def ack(pkt = None):
    if pkt is None:
        return;
    layer_ip    = IP(
            src     = pkt[IP].dst,
            dst     = pkt[IP].src
    )
    layer_tcp   = TCP(
            dport   = pkt[TCP].sport,
            sport   = pkt[TCP].dport,
            flags   = 'A',
            seq     = pkt[TCP].ack,
            ack     = pkt[TCP].seq + len(pkt[TCP].load),
    return layer_ip/tcp_layer;

def send(pkt = None):
    if pkt is None:
        return;
    sendp(pkt, verbose=False)

def receive():
    def thread():
        while True:
            # print response receive ?
            print(, end="")
    threading.Thread(target=thread).start()
