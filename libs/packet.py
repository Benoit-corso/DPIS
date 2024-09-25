from scapy.all import *
from libs import sniffer

# Append a packet to the list
def append_packet(pkt = None):
    global settings
    if pkt is None:
        return;
    sniffer.settings.plist.append(pkt)

# Dump datas to a pcap file
def dump_data(pkts = None, filename = None):
    global settings
    if sniffer.settings.pcap == False:
        return;
    if pkts is None:
        scapy.wrpcap(("dyndump.pcap" if filename is None else filename), sniffer.settings.plist)
    else:
        scapy.wrpcap(("dyndump.pcap" if filename is None else filename), pkts)

# Create a psh packet
def psh(pkt = None, payload = ""):
    if len(payload) == 0 or pkt is None:
        return;
    forge = pkt
    forge.load = payload
    del forge.len
    del forge.options
    del forge.chksum
    del forge[TCP].chksum
    return forge;

# Create an ack packet
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
            ack     = pkt[TCP].seq + len(pkt[TCP].load)
    )
    return layer_ip/layer_tcp;

def syn(pkt = None):
    if pkt is None:
        return;
    True

def fin(pkt = None):
    if pkt is None:
        return;
    True

# send a packet
def send(pkt = None):
    if pkt is None:
        return;
    sendp(pkt, verbose=False)

# Should be a hook function when a response is recieved
# Actually disabled, this function should be into proto.????
def receive():
    def thread():
        while True:
            # print response receive ?
            print("", end="")
    threading.Thread(target=thread).start()
