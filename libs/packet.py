from scapy.all import *
from libs import sniffer

kill = False
def create_payload(payload):
    pkt = sniffer.inject_packet
    pkt.load = payload
    del pkt.len
    del pkt.options
    del pkt.chksum
    del pkt[TCP].chksum
    return pkt

def onfly_reproduce(pkt):
    layer_ip = pkt[IP]
    layer_tcp = pkt[TCP]
    del pkt.len
    del pkt.options
    del pkt.chksum
    del pkt[TCP].chksum
    return pkt

def create_ack(pkt):
    layer_ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
    layer_tcp = TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, flags='A', seq=pkt[TCP].ack, ack=psh[TCP].seq + len(pkt[TCP].load))
    pkt_ack = ip_layer/tcp_layer
    return pkt_ack

def send(pkt):
    sendp(pkt, verbose=False)

def receive():
    def thread():
        while True:
            response = sniffer.current_response
            while sniffer.current_response == response and not kill:
                time.sleep(0.1)
            response = sniffer.current_response
            if kill:
                return
            print(response.load.decode(), end="")
    threading.Thread(target=thread).start()
