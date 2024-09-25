from scapy.all import *
from libs import sniffer

# Append a packet to the list
def append_packet(pkt = None):
    # import global settings object
    global settings
    # If no packet return immediatly
    if pkt is None:
        return;
    # Append the given packet to the packet list in the sniffer settings
    sniffer.settings.plist.append(pkt)

# Dump datas to a pcap file
def dump_data(pkts = None, filename = None):
    # Import global settings object
    global settings
    # No output file, return
    if sniffer.settings.pcap == False:
        return;
    # If no packet list is provided, dump the sniffers packer list 
    if pkts is None:
        scapy.wrpcap(("dyndump.pcap" if filename is None else filename), sniffer.settings.plist)
    # Else write the packet in .pcap file
    else:
        scapy.wrpcap(("dyndump.pcap" if filename is None else filename), pkts)

# Create a psh packet with payload
def psh(pkt = None, payload = ""):
    # IF no payload return immediatluy
    if len(payload) == 0 or pkt is None:
        return;
    #MAke a copy of the origianl packet(gonna be modified)
    forge = pkt
    #Insert the custom payload in the pacekt 
    forge.load = payload
    # Del header fields, they gonna be recalculated later
    del forge.len
    del forge.options
    del forge.chksum
    del forge[TCP].chksum
    return forge;

# Create an ack packet
def ack(pkt = None):
    #if no packet return immedialty
    if pkt is None:
        return;
    
    # Create a new IP layer with swapped source and destination IP addresses
    layer_ip    = IP(
            src     = pkt[IP].dst,
            dst     = pkt[IP].src
    )
    
    # Create a new TCP layer with the destination port set to the source port, and vice versa
    # Set the flags to ACK, the sequence number to the original packet's ACK number, and the acknowledgment number to the original packet's sequence number + payload length
    layer_tcp   = TCP(
            dport   = pkt[TCP].sport,
            sport   = pkt[TCP].dport,
            flags   = 'A',
            seq     = pkt[TCP].ack,
            ack     = pkt[TCP].seq + len(pkt[TCP].load)
    )
    # Return the combined IP and TCP layers to form ACK Packet
    return layer_ip/layer_tcp;

# Creat a SYN packet
def syn(pkt = None):
    # Function for creating SYN packet
    if pkt is None:
        return;
    True
    # WORK IN PROGRESS, currently do nothing

# Creat a FIN packet
def fin(pkt = None):
    # Placeholder function for creating a FIN packet
    if pkt is None:
        return;
    True
    # WORK IN PROGRESS, currently do nothing

# send a packet
def send(pkt = None):
    # if no packet providede return the function.
    if pkt is None:
        return;
    # Use Scapy to send packet in data link layer
    sendp(pkt, verbose=False)

# Should be a hook function when a response is recieved
# Actually disabled, this function should be into proto.????
# Fonction to handle receiving response (curentrly in progress)
def receive():
    # Create thread that continuously listens for responses
    def thread():
        #Infinite loop to kipe tread alive
        while True:
            # print response receive ?
            print("", end="")
    threading.Thread(target=thread).start()
    # Start the receiving fonction in separate thread
