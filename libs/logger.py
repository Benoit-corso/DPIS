from scapy.all import *

class settings:
    level   = 0

# This class isn't multi threaded
class logger:
    # print args and key/value args
    def print(*args, **kargs):
        global settings
        if settings.level == 0:
            return;
        print(*args)
        for key, value in kargs.items():
            print("{}: {}", key, value)

    # print packetlist infos like tcpdump
    def packetlist(pkts = None):
        global settings
        if pkts is None:
            return;
        elif settings.level > 2:
            pkts.hexraw()
        
    # print packet info
    def packet(pkt = None):
        global settings
        if pkts is None:
            return;
        elif settings.level > 1:
            pkt.show2()

    def __init__(self):
        global settings
        print("logger initialized with level "+str(settings.level)+".")

def init(level = 1):
    global settings
    settings.level = level
