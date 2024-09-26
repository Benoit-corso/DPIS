import scapy.all as scapy

log = None
loglevel = 0

# This class isn't multi threaded
class log:
    # print args and key/value args
    def print(*args, **kargs):
        global loglevel
        if loglevel == 0:
            return;
        print(*args)
        for key, value in kargs.items():
            print("{}: {}", key, value)

    # print packetlist infos like tcpdump
    def packetlist(pkts = None):
        global loglevel
        if pkts is None:
            return;
        elif loglevel > 2:
            pkts.hexraw()

    # print packet info
    def packet(pkt = None):
        global loglevel
        if pkt is None:
            return;
        elif loglevel > 1:
            pkt.show2()

    def __init__(self, level = 0):
        global loglevel, log
        print("logger initialized with level "+str(loglevel)+".")
        if log is None:
            log = self
        else: return;
        loglevel = level;
