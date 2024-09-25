from scapy.all import *

class settings:
    level   = 0

class logger:
    def print(*args, **kargs):
        global settings
        if settings.level == 0:
            return;
        print(*args)
        for key, value in kargs.items():
            print("{}: {}", key, value)

    def packetlist(pkt):
        

    def packet(pkt):
        pkt.show2()

    def __init__(self):
        global settings
        print("logger initialized with level "+str(settings.level)+".")

def init(level = 1):
    global settings
    settings.level = level
