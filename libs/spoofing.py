from scapy.all import *
import time
import threading
from libs import packet as lpacket

class settings:
    mac = ""
    src = ""
    dst = ""
    stop = threading.Event()
    terminate = False

# execute arp spoofing (is Multi-threaded)
class spoofer:
    def __init__(self):
        global settings

# A hook function to stop arp spoofing
def stop():
    global settings
    settings.stop.set()

# Setup and execute arp spoofing
def start(mac, src, dst):
    global settings

    settings.mac = mac
    settings.src = src
    settings.dst = dst

    threading.Thread(target=spoofer).start()
    print("Arp spoofing started. Waiting 5 seconds before continue...")
    time.sleep(5)
