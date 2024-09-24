from scapy.all import *
import time
import threading
from libs import packet as lpacket

class spoof_settings:
    mac = ""
    src = ""
    dst = ""
    stop = threading.Event()
    terminate = False

class spoofer:
    def __init__(self):
        global spoof_settings

def stop():
    global spoof_settings
    spoof_settings.stop.set()

def start(mac, src, dst):
    global spoof_settings
    spoof_settings.mac = mac
    spoof_settings.src = src
    spoof_settings.dst = dst
    threading.Thread(target=spoofer).start()
    while not spoof_settings.terminate:
        True
