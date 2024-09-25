from scapy.all import *
from libs import packet as lpkt
from libs import injector
from libs import logger

class mysql:
    events = None

    def __init__(self):
        events = injector.Events()

def init():
    global mysql
    proto = mysql()
    threading.Thread(target=proto.events.check_conditions).start()