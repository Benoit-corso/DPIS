import importlib
from scapy.all import *
from libs import packet as lpkt
from libs import sniffer
from libs import logger

log = logger.settings.logger

class settings:
    proto = None

class Events:
    # eventname: Callback
    events      = {}
    # eventname: Condition
    # Condition: Callback
    conditions  = {}
    PacketQueue = []
    syn         = 0
    psh         = 0
    ack         = 0
    fin         = 0

    def reset():
        syn = 0
        psh = 0
        ack = 0
        fin = 0

    def add(self, name, callback, *conditions):
        wrapper = self.create_wrapper(name, callback);
        self.events[name] = wrapper
        for key, value in self.conditions.items():
            print(key, "added for: ", name)
            self.conditions[key] = wrapper
    
    def create_wrapper(self, name, callback):
        def wrapper(pkt):
            if logger.settings.level > 1:
                print("Event: " + name + "was called!")
            return callback(pkt);
        return wrapper;    
    
    def add_queue(self, pkt = None):
        if pkt is None:
            return;
        self.PacketQueue.append(pkt)

    def check_conditions(self):
        pkt = None
        while True:
            if pkt is not None:
                for key, value in self.conditions.items():
                    print(eval(key, {
                        'pkt': pkt,
                        'syn': self.syn,
                        'psh': self.psh,
                        'ack': self.ack,
                        'fin': self.fin,
                        'src': self.src,
                        'dst': self.dst
                    }))
                       # value(pkt)
            elif len(self.PacketQueue) != 0:
                pkt = self.PacketQueue.pop(0)
    
    def __init__(self, src, dst):
        logger.logger.print("events init")
        self.src = src
        self.dst = dst

def init(proto = None, src = "", dst = "", mac = ""):
    global settings
    if proto is None:
        # actually don't have simple tcp session handler
        log.print("can't use injector without protocol.")
        return;
    logger.logger.print("protocol "+proto+" selected.")
    settings.proto = importlib.import_module("libs.proto."+proto).init(src, dst, mac)
    logger.logger.print("after logger")
