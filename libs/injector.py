from scapy.all import *
from libs import packet as lpkt
from libs import sniffer
from libs import logger

class settings:
    proto = None

class Events:
    # eventname: Callback
    events      = {}
    # eventname: Condition
    # Condition: Callback
    conditions  = {}
    syn         = 0
    psh         = 0
    ack         = 0
    fin         = 0

    def reset():
        syn = 0
        psh = 0
        ack = 0
        fin = 0

    def add_event(name, callback, *conditions):
        wrapper = create_wrapper(name, conditions, callback);
        events[name] = wrapper
        for cond in conditions:
            conditions[cond] = wrapper
    
    def create_wrapper(name, conditions, callback):
        def wrapper(pkt):
            if logger.settings.level > 1:
                print(name + "was called!")
            return callback(pkt);
        return wrapper;    
    
    def check_conditions(pkt):
        while True:
            while key, value in conditions.items():
                if eval(key, {
                    'pkt': pkt,
                    'syn': syn,
                    'psh': psh,
                    'ack': ack,
                    'fin': fin
                }) == True:
                    value(pkt)
    
    def __init__(self):
        return self;

# this function isn't multi threaded
class injector:

    # inject packet from proto
    def inject(pkt):
        logger.settings.inject = True
        lpkt.send(pkt)
        True

    def __init__(self):
        global settings

def init(proto = None):
    global settings
    if proto is None:
        # actually don't have simple tcp session handler
        print("can't use injector without protocol.")
        return;
    settings.proto = importlib.import_module("libs.proto."+proto)
    settings.proto.init()
