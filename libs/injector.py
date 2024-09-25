import importlib
from scapy.all import *
from libs import packet as lpkt
from libs import sniffer
from libs import logger

# Get he logger instance for print message
log = logger.settings.logger

# Define settings class to store protocol information
class settings:
    # Var to stock the protocol that will be initilized later
    proto = None

# Define Event class to manage event s
class Events:
    # eventname: Callback
    # 
    # Dictionnary to store events, where the key is the event name, and the value is the callback function 
    events      = {}
    
    # eventname: Condition
    # Condition: Callback
    
    #Dictionnary to store conditoon, where the key is the cond, and the value == callback when conditon has been met
    conditions  = {}
    PacketQueue = []
    syn         = 0
    psh         = 0
    ack         = 0
    fin         = 0

    # Function to reset TCP flag counters
    def reset():
        syn = 0
        psh = 0
        ack = 0
        fin = 0

    # Function to add a new event with the callback and optional condtions
    def add(self, name, callback, *conditions):
        wrapper = self.create_wrapper(name, callback);
        self.events[name] = wrapper
        for key, value in self.conditions.items():
            print(key, "added for: ", name)
            self.conditions[key] = wrapper
    
    # function to create a wrapperr for the event callback
    def create_wrapper(self, name, callback):
        # Inner function thar wraps the original callback
        def wrapper(pkt):
            # If logging level > print the event triggered
            if logger.settings.level > 1:
                print("Event: " + name + "was called!")
            # call the original callback function, with the packet as the arguements
            return callback(pkt);
        # Return the wrapped callback
        return wrapper;    
    
    # function to add a packet to the processing queuez
    def add_queue(self, pkt = None):
        # If no pkt return the function 
        if pkt is None:
            return;
        # Add the packet to the packet queue
        self.PacketQueue.append(pkt)

    # function that checks conditions againdt queued packets
    def check_conditions(self):
        # Initilisation packet = None
        pkt = None
        while True:
            # If packet available for processing
            if pkt is not None:
                # loopt throught each condition and its assoiciated callback
                for key, value in self.conditions.items():
                    # Evaluate the condition as a Python expression, checking values like flags and IP addresses
                    if eval(key, {
                        'pkt': pkt,
                        'syn': self.syn,
                        'psh': self.psh,
                        'ack': self.ack,
                        'fin': self.fin,
                        'src': self.src,
                        'dst': self.dst
                    }) == True:
                        # If the condition is met, execute the associated callback with the packet
                        value(pkt)
                # reset pkt after processing
                pkt = None
            # if packet queu is not empty, get the next pakcet
            elif len(self.PacketQueue) != 0:
                # pop the next pakcet from the queue for processing
                pkt = self.PacketQueue.pop()
    
    #initilize rhe events class 
    def __init__(self, src, dst):
        # call loger functuion for print
        logger.logger.print("events init")
        self.src = src
        self.dst = dst

# Function to initialize the protocol and the event handling system
def init(proto = None, src = "", dst = "", mac = ""):
    # Use global settings object
    global settings
    # if no proto, print an error
    if proto is None:
        # actually don't have simple tcp session handler
        log.print("can't use injector without protocol.")
        return;
    # Print the protocol
    logger.logger.print("protocol "+proto+" selected.")
    #Import the protocol form le libs/proto, and initialize it
    settings.proto = importlib.import_module("libs.proto."+proto).init(src, dst, mac)
    # Print message that the logger has been executed
    logger.logger.print("after logger")
