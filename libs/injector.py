import importlib
import time
import scapy.all as scapy
from threading import Thread, Event
from libs import packet as lpkt,sniffer,logger as _

log = _.log

# Define Event class to manage event s
class Events(Thread):
    proto = None
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
            log.print("Event: " + name + "was called!")
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
    def run(self):
        # Initilisation packet = None
        pkt = None
        try:
            while not self.exit.is_set():
                # If packet available for processing
                if pkt is not None:
                    # loopt throught each condition and its assoiciated callback
                    for key, value in self.conditions.items():
                        retval = None
                        # Evaluate the condition as a Python expression, checking values like flags and IP addresses
                        retval = eval(key, {
                            'pkt': pkt,
                            'syn': self.syn,
                            'psh': self.psh,
                            'ack': self.ack,
                            'fin': self.fin,
                            'src': self.src,
                            'dst': self.dst
                        })
                        if retval == True:
                            # If the condition is met, execute the associated callback with the packet
                            value(pkt)
                        else: log.print(retval)
                    # reset pkt after processing
                    pkt = None
                # if packet queu is not empty, get the next pakcet
                elif len(self.PacketQueue) != 0:
                    # pop the next pakcet from the queue for processing
                    pkt = self.PacketQueue.pop()
        except KeyboardInterrupt or self.exit.is_set():
            log.print("Event thread was stopped.")
            return;

    # Fire the stop event
    def stop(self):
        self.exit.set();
        log.print("Stopping Event thread, please wait.")
    
    #initilize rhe events class
    def __init__(self, src, dst):
        super(Events, self).__init__()
        # call loger function for print
        log.print("events init")
        self.exit = Event()
        self.src = src
        self.dst = dst
