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
        [wrapper, add_condition] = self.create_wrapper(name, callback);
        self.events[name] = wrapper
        for cond in conditions:
            for c in cond:
                add_condition(c)
    
    # function to create a wrapperr for the event callback
    def create_wrapper(self, name, callback):
        global log
        conditions = []
        # Inner function thar wraps the original callback
        def wrapper(pkt):
            for cond in conditions:
                retval = eval(cond, {
#                    'pkt': pkt,
#                    'eth': pkt[scapy.Ether],
                    'tcp': pkt[scapy.TCP],
#                    'udp': pkt[scapy.UDP],
#                    'ip' : pkt[scapy.IP],
                    'syn': self.syn,
                    'psh': self.psh,
                    'ack': self.ack,
                    'fin': self.fin,
#                    'src': self.src,
#                    'dst': self.dst
                    })
                if retval == True:
#                        log.print(name + " was fired")
                        return callback(name, pkt)
        def add_condition(cond):
            conditions.append(cond)
            log.print("{} was added for {}".format(cond, name))
            # If logging level > print the event triggered
#            log.print("Event: " + name + "was called!")
            # call the original callback function, with the packet as the arguements
#            return callback(name, pkt);
        # Return the wrapped callback
        return [wrapper, add_condition];    
    
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
                if len(self.PacketQueue) != 0:
                    pkt = self.PacketQueue.pop()
                # If packet available for processing
                # loopt throught each condition and its assoiciated callback
                    for name, wrapper in self.events.items():
                        wrapper(pkt)
                # reset pkt after processing
                # if packet queu is not empty, get the next pakcet
                    # pop the next pakcet from the queue for processing
                pkt = None
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
