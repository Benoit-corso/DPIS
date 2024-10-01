import sys
from threading import Thread, Event
import scapy.layers.inet as layer
from datas import logger as _

log = _.log

# Define Event class to manage event s
class Events(Thread):
	proto = None
	# eventname: Callback
	# 
	# Dictionnary to store events, where the key is the event name, and the value is the callback function 
	events	  = {}
	layers	  = { 'Ether': layer.Ether, 'IP': layer.IP }
	# eventname: Condition
	# Condition: Callback
	
	#Dictionnary to store conditoon, where the key is the cond, and the value == callback when conditon has been met
	PacketQueue = []
	syn		 = 0
	psh		 = 0
	ack		 = 0
	fin		 = 0
	rst		 = 0

	# Function to reset TCP flag counters
	def reset():
		syn	 = 0
		psh	 = 0
		ack	 = 0
		fin	 = 0
	
	# Initialize the events class
	def __init__(self, netProto = 'tcp'):
		super(Events, self).__init__()
		self.exit = Event()
		if netProto == 'tcp':
			self.protocol = 'tcp'
			self.layers = { **self.layers, 'TCP': layer.TCP }
		else:
			self.protocol = 'udp'
			self.layers = { **self.layers, 'UDP': layer.UDP }

	# Function to add a new event with the callback and optional condtions
	def add(self, name, callback, *conditions):
		[wrapper, add_condition] = self.create_wrapper(name, callback);
		if name in self.events is None:
			self.events[str(name)] = [wrapper, add_condition];
		for cond in conditions:
			add_condition(cond)
	
	# function to create a wrapperr for the event callback
	def create_wrapper(self, name, callback):
		global log
		conditions = []
		def add_condition(cond):
			conditions.append(cond)
			log.debug("for {} event new condition: {}".format(name, cond))
		# Inner function thar wraps the original callback
		def wrapper(pkt):
			for cond in conditions:
				retval = eval(cond, {
					'pkt': pkt,
					'syn': self.syn,
					'psh': self.psh,
					'ack': self.ack,
					'fin': self.fin,
					'rst': self.rst,
					**self.layers
				})
				if retval == True:
					log.debug("{} event was fired.".format(name))
					return callback(name, pkt)
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
		log.debug("Events thread started.")
		# Initilisation packet = None
		pkt = None
		try:
			while not self.exit.is_set():
				if len(self.PacketQueue) != 0:
					# If packet available for processing
					pkt = self.PacketQueue.pop()
					# loop throught each condition and its associated callback
					for name, wrapper in self.events.items():
						wrapper[0](pkt)
					self.last = pkt
				pkt = None
		except KeyboardInterrupt or self.exit.is_set():
			return;

	# Fire the stop event
	def stop(self):
		global log
		self.exit.set();
		log.debug("Stopping Events thread, please wait.")

def htos(hexstring):
	return bytes.fromhex(hexstring)

def atoh(string):
	return string.encode('utf-8').hex()