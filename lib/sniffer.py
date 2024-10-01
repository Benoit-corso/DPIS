from threading import Event
import scapy.all as scapy
from lib import logger as _

# Get the logger instance from logger
log = _.log

# Sniff connection and execute conditions (Is multi-threaded)
class Sniffer:
	# Sniffer class that initialize packet sniffing
	def __init__(self, iface, routes, _filter, info):
		global log
		self.exit   = Event()
		self.iface	= iface
		self.filter	= _filter
		self.routes	= routes
		log.print("Sniffer prepared on iface {} port {}".format(self.iface, info))
		log.print("routes: {}".format(len(routes)))
		log.print("filter: {}".format(_filter))

	#Function to handle each packet that is sniffed
	def sniff(self, pkt):
		for r in self.routes:
			if r.layer == 'tcp' and pkt.haslayer(scapy.TCP):
				r(pkt[scapy.TCP].sport, pkt[scapy.TCP].dport, pkt)
			elif pkt.haslayer(scapy.UDP):
				r(pkt[scapy.UDP].sport, pkt[scapy.UDP].dport, pkt)
#--------------------------------------------------------------------------------------
	def start(self):
		#Scapy sniff function to start capturing packet
		scapy.sniff(prn=self.sniff,# Function that call for each packet captured 
					  iface=self.iface, 
					  filter=self.filter, 
					  stop_filter=lambda p: self.exit.is_set(),
					  store=False)
		#Set running to false when sniffing is done
		self.running = False

	def stop(self):
		global log
		self.exit.set()
		log.print("Stopping sniffer...")