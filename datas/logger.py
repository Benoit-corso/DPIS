import scapy.all as scapy
import sys

log = None
loglevel = 0

# This class isn't multi threaded
class Logger:
	# print args and key/value args
	def print(*args, **kargs) -> None:
		global loglevel
		if loglevel == 0:
			return;
		print(*args)
		for key, value in kargs.items():
			print("{}: {}", key, value)

	def error(*args, **kargs) -> None:
		print("\x1b[0;31;40m",*args,"\x1b[0m", sep="", file=sys.stderr)
		for key, value in kargs.items():
			print("\x1b[0;31;40m{}: {}".format(key, value), "\x1b[0m", sep="", file=sys.stderr)

	def debug(*args, **kargs) -> None:
		global loglevel
		if loglevel <= 1:
			return;
		print("\x1b[0;32;40m",*args,"\x1b[0m", sep="")
		for key, value in kargs.items():
			print("\x1b[0;32;40m{}: {}".format(key, value), "\x1b[0m", sep="")

	# print packetlist infos like tcpdump
	def packetlist(pkts = None) -> None:
		global loglevel
		if pkts is None:
			return;
		elif loglevel > 2:
			pkts.hexraw()

	# print packet info
	def packet(pkt = None) -> None:
		global loglevel
		if pkt is None:
			return;
		elif loglevel > 1:
			pkt.show2()

	def __init__(self, level = 0):
		global loglevel, log
		loglevel = level
		print("logger initialized with level "+str(loglevel)+".")
		if log is None:
			log = self
		else: return;
