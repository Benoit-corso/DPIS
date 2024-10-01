import os
from lib import logger as _

log = _.log

class settings:
	cmd_list = []

def add_rule(table = "", *args):
	os.system("iptables -t "+table)
