import os
from libs import logger

class settings:
    cmd_list = []

def add_rule(table = "", *args):
    os.system("iptables -t "+table)
