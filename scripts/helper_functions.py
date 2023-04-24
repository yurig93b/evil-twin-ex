import subprocess as sp
from scapy.all import *
from scapy.layers.dot11 import Dot11


def get_all_interfaces(wireless_only=True):
    interfaces = []
    if wireless_only:
        output = sp.getoutput('iwconfig')
    else:
        output = sp.getoutput("ifconfig -a | sed 's/[ \t].*//;/^$/d'")
    output = output.split('\n')
    for line in output:
        if line == '\n' or line == '':
            continue
        interface_name = line.split(' ')[0].replace(':', '')
        if interface_name != '':
            interfaces.append(interface_name)
    return interfaces


def scan_for_networks(interface='wlxc83a35c2e034'):
    def handle_packet(pkt):
        if pkt.haslayer(Dot11):
            # print the SSID and MAC address of the access point
            if pkt.type == 0 and pkt.subtype == 8:
                print(f"SSID: {pkt.info.decode()}  MAC address: {pkt.addr2}")
    sniff(iface=interface, prn=handle_packet)