from scapy.all import *
from scapy.layers.dot11 import Dot11
from process.process_executor import ProcessExecutor

interface = "wlxc83a35c2e034"

def get_all_interfaces(wireless_only=True):
    interfaces = []
    pe = ProcessExecutor()
    if wireless_only:
        output = pe.run(cmd='iwconfig').stdout
    else:
        output = pe.run(cmd="ifconfig -a | sed 's/[ \t].*//;/^$/d'").stdout
    output = output.split('\n')
    for line in output:
        if line == '\n' or line == '':
            continue
        interface_name = line.split(' ')[0].replace(':', '')
        if interface_name != '':
            interfaces.append(interface_name)
    return interfaces


def scan_for_networks(interface=interface):
    def handle_packet(pkt):
        if pkt.haslayer(Dot11):
            # print the SSID and MAC address of the access point
            if pkt.type == 0 and pkt.subtype == 8:
                if pkt.addr2 not in ap_list:
                    print(f"SSID: {pkt.info.decode()}  MAC address: {pkt.addr2}")
                    ap_list.append(pkt.addr2)
    ap_list = []
    sniff(iface=interface, prn=handle_packet)
    return ap_list


