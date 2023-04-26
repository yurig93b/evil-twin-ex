import subprocess as sp
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon

network_list = []


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


def scan_for_networks(interface):
    global network_list
    print(f'sniffing for networks with {interface}. please wait...')
    print(f'# ||  SSID   ||   MAC ADDR   ||   Encrypted?')
    sniff(iface=interface, prn=_packet_filter, count=2500)
    return network_list


def _packet_filter(packet):
    global network_list
    if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 8:
        ssid, mac, is_encrypted = packet.info.decode(), packet.addr2, packet[Dot11Beacon].network_stats()['crypto'] == {'OPN'}
        if ssid and mac and packet[Dot11Beacon]:
            if not len(network_list):
                network_list.append((ssid, mac))
            elif mac in list(zip(*network_list))[1]:
                return
            print(f'{len(network_list)}. {ssid} || {mac} || {is_encrypted}')
            network_list.append((ssid, mac, is_encrypted))


# main function
# returns (<ssid>,<mac>) of the user chosen network
def run_scan():
    interfaces = get_all_interfaces(True)
    print("interfaces found: ")
    [print(f'{index}. {interface}') for index, interface in enumerate(interfaces)]
    interface_number = input('press the index of the interface you would like to scan networks with\n')
    netlist = scan_for_networks(interfaces[int(interface_number)])
    net_number = input('press the index of the network you would like to attack\n')
    return netlist[int(net_number)]
