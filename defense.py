import time
from multiprocessing import Event

from interface_manager import InterfaceManager
from runtime_config import RuntimeConfig
from wlan_manager import WlanManager


class Defence(object):
    def __init__(self, rc: RuntimeConfig, wl: WlanManager, im: InterfaceManager):
        self._rc = rc
        self._wl = wl
        self._im = im

    def _worker_diassoc_attack(self, should_exit_event: Event):
        while not should_exit_event.is_set():
            print("Sending disassociation packets...")
            self._wl.send_diassoc_packets(self._rc.monitor_wlan_interface,
                                          self._rc.target_ap.bssid,
                                          self._rc.attacked_endpoint)
            time.sleep(1)
        print("Endpoint connected to us!")

    def start_defence(self):
        if not self._rc.target_ap:
            raise RuntimeError("No AP selected...")

        if not self._rc.monitor_wlan_interface:
            raise RuntimeError("No monitor iface selected")

        while True:
            for bssid, ap in self._wl.scan_for_aps(self._rc.monitor_wlan_interface, 2).items():
                if ap.ssid == self._rc.target_ap.ssid and ap.bssid != self._rc.target_ap.bssid:
                    print("Found an AP with same SSID but different BSSID {} != {}".format(self._rc.target_ap.bssid,
                                                                                           ap.bssid))
                    for e in self._wl.scan_for_endpoint_of_ap(self._rc.monitor_wlan_interface, ap.channel, ap.bssid):
                        print("Disconnecting {} from AP {} => {}".format(e, ap.ssid, ap.bssid))
                        self._wl.send_diassoc_packets(self._rc.monitor_wlan_interface, e, ap.bssid)