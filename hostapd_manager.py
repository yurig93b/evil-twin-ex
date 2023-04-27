from multiprocessing import Process

from interface_manager import InterfaceManager
from process.process_executor import ProcessExecutor
from service_manager import ServiceManager


class HostapdManager(object):
    DEFAULT_CONF_PATH = '/etc/hostapd/hostapd.conf'

    def __init__(self, pe: ProcessExecutor, sm: ServiceManager, im: InterfaceManager):
        self._sm = sm
        self._im = im
        self._pe = pe

        self._config_path = None
        self._running_proc: Process = None

    def configure(self, interface, channel, ssid, conf_path=DEFAULT_CONF_PATH):
        data = \
            f'''interface={interface}
driver=nl80211
ssid={ssid}
hw_mode=g
ignore_broadcast_ssid=0
country_code=IL
channel={channel}
'''

        with open(conf_path, mode='w') as f:
            f.write(data)

        self._config_path = conf_path

    def run(self):
        if self._running_proc and self._running_proc.is_alive():
            raise RuntimeError("Hostapd is already running.")
        if not self._config_path:
            raise RuntimeError("Hostapd is not configured.")

        self._running_proc = Process(target=self._pe.run,
                                     args=(f'hostapd -dd > /var/log/hostapd.log {self._config_path}',), daemon=True)
        self._running_proc.start()

    def stop(self):
        if self._running_proc and self._running_proc.is_alive():
            self._running_proc.terminate()
