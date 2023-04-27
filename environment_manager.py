from dnsmasq_manager import DnsMasqManager
from hostapd_manager import HostapdManager
from interface_manager import InterfaceManager
from portal_manager import PortalManager
from process.process_execution_error import ProcessExecutionError
from process.process_executor import ProcessExecutor
from runtime_config import RuntimeConfig
from service_manager import ServiceManager
from wlan_manager import WlanManager


class EnvironmentManager(object):
    DEFAULT_PKGS = ['iw', 'dnsmasq', 'net-tools', 'vim', 'hostapd', 'wireless-tools', 'bridge-utils']

    def __init__(self, pe: ProcessExecutor, rc: RuntimeConfig, im: InterfaceManager, sm: ServiceManager,
                 hostapdm: HostapdManager, portalm: PortalManager, wl: WlanManager
                 ):
        self._pe = pe
        self._rc = rc
        self._sm = sm
        self._im = im
        self._wl = wl
        self._hostapdm = hostapdm
        self._dnsmasq_manager = DnsMasqManager(self._sm)
        self._portalm = portalm

    def install_pkg(self, pkg):
        print("Installing pkg {}".format(pkg))
        try:
            self._pe.run("apt install -yq {}".format(pkg))
            print("Installed {}".format(pkg))
        except ProcessExecutionError as e:
            print("Failed installing {}".format(pkg))
            print(e.per.stdout)
            print(e.per.stderr)
            raise

    def install_pkgs(self, pkgs=None):
        if pkgs is None:
            pkgs = self.DEFAULT_PKGS

        for pkg in pkgs:
            self.install_pkg(pkg)

    def configure_iptables_and_forwarding(self, internet_gateway_if, wlan_if):
        if not internet_gateway_if or not wlan_if:
            raise RuntimeError("One of the interfaces not selected... Please config from menu first.")

        try:
            self._pe.run("echo 1 > /proc/sys/net/ipv4/ip_forward")
            self._pe.run(f"iptables -A FORWARD -i {wlan_if} -j ACCEPT")
            self._pe.run(f"iptables -A FORWARD -o {wlan_if} -j ACCEPT")
            self._pe.run(f"iptables -t nat -A POSTROUTING -o {internet_gateway_if} -j MASQUERADE")
            self._pe.run("ufw allow http")
            # self._pe.run("ufw allow dns")
            # print("Configured ok!")
        except ProcessExecutionError as e:
            print("Failed configuring iptables and forwarding")
            print(e.per.stdout)
            print(e.per.stderr)
            raise

    def configure(self):
        # print("Upping interfaces...")
        # self._im.up(self._rc.monitor_wlan_interface) # Do not start before setting to monitor mode.
        self._im.up(self._rc.ap_wlan_interface, self._rc.router_ip, self._rc.router_mask)

        print("Configuring interfaces...")
        self._wl.set_monitor(self._rc.monitor_wlan_interface)
        self._wl.set_channel(self._rc.monitor_wlan_interface, self._rc.target_ap.channel)

        print("Configuring iptables and packet forwarding")
        self.configure_iptables_and_forwarding(self._rc.gateway_interface, self._rc.ap_wlan_interface)

        print("Configuring dnsmasq")
        self._dnsmasq_manager.configure(interface=self._rc.ap_wlan_interface,
                                        gateway_ip=self._rc.router_ip,
                                        dhcp_range_start=self._rc.dhcp_range_start,
                                        dhcp_range_end=self._rc.dhcp_range_end)

        print("Configuring hostapd")
        self._hostapdm.configure(interface=self._rc.ap_wlan_interface,
                                 channel=self._rc.target_ap.channel,
                                 ssid=self._rc.target_ap.ssid)

    def start_services(self):
        self._rc.validate_all()
        print("Restarting dnsmasq")
        self._dnsmasq_manager.restart()

        print("Running hostapd")
        self._hostapdm.run()

        print("Running fake portal")
        self._portalm.start()

    def stop_services(self):
        self._hostapdm.stop()
        self._portalm.stop()
