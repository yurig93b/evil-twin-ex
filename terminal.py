# Import the necessary packages
import traceback

from consolemenu import *
from consolemenu.items import *

from ap_info import AccessPointInfo
from attack import Attack
from environment_manager import EnvironmentManager
from hostapd_manager import HostapdManager
from interface_manager import InterfaceManager
from portal_manager import PortalManager
from process.process_executor import ProcessExecutor
from runtime_config import RuntimeConfig
from service_manager import ServiceManager
from wlan_manager import WlanManager


class ConsoleMenuWithErrorHalt(ConsoleMenu):
    def _start(self, show_exit_option=None):
        raise NotImplementedError()

    def start(self, show_exit_option=None):

        try:
            self._start(show_exit_option)
            super().start(show_exit_option)
        except BaseException as e:
            print(e)
            input("Press return to continue...")


class TargetSelectMenu(ConsoleMenuWithErrorHalt):

    def __init__(self, wl: WlanManager, rc: RuntimeConfig, title=None, subtitle=None, screen=None, formatter=None,
                 prologue_text=None, epilogue_text=None,
                 clear_screen=True, show_exit_option=True, exit_option_text='Exit', exit_menu_char=None):
        super().__init__(title, subtitle, screen, formatter, prologue_text, epilogue_text, clear_screen,
                         show_exit_option, exit_option_text, exit_menu_char)
        self._rc = rc
        self._wl = wl

    def _update_selected_target(self, bssid: str):
        self._rc.attacked_endpoint = bssid

    def _start(self, show_exit_option=None):
        if not self._rc.monitor_wlan_interface:
            raise RuntimeError("No interface selected...")

        if not self._rc.attacked_ap:
            raise RuntimeError("No AP selected...")

        print("Scanning endpoints...")

        for bssid in self._wl.scan_for_endpoint_of_ap(self._rc.monitor_wlan_interface, self._rc.attacked_ap.channel,
                                                      self._rc.attacked_ap.bssid):
            self.append_item(
                FunctionItemWithErrorHalt(bssid, self._update_selected_target, [bssid], should_exit=True))


class APSelectMenu(ConsoleMenuWithErrorHalt):

    def __init__(self, wl: WlanManager, rc: RuntimeConfig, title=None, subtitle=None, screen=None, formatter=None,
                 prologue_text=None, epilogue_text=None,
                 clear_screen=True, show_exit_option=True, exit_option_text='Exit', exit_menu_char=None):
        super().__init__(title, subtitle, screen, formatter, prologue_text, epilogue_text, clear_screen,
                         show_exit_option, exit_option_text, exit_menu_char)
        self._rc = rc
        self._wl = wl

    def _update_selected_ap(self, ap: AccessPointInfo):
        self._rc.attacked_ap = ap

    def _start(self, show_exit_option=None):
        if not self._rc.monitor_wlan_interface:
            raise RuntimeError("No interface selected...")

        print("Scanning networks...")

        self.items = []

        for k, v in self._wl.scan_for_aps(self._rc.monitor_wlan_interface).items():
            if not k:
                continue
            self.append_item(
                FunctionItemWithErrorHalt(f'{k} => {v.bssid}', self._update_selected_ap, [v], should_exit=True))


class FunctionItemWithErrorHalt(FunctionItem):
    def action(self):
        try:
            super().action()
        except BaseException as e:
            print(e)
            input("Press return to resume...")


class Terminal(object):
    def __init__(self):
        self._rc_config = RuntimeConfig()

        self._pe = ProcessExecutor()
        self._sm = ServiceManager(self._pe)
        self._im = InterfaceManager(self._pe)
        self._wl = WlanManager(self._pe, self._sm, self._im, self._rc_config)
        self._ec = EnvironmentManager(self._pe, self._rc_config, self._im, self._sm,
                                      HostapdManager(self._pe, self._sm, self._im),
                                      PortalManager(self._pe), self._wl)

        self._attack = Attack(self._rc_config, self._wl, self._im)

        self._menu = ConsoleMenu("Evil Twin Attack Terminal", "Yuri Grigorian / Ben Gendler")
        self._menu_interfaces_targerts_main = ConsoleMenu("Select interfaces and targets")
        self._menu_interfaces_ap = ConsoleMenu("Select AP interface")
        self._menu_interfaces_monitor = ConsoleMenu("Select Monitor interface")
        self._menu_interfaces_gateway = ConsoleMenu("Select Gateway interface")

        self._mene_attack_aps = APSelectMenu(wl=self._wl, rc=self._rc_config, title="Select AP to attack")
        self._mene_attack_endpoints = TargetSelectMenu(wl=self._wl, rc=self._rc_config,
                                                       title="Select endpoint to attack")

        self._populate_interfaces_menus()

    def _update_ap_interface(self, i):
        self._rc_config.ap_wlan_interface = i

    def _update_monitor_interface(self, i):
        self._rc_config.monitor_wlan_interface = i

    def _update_gateway_interface(self, i):
        self._rc_config.gateway_interface = i

    def _populate_interfaces_menus(self):
        for i in self._im.get_interfaces(wireless_only=True):
            self._menu_interfaces_ap.append_item(
                FunctionItemWithErrorHalt(i, self._update_ap_interface, [i], should_exit=True))
            self._menu_interfaces_monitor.append_item(
                FunctionItemWithErrorHalt(i, self._update_monitor_interface, [i], should_exit=True))

        for i in self._im.get_interfaces(wireless_only=False):
            self._menu_interfaces_gateway.append_item(
                FunctionItemWithErrorHalt(i, self._update_gateway_interface, [i], should_exit=True))

    def _go_for_attack(self):
        try:
            self._rc_config.validate()
            self._ec.stop_services()
            self._ec.configure()
            self._ec.start_services()
            self._attack.start_attack()
        except BaseException as e:
            print("Something went wrong with starting the attack. Please make sure all is configured well and restart.")
            traceback.print_exc()
            exit(1)
        input("Endpoint connected to us. Press return to shutdown and exit.")
        exit(0)

    def show(self):
        item_svc_validation = FunctionItemWithErrorHalt("Perform service validations", self._sm.validate, [])
        item_pkgs_install = FunctionItemWithErrorHalt("Perform package installations", self._ec.install_pkgs, [])
        item_rc_config = FunctionItemWithErrorHalt("Show runtime config", self._rc_config.show_config, [])
        item_go_attack = FunctionItemWithErrorHalt("Launch Attack", self._go_for_attack, [])

        # Create the menu

        self._menu_interfaces_targerts_main.append_item(
            SubmenuItem("Select AP interface", self._menu_interfaces_ap, self._menu))
        self._menu_interfaces_targerts_main.append_item(
            SubmenuItem("Select Monitor interface", self._menu_interfaces_monitor, self._menu))
        self._menu_interfaces_targerts_main.append_item(
            SubmenuItem("Select Gateway interface", self._menu_interfaces_gateway, self._menu))

        self._menu_interfaces_targerts_main.append_item(
            SubmenuItem("Select AP to attack", self._mene_attack_aps, self._menu))

        self._menu_interfaces_targerts_main.append_item(
            SubmenuItem("Select endpoint to attack", self._mene_attack_endpoints, self._menu))

        submenu_item = SubmenuItem("Select interfaces and targets", self._menu_interfaces_targerts_main, self._menu)
        self._menu.append_item(item_svc_validation)
        self._menu.append_item(item_pkgs_install)
        self._menu.append_item(submenu_item)
        self._menu.append_item(item_rc_config)
        self._menu.append_item(item_go_attack)

        # Finally, we call show to show the menu and allow the user to interact
        self._menu.start(show_exit_option=False)
        self._menu.join()
