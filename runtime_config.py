import dataclasses
from dataclasses import dataclass

from ap_info import AccessPointInfo

DEFAULT_ROUTER_IP = '192.168.168.1'
DEFAULT_ROUTER_MASK = '255.255.255.0'
DEFAULT_ROUTER_DHCP_START = '192.168.168.10'
DEFAULT_ROUTER_DHCP_END = '192.168.168.100'

# Generally we would need to scan all channels but our device/driver stops responding after some switches
DEFAULT_SUPPORTED_CHANNELS = [1, 6, 11]  # range(1,14)

_org = {'ap_wlan_interface': 'wlxc83a35c2e034',
        'attacked_ap': {'bssid': '64:64:4a:86:25:6a',
                        'channel': 6,
                        'crypto': list[{'OPN'}],
                        'raw_stats': {'channel': 6,
                                      'country': 'CN',
                                      'country_desc_type': None,
                                      'crypto': {'OPN'},
                                      'rates': [1.0,
                                                2.0,
                                                5.5,
                                                11.0,
                                                6.0,
                                                9.0,
                                                12.0,
                                                18.0,
                                                24.0,
                                                36.0,
                                                48.0,
                                                54.0],
                                      'ssid': 'Test'},
                        'ssid': 'Test'},
        'attacked_channels': [6],
        'attacked_endpoint': '28:ea:2d:c6:27:f3',
        'dhcp_range_end': '192.168.168.100 ',
        'dhcp_range_start': '192.168.168.10',
        'gateway_interface': 'eth0',
        'monitor_wlan_interface': 'wlan0',
        'router_ip': '192.168.168.1',
        'router_mask': '255.255.255.0'}


@dataclass
class RuntimeConfig:
    ap_wlan_interface: str = None  # "wlxc83a35c2e034"
    monitor_wlan_interface: str = None  # "wlxc83a35c2fcb0"
    gateway_interface: str = None  # "ens33"
    attacked_ap: AccessPointInfo = None  # dataclasses.field(default_factory=lambda:  AccessPointInfo(**_org['attacked_ap']))
    attacked_endpoint: str = None  # '28:ea:2d:c6:27:f3'
    attacked_channels: list = dataclasses.field(default_factory=lambda: DEFAULT_SUPPORTED_CHANNELS)
    dhcp_range_start: str = DEFAULT_ROUTER_DHCP_START
    dhcp_range_end: str = DEFAULT_ROUTER_DHCP_END
    router_ip: str = DEFAULT_ROUTER_IP
    router_mask: str = DEFAULT_ROUTER_MASK

    def validate(self):
        for f, v in self.__dict__.items():
            if not v:
                raise RuntimeError(
                    f'{f} is not set.\n'
                    f'Please make sure to configure all interfaces and select a target AP/endpoint.')

        if self.monitor_wlan_interface == self.ap_wlan_interface:
            raise RuntimeError("AP and Monitor interfaces are the same...")

        if self.monitor_wlan_interface == self.gateway_interface:
            raise RuntimeError("Gateway and Monitor interfaces are the same...")

    def show_config(self, wait=True):
        import pprint

        data = {k: v for k, v in self.__dict__.items()}
        data['attacked_ap'] = data['attacked_ap'].to_dict() if data['attacked_ap'] else None
        pprint.pprint(data)

        if wait:
            input("Press return to exit...")
