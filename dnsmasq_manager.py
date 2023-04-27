from service_manager import ServiceManager


class DnsMasqManager(object):
    DEFAULT_CONF_PATH = '/etc/dnsmasq.conf'

    def __init__(self, sm: ServiceManager):
        self._sm = sm

    def configure(self, interface: str, gateway_ip: str, dhcp_range_start: str, dhcp_range_end: str,
                  hijack_dns=True, out_path=DEFAULT_CONF_PATH):

        hijacking_data = f'address=/#/{gateway_ip}' if hijack_dns else ''

        data = \
        f'''
        interface={interface}
        bind-interfaces
        {hijacking_data}
        auth-ttl=0
        dhcp-range={dhcp_range_start},{dhcp_range_end},12h
        '''

        with open(out_path, mode='w') as f:
            f.write(data)

    def restart(self):
        self._sm.restart_service('dnsmasq')