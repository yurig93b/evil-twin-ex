from process.process_execution_error import ProcessExecutionError
from process.process_executor import ProcessExecutor


class InterfaceManager(object):
    def __init__(self, pe):
        self._pe: ProcessExecutor = pe
        pass

    def down(self, interface):
        self._pe.run("ifconfig {} down".format(interface))

    def up(self, interface, ip='', mask=''):
        if mask:
            self._pe.run("ifconfig {} {} netmask {} up".format(interface, ip, mask))
        else:
            self._pe.run("ifconfig {} up".format(interface))

    def get_interface_addr(self, interface):
        return self._pe.run(f"ip -brief link | grep {interface} | tr -s ' ' | cut -d' ' -f 3").stdout.decode().replace('\n','')

    def is_wlan_interface_in_monitor(self, interface):
        try:
            self._pe.run(f"iwconfig | grep {interface} | grep 'Mode:Monitor'")
            return True
        except ProcessExecutionError:
            return False

    def get_interfaces(self, wireless_only=False):
        interfaces = []
        if wireless_only:
            output = self._pe.run(cmd='iwconfig').stdout.decode()
        else:
            output = self._pe.run(cmd="ifconfig -a | sed 's/[ \t].*//;/^$/d'").stdout.decode()

        output = output.split('\n')
        for line in output:
            if line == '\n' or line == '':
                continue
            interface_name = line.split(' ')[0].replace(':', '')
            if interface_name != '':
                interfaces.append(interface_name)
        return interfaces
