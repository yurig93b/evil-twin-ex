from process.process_execution_error import ProcessExecutionError
from process.process_execution_result import ProcessExecutionResult
from process.process_executor import ProcessExecutor

class ServiceManager(object):
    DEFAULT_NEEDED_SERVICES = ['dnsmasq']

    def __init__(self, pe : ProcessExecutor):
        self._pe = pe

    def validate(self):
        self.validate_svcs_exist()

    def validate_svcs_exist(self, svcs=None):
        if svcs is None:
            svcs = self.DEFAULT_NEEDED_SERVICES

        for s in svcs:
            try:
                print(f"Checking if service {s} exists")
                self.is_service_exists(s)
                print(f"Service {s} exists")
            except ProcessExecutionError:
                print(f"Service {s} is missing")
                raise

    def stop_service(self, service_name: str) -> bool:
        try:
            self._pe.run("service {} stop".format(service_name))
            return True
        except ProcessExecutionError:
            return False

    def start_service(self, service_name: str) -> bool:
        try:
            self._pe.run("service {} start".format(service_name))
            return True
        except ProcessExecutionError:
            return False

    def restart_service(self, service_name: str) -> bool:
        try:
            self._pe.run("service {} restart".format(service_name))
            return True
        except ProcessExecutionError:
            return False

    def is_service_exists(self, service_name: str) -> bool:
        try:
            self._pe.run("service --status-all | grep '{}'".format(service_name))
            return True
        except ProcessExecutionError:
            return False
