import shlex
import subprocess

from process.process_execution_error import ProcessExecutionError
from process.process_execution_result import ProcessExecutionResult


class ProcessExecutor(object):
    def __init__(self):
        pass

    def run(self, cmd, shell=True, raise_on_non_zero_rc=True, print_err=True) -> ProcessExecutionResult:
        p = subprocess.Popen(cmd, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Careful here around deadlocks
        stdout, stderr = p.communicate()

        per = ProcessExecutionResult(p, stdout, stderr, p.returncode)

        if p.returncode and raise_on_non_zero_rc:
            if print_err:
                print(stdout)
                print(stderr)
            raise ProcessExecutionError(per)
        return per
