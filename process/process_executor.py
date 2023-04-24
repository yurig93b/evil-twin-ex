import shlex
import subprocess

from process.process_execution_result import ProcessExecutionResult


class ProcessExecutor(object):
    def __init__(self):
        pass

    def run(self, cmd, shell=True) -> ProcessExecutionResult:
        args = shlex.split(cmd)
        p = subprocess.Popen(args, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Careful here around deadlocks
        stdout, stderr = p.communicate()
        return ProcessExecutionResult(p, stdout, stderr, p.returncode)
