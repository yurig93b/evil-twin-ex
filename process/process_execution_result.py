from subprocess import Popen


class ProcessExecutionResult(object):
    def __init__(self, process: Popen, stdout, stderr, rc):
        self.process = process
        self.stdout = stdout
        self.stderr = stderr
        self.rc = rc