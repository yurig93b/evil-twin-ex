from multiprocessing import Process
from typing import Union

from process.process_executor import ProcessExecutor


class PortalManager(object):
    def __init__(self, pe: ProcessExecutor):
        self._pe = pe
        self._proc: Union[Process, None] = None

    def _worker(self):
        # portal.app.run(debug=True, host="0.0.0.0", port=80)
        self._pe.run("cd portal && python3 portal.py")

    def start(self):
        if self._proc and self._proc.is_alive():
            raise RuntimeError("Portal is already running")

        self._proc = Process(target=self._worker, daemon=True)
        self._proc.start()

    def stop(self):
        if self._proc and self._proc.is_alive():
            self._proc.terminate()
