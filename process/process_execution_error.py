from process.process_execution_result import ProcessExecutionResult


class ProcessExecutionError(BaseException):
    def __init__(self, per: ProcessExecutionResult, *args: object) -> None:
        super().__init__(*args)
        self.per = per
