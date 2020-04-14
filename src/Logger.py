import time
import json
import monotonic

class Logger(object):
    LOG_EV_DUMP = "LOG_WRITE"
    LOG_EV_IN = "LOG_INPUT"
    LOG_EV_OUT = "LOG_OUTPUT"

    def __init__(self, path):
        self.handle = open(path, "w")

    def __del__(self):
        if not self.handle.closed:
            self.handle.close()

    def ok(self):
        return not bool(self.handle.errors)

    def get_time(self):
        return int(monotonic.monotonic() * 1.0e9)

    def new_input_msg(self, m):
        self.handle.write("{} {} {}\n".format(self.get_time(),
                                            Logger.LOG_EV_IN,
                                            str(m)))
        self.handle.flush()

    def new_output_msg(self, m):
        self.handle.write("{} {} {}\n".format(self.get_time(),
                                            Logger.LOG_EV_OUT,
                                            str(m)))
        self.handle.flush()
