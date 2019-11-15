import time
import json

class Logger(object):
    LOG_EV_DUMP = "LOG_WRITE"
    LOG_EV_IN = "LOG_INPUT"
    LOG_EV_OUT = "LOG_OUTPUT"

    def __init__(self, path):
        self.handle = open(path, "r")

    def __del__(self):
        if not self.handle.closed:
            self.handle.close()

    def ok(self):
        return not bool(self.handle.errors)

    def new_input_msg(self, m):
        self.handle.write("{} {} {}".format(int(round(time.time() * 1000)),
                                            Logger.LOG_EV_IN,
                                            str(m)))

    def new_output_msg(self, m):
        self.handle.write("{} {} {}".format(int(round(time.time() * 1000)),
                                            Logger.LOG_EV_OUT,
                                            str(m)))
