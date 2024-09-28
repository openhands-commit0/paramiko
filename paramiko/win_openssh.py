import os.path
import time
PIPE_NAME = '\\\\.\\pipe\\openssh-ssh-agent'

class OpenSSHAgentConnection:

    def __init__(self):
        while True:
            try:
                self._pipe = os.open(PIPE_NAME, os.O_RDWR | os.O_BINARY)
            except OSError as e:
                if e.errno != 22:
                    raise
            else:
                break
            time.sleep(0.1)