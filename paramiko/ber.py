from paramiko.common import max_byte, zero_byte, byte_ord, byte_chr
import paramiko.util as util
from paramiko.util import b
from paramiko.sftp import int64

class BERException(Exception):
    pass

class BER:
    """
    Robey's tiny little attempt at a BER decoder.
    """

    def __init__(self, content=bytes()):
        self.content = b(content)
        self.idx = 0

    def __str__(self):
        return self.asbytes()

    def __repr__(self):
        return "BER('" + repr(self.content) + "')"