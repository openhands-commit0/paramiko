"""
Variant on `KexGroup1 <paramiko.kex_group1.KexGroup1>` where the prime "p" and
generator "g" are provided by the server.  A bit more work is required on the
client side, and a **lot** more on the server side.
"""
import os
from hashlib import sha1, sha256
from paramiko import util
from paramiko.common import DEBUG, byte_chr, byte_ord, byte_mask
from paramiko.message import Message
from paramiko.ssh_exception import SSHException
_MSG_KEXDH_GEX_REQUEST_OLD, _MSG_KEXDH_GEX_GROUP, _MSG_KEXDH_GEX_INIT, _MSG_KEXDH_GEX_REPLY, _MSG_KEXDH_GEX_REQUEST = range(30, 35)
c_MSG_KEXDH_GEX_REQUEST_OLD, c_MSG_KEXDH_GEX_GROUP, c_MSG_KEXDH_GEX_INIT, c_MSG_KEXDH_GEX_REPLY, c_MSG_KEXDH_GEX_REQUEST = [byte_chr(c) for c in range(30, 35)]

class KexGex:
    name = 'diffie-hellman-group-exchange-sha1'
    min_bits = 1024
    max_bits = 8192
    preferred_bits = 2048
    hash_algo = sha1

    def __init__(self, transport):
        self.transport = transport
        self.p = None
        self.q = None
        self.g = None
        self.x = None
        self.e = None
        self.f = None
        self.old_style = False

class KexGexSHA256(KexGex):
    name = 'diffie-hellman-group-exchange-sha256'
    hash_algo = sha256