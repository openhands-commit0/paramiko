import binascii
import hashlib
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import constant_time, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from paramiko.message import Message
from paramiko.common import byte_chr
from paramiko.ssh_exception import SSHException
_MSG_KEXECDH_INIT, _MSG_KEXECDH_REPLY = range(30, 32)
c_MSG_KEXECDH_INIT, c_MSG_KEXECDH_REPLY = [byte_chr(c) for c in range(30, 32)]

class KexCurve25519:
    hash_algo = hashlib.sha256
    name = 'curve25519-sha256@libssh.org'

    @classmethod
    def is_available(cls):
        """Check if curve25519 is available on this system."""
        try:
            X25519PrivateKey.generate()
            return True
        except UnsupportedAlgorithm:
            return False

    def __init__(self, transport):
        self.transport = transport
        self.key = None