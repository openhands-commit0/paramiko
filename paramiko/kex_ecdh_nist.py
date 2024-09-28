"""
Ephemeral Elliptic Curve Diffie-Hellman (ECDH) key exchange
RFC 5656, Section 4
"""
from hashlib import sha256, sha384, sha512
from paramiko.common import byte_chr
from paramiko.message import Message
from paramiko.ssh_exception import SSHException
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from binascii import hexlify
_MSG_KEXECDH_INIT, _MSG_KEXECDH_REPLY = range(30, 32)
c_MSG_KEXECDH_INIT, c_MSG_KEXECDH_REPLY = [byte_chr(c) for c in range(30, 32)]

class KexNistp256:
    name = 'ecdh-sha2-nistp256'
    hash_algo = sha256
    curve = ec.SECP256R1()

    def __init__(self, transport):
        self.transport = transport
        self.P = 0
        self.Q_C = None
        self.Q_S = None

class KexNistp384(KexNistp256):
    name = 'ecdh-sha2-nistp384'
    hash_algo = sha384
    curve = ec.SECP384R1()

class KexNistp521(KexNistp256):
    name = 'ecdh-sha2-nistp521'
    hash_algo = sha512
    curve = ec.SECP521R1()