"""
Standard SSH key exchange ("kex" if you wanna sound cool).  Diffie-Hellman of
1024 bit key halves, using a known "p" prime and "g" generator.
"""
import os
from hashlib import sha1
from paramiko import util
from paramiko.common import max_byte, zero_byte, byte_chr, byte_mask
from paramiko.message import Message
from paramiko.ssh_exception import SSHException
_MSG_KEXDH_INIT, _MSG_KEXDH_REPLY = range(30, 32)
c_MSG_KEXDH_INIT, c_MSG_KEXDH_REPLY = [byte_chr(c) for c in range(30, 32)]
b7fffffffffffffff = byte_chr(127) + max_byte * 7
b0000000000000000 = zero_byte * 8

class KexGroup1:
    P = 179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007
    G = 2
    name = 'diffie-hellman-group1-sha1'
    hash_algo = sha1

    def __init__(self, transport):
        self.transport = transport
        self.x = 0
        self.e = 0
        self.f = 0