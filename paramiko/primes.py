"""
Utility functions for dealing with primes.
"""
import os
from paramiko import util
from paramiko.common import byte_mask
from paramiko.ssh_exception import SSHException

def _roll_random(n):
    """returns a random # from 0 to N-1"""
    pass

class ModulusPack:
    """
    convenience object for holding the contents of the /etc/ssh/moduli file,
    on systems that have such a file.
    """

    def __init__(self):
        self.pack = {}
        self.discarded = []

    def read_file(self, filename):
        """
        :raises IOError: passed from any file operations that fail.
        """
        pass