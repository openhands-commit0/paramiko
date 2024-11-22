"""
Useful functions used by the rest of paramiko.
"""
import sys
import struct
import traceback
import threading
import logging
from paramiko.common import DEBUG, zero_byte, xffffffff, max_byte, byte_ord, byte_chr
from paramiko.config import SSHConfig

def inflate_long(s, always_positive=False):
    """turns a normalized byte string into a long-int
    (adapted from Crypto.Util.number)"""
    pass

def deflate_long(n, add_sign_padding=True):
    """turns a long-int into a normalized byte string
    (adapted from Crypto.Util.number)"""
    pass

def generate_key_bytes(hash_alg, salt, key, nbytes):
    """
    Given a password, passphrase, or other human-source key, scramble it
    through a secure hash into some keyworthy bytes.  This specific algorithm
    is used for encrypting/decrypting private key files.

    :param function hash_alg: A function which creates a new hash object, such
        as ``hashlib.sha256``.
    :param salt: data to salt the hash with.
    :type bytes salt: Hash salt bytes.
    :param str key: human-entered password or passphrase.
    :param int nbytes: number of bytes to generate.
    :return: Key data, as `bytes`.
    """
    pass

def load_host_keys(filename):
    """
    Read a file of known SSH host keys, in the format used by openssh, and
    return a compound dict of ``hostname -> keytype ->`` `PKey
    <paramiko.pkey.PKey>`. The hostname may be an IP address or DNS name.  The
    keytype will be either ``"ssh-rsa"`` or ``"ssh-dss"``.

    This type of file unfortunately doesn't exist on Windows, but on posix,
    it will usually be stored in ``os.path.expanduser("~/.ssh/known_hosts")``.

    Since 1.5.3, this is just a wrapper around `.HostKeys`.

    :param str filename: name of the file to read host keys from
    :return:
        nested dict of `.PKey` objects, indexed by hostname and then keytype
    """
    pass

def parse_ssh_config(file_obj):
    """
    Provided only as a backward-compatible wrapper around `.SSHConfig`.

    .. deprecated:: 2.7
        Use `SSHConfig.from_file` instead.
    """
    pass

def lookup_ssh_host_config(hostname, config):
    """
    Provided only as a backward-compatible wrapper around `.SSHConfig`.
    """
    pass
_g_thread_data = threading.local()
_g_thread_counter = 0
_g_thread_lock = threading.Lock()

def log_to_file(filename, level=DEBUG):
    """send paramiko logs to a logfile,
    if they're not already going somewhere"""
    pass

class PFilter:
    pass
_pfilter = PFilter()

class ClosingContextManager:

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

def asbytes(s):
    """
    Coerce to bytes if possible or return unchanged.
    """
    pass

def b(s, encoding='utf8'):
    """cast unicode or bytes to bytes"""
    pass

def u(s, encoding='utf8'):
    """cast bytes or unicode to unicode"""
    pass

def clamp_value(minimum, val, maximum):
    """Clamp a value between minimum and maximum values."""
    return max(minimum, min(val, maximum))

def get_logger(name):
    """Get a logger with the specified name.

    This logger is configured to output messages in a format suitable for paramiko.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(levelname)s:%(name)s:%(message)s'))
        logger.addHandler(handler)
    return logger

def constant_time_bytes_eq(a, b):
    """Compare two byte strings in constant time.

    This function is intended to prevent timing attacks by ensuring that
    the comparison of two byte strings takes the same amount of time
    regardless of how many characters are the same between the two strings.

    :param bytes a: first byte string
    :param bytes b: second byte string
    :return: True if the strings are equal, False otherwise
    """
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0

def safe_string(s):
    """Convert a potentially unsafe string to a safe one by escaping non-printable bytes.

    :param bytes s: The string to make safe
    :return: A safe version of the string with non-printable bytes escaped
    """
    out = []
    for c in s:
        if isinstance(c, int):
            val = c
        else:
            val = ord(c)
        if (val >= 32) and (val <= 127):
            out.append(chr(val))
        else:
            out.append('%{:02x}'.format(val))
    return ''.join(out).encode('ascii')