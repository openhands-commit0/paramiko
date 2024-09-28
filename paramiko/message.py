"""
Implementation of an SSH2 "message".
"""
import struct
from io import BytesIO
from paramiko import util
from paramiko.common import zero_byte, max_byte, one_byte
from paramiko.util import u

class Message:
    """
    An SSH2 message is a stream of bytes that encodes some combination of
    strings, integers, bools, and infinite-precision integers.  This class
    builds or breaks down such a byte stream.

    Normally you don't need to deal with anything this low-level, but it's
    exposed for people implementing custom extensions, or features that
    paramiko doesn't support yet.
    """
    big_int = 4278190080

    def __init__(self, content=None):
        """
        Create a new SSH2 message.

        :param bytes content:
            the byte stream to use as the message content (passed in only when
            decomposing a message).
        """
        if content is not None:
            self.packet = BytesIO(content)
        else:
            self.packet = BytesIO()

    def __bytes__(self):
        return self.asbytes()

    def __repr__(self):
        """
        Returns a string representation of this object, for debugging.
        """
        return 'paramiko.Message(' + repr(self.packet.getvalue()) + ')'

    def asbytes(self):
        """
        Return the byte stream content of this Message, as a `bytes`.
        """
        pass

    def rewind(self):
        """
        Rewind the message to the beginning as if no items had been parsed
        out of it yet.
        """
        pass

    def get_remainder(self):
        """
        Return the `bytes` of this message that haven't already been parsed and
        returned.
        """
        pass

    def get_so_far(self):
        """
        Returns the `bytes` of this message that have been parsed and
        returned. The string passed into a message's constructor can be
        regenerated by concatenating ``get_so_far`` and `get_remainder`.
        """
        pass

    def get_bytes(self, n):
        """
        Return the next ``n`` bytes of the message, without decomposing into an
        int, decoded string, etc.  Just the raw bytes are returned. Returns a
        string of ``n`` zero bytes if there weren't ``n`` bytes remaining in
        the message.
        """
        pass

    def get_byte(self):
        """
        Return the next byte of the message, without decomposing it.  This
        is equivalent to `get_bytes(1) <get_bytes>`.

        :return:
            the next (`bytes`) byte of the message, or ``b'\x00'`` if there
            aren't any bytes remaining.
        """
        pass

    def get_boolean(self):
        """
        Fetch a boolean from the stream.
        """
        pass

    def get_adaptive_int(self):
        """
        Fetch an int from the stream.

        :return: a 32-bit unsigned `int`.
        """
        pass

    def get_int(self):
        """
        Fetch an int from the stream.
        """
        pass

    def get_int64(self):
        """
        Fetch a 64-bit int from the stream.

        :return: a 64-bit unsigned integer (`int`).
        """
        pass

    def get_mpint(self):
        """
        Fetch a long int (mpint) from the stream.

        :return: an arbitrary-length integer (`int`).
        """
        pass

    def get_string(self):
        """
        Fetch a "string" from the stream.  This will actually be a `bytes`
        object, and may contain unprintable characters.  (It's not unheard of
        for a string to contain another byte-stream message.)
        """
        pass

    def get_text(self):
        """
        Fetch a Unicode string from the stream.

        This currently operates by attempting to encode the next "string" as
        ``utf-8``.
        """
        pass

    def get_binary(self):
        """
        Alias for `get_string` (obtains a bytestring).
        """
        pass

    def get_list(self):
        """
        Fetch a list of `strings <str>` from the stream.

        These are trivially encoded as comma-separated values in a string.
        """
        pass

    def add_bytes(self, b):
        """
        Write bytes to the stream, without any formatting.

        :param bytes b: bytes to add
        """
        pass

    def add_byte(self, b):
        """
        Write a single byte to the stream, without any formatting.

        :param bytes b: byte to add
        """
        pass

    def add_boolean(self, b):
        """
        Add a boolean value to the stream.

        :param bool b: boolean value to add
        """
        pass

    def add_int(self, n):
        """
        Add an integer to the stream.

        :param int n: integer to add
        """
        pass

    def add_adaptive_int(self, n):
        """
        Add an integer to the stream.

        :param int n: integer to add
        """
        pass

    def add_int64(self, n):
        """
        Add a 64-bit int to the stream.

        :param int n: long int to add
        """
        pass

    def add_mpint(self, z):
        """
        Add a long int to the stream, encoded as an infinite-precision
        integer.  This method only works on positive numbers.

        :param int z: long int to add
        """
        pass

    def add_string(self, s):
        """
        Add a bytestring to the stream.

        :param byte s: bytestring to add
        """
        pass

    def add_list(self, l):
        """
        Add a list of strings to the stream.  They are encoded identically to
        a single string of values separated by commas.  (Yes, really, that's
        how SSH2 does it.)

        :param l: list of strings to add
        """
        pass

    def add(self, *seq):
        """
        Add a sequence of items to the stream.  The values are encoded based
        on their type: bytes, str, int, bool, or list.

        .. warning::
            Longs are encoded non-deterministically.  Don't use this method.

        :param seq: the sequence of items
        """
        pass