from io import BytesIO
from paramiko.common import linefeed_byte_value, crlf, cr_byte, linefeed_byte, cr_byte_value
from paramiko.util import ClosingContextManager, u

class BufferedFile(ClosingContextManager):
    """
    Reusable base class to implement Python-style file buffering around a
    simpler stream.
    """
    _DEFAULT_BUFSIZE = 8192
    SEEK_SET = 0
    SEEK_CUR = 1
    SEEK_END = 2
    FLAG_READ = 1
    FLAG_WRITE = 2
    FLAG_APPEND = 4
    FLAG_BINARY = 16
    FLAG_BUFFERED = 32
    FLAG_LINE_BUFFERED = 64
    FLAG_UNIVERSAL_NEWLINE = 128

    def __init__(self):
        self.newlines = None
        self._flags = 0
        self._bufsize = self._DEFAULT_BUFSIZE
        self._wbuffer = BytesIO()
        self._rbuffer = bytes()
        self._at_trailing_cr = False
        self._closed = False
        self._pos = self._realpos = 0
        self._size = 0

    def __del__(self):
        self.close()

    def __iter__(self):
        """
        Returns an iterator that can be used to iterate over the lines in this
        file.  This iterator happens to return the file itself, since a file is
        its own iterator.

        :raises: ``ValueError`` -- if the file is closed.
        """
        if self._closed:
            raise ValueError('I/O operation on closed file')
        return self

    def close(self):
        """
        Close the file.  Future read and write operations will fail.
        """
        pass

    def flush(self):
        """
        Write out any data in the write buffer.  This may do nothing if write
        buffering is not turned on.
        """
        pass

    def __next__(self):
        """
        Returns the next line from the input, or raises ``StopIteration``
        when EOF is hit.  Unlike python file objects, it's okay to mix
        calls to `.next` and `.readline`.

        :raises: ``StopIteration`` -- when the end of the file is reached.

        :returns:
            a line (`str`, or `bytes` if the file was opened in binary mode)
            read from the file.
        """
        line = self.readline()
        if not line:
            raise StopIteration
        return line

    def readable(self):
        """
        Check if the file can be read from.

        :returns:
            `True` if the file can be read from. If `False`, `read` will raise
            an exception.
        """
        pass

    def writable(self):
        """
        Check if the file can be written to.

        :returns:
            `True` if the file can be written to. If `False`, `write` will
            raise an exception.
        """
        pass

    def seekable(self):
        """
        Check if the file supports random access.

        :returns:
            `True` if the file supports random access. If `False`, `seek` will
            raise an exception.
        """
        pass

    def readinto(self, buff):
        """
        Read up to ``len(buff)`` bytes into ``bytearray`` *buff* and return the
        number of bytes read.

        :returns:
            The number of bytes read.
        """
        pass

    def read(self, size=None):
        """
        Read at most ``size`` bytes from the file (less if we hit the end of
        the file first).  If the ``size`` argument is negative or omitted,
        read all the remaining data in the file.

        .. note::
            ``'b'`` mode flag is ignored (``self.FLAG_BINARY`` in
            ``self._flags``), because SSH treats all files as binary, since we
            have no idea what encoding the file is in, or even if the file is
            text data.

        :param int size: maximum number of bytes to read
        :returns:
            data read from the file (as bytes), or an empty string if EOF was
            encountered immediately
        """
        pass

    def readline(self, size=None):
        """
        Read one entire line from the file.  A trailing newline character is
        kept in the string (but may be absent when a file ends with an
        incomplete line).  If the size argument is present and non-negative, it
        is a maximum byte count (including the trailing newline) and an
        incomplete line may be returned.  An empty string is returned only when
        EOF is encountered immediately.

        .. note::
            Unlike stdio's ``fgets``, the returned string contains null
            characters (``'\\0'``) if they occurred in the input.

        :param int size: maximum length of returned string.
        :returns:
            next line of the file, or an empty string if the end of the
            file has been reached.

            If the file was opened in binary (``'b'``) mode: bytes are returned
            Else: the encoding of the file is assumed to be UTF-8 and character
            strings (`str`) are returned
        """
        pass

    def readlines(self, sizehint=None):
        """
        Read all remaining lines using `readline` and return them as a list.
        If the optional ``sizehint`` argument is present, instead of reading up
        to EOF, whole lines totalling approximately sizehint bytes (possibly
        after rounding up to an internal buffer size) are read.

        :param int sizehint: desired maximum number of bytes to read.
        :returns: list of lines read from the file.
        """
        pass

    def seek(self, offset, whence=0):
        """
        Set the file's current position, like stdio's ``fseek``.  Not all file
        objects support seeking.

        .. note::
            If a file is opened in append mode (``'a'`` or ``'a+'``), any seek
            operations will be undone at the next write (as the file position
            will move back to the end of the file).

        :param int offset:
            position to move to within the file, relative to ``whence``.
        :param int whence:
            type of movement: 0 = absolute; 1 = relative to the current
            position; 2 = relative to the end of the file.

        :raises: ``IOError`` -- if the file doesn't support random access.
        """
        pass

    def tell(self):
        """
        Return the file's current position.  This may not be accurate or
        useful if the underlying file doesn't support random access, or was
        opened in append mode.

        :returns: file position (`number <int>` of bytes).
        """
        pass

    def write(self, data):
        """
        Write data to the file.  If write buffering is on (``bufsize`` was
        specified and non-zero), some or all of the data may not actually be
        written yet.  (Use `flush` or `close` to force buffered data to be
        written out.)

        :param data: ``str``/``bytes`` data to write
        """
        pass

    def writelines(self, sequence):
        """
        Write a sequence of strings to the file.  The sequence can be any
        iterable object producing strings, typically a list of strings.  (The
        name is intended to match `readlines`; `writelines` does not add line
        separators.)

        :param sequence: an iterable sequence of strings.
        """
        pass

    def xreadlines(self):
        """
        Identical to ``iter(f)``.  This is a deprecated file interface that
        predates Python iterator support.
        """
        pass

    def _read(self, size):
        """
        (subclass override)
        Read data from the stream.  Return ``None`` or raise ``EOFError`` to
        indicate EOF.
        """
        pass

    def _write(self, data):
        """
        (subclass override)
        Write data into the stream.
        """
        pass

    def _get_size(self):
        """
        (subclass override)
        Return the size of the file.  This is called from within `_set_mode`
        if the file is opened in append mode, so the file position can be
        tracked and `seek` and `tell` will work correctly.  If the file is
        a stream that can't be randomly accessed, you don't need to override
        this method,
        """
        pass

    def _set_mode(self, mode='r', bufsize=-1):
        """
        Subclasses call this method to initialize the BufferedFile.
        """
        pass