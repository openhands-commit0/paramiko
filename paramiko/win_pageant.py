"""
Functions for communicating with Pageant, the basic windows ssh agent program.
"""
import array
import ctypes.wintypes
import platform
import struct
from paramiko.common import zero_byte
from paramiko.util import b
import _thread as thread
from . import _winapi
_AGENT_COPYDATA_ID = 2152616122
_AGENT_MAX_MSGLEN = 8192
win32con_WM_COPYDATA = 74

def can_talk_to_agent():
    """
    Check to see if there is a "Pageant" agent we can talk to.

    This checks both if we have the required libraries (win32all or ctypes)
    and if there is a Pageant currently running.
    """
    pass
if platform.architecture()[0] == '64bit':
    ULONG_PTR = ctypes.c_uint64
else:
    ULONG_PTR = ctypes.c_uint32

class COPYDATASTRUCT(ctypes.Structure):
    """
    ctypes implementation of
    http://msdn.microsoft.com/en-us/library/windows/desktop/ms649010%28v=vs.85%29.aspx
    """
    _fields_ = [('num_data', ULONG_PTR), ('data_size', ctypes.wintypes.DWORD), ('data_loc', ctypes.c_void_p)]

def _query_pageant(msg):
    """
    Communication with the Pageant process is done through a shared
    memory-mapped file.
    """
    pass

class PageantConnection:
    """
    Mock "connection" to an agent which roughly approximates the behavior of
    a unix local-domain socket (as used by Agent).  Requests are sent to the
    pageant daemon via special Windows magick, and responses are buffered back
    for subsequent reads.
    """

    def __init__(self):
        self._response = None