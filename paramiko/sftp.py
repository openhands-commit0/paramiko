import select
import socket
import struct
from paramiko import util
from paramiko.common import DEBUG, byte_chr, byte_ord
from paramiko.message import Message
CMD_INIT, CMD_VERSION, CMD_OPEN, CMD_CLOSE, CMD_READ, CMD_WRITE, CMD_LSTAT, CMD_FSTAT, CMD_SETSTAT, CMD_FSETSTAT, CMD_OPENDIR, CMD_READDIR, CMD_REMOVE, CMD_MKDIR, CMD_RMDIR, CMD_REALPATH, CMD_STAT, CMD_RENAME, CMD_READLINK, CMD_SYMLINK = range(1, 21)
CMD_STATUS, CMD_HANDLE, CMD_DATA, CMD_NAME, CMD_ATTRS = range(101, 106)
CMD_EXTENDED, CMD_EXTENDED_REPLY = range(200, 202)
SFTP_OK = 0
SFTP_EOF, SFTP_NO_SUCH_FILE, SFTP_PERMISSION_DENIED, SFTP_FAILURE, SFTP_BAD_MESSAGE, SFTP_NO_CONNECTION, SFTP_CONNECTION_LOST, SFTP_OP_UNSUPPORTED = range(1, 9)
SFTP_DESC = ['Success', 'End of file', 'No such file', 'Permission denied', 'Failure', 'Bad message', 'No connection', 'Connection lost', 'Operation unsupported']
SFTP_FLAG_READ = 1
SFTP_FLAG_WRITE = 2
SFTP_FLAG_APPEND = 4
SFTP_FLAG_CREATE = 8
SFTP_FLAG_TRUNC = 16
SFTP_FLAG_EXCL = 32
_VERSION = 3
CMD_NAMES = {CMD_INIT: 'init', CMD_VERSION: 'version', CMD_OPEN: 'open', CMD_CLOSE: 'close', CMD_READ: 'read', CMD_WRITE: 'write', CMD_LSTAT: 'lstat', CMD_FSTAT: 'fstat', CMD_SETSTAT: 'setstat', CMD_FSETSTAT: 'fsetstat', CMD_OPENDIR: 'opendir', CMD_READDIR: 'readdir', CMD_REMOVE: 'remove', CMD_MKDIR: 'mkdir', CMD_RMDIR: 'rmdir', CMD_REALPATH: 'realpath', CMD_STAT: 'stat', CMD_RENAME: 'rename', CMD_READLINK: 'readlink', CMD_SYMLINK: 'symlink', CMD_STATUS: 'status', CMD_HANDLE: 'handle', CMD_DATA: 'data', CMD_NAME: 'name', CMD_ATTRS: 'attrs', CMD_EXTENDED: 'extended', CMD_EXTENDED_REPLY: 'extended_reply'}

class int64(int):
    pass

class SFTPError(Exception):
    pass

class BaseSFTP:

    def __init__(self):
        self.logger = util.get_logger('paramiko.sftp')
        self.sock = None
        self.ultra_debug = False