"""
`.AuthHandler`
"""
import weakref
import threading
import time
import re
from paramiko.common import cMSG_SERVICE_REQUEST, cMSG_DISCONNECT, DISCONNECT_SERVICE_NOT_AVAILABLE, DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, cMSG_USERAUTH_REQUEST, cMSG_SERVICE_ACCEPT, DEBUG, AUTH_SUCCESSFUL, INFO, cMSG_USERAUTH_SUCCESS, cMSG_USERAUTH_FAILURE, AUTH_PARTIALLY_SUCCESSFUL, cMSG_USERAUTH_INFO_REQUEST, WARNING, AUTH_FAILED, cMSG_USERAUTH_PK_OK, cMSG_USERAUTH_INFO_RESPONSE, MSG_SERVICE_REQUEST, MSG_SERVICE_ACCEPT, MSG_USERAUTH_REQUEST, MSG_USERAUTH_SUCCESS, MSG_USERAUTH_FAILURE, MSG_USERAUTH_BANNER, MSG_USERAUTH_INFO_REQUEST, MSG_USERAUTH_INFO_RESPONSE, cMSG_USERAUTH_GSSAPI_RESPONSE, cMSG_USERAUTH_GSSAPI_TOKEN, cMSG_USERAUTH_GSSAPI_MIC, MSG_USERAUTH_GSSAPI_RESPONSE, MSG_USERAUTH_GSSAPI_TOKEN, MSG_USERAUTH_GSSAPI_ERROR, MSG_USERAUTH_GSSAPI_ERRTOK, MSG_USERAUTH_GSSAPI_MIC, MSG_NAMES, cMSG_USERAUTH_BANNER
from paramiko.message import Message
from paramiko.util import b, u
from paramiko.ssh_exception import SSHException, AuthenticationException, BadAuthenticationType, PartialAuthentication
from paramiko.server import InteractiveQuery
from paramiko.ssh_gss import GSSAuth, GSS_EXCEPTIONS

class AuthHandler:
    """
    Internal class to handle the mechanics of authentication.
    """

    def __init__(self, transport):
        self.transport = weakref.proxy(transport)
        self.username = None
        self.authenticated = False
        self.auth_event = None
        self.auth_method = ''
        self.banner = None
        self.password = None
        self.private_key = None
        self.interactive_handler = None
        self.submethods = None
        self.auth_username = None
        self.auth_fail_count = 0
        self.gss_host = None
        self.gss_deleg_creds = True

    def auth_interactive(self, username, handler, event, submethods=''):
        """
        response_list = handler(title, instructions, prompt_list)
        """
        pass

    def _get_key_type_and_bits(self, key):
        """
        Given any key, return its type/algorithm & bits-to-sign.

        Intended for input to or verification of, key signatures.
        """
        pass

class GssapiWithMicAuthHandler:
    """A specialized Auth handler for gssapi-with-mic

    During the GSSAPI token exchange we need a modified dispatch table,
    because the packet type numbers are not unique.
    """
    method = 'gssapi-with-mic'

    def __init__(self, delegate, sshgss):
        self._delegate = delegate
        self.sshgss = sshgss

    def _parse_service_request(self, m):
        """Parse incoming service request."""
        service = m.get_text()
        if self._delegate.transport.server_mode and service == 'ssh-userauth':
            # Accept service request
            m = Message()
            m.add_byte(cMSG_SERVICE_ACCEPT)
            m.add_string('ssh-userauth')
            self._delegate.transport._send_message(m)
            return
        self._delegate.transport._disconnect_reason = DISCONNECT_SERVICE_NOT_AVAILABLE
        raise SSHException('Service request "{}" not supported'.format(service))

    def _parse_userauth_request(self, m):
        """Parse incoming userauth request."""
        username = m.get_text()
        service = m.get_text()
        method = m.get_text()
        if method != 'gssapi-with-mic':
            return self._delegate._parse_userauth_request(m)
        self._delegate.auth_username = username
        self._delegate.transport.gss_kex_used = True
        self._delegate.transport._expected_packet = (MSG_USERAUTH_GSSAPI_TOKEN,)
        try:
            self.sshgss.ssh_init_sec_context()
            token = self.sshgss.ssh_get_mic(self._delegate.transport.session_id)
            m = Message()
            m.add_byte(cMSG_USERAUTH_GSSAPI_RESPONSE)
            m.add_string(token)
            self._delegate.transport._send_message(m)
        except GSS_EXCEPTIONS as e:
            self._delegate.transport.saved_exception = e
            raise

    def _parse_userauth_gssapi_token(self, m):
        """Parse incoming GSSAPI token."""
        try:
            token = m.get_string()
            self.sshgss.ssh_init_sec_context(token)
            token = self.sshgss.ssh_get_mic(self._delegate.transport.session_id)
            m = Message()
            m.add_byte(cMSG_USERAUTH_GSSAPI_TOKEN)
            m.add_string(token)
            self._delegate.transport._send_message(m)
        except GSS_EXCEPTIONS as e:
            self._delegate.transport.saved_exception = e
            raise

    def _parse_userauth_gssapi_mic(self, m):
        """Parse incoming GSSAPI MIC."""
        mic_token = m.get_string()
        if self.sshgss.ssh_check_mic(self._delegate.transport.session_id, mic_token):
            m = Message()
            m.add_byte(cMSG_USERAUTH_SUCCESS)
            self._delegate.transport._send_message(m)
            self._delegate.transport._auth_handler = self._delegate
            self._delegate.transport.auth_handler = self._delegate
            self._delegate.transport._expected_packet = tuple(self._delegate.transport._preferred_packets)
            self._delegate.transport.authenticated = True
            self._delegate.transport._log(INFO, 'Authentication successful.')
            self._delegate.transport.auth_event.set()
            self._delegate.transport.auth_event = None
        else:
            raise SSHException('GSSAPI MIC check failed')

    __handler_table = {MSG_SERVICE_REQUEST: _parse_service_request, MSG_USERAUTH_REQUEST: _parse_userauth_request, MSG_USERAUTH_GSSAPI_TOKEN: _parse_userauth_gssapi_token, MSG_USERAUTH_GSSAPI_MIC: _parse_userauth_gssapi_mic}

class AuthOnlyHandler(AuthHandler):
    """
    AuthHandler, and just auth, no service requests!

    .. versionadded:: 3.2
    """

    def send_auth_request(self, username, method, finish_message=None):
        """
        Submit a userauth request message & wait for response.

        Performs the transport message send call, sets self.auth_event, and
        will lock-n-block as necessary to both send, and wait for response to,
        the USERAUTH_REQUEST.

        Most callers will want to supply a callback to ``finish_message``,
        which accepts a Message ``m`` and may call mutator methods on it to add
        more fields.
        """
        pass

    def auth_interactive(self, username, handler, submethods=''):
        """
        response_list = handler(title, instructions, prompt_list)
        """
        pass