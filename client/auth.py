"""
Authentication utilities for NFS client
"""

import struct
import time
import socket
import platform


def build_auth_unix_payload(hostname, uid, gid, gids=None):
    """
    Build AUTH_UNIX payload for RPC authentication
    
    :param hostname: hostname to use in authentication
    :param uid: user ID
    :param gid: group ID
    :param gids: list of additional group IDs
    :return: AUTH_UNIX payload bytes
    """
    if gids is None:
        gids = []
    
    # Ensure hostname is not too long
    if len(hostname) > 255:
        hostname = hostname[:255]
    
    # Get current timestamp
    timestamp = int(time.time())
    
    # Build hostname with XDR padding
    hostname_bytes = hostname.encode('utf-8')
    hostname_len = len(hostname_bytes)
    hostname_pad = (4 - (hostname_len % 4)) % 4
    
    # Build the payload
    payload = struct.pack('!I', timestamp)  # timestamp
    payload += struct.pack('!I', hostname_len)  # hostname length
    payload += hostname_bytes + (b'\x00' * hostname_pad)  # hostname with padding
    payload += struct.pack('!I', uid)  # uid
    payload += struct.pack('!I', gid)  # gid
    payload += struct.pack('!I', len(gids))  # number of additional gids
    
    # Add additional gids
    for gid_item in gids:
        payload += struct.pack('!I', gid_item)
    
    return payload


def build_auth_null_payload():
    """
    Build AUTH_NULL payload (empty)
    
    :return: empty bytes
    """
    return b''


def get_system_hostname():
    """
    Get system hostname with cross-platform compatibility
    
    :return: system hostname
    """
    try:
        return socket.gethostname()
    except:
        return platform.node() or "nfsclient"


def get_system_uid():
    """
    Get current user ID (Unix-like systems only)
    
    :return: user ID or 1001 as default
    """
    try:
        import os
        return os.getuid()
    except (ImportError, AttributeError):
        # Windows or other systems
        return 1001


def get_system_gid():
    """
    Get current group ID (Unix-like systems only)
    
    :return: group ID or 1001 as default
    """
    try:
        import os
        return os.getgid()
    except (ImportError, AttributeError):
        # Windows or other systems
        return 1001


def get_system_gids():
    """
    Get additional group IDs (Unix-like systems only)
    
    :return: list of group IDs
    """
    try:
        import os
        return os.getgroups()
    except (ImportError, AttributeError):
        # Windows or other systems
        return []


class AuthManager:
    """
    Manages authentication credentials for NFS operations
    """
    
    def __init__(self, hostname=None, uid=None, gid=None, gids=None, 
                 username=None, password=None):
        """
        Initialize authentication manager
        
        :param hostname: hostname for AUTH_UNIX
        :param uid: user ID
        :param gid: group ID
        :param gids: additional group IDs
        :param username: username (for future authentication methods)
        :param password: password (for future authentication methods)
        """
        self.hostname = hostname or get_system_hostname()
        self.uid = uid or get_system_uid()
        self.gid = gid or get_system_gid()
        self.gids = gids or []
        self.username = username
        self.password = password
    
    def get_auth_unix_credentials(self):
        """
        Get AUTH_UNIX credentials tuple
        
        :return: tuple (flavor, payload)
        """
        payload = build_auth_unix_payload(self.hostname, self.uid, self.gid, self.gids)
        return (1, payload)  # AUTH_UNIX = 1
    
    def get_auth_null_credentials(self):
        """
        Get AUTH_NULL credentials tuple
        
        :return: tuple (flavor, payload)
        """
        return (0, b'')  # AUTH_NULL = 0
    
    def get_default_verifier(self):
        """
        Get default verifier (AUTH_NULL)
        
        :return: tuple (flavor, payload)
        """
        return (0, b'')  # AUTH_NULL = 0
    
    def update_credentials(self, uid=None, gid=None, gids=None):
        """
        Update authentication credentials
        
        :param uid: new user ID
        :param gid: new group ID
        :param gids: new additional group IDs
        """
        if uid is not None:
            self.uid = uid
        if gid is not None:
            self.gid = gid
        if gids is not None:
            self.gids = gids
    
    def clone_with_credentials(self, uid, gid, gids=None):
        """
        Create a clone with different credentials
        
        :param uid: new user ID
        :param gid: new group ID
        :param gids: new additional group IDs
        :return: new AuthManager instance
        """
        return AuthManager(
            hostname=self.hostname,
            uid=uid,
            gid=gid,
            gids=gids or [],
            username=self.username,
            password=self.password
        )
