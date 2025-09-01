"""
NFS client implementation with comprehensive functionality
"""

import struct
import logging
import socket
import time
import os
from .rpc_transport import RPCTransport, RPCError
from .socks_socket import ProxySocket
from .auth import AuthManager
from .nfs_constants import *


def pack_xdr_string(s):
    """
    Pack a string in XDR format
    
    :param s: string to pack
    :return: XDR-encoded bytes
    """
    if isinstance(s, str):
        b = s.encode('utf-8')
    else:
        b = s
    
    pad = (4 - (len(b) % 4)) % 4
    return struct.pack('!I', len(b)) + b + (b'\x00' * pad)


def unpack_xdr_string(data, offset):
    """
    Unpack an XDR string
    
    :param data: data bytes
    :param offset: starting offset
    :return: tuple (string, new_offset)
    """
    if offset + 4 > len(data):
        raise ValueError("Truncated string length")
    
    length = struct.unpack('!I', data[offset:offset+4])[0]
    offset += 4
    
    if offset + length > len(data):
        raise ValueError("Truncated string data")
    
    string_data = data[offset:offset+length]
    offset += length
    
    # Handle XDR padding
    pad = (4 - (length % 4)) % 4
    offset += pad
    
    return string_data.decode('utf-8', errors='replace'), offset


class NFSClient:
    """
    Comprehensive NFS client with support for multiple versions and operations
    """
    
    def __init__(self, target_host, export_path="/", proxy_type="direct",
                 proxy_host=None, proxy_port=None, nfs_version=3,
                 nfs_port=2049, mount_port=2049, rpc_port=111,
                 nfs_program=100003, mount_program=100005, pmap_program=100000,
                 hostname=None, uid=None, gid=None, gids=None, timeout=10, chunk_size=8192,
                 use_privileged_ports=False):
        """
        Initialize NFS client
        
        :param target_host: NFS server hostname or IP
        :param export_path: NFS export path
        :param proxy_type: proxy type (direct, socks4, socks5)
        :param proxy_host: proxy host
        :param proxy_port: proxy port
        :param nfs_version: NFS protocol version
        :param nfs_port: NFS service port
        :param mount_port: Mount service port
        :param rpc_port: RPC Portmapper port
        :param nfs_program: NFS RPC program number
        :param mount_program: Mount RPC program number  
        :param pmap_program: Portmapper RPC program number
        :param hostname: hostname for authentication
        :param uid: user ID
        :param gid: group ID
        :param gids: additional group IDs
        :param timeout: connection timeout
        :param chunk_size: chunk size for large operations
        :param use_privileged_ports: use privileged ports (<1024) for connections
        """
        self.target_host = target_host
        self.export_path = export_path
        self.proxy_type = proxy_type
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.nfs_version = nfs_version
        self.nfs_port = nfs_port
        self.mount_port = mount_port
        self.rpc_port = rpc_port
        self.nfs_program = nfs_program
        self.mount_program = mount_program
        self.pmap_program = pmap_program
        self.timeout = timeout
        self.chunk_size = chunk_size
        self.use_privileged_ports = use_privileged_ports
        
        # Authentication manager
        self.auth_manager = AuthManager(
            hostname=hostname,
            uid=uid,
            gid=gid,
            gids=gids
        )
        
        # Connection state
        self.export_handle = None
        self.connected = False
        
        # Version-specific constants
        self.mount_version = MOUNT_VERS_3 if nfs_version == 3 else MOUNT_VERS_1
        
        # Logging dei parametri configurabili
        logging.info(f"[CONFIG] NFS Program: {self.nfs_program}")
        logging.info(f"[CONFIG] Mount Program: {self.mount_program}")
        logging.info(f"[CONFIG] Portmapper Program: {self.pmap_program}")
        logging.info(f"[CONFIG] RPC Port: {self.rpc_port}")
        logging.info(f"[CONFIG] NFS Port: {self.nfs_port}")
        logging.info(f"[CONFIG] Mount Port: {self.mount_port}")
        
    def connect(self):
        """
        Connect to NFS server and mount export
        """
        logging.info(f"Connecting to {self.target_host} (NFS v{self.nfs_version})")
        
        try:
            # Discover service ports via portmapper
            self._discover_ports()
            
            # Mount the export
            self._mount_export()
            
            self.connected = True
            logging.info("Successfully connected to NFS server")
            
        except Exception as e:
            logging.error(f"Connection failed: {e}")
            raise
    
    def _discover_ports(self):
        """
        Discover NFS and mount service ports via portmapper
        """
        logging.debug("Discovering service ports via portmapper")
        
        try:
            # Connect to portmapper
            logging.debug(f"Connecting to portmapper on port {self.rpc_port}")
            sock = ProxySocket(
                self.target_host, self.rpc_port,
                self.proxy_host, self.proxy_port,
                self.proxy_type, self.timeout,
                use_privileged_port=self.use_privileged_ports
            ).connect()
            
            rpc_transport = RPCTransport(sock)
            
            # Query mount service port
            logging.debug(f"Querying mount service: program {self.mount_program}, version {self.mount_version}")
            mount_payload = struct.pack('!IIII', 
                                       self.mount_program, self.mount_version,
                                       socket.IPPROTO_TCP, 0)
            
            _, mount_response = rpc_transport.send_rpc_request(
                self.pmap_program, PMAP_VERS, PMAP_PROC_GETPORT, mount_payload
            )
            
            mount_port = self._parse_portmapper_response(mount_response)
            if mount_port > 0:
                self.mount_port = mount_port
                logging.debug(f"Mount service port: {self.mount_port}")
            
            # Query NFS service port
            logging.debug(f"Querying NFS service: program {self.nfs_program}, version {self.nfs_version}")
            nfs_payload = struct.pack('!IIII', 
                                     self.nfs_program, self.nfs_version,
                                     socket.IPPROTO_TCP, 0)
            
            _, nfs_response = rpc_transport.send_rpc_request(
                self.pmap_program, PMAP_VERS, PMAP_PROC_GETPORT, nfs_payload
            )
            
            nfs_port = self._parse_portmapper_response(nfs_response)
            if nfs_port > 0:
                self.nfs_port = nfs_port
                logging.debug(f"NFS service port: {self.nfs_port}")
            
            sock.close()
            
        except Exception as e:
            logging.warning(f"Portmapper query failed, using default ports: {e}")
    
    def _parse_portmapper_response(self, data):
        """
        Parse portmapper response to extract port number
        
        :param data: response data
        :return: port number
        """
        try:
            # Parse RPC response header
            parsed = RPCTransport(None).parse_rpc_response(data)
            
            if parsed['accept_stat'] != SUCCESS:
                raise RPCError("Portmapper request failed")
            
            # Extract port from response data
            offset = parsed['data_offset']
            if offset + 4 > len(data):
                raise ValueError("Truncated portmapper response")
            
            port = struct.unpack('!I', data[offset:offset+4])[0]
            
            if not (1 <= port <= 65535):
                raise ValueError(f"Invalid port: {port}")
            
            return port
            
        except Exception as e:
            logging.error(f"Failed to parse portmapper response: {e}")
            raise
    
    def _mount_export(self):
        """
        Mount the NFS export
        """
        logging.info(f"Mounting export: {self.export_path}")
        
        try:
            # Connect to mount service
            sock = ProxySocket(
                self.target_host, self.mount_port,
                self.proxy_host, self.proxy_port,
                self.proxy_type, self.timeout,
                use_privileged_port=self.use_privileged_ports
            ).connect()
            
            rpc_transport = RPCTransport(sock)
            
            # Build mount request payload
            payload = pack_xdr_string(self.export_path)
            
            # Get credentials
            credentials = self.auth_manager.get_auth_unix_credentials()
            verifier = self.auth_manager.get_default_verifier()
            
            # Send mount request
            logging.debug(f"Sending mount request to program {self.mount_program}")
            _, response = rpc_transport.send_rpc_request(
                self.mount_program, self.mount_version, MOUNT_PROC_MNT,
                payload, credentials, verifier
            )
            
            # Parse mount response
            self.export_handle = self._parse_mount_response(response)
            
            sock.close()
            
            logging.info(f"Export mounted successfully, handle: {self.export_handle.hex()}")
            
        except Exception as e:
            logging.error(f"Mount failed: {e}")
            raise
    
    def _parse_mount_response(self, data):
        """
        Parse mount response to extract file handle
        
        :param data: response data
        :return: file handle bytes
        """
        try:
            # Parse RPC response header
            parsed = RPCTransport(None).parse_rpc_response(data)
            
            if parsed['accept_stat'] != SUCCESS:
                raise RPCError("Mount request failed")
            
            offset = parsed['data_offset']
            
            # Parse mount status
            if offset + 4 > len(data):
                raise ValueError("Missing mount status")
            
            mount_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if mount_status != 0:
                raise RPCError(f"Mount failed with status {mount_status}")
            
            # Parse file handle
            if offset + 4 > len(data):
                raise ValueError("Missing file handle length")
            
            fh_length = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if offset + fh_length > len(data):
                raise ValueError("Truncated file handle")
            
            file_handle = data[offset:offset+fh_length]
            
            return file_handle
            
        except Exception as e:
            logging.error(f"Failed to parse mount response: {e}")
            raise
    
    def readdir(self, path="/"):
        """
        Read directory contents
        
        :param path: directory path
        :return: list of directory entries
        """
        logging.info(f"Reading directory: {path}")
        
        if not self.connected:
            raise RuntimeError("Not connected to NFS server")
        
        # Get file handle for the directory
        dir_handle = self.export_handle
        if path != "/":
            dir_handle = self._lookup_path(path)
        
        try:
            # Connect to NFS service
            sock = ProxySocket(
                self.target_host, self.nfs_port,
                self.proxy_host, self.proxy_port,
                self.proxy_type, self.timeout,
                use_privileged_port=self.use_privileged_ports
            ).connect()
            
            rpc_transport = RPCTransport(sock)
            
            # Build readdir request
            cookie = b'\x00' * 8
            verifier = b'\x00' * 8
            count = 4096
            
            payload = (
                struct.pack('!I', len(dir_handle)) + dir_handle +
                cookie + verifier +
                struct.pack('!II', count, count)
            )
            
            # Get credentials
            credentials = self.auth_manager.get_auth_unix_credentials()
            auth_verifier = self.auth_manager.get_default_verifier()
            
            # Send readdir request
            logging.debug(f"Sending readdir request to NFS program {self.nfs_program}")
            _, response = rpc_transport.send_rpc_request(
                self.nfs_program, self.nfs_version, 16,  # READDIR
                payload, credentials, auth_verifier
            )
            
            sock.close()
            
            # Parse response
            entries = self._parse_readdir_response(response)
            
            logging.info(f"Found {len(entries)} directory entries")
            return entries
            
        except Exception as e:
            logging.error(f"Readdir failed: {e}")
            raise
    
    def _parse_readdir_response(self, data):
        """
        Parse readdir response
        
        :param data: response data
        :return: list of directory entries
        """
        try:
            # Parse RPC response header
            parsed = RPCTransport(None).parse_rpc_response(data)
            
            if parsed['accept_stat'] != SUCCESS:
                raise RPCError("Readdir request failed")
            
            offset = parsed['data_offset']
            logging.debug(f"Starting READDIR parse at offset {offset}, data length: {len(data)}")
            
            # Parse NFS status
            if offset + 4 > len(data):
                raise ValueError("Missing NFS status")
            
            nfs_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            logging.debug(f"NFS status: {nfs_status}")
            
            if nfs_status != NFS_OK:
                error_msg = NFS_ERROR_MESSAGES.get(nfs_status, f"Unknown error ({nfs_status})")
                raise RPCError(f"NFS error: {error_msg}")
            
            # Skip post-op attributes if present
            if offset + 4 > len(data):
                raise ValueError("Truncated readdir response")
            
            attrs_follow = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            logging.debug(f"Attributes follow: {attrs_follow}, offset now: {offset}")
            
            if attrs_follow == 1:
                offset += 84  # Skip file attributes
                logging.debug(f"Skipped attributes, offset now: {offset}")
            
            # Skip cookie verifier (8 bytes)
            if offset + 8 > len(data):
                raise ValueError("Missing cookie verifier")
            offset += 8
            logging.debug(f"Skipped verifier, offset now: {offset}")
            
            # Parse directory entries
            entries = []
            entry_count = 0
            
            # Continue parsing until we reach EOF marker or run out of data
            while offset + 4 <= len(data):
                # Check for "entry follows" marker
                entry_follows = struct.unpack('!I', data[offset:offset+4])[0]
                offset += 4
                logging.debug(f"Entry {entry_count}: follows={entry_follows}, offset={offset}")
                
                if entry_follows == 0:
                    # No more entries - check for EOF marker
                    if offset + 4 <= len(data):
                        eof = struct.unpack('!I', data[offset:offset+4])[0]
                        logging.debug(f"EOF marker: {eof}")
                    logging.debug("No more entries (entry_follows=0)")
                    break
                
                # Parse file ID
                if offset + 8 > len(data):
                    logging.debug(f"Breaking: not enough data for fileid at offset {offset}")
                    break
                
                fileid = struct.unpack('!Q', data[offset:offset+8])[0]
                offset += 8
                logging.debug(f"Entry {entry_count}: fileid={fileid}, offset={offset}")
                
                # Parse filename
                try:
                    filename, offset = unpack_xdr_string(data, offset)
                    logging.debug(f"Entry {entry_count}: filename='{filename}', offset={offset}")
                except ValueError as e:
                    logging.debug(f"Breaking: failed to parse filename: {e}")
                    break
                except Exception as e:
                    logging.debug(f"Breaking: unexpected error parsing filename: {e}")
                    break
                
                # Parse cookie
                if offset + 8 > len(data):
                    logging.debug(f"Breaking: not enough data for cookie at offset {offset}")
                    break
                
                cookie = struct.unpack('!Q', data[offset:offset+8])[0]
                offset += 8
                logging.debug(f"Entry {entry_count}: cookie={cookie}, offset={offset}")
                
                # Only add entries that aren't '.' or '..' unless specifically requested
                if filename not in ['.', '..']:
                    entries.append({
                        'fileid': fileid,
                        'name': filename,
                        'cookie': cookie
                    })
                
                entry_count += 1
            
            logging.debug(f"READDIR parsing complete: {len(entries)} entries found (excluding . and ..)")
            return entries
            
        except Exception as e:
            logging.error(f"Failed to parse readdir response: {e}")
            import traceback
            logging.debug(f"Full traceback: {traceback.format_exc()}")
            raise
    
    def read_file(self, path, offset=0, size=None):
        """
        Read file contents
        
        :param path: file path
        :param offset: starting offset
        :param size: number of bytes to read (None for entire file)
        :return: file contents as bytes
        """
        logging.info(f"Reading file: {path}")
        
        if not self.connected:
            raise RuntimeError("Not connected to NFS server")
        
        # Get file handle
        file_handle = self._lookup_path(path)
        
        # Determine read size
        if size is None:
            # Try to get file size from attributes
            try:
                attrs = self.getattr(path)
                size = attrs.get('size', self.chunk_size)
            except:
                size = self.chunk_size
        
        # Read file in chunks
        data = b''
        current_offset = offset
        
        while len(data) < size:
            chunk_size = min(self.chunk_size, size - len(data))
            chunk = self._read_chunk(file_handle, current_offset, chunk_size)
            
            if not chunk:
                break  # EOF
            
            data += chunk
            current_offset += len(chunk)
            
            if len(chunk) < chunk_size:
                break  # EOF
        
        logging.info(f"Read {len(data)} bytes from {path}")
        return data
    
    def _read_chunk(self, file_handle, offset, size):
        """
        Read a chunk of data from a file
        
        :param file_handle: file handle
        :param offset: starting offset
        :param size: chunk size
        :return: chunk data
        """
        try:
            # Connect to NFS service
            sock = ProxySocket(
                self.target_host, self.nfs_port,
                self.proxy_host, self.proxy_port,
                self.proxy_type, self.timeout,
                use_privileged_port=self.use_privileged_ports
            ).connect()
            
            rpc_transport = RPCTransport(sock)
            
            # Build read request
            payload = (
                struct.pack('!I', len(file_handle)) + file_handle +
                struct.pack('!Q', offset) +
                struct.pack('!I', size)
            )
            
            # Get credentials
            credentials = self.auth_manager.get_auth_unix_credentials()
            verifier = self.auth_manager.get_default_verifier()
            
            # Send read request
            logging.debug(f"Sending read request to NFS program {self.nfs_program}")
            _, response = rpc_transport.send_rpc_request(
                self.nfs_program, self.nfs_version, 6,  # READ
                payload, credentials, verifier
            )
            
            sock.close()
            
            # Parse response
            return self._parse_read_response(response)
            
        except Exception as e:
            logging.error(f"Read chunk failed: {e}")
            raise
    
    def _parse_read_response(self, data):
        """
        Parse read response
        
        :param data: response data
        :return: file data bytes
        """
        try:
            # Parse RPC response header
            parsed = RPCTransport(None).parse_rpc_response(data)
            
            if parsed['accept_stat'] != SUCCESS:
                raise RPCError("Read request failed")
            
            offset = parsed['data_offset']
            
            # Parse NFS status
            if offset + 4 > len(data):
                raise ValueError("Missing NFS status")
            
            nfs_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if nfs_status != NFS_OK:
                error_msg = NFS_ERROR_MESSAGES.get(nfs_status, f"Unknown error ({nfs_status})")
                raise RPCError(f"NFS error: {error_msg}")
            
            # Skip post-op attributes if present
            if offset + 4 > len(data):
                raise ValueError("Truncated read response")
            
            attrs_follow = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if attrs_follow == 1:
                offset += 84  # Skip file attributes
            
            # Parse read data - NFSv3 format
            if offset + 8 > len(data):
                raise ValueError("Missing read data fields")
            
            count = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            eof = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            # Read the data length (XDR format)
            if offset + 4 > len(data):
                raise ValueError("Missing data length field")
            
            data_length = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if offset + data_length > len(data):
                raise ValueError("Truncated read data")
            
            file_data = data[offset:offset+data_length]
            
            logging.debug(f"Read result: count={count}, eof={eof}, data_length={data_length}")
            return file_data
            
        except Exception as e:
            logging.error(f"Failed to parse read response: {e}")
            raise
    
    def write_file(self, path, data, offset=0):
        """
        Write data to a file
        
        :param path: file path
        :param data: data to write
        :param offset: starting offset
        :return: True if successful
        """
        logging.info(f"Writing {len(data)} bytes to {path}")
        
        if not self.connected:
            raise RuntimeError("Not connected to NFS server")
        
        # Get or create file handle
        try:
            file_handle = self._lookup_path(path)
        except:
            # File doesn't exist, create it
            file_handle = self._create_file(path)
        
        # Write data in chunks
        current_offset = offset
        bytes_written = 0
        
        while bytes_written < len(data):
            chunk_size = min(self.chunk_size, len(data) - bytes_written)
            chunk = data[bytes_written:bytes_written + chunk_size]
            
            written = self._write_chunk(file_handle, current_offset, chunk)
            bytes_written += written
            current_offset += written
            
            if written < len(chunk):
                break  # Write failed
        
        logging.info(f"Wrote {bytes_written} bytes to {path}")
        return bytes_written == len(data)
    
    def _write_chunk(self, file_handle, offset, data):
        """
        Write a chunk of data to a file
        
        :param file_handle: file handle
        :param offset: starting offset
        :param data: chunk data
        :return: number of bytes written
        """
        try:
            # Connect to NFS service
            sock = ProxySocket(
                self.target_host, self.nfs_port,
                self.proxy_host, self.proxy_port,
                self.proxy_type, self.timeout,
                use_privileged_port=self.use_privileged_ports
            ).connect()
            
            rpc_transport = RPCTransport(sock)
            
            # Build write request
            payload = (
                struct.pack('!I', len(file_handle)) + file_handle +
                struct.pack('!Q', offset) +
                struct.pack('!I', len(data)) +
                struct.pack('!I', 1) +  # FILE_SYNC
                struct.pack('!I', len(data)) + data
            )
            
            # Add padding for XDR alignment
            pad = (4 - (len(data) % 4)) % 4
            payload += b'\x00' * pad
            
            # Get credentials
            credentials = self.auth_manager.get_auth_unix_credentials()
            verifier = self.auth_manager.get_default_verifier()
            
            # Send write request
            _, response = rpc_transport.send_rpc_request(
                self.nfs_program, self.nfs_version, 7,  # WRITE
                payload, credentials, verifier
            )
            
            sock.close()
            
            # Parse response
            return self._parse_write_response(response)
            
        except Exception as e:
            logging.error(f"Write chunk failed: {e}")
            raise
    
    def _parse_write_response(self, data):
        """
        Parse write response
        
        :param data: response data
        :return: number of bytes written
        """
        try:
            # Parse RPC response header
            parsed = RPCTransport(None).parse_rpc_response(data)
            
            if parsed['accept_stat'] != SUCCESS:
                raise RPCError("Write request failed")
            
            offset = parsed['data_offset']
            
            # Parse NFS status
            if offset + 4 > len(data):
                raise ValueError("Missing NFS status")
            
            nfs_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if nfs_status != NFS_OK:
                error_msg = NFS_ERROR_MESSAGES.get(nfs_status, f"Unknown error ({nfs_status})")
                raise RPCError(f"NFS error: {error_msg}")
            
            # Parse file_wcc (wcc_data) structure for NFSv3 WRITE response
            # wcc_data = before_attrs? + after_attrs?
            
            # Skip before_attrs if present
            if offset + 4 > len(data):
                raise ValueError("Truncated write response")
            
            before_attrs_follow = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if before_attrs_follow == 1:
                offset += 24  # Skip wcc_attr (size + mtime + ctime)
            
            # Skip after_attrs if present
            if offset + 4 > len(data):
                raise ValueError("Missing after_attrs")
            
            after_attrs_follow = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if after_attrs_follow == 1:
                offset += 84  # Skip fattr3
            
            # Parse write result: count + committed + verifier
            if offset + 12 > len(data):
                raise ValueError("Missing write result")
            
            count = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            committed = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            # Skip 8-byte verifier 
            offset += 8
            
            logging.debug(f"Write result: count={count}, committed={committed}")
            return count
            
        except Exception as e:
            logging.error(f"Failed to parse write response: {e}")
            raise
    
    def _lookup_path(self, path):
        """
        Lookup file handle for a path
        
        :param path: file path
        :return: file handle
        """
        if path == "/":
            return self.export_handle
        
        # Split path into components
        components = [c for c in path.split('/') if c]
        current_handle = self.export_handle
        
        for component in components:
            current_handle = self._lookup_component(current_handle, component)
        
        return current_handle
    
    def _lookup_component(self, dir_handle, name):
        """
        Lookup a single path component
        
        :param dir_handle: directory handle
        :param name: component name
        :return: file handle
        """
        try:
            # Connect to NFS service
            sock = ProxySocket(
                self.target_host, self.nfs_port,
                self.proxy_host, self.proxy_port,
                self.proxy_type, self.timeout,
                use_privileged_port=self.use_privileged_ports
            ).connect()
            
            rpc_transport = RPCTransport(sock)
            
            # Build lookup request
            payload = (
                struct.pack('!I', len(dir_handle)) + dir_handle +
                pack_xdr_string(name)
            )
            
            # Get credentials
            credentials = self.auth_manager.get_auth_unix_credentials()
            verifier = self.auth_manager.get_default_verifier()
            
            # Send lookup request
            _, response = rpc_transport.send_rpc_request(
                self.nfs_program, self.nfs_version, 3,  # LOOKUP
                payload, credentials, verifier
            )
            
            sock.close()
            
            # Parse response
            return self._parse_lookup_response(response)
            
        except Exception as e:
            logging.error(f"Lookup failed for {name}: {e}")
            raise
    
    def _parse_lookup_response(self, data):
        """
        Parse lookup response
        
        :param data: response data
        :return: file handle
        """
        try:
            # Parse RPC response header
            parsed = RPCTransport(None).parse_rpc_response(data)
            
            if parsed['accept_stat'] != SUCCESS:
                raise RPCError("Lookup request failed")
            
            offset = parsed['data_offset']
            
            # Parse NFS status
            if offset + 4 > len(data):
                raise ValueError("Missing NFS status")
            
            nfs_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if nfs_status != NFS_OK:
                error_msg = NFS_ERROR_MESSAGES.get(nfs_status, f"Unknown error ({nfs_status})")
                raise RPCError(f"NFS error: {error_msg}")
            
            # Parse object file handle (sempre presente in caso di successo)
            if offset + 4 > len(data):
                raise ValueError("Missing file handle length")
            
            fh_length = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if offset + fh_length > len(data):
                raise ValueError("Truncated file handle")
            
            file_handle = data[offset:offset+fh_length]
            offset += fh_length
            
            logging.debug(f"Parsed file handle: length={fh_length}, handle={file_handle.hex()}")
            
            # Skip obj_attributes if present
            if offset + 4 <= len(data):
                obj_attrs_follow = struct.unpack('!I', data[offset:offset+4])[0]
                offset += 4
                if obj_attrs_follow == 1:
                    offset += 84  # Skip obj attributes
            
            # Skip dir_attributes if present  
            if offset + 4 <= len(data):
                dir_attrs_follow = struct.unpack('!I', data[offset:offset+4])[0]
                offset += 4
                if dir_attrs_follow == 1:
                    offset += 84  # Skip dir attributes
            
            return file_handle
            
        except Exception as e:
            logging.error(f"Failed to parse lookup response: {e}")
            raise
    
    def _create_file(self, path):
        """
        Create a new file
        
        :param path: file path
        :return: file handle
        """
        # Split path into directory and filename
        dir_path, filename = os.path.split(path)
        if not dir_path:
            dir_path = "/"
        
        # Get directory handle
        dir_handle = self._lookup_path(dir_path)
        
        try:
            # Connect to NFS service
            sock = ProxySocket(
                self.target_host, self.nfs_port,
                self.proxy_host, self.proxy_port,
                self.proxy_type, self.timeout,
                use_privileged_port=self.use_privileged_ports
            ).connect()
            
            rpc_transport = RPCTransport(sock)
            
            # Build create request - NFSv3 CREATE format
            # Mode: UNCHECKED (1), GUARDED (0), EXCLUSIVE (2)
            create_mode = 1  # UNCHECKED
            
            payload = (
                struct.pack('!I', len(dir_handle)) + dir_handle +
                pack_xdr_string(filename) +
                struct.pack('!I', create_mode)
            )
            
            # Add file attributes for UNCHECKED mode
            if create_mode == 1:  # UNCHECKED
                # sattr3 structure
                payload += (
                    struct.pack('!I', 1) +  # mode set
                    struct.pack('!I', 0o644) +  # mode value (rw-r--r--)
                    struct.pack('!I', 0) +  # uid not set
                    struct.pack('!I', 0) +  # gid not set  
                    struct.pack('!I', 0) +  # size not set
                    struct.pack('!I', 0) +  # atime not set
                    struct.pack('!I', 0)    # mtime not set
                )
            
            # Get credentials
            credentials = self.auth_manager.get_auth_unix_credentials()
            verifier = self.auth_manager.get_default_verifier()
            
            # Send create request
            _, response = rpc_transport.send_rpc_request(
                self.nfs_program, self.nfs_version, 8,  # CREATE
                payload, credentials, verifier
            )
            
            sock.close()
            
            # Parse response
            return self._parse_create_response(response)
            
        except Exception as e:
            logging.error(f"Create failed for {path}: {e}")
            raise
    
    def _parse_create_response(self, data):
        """
        Parse create response
        
        :param data: response data
        :return: file handle
        """
        try:
            # Parse RPC response header
            parsed = RPCTransport(None).parse_rpc_response(data)
            
            if parsed['accept_stat'] != SUCCESS:
                raise RPCError("Create request failed")
            
            offset = parsed['data_offset']
            
            # Parse NFS status
            if offset + 4 > len(data):
                raise ValueError("Missing NFS status")
            
            nfs_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if nfs_status != NFS_OK:
                error_msg = NFS_ERROR_MESSAGES.get(nfs_status, f"Unknown error ({nfs_status})")
                raise RPCError(f"NFS error: {error_msg}")
            
            # Parse file handle
            if offset + 4 > len(data):
                raise ValueError("Missing file handle")
            
            handle_follows = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if handle_follows != 1:
                raise RPCError("Create response missing file handle")
            
            if offset + 4 > len(data):
                raise ValueError("Missing file handle length")
            
            fh_length = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if offset + fh_length > len(data):
                raise ValueError("Truncated file handle")
            
            file_handle = data[offset:offset+fh_length]
            
            return file_handle
            
        except Exception as e:
            logging.error(f"Failed to parse create response: {e}")
            raise
    
    def lookup(self, path):
        """
        Lookup a file or directory
        
        :param path: file path
        :return: file handle
        """
        return self._lookup_path(path)
    
    def check_access(self, path, access_mask):
        """
        Check access permissions for a file or directory
        
        :param path: file path
        :param access_mask: access mask (combination of ACCESS_* constants)
        :return: granted access mask
        """
        # Get file handle
        file_handle = self._lookup_path(path)
        
        try:
            # Connect to NFS service
            sock = ProxySocket(
                self.target_host, self.nfs_port,
                self.proxy_host, self.proxy_port,
                self.proxy_type, self.timeout,
                use_privileged_port=self.use_privileged_ports
            ).connect()
            
            rpc_transport = RPCTransport(sock)
            
            # Build access request
            payload = (
                struct.pack('!I', len(file_handle)) + file_handle +
                struct.pack('!I', access_mask)
            )
            
            # Get credentials
            credentials = self.auth_manager.get_auth_unix_credentials()
            verifier = self.auth_manager.get_default_verifier()
            
            # Send access request
            _, response = rpc_transport.send_rpc_request(
                self.nfs_program, self.nfs_version, 4,  # ACCESS
                payload, credentials, verifier
            )
            
            sock.close()
            
            # Parse response
            return self._parse_access_response(response)
            
        except Exception as e:
            logging.error(f"Access check failed for {path}: {e}")
            raise
    
    def _parse_access_response(self, data):
        """
        Parse access response
        
        :param data: response data
        :return: granted access mask
        """
        try:
            # Parse RPC response header
            parsed = RPCTransport(None).parse_rpc_response(data)
            
            if parsed['accept_stat'] != SUCCESS:
                raise RPCError("Access request failed")
            
            offset = parsed['data_offset']
            
            # Parse NFS status
            if offset + 4 > len(data):
                raise ValueError("Missing NFS status")
            
            nfs_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if nfs_status != NFS_OK:
                error_msg = NFS_ERROR_MESSAGES.get(nfs_status, f"Unknown error ({nfs_status})")
                raise RPCError(f"NFS error: {error_msg}")
            
            # Skip attributes
            if offset + 4 > len(data):
                raise ValueError("Truncated access response")
            
            attrs_follow = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if attrs_follow == 1:
                offset += 84  # Skip file attributes
            
            # Parse access result
            if offset + 4 > len(data):
                raise ValueError("Missing access result")
            
            granted_access = struct.unpack('!I', data[offset:offset+4])[0]
            
            return granted_access
            
        except Exception as e:
            logging.error(f"Failed to parse access response: {e}")
            raise
    
    def getattr(self, path):
        """
        Get file attributes
        
        :param path: file path
        :return: dict with file attributes
        """
        # Get file handle
        file_handle = self._lookup_path(path)
        
        try:
            # Connect to NFS service
            sock = ProxySocket(
                self.target_host, self.nfs_port,
                self.proxy_host, self.proxy_port,
                self.proxy_type, self.timeout,
                use_privileged_port=self.use_privileged_ports
            ).connect()
            
            rpc_transport = RPCTransport(sock)
            
            # Build getattr request
            payload = struct.pack('!I', len(file_handle)) + file_handle
            
            # Get credentials
            credentials = self.auth_manager.get_auth_unix_credentials()
            verifier = self.auth_manager.get_default_verifier()
            
            # Send getattr request
            _, response = rpc_transport.send_rpc_request(
                self.nfs_program, self.nfs_version, 1,  # GETATTR
                payload, credentials, verifier
            )
            
            sock.close()
            
            # Parse response
            return self._parse_getattr_response(response)
            
        except Exception as e:
            logging.error(f"Getattr failed for {path}: {e}")
            raise
    
    def _parse_getattr_response(self, data):
        """
        Parse getattr response
        
        :param data: response data
        :return: dict with file attributes
        """
        try:
            # Parse RPC response header
            parsed = RPCTransport(None).parse_rpc_response(data)
            
            if parsed['accept_stat'] != SUCCESS:
                raise RPCError("Getattr request failed")
            
            offset = parsed['data_offset']
            
            # Parse NFS status
            if offset + 4 > len(data):
                raise ValueError("Missing NFS status")
            
            nfs_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if nfs_status != NFS_OK:
                error_msg = NFS_ERROR_MESSAGES.get(nfs_status, f"Unknown error ({nfs_status})")
                raise RPCError(f"NFS error: {error_msg}")
            
            # Parse file attributes (84 bytes for NFSv3)
            if offset + 84 > len(data):
                raise ValueError("Truncated file attributes")
            
            attrs_data = data[offset:offset+84]
            
            # Parse key attributes
            ftype = struct.unpack('!I', attrs_data[0:4])[0]
            mode = struct.unpack('!I', attrs_data[4:8])[0]
            nlink = struct.unpack('!I', attrs_data[8:12])[0]
            uid = struct.unpack('!I', attrs_data[12:16])[0]
            gid = struct.unpack('!I', attrs_data[16:20])[0]
            size = struct.unpack('!Q', attrs_data[20:28])[0]
            
            return {
                'type': ftype,
                'mode': mode,
                'nlink': nlink,
                'uid': uid,
                'gid': gid,
                'size': size
            }
            
        except Exception as e:
            logging.error(f"Failed to parse getattr response: {e}")
            raise
    
    def clone_with_credentials(self, uid, gid, gids=None):
        """
        Create a clone of this client with different credentials
        
        :param uid: new user ID
        :param gid: new group ID
        :param gids: new additional group IDs
        :return: new NFSClient instance
        """
        new_client = NFSClient(
            target_host=self.target_host,
            export_path=self.export_path,
            proxy_type=self.proxy_type,
            proxy_host=self.proxy_host,
            proxy_port=self.proxy_port,
            nfs_version=self.nfs_version,
            nfs_port=self.nfs_port,
            mount_port=self.mount_port,
            rpc_port=self.rpc_port,
            nfs_program=self.nfs_program,
            mount_program=self.mount_program,
            pmap_program=self.pmap_program,
            hostname=self.auth_manager.hostname,
            uid=uid,
            gid=gid,
            gids=gids or [],
            timeout=self.timeout,
            chunk_size=self.chunk_size,
            use_privileged_ports=self.use_privileged_ports
        )
        
        return new_client
    
    def disconnect(self):
        """
        Disconnect from NFS server
        """
        if self.connected:
            # Optionally send UMOUNT request
            try:
                self._unmount_export()
            except:
                pass
            
            self.connected = False
            self.export_handle = None
            
            logging.info("Disconnected from NFS server")
    
    def _unmount_export(self):
        """
        Unmount the NFS export
        """
        try:
            # Connect to mount service
            sock = ProxySocket(
                self.target_host, self.mount_port,
                self.proxy_host, self.proxy_port,
                self.proxy_type, self.timeout,
                use_privileged_port=self.use_privileged_ports
            ).connect()
            
            rpc_transport = RPCTransport(sock)
            
            # Build unmount request
            payload = pack_xdr_string(self.export_path)
            
            # Get credentials
            credentials = self.auth_manager.get_auth_unix_credentials()
            verifier = self.auth_manager.get_default_verifier()
            
            # Send unmount request
            logging.debug(f"Sending unmount request to program {self.mount_program}")
            rpc_transport.send_rpc_request(
                self.mount_program, self.mount_version, MOUNT_PROC_UMNT,
                payload, credentials, verifier
            )
            
            sock.close()
            
        except Exception as e:
            logging.debug(f"Unmount failed: {e}")
    
    def __enter__(self):
        """
        Context manager entry
        """
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Context manager exit
        """
        self.disconnect()
