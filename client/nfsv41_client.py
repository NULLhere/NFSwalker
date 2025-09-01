#!/usr/bin/env python3
"""
NFSv4.1 Client with Session Support
Based on nfsv4_client.py but with NFSv4.1 session management integrated
"""

import logging
import socket
import struct
import time
import os
import sys

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from .auth import AuthManager
from .rpc_transport import RPCTransport
from .socks_socket import ProxySocket
from .nfs_constants import *
from nfsv4_session_manager import NFSv4SessionManager

# RPC constants needed for parsing
SUCCESS = 0
NFS4_ERROR_CODES = {
    0: "NFS4_OK",
    2: "NFS4ERR_NOENT", 
    13: "NFS4ERR_ACCESS",
    10021: "NFS4ERR_MINOR_VERS_MISMATCH",
    10071: "NFS4ERR_OP_NOT_IN_SESSION"
}


class NFSv41Client:
    """NFSv4.1 Client with integrated session management"""
    
    def __init__(self, target_host, export_path="/", 
                 proxy_type=None, proxy_host=None, proxy_port=None,
                 nfs_port=2049, nfs_program=100003,
                 hostname="nfsclient", uid=0, gid=0, gids=None,
                 timeout=10, chunk_size=1024*1024, use_privileged_ports=False):
        """
        Initialize NFSv4.1 client with session support
        
        :param target_host: target NFS server hostname/IP
        :param export_path: NFS export path  
        :param proxy_type: SOCKS proxy type ('socks4', 'socks5', None)
        :param proxy_host: SOCKS proxy hostname/IP
        :param proxy_port: SOCKS proxy port
        :param nfs_port: NFS service port
        :param nfs_program: NFS RPC program number
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
        self.nfs_port = nfs_port
        self.nfs_program = nfs_program
        self.nfs_version = 4
        self.minor_version = 1  # NFSv4.1
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
        
        # NFSv4.1 session state
        self.session_manager = None
        self.session_id = None
        self.clientid = None
        self.sequenceid = 0
        self.root_fh = None
        self.current_fh = None
        self.connected = False
        self.slot_sequence = 1  # Start from 1 for slot sequences
        
    def connect(self):
        """Connect to NFSv4.1 server with session establishment"""
        # Skip if already connected
        if self.connected:
            logging.info(f"Already connected to {self.target_host} (NFSv4.1 with sessions)")
            return True
            
        logging.info(f"Connecting to {self.target_host} (NFSv4.1 with sessions)")
        
        try:
            # Create session manager
            self.session_manager = NFSv4SessionManager(
                target_host=self.target_host,
                nfs_port=self.nfs_port,
                proxy_host=self.proxy_host,
                proxy_port=self.proxy_port,
                proxy_type=self.proxy_type,
                timeout=self.timeout,
                auth_manager=self.auth_manager,
                use_privileged_ports=self.use_privileged_ports
            )
            
            # Establish NFSv4.1 session
            if self.session_manager.establish_session(minor_version=1):
                # Get root filehandle using session
                self.root_fh = self.session_manager.get_root_filehandle_with_session()
                self.current_fh = self.root_fh
                self.session_id = self.session_manager.session_id
                self.clientid = self.session_manager.clientid
                
                # SYNC: Make sure client slot_sequence is synchronized with session_manager
                # Session manager has incremented its sequence during get_root_filehandle_with_session()
                # Client needs to continue from the next sequence number
                if hasattr(self.session_manager, 'slot_sequence'):
                    self.slot_sequence = self.session_manager.slot_sequence
                else:
                    # Fallback: session_manager used at least 1 sequence for root filehandle
                    self.slot_sequence = 2
                
                self.connected = True
                logging.info(f"Successfully connected to NFSv4.1 with session")
                return True
            else:
                raise Exception("Failed to establish NFSv4.1 session")
                
        except Exception as e:
            logging.error(f"NFSv4.1 connection failed: {e}")
            raise
    
    def _send_compound_with_session(self, operations, num_operations=None):
        """Send COMPOUND request with SEQUENCE operation for NFSv4.1"""
        if not self.session_manager or not self.session_id:
            raise RuntimeError("No active NFSv4.1 session")
        
        logging.debug(f"[TRACE] _send_compound_with_session: called with {len(operations)} operations")
        
        # Build SEQUENCE operation
        sequence_op = self._build_sequence_operation()
        
        # Prepend SEQUENCE to operations  
        all_operations = [sequence_op] + operations
        
        # Build COMPOUND payload manually
        payload = self._build_compound_payload(all_operations)
        
        # Use persistent transport directly (SAME connection as session)
        response_data = self.session_manager.call(
            program=100003,  # NFS_PROGRAM
            version=4,       # NFSv4
            procedure=1,     # COMPOUND
            data=payload
        )
        logging.debug(f"[TRACE] _send_compound_with_session: returning {len(response_data)} bytes")
        logging.debug(f"[TRACE] Return data hex: {response_data[:16].hex()}")
        return response_data
    
    def _build_compound_payload(self, operations):
        """Build COMPOUND payload for NFSv4.1"""
        minor_ver = 1  # NFSv4.1
        payload = (
            struct.pack('!I', 0) +  # tag length (empty)
            struct.pack('!I', minor_ver) +  # minor version
            struct.pack('!I', len(operations))  # number of operations
        )
        
        # Add operations
        for op in operations:
            payload += op
            
        return payload
    
    def _build_sequence_operation(self):
        """Build SEQUENCE operation for NFSv4.1"""
        sequence_op = (
            struct.pack('!I', OP_SEQUENCE) +      # opcode
            self.session_id +                      # sessionid (16 bytes)
            struct.pack('!I', self.slot_sequence) + # sequenceid
            struct.pack('!I', 0) +                 # slotid
            struct.pack('!I', 0) +                 # highest_slotid
            struct.pack('!I', 1)                   # cachethis
        )
        
        # Increment slot sequence for next operation
        self.slot_sequence += 1
        
        return sequence_op
    
    def _parse_compound_response_with_session(self, data):
        """Parse COMPOUND response with SEQUENCE operation for NFSv4.1"""
        try:
            logging.debug(f"[TRACE] _parse_compound_response_with_session: called with {len(data)} bytes")
            logging.debug(f"[TRACE] Input data hex: {data[:16].hex()}")
            
            # Use SessionRPCTransport parsing (CORRECT method)
            logging.debug(f"[TRACE] About to call _extract_data() with {len(data)} bytes")
            nfsv4_data = self.session_manager.persistent_transport._extract_data(data)
            logging.debug(f"[TRACE] _extract_data() returned {len(nfsv4_data)} bytes")
            
            # Parse NFSv4 COMPOUND response starting with NFS status
            offset = 0
            
            # COMPOUND status
            compound_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if compound_status != 0:  # NFS4_OK

                error_name = NFS4_ERROR_CODES.get(compound_status, f"UNKNOWN_ERROR")
                raise RuntimeError(f"NFSv4 COMPOUND failed: {error_name} ({compound_status})")
            
            # Tag length (skip)
            tag_len = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4 + tag_len
            
            # Number of results
            if offset + 4 > len(nfsv4_data):
                raise ValueError("Missing results count")
            
            num_results = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            # First operation should be SEQUENCE - skip it
            seq_opcode = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if seq_opcode != OP_SEQUENCE:
                raise Exception(f"Expected SEQUENCE operation, got {seq_opcode}")
            
            # Skip SEQUENCE status
            seq_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if seq_status != 0:  # NFS4_OK
                raise Exception(f"SEQUENCE operation failed: {seq_status}")
            
            # Skip SEQUENCE response fields (sessionid + sequence details)
            # sessionid (16 bytes) + sequenceid (4) + slotid (4) + highest_slotid (4) + target_highest_slotid (4) + status_flags (4)
            offset += 16 + 4 + 4 + 4 + 4 + 4
            
            # Return parsed NFSv4 data with offset to next operation
            return {'data': nfsv4_data, 'offset': offset}
            
        except Exception as e:
            logging.error(f"Failed to parse COMPOUND response with session: {e}")
            raise
    
    def _pad_len(self, length):
        """Calculate XDR padding length"""
        return (4 - (length % 4)) % 4
    
    def _lookup_path(self, path):
        """Lookup file handle for path using NFSv4.1 session"""
        if not self.connected:
            raise RuntimeError("Not connected to NFSv4.1 server")
        
        # Handle root path with export_path consideration
        if path == "/" or path == "":
            # If there's an export_path, navigate to it instead of returning server root
            if self.export_path and self.export_path != "/":
                # For root path with export, we want to read the export directory
                full_path = self.export_path
            else:
                # No export path, return server root
                return self.root_fh
        else:
            # Combine export path with requested path
            if self.export_path and self.export_path != "/":
                if path.startswith("/"):
                    path = path[1:]
                full_path = os.path.join(self.export_path, path).replace("\\", "/")
            else:
                full_path = path
        
        # Remove leading slash for component parsing
        if full_path.startswith("/"):
            full_path = full_path[1:]
        
        # Split into components
        if not full_path:
            return self.root_fh
        
        components = [c for c in full_path.split("/") if c]
        logging.debug(f"NFSv4.1 LOOKUP path: {path} -> full_path: {full_path} -> components: {components}")
        
        # Start from root filehandle
        current_fh = self.root_fh
        
        # Lookup each component
        for component in components:
            current_fh = self._lookup_component(current_fh, component)
        
        return current_fh
    
    def _lookup_component(self, base_fh, name):
        """Lookup single component using NFSv4.1 session"""
        try:
            # Build operations: PUTFH + LOOKUP + GETFH
            operations = []
            
            # PUTFH operation
            operations.append(
                struct.pack('!I', OP_PUTFH) +
                struct.pack('!I', len(base_fh)) + base_fh
            )
            
            # LOOKUP operation
            name_bytes = name.encode('utf-8')
            operations.append(
                struct.pack('!I', OP_LOOKUP) +
                struct.pack('!I', len(name_bytes)) + name_bytes +
                b'\x00' * self._pad_len(len(name_bytes))
            )
            
            # GETFH operation
            operations.append(struct.pack('!I', OP_GETFH))
            
            response = self._send_compound_with_session(operations, num_operations=4)
            
            # Parse NFSv4 data directly (no double-parsing)
            nfsv4_data = response
            offset = 0
            
            # Parse NFSv4 COMPOUND response starting with NFS status
            compound_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if compound_status != 0:  # NFS4_OK

                error_name = NFS4_ERROR_CODES.get(compound_status, f"UNKNOWN_ERROR")
                raise RuntimeError(f"NFSv4 COMPOUND failed: {error_name} ({compound_status})")
            
            # Tag length (skip)
            tag_len = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4 + tag_len
            
            # Number of results
            if offset + 4 > len(nfsv4_data):
                raise ValueError("Missing results count")
            
            num_results = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            # First operation should be SEQUENCE - skip it
            seq_opcode = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if seq_opcode != OP_SEQUENCE:
                raise Exception(f"Expected SEQUENCE operation, got {seq_opcode}")
            
            # Skip SEQUENCE status
            seq_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if seq_status != 0:  # NFS4_OK
                raise Exception(f"SEQUENCE operation failed: {seq_status}")
            
            # Skip SEQUENCE response fields (sessionid + sequence details)
            # sessionid (16 bytes) + sequenceid (4) + slotid (4) + highest_slotid (4) + target_highest_slotid (4) + status_flags (4)
            offset += 16 + 4 + 4 + 4 + 4 + 4
            
            data = nfsv4_data
            
            # Parse PUTFH result (opcode + status)
            putfh_opcode = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            putfh_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            if putfh_status != NFS4_OK:
                raise RPCError(f"PUTFH failed: {putfh_status}")
            
            # Parse LOOKUP result (opcode + status)
            lookup_opcode = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            lookup_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            if lookup_status != NFS4_OK:
                error_name = NFS4_ERROR_CODES.get(lookup_status, f"UNKNOWN_ERROR")
                logging.error(f"LOOKUP failed for {name}: {error_name} ({lookup_status})")
                raise RPCError(f"LOOKUP failed for {name}: {error_name} ({lookup_status})")
            
            # Parse GETFH result (opcode + status)
            getfh_opcode = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            getfh_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            if getfh_status != NFS4_OK:
                raise RPCError(f"GETFH failed: {getfh_status}")
            
            # Get file handle
            fh_length = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            file_handle = data[offset:offset+fh_length]
            
            return file_handle
            
        except Exception as e:
            logging.error(f"Lookup failed for {name}: {e}")
            raise
    
    def check_access(self, path, access_mask=ACCESS_READ):
        """Check file access permissions using NFSv4.1 session"""
        if not self.connected:
            raise RuntimeError("Not connected to NFSv4.1 server")
        
        try:
            # Get file handle for path
            file_fh = self._lookup_path(path)
            
            # Build operations: PUTFH + ACCESS
            operations = []
            
            # PUTFH operation
            operations.append(
                struct.pack('!I', OP_PUTFH) +
                struct.pack('!I', len(file_fh)) + file_fh
            )
            
            # ACCESS operation
            operations.append(
                struct.pack('!I', OP_ACCESS) +
                struct.pack('!I', access_mask)
            )
            
            response = self._send_compound_with_session(operations, num_operations=3)
            
            # Parse NFSv4 data directly (no double-parsing)
            nfsv4_data = response
            offset = 0
            
            # Parse NFSv4 COMPOUND response starting with NFS status
            compound_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if compound_status != 0:  # NFS4_OK

                error_name = NFS4_ERROR_CODES.get(compound_status, f"UNKNOWN_ERROR")
                raise RuntimeError(f"NFSv4 COMPOUND failed: {error_name} ({compound_status})")
            
            # Tag length (skip)
            tag_len = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4 + tag_len
            
            # Number of results
            if offset + 4 > len(nfsv4_data):
                raise ValueError("Missing results count")
            
            num_results = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            # First operation should be SEQUENCE - skip it
            seq_opcode = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if seq_opcode != OP_SEQUENCE:
                raise Exception(f"Expected SEQUENCE operation, got {seq_opcode}")
            
            # Skip SEQUENCE status
            seq_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if seq_status != 0:  # NFS4_OK
                raise Exception(f"SEQUENCE operation failed: {seq_status}")
            
            # Skip SEQUENCE response fields (sessionid + sequence details)
            # sessionid (16 bytes) + sequenceid (4) + slotid (4) + highest_slotid (4) + target_highest_slotid (4) + status_flags (4)
            offset += 16 + 4 + 4 + 4 + 4 + 4
            
            data = nfsv4_data
            
            # Parse PUTFH result
            putfh_opcode = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            putfh_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            if putfh_status != NFS4_OK:
                raise RPCError(f"PUTFH failed: {putfh_status}")
            
            # Parse ACCESS result
            access_opcode = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            access_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            if access_status != NFS4_OK:
                error_name = NFS4_ERROR_CODES.get(access_status, f"UNKNOWN_ERROR")
                raise RPCError(f"ACCESS failed: {error_name} ({access_status})")
            
            # Get supported and access values
            supported = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            access = struct.unpack('!I', data[offset:offset+4])[0]
            
            return {
                'supported': supported,
                'access': access,
                'requested': access_mask
            }
            
        except Exception as e:
            logging.error(f"Access check failed: {e}")
            raise
    
    def get_attributes(self, path, attr_mask=None):
        """Get file attributes using NFSv4.1 session"""
        if not self.connected:
            raise RuntimeError("Not connected to NFSv4.1 server")
        
        logging.debug(f"[TRACE] get_attributes: called for path '{path}'")
        
        if attr_mask is None:
            attr_mask = [FATTR4_TYPE, FATTR4_MODE, FATTR4_SIZE, FATTR4_OWNER, FATTR4_OWNER_GROUP]
        
        try:
            # Get file handle for path
            file_fh = self._lookup_path(path)
            
            # Build operations: PUTFH + GETATTR
            operations = []
            
            # PUTFH operation
            operations.append(
                struct.pack('!I', OP_PUTFH) +
                struct.pack('!I', len(file_fh)) + file_fh
            )
            
            # GETATTR operation (IDENTICAL to NFSv4Client)
            attr_request = pack_bitmap([
                FATTR4_TYPE, FATTR4_SIZE, FATTR4_MODE,
                FATTR4_NUMLINKS, FATTR4_OWNER, FATTR4_OWNER_GROUP,
                FATTR4_TIME_ACCESS, FATTR4_TIME_MODIFY, FATTR4_TIME_METADATA
            ])
            
            operations.append(
                struct.pack('!I', OP_GETATTR) +
                attr_request
            )
            
            logging.debug(f"[TRACE] About to call _send_compound_with_session() with {len(operations)} operations")
            response = self._send_compound_with_session(operations, num_operations=3)
            logging.debug(f"[TRACE] _send_compound_with_session() returned {len(response)} bytes")
            
            # Parse response
            logging.debug(f"[TRACE] About to call _parse_getattr_response_v41() with {len(response)} bytes")
            return self._parse_getattr_response_v41(response)
            
        except Exception as e:
            logging.error(f"Get attributes failed: {e}")
            raise
    
    def getattr(self, path):
        """Get file attributes using GETATTR operation with NFSv4.1 session"""
        try:
            # Build COMPOUND request based on path
            operations = []
            
            if path == "/" or not path:
                # For root path, use PUTROOTFH + GETATTR
                operations.append(struct.pack('!I', OP_PUTROOTFH))
            else:
                # For non-root paths, get filehandle and use PUTFH + GETATTR
                file_fh = self._lookup_path(path)
                operations.append(
                    struct.pack('!I', OP_PUTFH) +
                    struct.pack('!I', len(file_fh)) + file_fh
                )
            
            # GETATTR operation - REQUEST OWNER ATTRIBUTES AND ACL FROM SERVER
            attr_request = pack_bitmap([
                FATTR4_TYPE, FATTR4_SIZE, FATTR4_MODE,
                FATTR4_NUMLINKS, FATTR4_OWNER, FATTR4_OWNER_GROUP,
                FATTR4_TIME_ACCESS, FATTR4_TIME_MODIFY, FATTR4_TIME_METADATA,
                FATTR4_ACL
            ])
            
            operations.append(
                struct.pack('!I', OP_GETATTR) +
                attr_request
            )
            
            # USE SESSION - send COMPOUND with GETATTR
            response = self._send_compound_with_session(operations, num_operations=2)
            
            # Parse GETATTR response (not GETFH)
            return self._parse_getattr_response_with_actual_attributes(response)
            
        except Exception as e:
            logging.error(f"Getattr failed: {e}")
            raise
    
    def _parse_getattr_response_v41(self, response_data):
        """Parse GETATTR response for NFSv4.1 with session"""
        try:
            logging.debug(f"[TRACE] _parse_getattr_response_v41: called with {len(response_data)} bytes")
            logging.debug(f"[TRACE] Parsing NFSv4 data directly (no double-parsing)")
            
            # response_data is already NFSv4 data from _send_compound_with_session()
            nfsv4_data = response_data
            offset = 0
            
            # Parse NFSv4 COMPOUND response starting with NFS status
            compound_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if compound_status != 0:  # NFS4_OK

                error_name = NFS4_ERROR_CODES.get(compound_status, f"UNKNOWN_ERROR")
                raise RuntimeError(f"NFSv4 COMPOUND failed: {error_name} ({compound_status})")
            
            # Tag length (skip)
            tag_len = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4 + tag_len
            
            # Number of results
            if offset + 4 > len(nfsv4_data):
                raise ValueError("Missing results count")
            
            num_results = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            # First operation should be SEQUENCE - skip it
            seq_opcode = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if seq_opcode != OP_SEQUENCE:
                raise Exception(f"Expected SEQUENCE operation, got {seq_opcode}")
            
            # Skip SEQUENCE status
            seq_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if seq_status != 0:  # NFS4_OK
                raise Exception(f"SEQUENCE operation failed: {seq_status}")
            
            # Skip SEQUENCE response fields (sessionid + sequence details)
            # sessionid (16 bytes) + sequenceid (4) + slotid (4) + highest_slotid (4) + target_highest_slotid (4) + status_flags (4)
            offset += 16 + 4 + 4 + 4 + 4 + 4
            
            logging.debug(f"[TRACE] Parsed SEQUENCE, now at offset {offset} for PUTFH")
            logging.debug(f"Parsing GETATTR response, starting offset: {offset}, data length: {len(nfsv4_data)}")
            
            # Check if we have enough data for PUTFH opcode
            if offset + 4 > len(nfsv4_data):
                raise ValueError(f"Not enough data for PUTFH opcode at offset {offset}, data length: {len(nfsv4_data)}")
            
            # Parse PUTROOTFH result (opcode + status) - Wireshark shows PUTROOTFH (24)
            putrootfh_opcode = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            logging.debug(f"PUTROOTFH opcode: {putrootfh_opcode}, reading status at offset: {offset}")
            
            if offset + 4 > len(nfsv4_data):
                raise ValueError(f"Not enough data for PUTROOTFH status at offset {offset}, data length: {len(nfsv4_data)}")
            
            putrootfh_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            logging.debug(f"PUTROOTFH status: {putrootfh_status}")
            
            if putrootfh_status != NFS4_OK:
                raise RPCError(f"PUTROOTFH failed: {putrootfh_status}")
            
            # Parse GETFH result (opcode + status) - Wireshark shows GETFH (10)
            logging.debug(f"Reading GETFH opcode at offset: {offset}")
            logging.debug(f"Remaining data: {len(nfsv4_data) - offset} bytes")
            logging.debug(f"Data at offset {offset}: {nfsv4_data[offset:offset+8].hex()}")
            
            if offset + 4 > len(nfsv4_data):
                raise ValueError(f"Not enough data for GETFH opcode at offset {offset}, data length: {len(nfsv4_data)}")
            
            getfh_opcode = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            logging.debug(f"GETFH opcode: {getfh_opcode}, reading status at offset: {offset}")
            
            if offset + 4 > len(nfsv4_data):
                raise ValueError(f"Not enough data for GETFH status at offset {offset}, data length: {len(nfsv4_data)}")
            
            getfh_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            logging.debug(f"GETFH status: {getfh_status}")
            
            if getfh_status != NFS4_OK:
                raise RPCError(f"GETFH failed: {getfh_status}")
            
            # Parse GETFH response (filehandle length + filehandle data)
            logging.debug(f"Reading filehandle length at offset: {offset}")
            
            if offset + 4 > len(nfsv4_data):
                raise ValueError(f"Not enough data for filehandle length at offset {offset}, data length: {len(nfsv4_data)}")
            
            fh_len = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            logging.debug(f"Filehandle length: {fh_len}")
            
            if offset + fh_len > len(nfsv4_data):
                raise ValueError(f"Not enough data for filehandle data at offset {offset}, length: {fh_len}, data length: {len(nfsv4_data)}")
            
            filehandle = nfsv4_data[offset:offset+fh_len]
            offset += fh_len
            logging.debug(f"Filehandle: {filehandle.hex()}")
            
            # For getattr(), we need to return file attributes, not just filehandle
            # Since this is a GETFH response, we need to create default attributes
            # This is a workaround - ideally we should call a separate GETATTR request
            attrs = {
                'type': 2,  # NF4DIR (directory) - default for root
                'mode': 0o755,  # Default directory permissions
                'owner': '0',  # NFSv4.1 RFC 5661: FATTR4_OWNER (string format)
                'owner_group': '0',  # NFSv4.1 RFC 5661: FATTR4_OWNER_GROUP (string format)
                'size': 4096,  # Default directory size
                'nlink': 1,  # Default link count
                'filehandle': filehandle
            }
            
            logging.debug(f"Returning default attributes for root directory: {attrs}")
            
            return attrs
            
        except Exception as e:
            logging.error(f"Failed to parse getattr response: {e}")
            raise
    
    def _parse_getattr_response_with_actual_attributes(self, response_data):
        """Parse GETATTR response with real server attributes (not GETFH)"""
        try:
            logging.debug(f"[TRACE] _parse_getattr_response_with_actual_attributes: called with {len(response_data)} bytes")
            logging.debug(f"[TRACE] Parsing NFSv4 GETATTR response for owner attributes")
            
            # response_data is already NFSv4 data from _send_compound_with_session()
            nfsv4_data = response_data
            offset = 0
            
            # Parse NFSv4 COMPOUND response starting with NFS status
            compound_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if compound_status != 0:  # NFS4_OK

                error_name = NFS4_ERROR_CODES.get(compound_status, f"UNKNOWN_ERROR")
                raise RuntimeError(f"NFSv4 COMPOUND failed: {error_name} ({compound_status})")
            
            # Tag length (skip)
            tag_len = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4 + tag_len
            
            # Number of results
            num_results = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            # First operation: SEQUENCE - skip it
            seq_opcode = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if seq_opcode != OP_SEQUENCE:
                raise Exception(f"Expected SEQUENCE operation, got {seq_opcode}")
            
            # Skip SEQUENCE status and response data
            seq_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if seq_status != 0:
                raise Exception(f"SEQUENCE operation failed: {seq_status}")
            
            # Skip SEQUENCE response (sessionid + sequenceid + slotid + highest_slotid + target_highest_slotid + status_flags)
            offset += 16 + 4 + 4 + 4 + 4 + 4
            
            logging.debug(f"[TRACE] Parsed SEQUENCE, now at offset {offset} for PUTROOTFH")
            
            # Second operation: PUTROOTFH or PUTFH
            putfh_opcode = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            putfh_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if putfh_status != 0:
                raise Exception(f"PUTFH operation failed: {putfh_status}")
            
            logging.debug(f"[TRACE] Parsed PUTFH, now at offset {offset} for GETATTR")
            
            # Third operation: GETATTR or GETFH (server decides)
            third_opcode = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if third_opcode == OP_GETATTR:
                # Server responded with GETATTR as requested
                getattr_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
                offset += 4
                
                if getattr_status != 0:
                    raise Exception(f"GETATTR operation failed: {getattr_status}")
                
                logging.debug(f"[TRACE] GETATTR successful, parsing attributes at offset {offset}")
                
                # Parse GETATTR response: attrs_count + bitmap_words + attribute_data
                return self._parse_nfsv4_attributes(nfsv4_data, offset)
                
            elif third_opcode == OP_GETFH:
                # Server responded with GETFH instead of GETATTR (Windows NFS behavior)
                logging.debug(f"[TRACE] Server returned GETFH instead of GETATTR, trying different approach")
                
                getfh_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
                offset += 4
                
                if getfh_status != 0:
                    raise Exception(f"GETFH operation failed: {getfh_status}")
                
                # Parse filehandle but we need attributes - make second request
                fh_len = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
                offset += 4
                filehandle = nfsv4_data[offset:offset+fh_len]
                
                logging.debug(f"[TRACE] Got filehandle from GETFH, making PUTFH + GETATTR request")
                
                # Make a second request: PUTFH + GETATTR with the filehandle we just got
                return self._getattr_with_filehandle(filehandle)
                
            else:
                raise Exception(f"Expected GETATTR (9) or GETFH (10), got opcode {third_opcode}")
            
        except Exception as e:
            logging.error(f"Failed to parse GETATTR response: {e}")
            raise
    
    def _parse_nfsv4_attributes(self, data, offset):
        """Parse NFSv4 attribute structure per RFC 5661"""
        try:
            logging.debug(f"[TRACE] _parse_nfsv4_attributes: starting at offset {offset}")
            
            # Parse attribute bitmap 
            bitmap_len = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            logging.debug(f"[TRACE] Bitmap length: {bitmap_len} words")
            
            # Read bitmap words
            bitmap = []
            for i in range(bitmap_len):
                word = struct.unpack('!I', data[offset:offset+4])[0]
                bitmap.append(word)
                offset += 4
                logging.debug(f"[TRACE] Bitmap word {i}: 0x{word:08x}")
            
            # Parse attribute data length
            attr_data_len = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            logging.debug(f"[TRACE] Attribute data length: {attr_data_len} bytes")
            
            # Extract attribute data
            attr_data = data[offset:offset+attr_data_len]
            attr_offset = 0
            
            # Initialize default attributes
            attrs = {
                'type': 2,    # Directory (default)
                'mode': 493,  # 0755 
                'owner': '0',
                'owner_group': '0',
                'size': 4096,
                'nlink': 1
            }
            
            # Parse each requested attribute based on bitmap
            for word_idx, word in enumerate(bitmap):
                for bit_idx in range(32):
                    if word & (1 << bit_idx):
                        attr_num = word_idx * 32 + bit_idx
                        attr_offset = self._parse_single_attribute(attr_data, attr_offset, attr_num, attrs)
            
            logging.debug(f"[TRACE] Final parsed attributes: {attrs}")
            return attrs
            
        except Exception as e:
            logging.error(f"Failed to parse NFSv4 attributes: {e}")
            raise
    
    def _parse_single_attribute(self, attr_data, offset, attr_num, attrs):
        """Parse a single NFSv4 attribute"""
        try:
            logging.debug(f"[TRACE] Parsing attribute {attr_num} at offset {offset}")
            
            if attr_num == FATTR4_TYPE:  # Type
                if offset + 4 <= len(attr_data):
                    attrs['type'] = struct.unpack('!I', attr_data[offset:offset+4])[0]
                    offset += 4
                    logging.debug(f"[TRACE] FATTR4_TYPE: {attrs['type']}")
                    
            elif attr_num == FATTR4_SIZE:  # Size
                if offset + 8 <= len(attr_data):
                    attrs['size'] = struct.unpack('!Q', attr_data[offset:offset+8])[0]
                    offset += 8
                    logging.debug(f"[TRACE] FATTR4_SIZE: {attrs['size']}")
                    
            elif attr_num == FATTR4_MODE:  # Mode
                if offset + 4 <= len(attr_data):
                    attrs['mode'] = struct.unpack('!I', attr_data[offset:offset+4])[0]
                    offset += 4
                    logging.debug(f"[TRACE] FATTR4_MODE: 0{attrs['mode']:o}")
                    
            elif attr_num == FATTR4_NUMLINKS:  # Number of links
                if offset + 4 <= len(attr_data):
                    attrs['nlink'] = struct.unpack('!I', attr_data[offset:offset+4])[0]
                    offset += 4
                    logging.debug(f"[TRACE] FATTR4_NUMLINKS: {attrs['nlink']}")
                    
            elif attr_num == FATTR4_OWNER:  # Owner (UTF-8 string)
                if offset + 4 <= len(attr_data):
                    owner_len = struct.unpack('!I', attr_data[offset:offset+4])[0]
                    offset += 4
                    if offset + owner_len <= len(attr_data):
                        owner_bytes = attr_data[offset:offset+owner_len]
                        attrs['owner'] = owner_bytes.decode('utf-8')
                        offset += owner_len
                        # XDR padding to 4-byte boundary
                        if owner_len % 4 != 0:
                            offset += 4 - (owner_len % 4)
                        logging.debug(f"[TRACE] FATTR4_OWNER: '{attrs['owner']}'")
                        
            elif attr_num == FATTR4_OWNER_GROUP:  # Owner group (UTF-8 string)
                if offset + 4 <= len(attr_data):
                    group_len = struct.unpack('!I', attr_data[offset:offset+4])[0]
                    offset += 4
                    if offset + group_len <= len(attr_data):
                        group_bytes = attr_data[offset:offset+group_len]
                        attrs['owner_group'] = group_bytes.decode('utf-8')
                        offset += group_len
                        # XDR padding to 4-byte boundary
                        if group_len % 4 != 0:
                            offset += 4 - (group_len % 4)
                        logging.debug(f"[TRACE] FATTR4_OWNER_GROUP: '{attrs['owner_group']}'")
                        
            elif attr_num == FATTR4_ACL:  # Access Control List
                if offset + 4 <= len(attr_data):
                    # Parse ACL according to RFC 3530/5661
                    acl_count = struct.unpack('!I', attr_data[offset:offset+4])[0]
                    offset += 4
                    logging.debug(f"[TRACE] FATTR4_ACL: {acl_count} ACE entries")
                    
                    acl_entries = []
                    for i in range(acl_count):
                        if offset + 16 <= len(attr_data):  # Minimum ACE size
                            # Parse ACE (Access Control Entry)
                            ace_type = struct.unpack('!I', attr_data[offset:offset+4])[0]
                            offset += 4
                            ace_flag = struct.unpack('!I', attr_data[offset:offset+4])[0] 
                            offset += 4
                            ace_mask = struct.unpack('!I', attr_data[offset:offset+4])[0]
                            offset += 4
                            
                            # Parse WHO (principal)
                            who_len = struct.unpack('!I', attr_data[offset:offset+4])[0]
                            offset += 4
                            if offset + who_len <= len(attr_data):
                                who_bytes = attr_data[offset:offset+who_len]
                                who = who_bytes.decode('utf-8', errors='replace')
                                offset += who_len
                                # XDR padding
                                if who_len % 4 != 0:
                                    offset += 4 - (who_len % 4)
                                
                                # Decode ACE type
                                ace_type_names = {0: "ALLOW", 1: "DENY", 2: "AUDIT", 3: "ALARM"}
                                type_name = ace_type_names.get(ace_type, f"UNKNOWN({ace_type})")
                                
                                # Decode access mask 
                                access_bits = []
                                if ace_mask & 0x00000001: access_bits.append("READ_DATA")
                                if ace_mask & 0x00000002: access_bits.append("WRITE_DATA") 
                                if ace_mask & 0x00000004: access_bits.append("APPEND_DATA")
                                if ace_mask & 0x00000008: access_bits.append("READ_NAMED_ATTRS")
                                if ace_mask & 0x00000010: access_bits.append("WRITE_NAMED_ATTRS")
                                if ace_mask & 0x00000020: access_bits.append("EXECUTE")
                                if ace_mask & 0x00000040: access_bits.append("DELETE_CHILD")
                                if ace_mask & 0x00000080: access_bits.append("READ_ATTRIBUTES")
                                if ace_mask & 0x00000100: access_bits.append("WRITE_ATTRIBUTES")
                                if ace_mask & 0x00010000: access_bits.append("DELETE")
                                if ace_mask & 0x00020000: access_bits.append("READ_ACL")
                                if ace_mask & 0x00040000: access_bits.append("WRITE_ACL")
                                if ace_mask & 0x00080000: access_bits.append("WRITE_OWNER")
                                if ace_mask & 0x001F01FF: access_bits.append("FULL_CONTROL")
                                
                                access_str = "|".join(access_bits) if access_bits else f"0x{ace_mask:08x}"
                                
                                acl_entry = {
                                    'type': type_name,
                                    'principal': who,
                                    'access': access_str,
                                    'mask': ace_mask
                                }
                                acl_entries.append(acl_entry)
                                logging.debug(f"[TRACE] ACE {i}: {type_name} {who} {access_str}")
                    
                    attrs['acl'] = acl_entries
                    logging.debug(f"[TRACE] FATTR4_ACL parsed: {len(acl_entries)} entries")
                        
            else:
                # For other attributes (time fields etc), skip them for now
                # This is a simplified implementation focusing on owner attributes
                logging.debug(f"[TRACE] Skipping attribute {attr_num} (not implemented)")
                
            return offset
            
        except Exception as e:
            logging.error(f"Failed to parse attribute {attr_num}: {e}")
            return offset
    
    def _getattr_with_filehandle(self, filehandle):
        """Make PUTFH + GETATTR request with given filehandle"""
        try:
            logging.debug(f"[TRACE] _getattr_with_filehandle: making second request with {len(filehandle)} byte filehandle")
            
            # Build COMPOUND request: PUTFH + GETATTR
            operations = []
            
            # PUTFH operation with filehandle from GETFH
            operations.append(
                struct.pack('!I', OP_PUTFH) +
                struct.pack('!I', len(filehandle)) + filehandle
            )
            
            # GETATTR operation - REQUEST OWNER ATTRIBUTES AND ACL
            attr_request = pack_bitmap([
                FATTR4_TYPE, FATTR4_SIZE, FATTR4_MODE,
                FATTR4_NUMLINKS, FATTR4_OWNER, FATTR4_OWNER_GROUP,
                FATTR4_TIME_ACCESS, FATTR4_TIME_MODIFY, FATTR4_TIME_METADATA,
                FATTR4_ACL
            ])
            
            operations.append(
                struct.pack('!I', OP_GETATTR) +
                attr_request
            )
            
            # Send second request
            response = self._send_compound_with_session(operations, num_operations=2)
            
            # Parse response (this should be PUTFH + GETATTR)
            return self._parse_putfh_getattr_response(response)
            
        except Exception as e:
            logging.error(f"Failed to get attributes with filehandle: {e}")
            raise
    
    def _parse_putfh_getattr_response(self, response_data):
        """Parse PUTFH + GETATTR response"""
        try:
            logging.debug(f"[TRACE] _parse_putfh_getattr_response: called with {len(response_data)} bytes")
            
            nfsv4_data = response_data
            offset = 0
            
            # Parse NFSv4 COMPOUND response
            compound_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if compound_status != 0:
                raise RuntimeError(f"NFSv4 COMPOUND failed: {compound_status}")
            
            # Tag length (skip)
            tag_len = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4 + tag_len
            
            # Number of results
            num_results = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            # First operation: SEQUENCE - skip it
            seq_opcode = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            seq_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if seq_status != 0:
                raise Exception(f"SEQUENCE operation failed: {seq_status}")
            
            # Skip SEQUENCE response data
            offset += 16 + 4 + 4 + 4 + 4 + 4
            
            # Second operation: PUTFH
            putfh_opcode = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            putfh_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if putfh_status != 0:
                raise Exception(f"PUTFH operation failed: {putfh_status}")
            
            # Third operation: GETATTR
            getattr_opcode = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if getattr_opcode != OP_GETATTR:
                raise Exception(f"Expected GETATTR, got {getattr_opcode}")
            
            getattr_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if getattr_status != 0:
                raise Exception(f"GETATTR operation failed: {getattr_status}")
            
            logging.debug(f"[TRACE] Second GETATTR successful, parsing attributes at offset {offset}")
            
            # Parse attributes
            return self._parse_nfsv4_attributes(nfsv4_data, offset)
            
        except Exception as e:
            logging.error(f"Failed to parse PUTFH + GETATTR response: {e}")
            raise
    
    def readdir(self, path="/"):
        """Read directory contents using NFSv4.1 session"""
        logging.info(f"Reading directory: {path}")
        
        if not self.connected:
            raise RuntimeError("Not connected to NFSv4.1 server")
        
        # Get directory file handle
        dir_fh = self._lookup_path(path)
        
        try:
            # Build operations: PUTFH + READDIR
            operations = []
            
            # PUTFH operation
            operations.append(
                struct.pack('!I', OP_PUTFH) +
                struct.pack('!I', len(dir_fh)) + dir_fh
            )
            
            # READDIR operation
            cookie = 0
            cookievf = b'\x00' * 8
            dircount = 4096
            maxcount = 4096
            
            attr_request = pack_bitmap([FATTR4_TYPE, FATTR4_SIZE, FATTR4_FILEID])
            
            readdir_op = (
                struct.pack('!I', OP_READDIR) +
                struct.pack('!Q', cookie) +
                cookievf +
                struct.pack('!I', dircount) +
                struct.pack('!I', maxcount) +
                attr_request
            )
            operations.append(readdir_op)
            
            response = self._send_compound_with_session(operations, num_operations=3)
            
            # Parse directory entries
            return self._parse_readdir_response(response)
            
        except Exception as e:
            logging.error(f"Readdir failed: {e}")
            raise
    
    def _parse_readdir_response(self, data):
        """Parse READDIR response"""
        try:
            # Parse NFSv4 data directly (no double-parsing)
            nfsv4_data = data
            offset = 0
            
            # Parse NFSv4 COMPOUND response starting with NFS status
            compound_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if compound_status != 0:  # NFS4_OK

                error_name = NFS4_ERROR_CODES.get(compound_status, f"UNKNOWN_ERROR")
                raise RuntimeError(f"NFSv4 COMPOUND failed: {error_name} ({compound_status})")
            
            # Tag length (skip)
            tag_len = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4 + tag_len
            
            # Number of results
            if offset + 4 > len(nfsv4_data):
                raise ValueError("Missing results count")
            
            num_results = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            # First operation should be SEQUENCE - skip it
            seq_opcode = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if seq_opcode != OP_SEQUENCE:
                raise Exception(f"Expected SEQUENCE operation, got {seq_opcode}")
            
            # Skip SEQUENCE status
            seq_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if seq_status != 0:  # NFS4_OK
                raise Exception(f"SEQUENCE operation failed: {seq_status}")
            
            # Skip SEQUENCE response fields (sessionid + sequence details)
            # sessionid (16 bytes) + sequenceid (4) + slotid (4) + highest_slotid (4) + target_highest_slotid (4) + status_flags (4)
            offset += 16 + 4 + 4 + 4 + 4 + 4
            
            data = nfsv4_data
            
            # Parse PUTFH result
            putfh_opcode = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            putfh_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            if putfh_status != NFS4_OK:
                raise RPCError(f"PUTFH failed: {putfh_status}")
            
            # Parse READDIR result
            readdir_opcode = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            readdir_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            if readdir_status != NFS4_OK:
                raise RPCError(f"READDIR failed: {readdir_status}")
            
            # Parse directory entries
            entries = []
            
            # Skip verifier
            offset += 8
            
            # Parse entries
            while True:
                if offset + 4 > len(data):
                    break
                
                value_follows = struct.unpack('!I', data[offset:offset+4])[0]
                offset += 4
                
                if value_follows == 0:
                    break
                
                # Parse entry
                entry = {}
                
                # Cookie
                cookie = struct.unpack('!Q', data[offset:offset+8])[0]
                offset += 8
                entry['cookie'] = cookie
                
                # Name
                name_len = struct.unpack('!I', data[offset:offset+4])[0]
                offset += 4
                name = data[offset:offset+name_len]
                try:
                    entry['name'] = name.decode('utf-8')
                except UnicodeDecodeError:
                    entry['name'] = name.decode('latin-1')
                offset += name_len + self._pad_len(name_len)
                
                # Attributes
                attrs = self._parse_entry_attributes(data, offset)
                entry.update(attrs['attributes'])
                offset = attrs['new_offset']
                
                entries.append(entry)
            
            return entries
            
        except Exception as e:
            logging.error(f"Failed to parse READDIR response: {e}")
            raise
    
    def _parse_entry_attributes(self, data, offset):
        """Parse entry attributes from READDIR response"""
        try:
            # Read bitmap
            bitmap_len = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            bitmap_words = []
            for i in range(bitmap_len):
                word = struct.unpack('!I', data[offset:offset+4])[0]
                bitmap_words.append(word)
                offset += 4
            
            # Read attribute data length
            attr_data_len = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            # Parse attributes
            attributes = {}
            attr_start = offset
            
            for word_idx, word in enumerate(bitmap_words):
                for bit_idx in range(32):
                    if word & (1 << bit_idx):
                        attr_num = word_idx * 32 + bit_idx
                        
                        if attr_num == FATTR4_TYPE:
                            file_type = struct.unpack('!I', data[offset:offset+4])[0]
                            attributes['type'] = file_type
                            offset += 4
                        elif attr_num == FATTR4_SIZE:
                            size = struct.unpack('!Q', data[offset:offset+8])[0]
                            attributes['size'] = size
                            offset += 8
                        elif attr_num == FATTR4_FILEID:
                            fileid = struct.unpack('!Q', data[offset:offset+8])[0]
                            attributes['fileid'] = fileid
                            offset += 8
            
            return {
                'attributes': attributes,
                'new_offset': attr_start + attr_data_len
            }
            
        except Exception as e:
            logging.error(f"Failed to parse entry attributes: {e}")
            raise
    
    def read_file(self, path, offset=0, length=None):
        """Read file contents using NFSv4.1 session"""
        if not self.connected:
            raise RuntimeError("Not connected to NFSv4.1 server")
        
        if length is None:
            # NFSv4.1 session limits: use smaller chunk size to avoid NFS4ERR_REP_TOO_BIG
            # Limit to 4KB for NFSv4.1 session compatibility 
            length = min(self.chunk_size, 4096)
        
        try:
            # Get file handle
            file_fh = self._lookup_path(path)
            
            # Build operations: PUTFH + READ
            operations = []
            
            # PUTFH operation
            operations.append(
                struct.pack('!I', OP_PUTFH) +
                struct.pack('!I', len(file_fh)) + file_fh
            )
            
            # READ operation with stateid (NFSv4.1 requirement)
            # Special stateid (all zeros) for stateless read
            special_stateid = b'\x00' * 16  # 16 bytes: seqid(4) + other(12)
            operations.append(
                struct.pack('!I', OP_READ) +
                special_stateid +
                struct.pack('!Q', offset) +
                struct.pack('!I', length)
            )
            
            response = self._send_compound_with_session(operations, num_operations=3)
            
            # Parse response
            return self._parse_read_response(response)
            
        except Exception as e:
            logging.error(f"Read file failed: {e}")
            raise
    
    def _parse_read_response(self, data):
        """Parse READ response"""
        try:
            # Parse NFSv4 data directly (no double-parsing)
            nfsv4_data = data
            offset = 0
            
            # Parse NFSv4 COMPOUND response starting with NFS status
            compound_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if compound_status != 0:  # NFS4_OK

                error_name = NFS4_ERROR_CODES.get(compound_status, f"UNKNOWN_ERROR")
                raise RuntimeError(f"NFSv4 COMPOUND failed: {error_name} ({compound_status})")
            
            # Tag length (skip)
            tag_len = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4 + tag_len
            
            # Number of results
            if offset + 4 > len(nfsv4_data):
                raise ValueError("Missing results count")
            
            num_results = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            # First operation should be SEQUENCE - skip it
            seq_opcode = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if seq_opcode != OP_SEQUENCE:
                raise Exception(f"Expected SEQUENCE operation, got {seq_opcode}")
            
            # Skip SEQUENCE status
            seq_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if seq_status != 0:  # NFS4_OK
                raise Exception(f"SEQUENCE operation failed: {seq_status}")
            
            # Skip SEQUENCE response fields (sessionid + sequence details)
            # sessionid (16 bytes) + sequenceid (4) + slotid (4) + highest_slotid (4) + target_highest_slotid (4) + status_flags (4)
            offset += 16 + 4 + 4 + 4 + 4 + 4
            
            data = nfsv4_data
            
            # Parse PUTFH result
            putfh_opcode = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            putfh_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            if putfh_status != NFS4_OK:
                raise RPCError(f"PUTFH failed: {putfh_status}")
            
            # Parse READ result
            read_opcode = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            read_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            if read_status != NFS4_OK:
                error_name = NFS4_ERROR_CODES.get(read_status, f"UNKNOWN_ERROR")
                raise RPCError(f"READ failed: {error_name} ({read_status})")
            
            # Parse read data
            eof = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            data_len = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            file_data = data[offset:offset+data_len]
            
            # Return file data directly for compatibility with main.py interface
            # (main.py expects bytes to decode, not a dict)
            return file_data
            
        except Exception as e:
            logging.error(f"Failed to parse READ response: {e}")
            raise
    
    def write_file(self, path, data, offset=0):
        """
        Write data to a file on NFSv4.1 server using sessions
        
        :param path: path to file
        :param data: data to write  
        :param offset: offset in file to start writing (default: 0)
        :return: number of bytes written
        """
        logging.info(f"Writing {len(data)} bytes to {path}")
        
        if not self.connected:
            raise RuntimeError("Not connected to NFSv4.1 server")
            
        try:
            # Try to lookup existing file
            try:
                file_fh = self._lookup_path(path)
                logging.debug(f"File exists, using existing handle")
            except Exception:
                # File doesn't exist, create it
                logging.debug(f"File doesn't exist, creating new file")
                file_fh = self._create_file_with_open(path)
            
            # Write data to file
            return self._write_to_file(file_fh, data, offset)
            
        except Exception as e:
            logging.error(f"Write failed: {e}")
            raise
    
    def _create_file_with_open(self, path):
        """
        Create a new file using NFSv4.1 OPEN operation with sessions
        
        :param path: path to file to create
        :return: file handle for created file
        """
        import os
        
        # Split path into directory and filename
        dirname = os.path.dirname(path) if path.startswith('/') else '/'
        filename = os.path.basename(path)
        
        # Get directory handle
        if dirname == '/':
            dir_fh = self._lookup_path('/')
        else:
            dir_fh = self._lookup_path(dirname)
            
        logging.debug(f"Creating file '{filename}' in directory")
        
        try:
            # Build COMPOUND request: PUTFH + OPEN + GETFH
            operations = []
            
            # PUTFH operation (directory)
            operations.append(
                struct.pack('!I', OP_PUTFH) +
                struct.pack('!I', len(dir_fh)) + dir_fh
            )
            
            # OPEN operation for NFSv4.1 (similar to NFSv4.0 but with session)
            filename_bytes = filename.encode('utf-8')
            filename_padding = (4 - (len(filename_bytes) % 4)) % 4
            
            open_op = struct.pack('!I', OP_OPEN)  # opcode
            
            # OPEN4args structure
            open_op += struct.pack('!I', 0)  # seqid4 seqid (0 for NFSv4.1)
            open_op += struct.pack('!I', OPEN4_SHARE_ACCESS_WRITE)  # share_access
            open_op += struct.pack('!I', OPEN4_SHARE_DENY_NONE)  # share_deny
            
            # open_owner4 owner - use session's clientid
            clientid = self.session_manager.clientid
            open_op += struct.pack('!Q', clientid)  # clientid from session
            owner_data = b'nfsclient'
            owner_padding = (4 - (len(owner_data) % 4)) % 4
            open_op += struct.pack('!I', len(owner_data)) + owner_data + b'\x00' * owner_padding
            
            # openflag4 openhow (CREATE)
            open_op += struct.pack('!I', 1)  # OPEN4_CREATE
            open_op += struct.pack('!I', 0)  # UNCHECKED4
            
            # createattrs (mode attribute)
            open_op += struct.pack('!I', 2)  # bitmap length = 2 words
            open_op += struct.pack('!I', 0x00000000)  # bitmap word 0
            open_op += struct.pack('!I', 0x00000002)  # bitmap word 1 (bit 33 = mode)
            open_op += struct.pack('!I', 4)  # attribute data length
            open_op += struct.pack('!I', 0o644)  # mode value
            
            # open_claim4 claim (CLAIM_NULL)
            open_op += struct.pack('!I', 0)  # CLAIM_NULL
            open_op += struct.pack('!I', len(filename_bytes)) + filename_bytes + b'\x00' * filename_padding
            
            operations.append(open_op)
            
            # GETFH operation to get file handle
            operations.append(struct.pack('!I', OP_GETFH))
            
            # Send COMPOUND with session
            response = self._send_compound_with_session(operations, num_operations=3)
            
            # Parse response
            return self._parse_create_response(response)
            
        except Exception as e:
            logging.error(f"File creation failed: {e}")
            raise
    
    def _parse_create_response(self, response_data):
        """Parse PUTFH + OPEN + GETFH response for file creation"""
        try:
            logging.debug(f"Parsing create response: {len(response_data)} bytes")
            
            nfsv4_data = response_data
            offset = 0
            
            # Parse NFSv4 COMPOUND response
            compound_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if compound_status != 0:
                error_name = NFS4_ERROR_CODES.get(compound_status, f"UNKNOWN_ERROR")
                raise RuntimeError(f"NFSv4 COMPOUND failed: {error_name} ({compound_status})")
            
            # Skip tag
            tag_len = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4 + tag_len
            
            # Number of results
            num_results = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if num_results != 4:  # SEQUENCE + PUTFH + OPEN + GETFH
                raise RuntimeError(f"Expected 4 operations, got {num_results}")
            
            # Skip SEQUENCE operation response
            seq_opcode = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            seq_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            if seq_status != 0:
                raise RuntimeError(f"SEQUENCE failed: {seq_status}")
            # Skip SEQUENCE response data (sessionid + seqid + slotid + highest_slotid + target_highest_slotid + status_flags)
            offset += 16 + 4 + 4 + 4 + 4 + 4
            
            # Parse PUTFH result
            putfh_opcode = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            putfh_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            if putfh_status != 0:
                raise RuntimeError(f"PUTFH failed: {putfh_status}")
            
            # Parse OPEN result
            open_opcode = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            open_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            if open_status != 0:
                if open_status == 17:  # NFS4ERR_EXIST
                    raise RuntimeError(f"OPEN failed: File already exists")
                elif open_status == 13:  # NFS4ERR_ACCESS
                    raise RuntimeError(f"OPEN failed: Permission denied")
                else:
                    raise RuntimeError(f"OPEN failed: {open_status}")
            
            # Skip OPEN response data (stateid + change_info + rflags + attrset + delegation)
            # stateid (16 bytes)
            offset += 16
            # change_info4 (atomic + before + after = 4 + 8 + 8 = 20 bytes)
            offset += 20
            # rflags (4 bytes)
            offset += 4
            # attrset bitmap
            bitmap_len = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4 + bitmap_len * 4
            # delegation type (4 bytes) - assuming OPEN_DELEGATE_NONE
            delegation_type = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            # No additional delegation data for OPEN_DELEGATE_NONE
            
            # Parse GETFH result
            getfh_opcode = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            getfh_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            if getfh_status != 0:
                raise RuntimeError(f"GETFH failed: {getfh_status}")
            
            # Extract file handle
            fh_len = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            file_fh = nfsv4_data[offset:offset+fh_len]
            
            logging.debug(f"Successfully created file, handle: {len(file_fh)} bytes")
            return file_fh
            
        except Exception as e:
            logging.error(f"Failed to parse create response: {e}")
            raise
    
    def _write_to_file(self, file_fh, data, offset=0):
        """
        Write data to an existing file handle using NFSv4.1 sessions
        
        :param file_fh: file handle
        :param data: data to write
        :param offset: offset in file to start writing
        :return: number of bytes written
        """
        try:
            # Build COMPOUND request: PUTFH + WRITE
            operations = []
            
            # PUTFH operation
            operations.append(
                struct.pack('!I', OP_PUTFH) +
                struct.pack('!I', len(file_fh)) + file_fh
            )
            
            # WRITE operation for NFSv4.1
            stateid = b'\x00' * 16  # Anonymous stateid
            stable = 2  # FILE_SYNC
            
            write_op = (
                struct.pack('!I', OP_WRITE) +
                stateid +
                struct.pack('!Q', offset) +
                struct.pack('!I', stable) +
                struct.pack('!I', len(data)) + data +
                (b'\x00' * ((4 - len(data) % 4) % 4))  # XDR padding
            )
            operations.append(write_op)
            
            # Send COMPOUND with session
            response = self._send_compound_with_session(operations, num_operations=2)
            
            # Parse response
            return self._parse_write_response(response)
            
        except Exception as e:
            logging.error(f"Write operation failed: {e}")
            raise
    
    def _parse_write_response(self, response_data):
        """Parse PUTFH + WRITE response"""
        try:
            logging.debug(f"Parsing write response: {len(response_data)} bytes")
            
            nfsv4_data = response_data
            offset = 0
            
            # Parse NFSv4 COMPOUND response
            compound_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if compound_status != 0:
                error_name = NFS4_ERROR_CODES.get(compound_status, f"UNKNOWN_ERROR")
                raise RuntimeError(f"NFSv4 COMPOUND failed: {error_name} ({compound_status})")
            
            # Skip tag
            tag_len = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4 + tag_len
            
            # Number of results
            num_results = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            if num_results != 3:  # SEQUENCE + PUTFH + WRITE
                raise RuntimeError(f"Expected 3 operations, got {num_results}")
            
            # Skip SEQUENCE operation response
            seq_opcode = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            seq_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            if seq_status != 0:
                raise RuntimeError(f"SEQUENCE failed: {seq_status}")
            # Skip SEQUENCE response data
            offset += 16 + 4 + 4 + 4 + 4 + 4
            
            # Parse PUTFH result
            putfh_opcode = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            putfh_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            if putfh_status != 0:
                raise RuntimeError(f"PUTFH failed: {putfh_status}")
            
            # Parse WRITE result
            write_opcode = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            write_status = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            if write_status != 0:
                error_name = "UNKNOWN_ERROR"
                if write_status == 13:
                    error_name = "NFS4ERR_ACCESS"
                elif write_status == 1:
                    error_name = "NFS4ERR_PERM"
                elif write_status == 28:
                    error_name = "NFS4ERR_NOSPC"
                raise RuntimeError(f"WRITE failed: {error_name} ({write_status})")
            
            # Get bytes written
            bytes_written = struct.unpack('!I', nfsv4_data[offset:offset+4])[0]
            offset += 4
            
            # Skip committed field and write verifier
            offset += 4 + 8
            
            logging.info(f"Successfully wrote {bytes_written} bytes")
            return bytes_written
            
        except Exception as e:
            logging.error(f"Failed to parse write response: {e}")
            raise


def pack_xdr_string(s):
    """Pack a string in XDR format"""
    if isinstance(s, str):
        s = s.encode('utf-8')
    length = len(s)
    padding = (4 - (length % 4)) % 4
    return struct.pack('!I', length) + s + b'\x00' * padding


def pack_bitmap(attr_list):
    """Pack attribute bitmap for NFSv4"""
    if not attr_list:
        return struct.pack('!I', 0)  # Empty bitmap
    
    max_attr = max(attr_list)
    words_needed = (max_attr // 32) + 1
    
    bitmap = [0] * words_needed
    
    for attr in attr_list:
        word_idx = attr // 32
        bit_idx = attr % 32
        bitmap[word_idx] |= (1 << bit_idx)
    
    result = struct.pack('!I', words_needed)
    for word in bitmap:
        result += struct.pack('!I', word)
    
    return result


class RPCError(Exception):
    """RPC operation error"""
    pass
