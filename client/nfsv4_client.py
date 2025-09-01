"""
NFSv4 client implementation with COMPOUND operations
"""

import struct
import logging
import os
from .socks_socket import ProxySocket
from .rpc_transport import RPCTransport
from .nfs_constants import *
from .auth import AuthManager

def pack_xdr_string(s):
    """Pack a string in XDR format"""
    if isinstance(s, str):
        s = s.encode('utf-8')
    length = len(s)
    padding = (4 - (length % 4)) % 4
    return struct.pack('!I', length) + s + b'\x00' * padding

def pack_xdr_array(items):
    """Pack an array in XDR format"""
    result = struct.pack('!I', len(items))
    for item in items:
        result += item
    return result

def pack_bitmap(attrs):
    """Pack attribute bitmap for NFSv4"""
    if not attrs:
        return struct.pack('!I', 0)
    
    # Calculate bitmap words needed
    max_attr = max(attrs) if attrs else 0
    words_needed = (max_attr // 32) + 1
    bitmap = [0] * words_needed
    
    for attr in attrs:
        word_idx = attr // 32
        bit_idx = attr % 32
        bitmap[word_idx] |= (1 << bit_idx)
    
    result = struct.pack('!I', words_needed)
    for word in bitmap:
        result += struct.pack('!I', word)
    return result

class NFSv4Client:
    """
    NFSv4 client implementation with COMPOUND operations
    """
    
    def __init__(self, target_host, export_path="/", proxy_type="direct",
                 proxy_host=None, proxy_port=None, nfs_port=2049,
                 nfs_program=100003, hostname=None, uid=None, gid=None, 
                 gids=None, timeout=10, chunk_size=8192, use_privileged_ports=False):
        """
        Initialize NFSv4 client
        
        :param target_host: NFS server hostname or IP
        :param export_path: NFS export path  
        :param proxy_type: proxy type (direct, socks4, socks5)
        :param proxy_host: proxy host
        :param proxy_port: proxy port
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
        
        # NFSv4 specific state
        self.clientid = None
        self.sequenceid = 0
        self.root_fh = None
        self.current_fh = None
        self.connected = False
        self.minor_version = None  # Auto-detected minor version
        self.session_manager = None  # For NFSv4.1+ sessions
        
    def connect(self):
        """Connect to NFSv4 server with automatic version negotiation"""
        logging.info(f"Connecting to {self.target_host} (NFS v4)")
        
        # Try NFSv4 versions: 4.0, 4.1, 4.2
        for minor_ver in [0, 1, 2]:
            try:
                logging.info(f"Trying NFSv4.{minor_ver}...")
                self.minor_version = minor_ver
                
                # Try to get root filehandle with this version
                self.root_fh = self._get_root_filehandle()
                self.current_fh = self.root_fh
                
                # If we get here, version works
                self.connected = True
                logging.info(f"Successfully connected using NFSv4.{self.minor_version}")
                return
                
            except Exception as e:
                error_msg = str(e)
                if "NFS4ERR_MINOR_VERS_MISMATCH" in error_msg:
                    logging.info(f"NFSv4.{minor_ver} not supported, trying next version...")
                    continue
                elif "UNKNOWN_ERROR (10071)" in error_msg or "NFS4ERR_OP_NOT_IN_SESSION" in error_msg:
                    # NFSv4.1+ detected - needs session management
                    logging.info(f"NFSv4.{minor_ver} requires session - attempting session establishment...")
                    if self._try_session_connection(minor_ver):
                        return
                    else:
                        logging.info(f"NFSv4.{minor_ver} session failed, trying next version...")
                        continue
                elif minor_ver == 2:  # Last version to try
                    logging.error(f"All NFSv4 versions failed. Last error: {e}")
                    raise
                else:
                    logging.info(f"NFSv4.{minor_ver} failed: {e}, trying next version...")
                    continue
        
        # If we get here, all versions failed
        raise Exception("Unable to connect with any NFSv4 version")
    
    def _try_session_connection(self, minor_ver):
        """Try to establish NFSv4.1+ session connection"""
        try:
            logging.info(f"Attempting to establish NFSv4.{minor_ver} session...")
            
            # Import session manager
            import sys
            import os
            sys.path.append(os.path.dirname(os.path.dirname(__file__)))
            from nfsv4_session_manager import NFSv4SessionManager
            
            # Create session manager with same configuration
            session_mgr = NFSv4SessionManager(
                target_host=self.target_host,
                nfs_port=self.nfs_port,
                proxy_host=self.proxy_host,
                proxy_port=self.proxy_port,
                proxy_type=self.proxy_type,
                timeout=self.timeout,
                auth_manager=self.auth_manager
            )
            
            # Try to establish session
            if session_mgr.establish_session(minor_version=minor_ver):
                # Get root filehandle using session
                self.root_fh = session_mgr.get_root_filehandle_with_session()
                self.current_fh = self.root_fh
                
                # Store session manager for future operations
                self.session_manager = session_mgr
                self.minor_version = minor_ver
                self.connected = True
                
                logging.info(f"Successfully connected using NFSv4.{minor_ver} with session")
                return True
            
            return False
            
        except Exception as e:
            logging.error(f"Session establishment failed: {e}")
            return False
    
    def _get_root_filehandle(self):
        """Get root filehandle using PUTROOTFH operation"""
        try:
            # Build COMPOUND request with PUTROOTFH + GETFH
            operations = []
            
            # PUTROOTFH operation
            operations.append(struct.pack('!I', OP_PUTROOTFH))
            
            # GETFH operation  
            operations.append(struct.pack('!I', OP_GETFH))
            
            response = self._send_compound(operations)
            
            # Parse response to get file handle
            return self._parse_getfh_response(response)
            
        except Exception as e:
            logging.error(f"Failed to get root filehandle: {e}")
            raise
    
    def _send_compound(self, operations):
        """Send COMPOUND request to NFSv4 server"""
        sock = None
        try:
            # Connect to NFS service
            sock = ProxySocket(
                self.target_host, self.nfs_port,
                self.proxy_host, self.proxy_port,
                self.proxy_type, self.timeout,
                use_privileged_port=self.use_privileged_ports
            ).connect()
            
            rpc_transport = RPCTransport(sock)
            
            # Build COMPOUND payload
            minor_ver = self.minor_version if self.minor_version is not None else 0
            payload = (
                struct.pack('!I', 0) +  # tag length (empty)
                struct.pack('!I', minor_ver) +  # negotiated minor version
                struct.pack('!I', len(operations))  # number of operations
            )
            
            # Add operations
            for op in operations:
                payload += op
            
            # Get credentials
            credentials = self.auth_manager.get_auth_unix_credentials()
            verifier = self.auth_manager.get_default_verifier()
            
            # Send COMPOUND request
            _, response = rpc_transport.send_rpc_request(
                self.nfs_program, self.nfs_version, NFS4_PROC_COMPOUND,
                payload, credentials, verifier
            )
            
            return response
            
        except Exception as e:
            logging.error(f"COMPOUND request failed: {e}")
            raise
        finally:
            # Always close socket, especially important for privileged ports
            if sock:
                try:
                    sock.close()
                except:
                    pass
    
    def _parse_compound_response(self, data):
        """Parse COMPOUND response header"""
        try:
            # Parse RPC response header
            parsed = RPCTransport(None).parse_rpc_response(data)
            
            if parsed['accept_stat'] != SUCCESS:
                raise RPCError("COMPOUND request failed")
            
            offset = parsed['data_offset']
            
            # Parse NFSv4 COMPOUND response
            if offset + 8 > len(data):
                raise ValueError("Truncated COMPOUND response")
            
            # Status
            status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            # Check for NFSv4 errors first
            if status != NFS4_OK:
                error_name = "UNKNOWN_ERROR"
                if status == 2:
                    error_name = "NFS4ERR_NOENT"
                elif status == 10021:
                    error_name = "NFS4ERR_MINOR_VERS_MISMATCH"
                elif status == 10004:
                    error_name = "NFS4ERR_NOTSUPP"
                raise RPCError(f"NFSv4 COMPOUND failed: {error_name} ({status})")
            
            # Tag length (skip)
            tag_len = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4 + tag_len
            
            # Number of results
            if offset + 4 > len(data):
                raise ValueError("Missing results count")
            
            num_results = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            return {
                'status': status,
                'num_results': num_results,
                'data_offset': offset
            }
            
        except Exception as e:
            logging.error(f"Failed to parse COMPOUND response: {e}")
            raise
    
    def _parse_getfh_response(self, data):
        """Parse GETFH operation response"""
        try:
            # Parse COMPOUND response header
            parsed = self._parse_compound_response(data)
            offset = parsed['data_offset']
            
            logging.debug(f"COMPOUND response parsed, operations count: {parsed['num_results']}, starting offset: {offset}")
            
            # Parse first operation result (PUTROOTFH) - includes both opcode and status
            if offset + 8 > len(data):
                raise ValueError("Missing PUTROOTFH operation data")
            
            # Read opcode (should be PUTROOTFH = 24)
            op_code = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            # Read status
            op_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            logging.debug(f"Operation 1: opcode={op_code} (PUTROOTFH=24), status={op_status} (expecting {NFS4_OK})")
            
            if op_status != NFS4_OK:
                raise RPCError(f"PUTROOTFH failed: {op_status}")
            
            # Parse second operation result (GETFH) - includes both opcode and status
            if offset + 8 > len(data):
                raise ValueError("Missing GETFH operation data")
            
            # Read opcode (should be GETFH = 10)
            getfh_code = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            # Read status
            getfh_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            logging.debug(f"Operation 2: opcode={getfh_code} (GETFH=10), status={getfh_status} (expecting {NFS4_OK})")
            
            if getfh_status != NFS4_OK:
                raise RPCError(f"GETFH failed: {getfh_status}")
            
            # Parse file handle
            if offset + 4 > len(data):
                raise ValueError("Missing file handle length")
            
            fh_length = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            logging.debug(f"File handle length: {fh_length}")
            
            if offset + fh_length > len(data):
                raise ValueError("Truncated file handle")
            
            file_handle = data[offset:offset+fh_length]
            
            logging.debug(f"Got root filehandle: length={fh_length}, data={file_handle.hex()}")
            return file_handle
            
        except Exception as e:
            logging.error(f"Failed to parse GETFH response: {e}")
            logging.debug(f"Response data length: {len(data)}, hex dump: {data.hex()}")
            raise
    
    def _lookup_path(self, path):
        """Lookup file handle for a path using LOOKUP operations"""
        # Combine export path with requested path for NFSv4
        if self.export_path and self.export_path != "/":
            # Remove leading slash from path if present
            clean_path = path.lstrip('/')
            # Combine export with path
            full_path = f"{self.export_path.rstrip('/')}/{clean_path}" if clean_path else self.export_path
        else:
            full_path = path
        
        if full_path == "/":
            return self.root_fh
        
        # Split path into components
        components = [c for c in full_path.split('/') if c]
        current_fh = self.root_fh
        
        logging.debug(f"NFSv4 LOOKUP path: {path} -> full_path: {full_path} -> components: {components}")
        
        for component in components:
            current_fh = self._lookup_component(current_fh, component)
        
        return current_fh
    
    def _lookup_component(self, dir_fh, name):
        """Lookup a single path component"""
        try:
            # Build COMPOUND request: PUTFH + LOOKUP + GETFH
            operations = []
            
            # PUTFH operation
            operations.append(
                struct.pack('!I', OP_PUTFH) +
                struct.pack('!I', len(dir_fh)) + dir_fh
            )
            
            # LOOKUP operation
            operations.append(
                struct.pack('!I', OP_LOOKUP) +
                pack_xdr_string(name)
            )
            
            # GETFH operation
            operations.append(struct.pack('!I', OP_GETFH))
            
            response = self._send_compound(operations)
            
            # Parse response
            parsed = self._parse_compound_response(response)
            offset = parsed['data_offset']
            
            # Parse PUTFH result (opcode + status)
            putfh_opcode = struct.unpack('!I', response[offset:offset+4])[0]
            offset += 4
            putfh_status = struct.unpack('!I', response[offset:offset+4])[0]
            offset += 4
            if putfh_status != NFS4_OK:
                raise RPCError(f"PUTFH failed: {putfh_status}")
            
            # Parse LOOKUP result (opcode + status)
            lookup_opcode = struct.unpack('!I', response[offset:offset+4])[0]
            offset += 4
            lookup_status = struct.unpack('!I', response[offset:offset+4])[0]
            offset += 4
            if lookup_status != NFS4_OK:
                error_name = "UNKNOWN_ERROR"
                if lookup_status == 2:
                    error_name = "NFS4ERR_NOENT"
                elif lookup_status == 13:
                    error_name = "NFS4ERR_ACCESS"
                elif lookup_status == 1:
                    error_name = "NFS4ERR_PERM"
                logging.error(f"LOOKUP failed for {name}: {error_name} ({lookup_status})")
                logging.debug(f"This could indicate: file doesn't exist, insufficient permissions, or hidden file restrictions")
                logging.debug(f"Try checking if the file exists in the directory listing first")
                raise RPCError(f"LOOKUP failed for {name}: {error_name} ({lookup_status})")
            
            # Parse GETFH result (opcode + status)
            getfh_opcode = struct.unpack('!I', response[offset:offset+4])[0]
            offset += 4
            getfh_status = struct.unpack('!I', response[offset:offset+4])[0]
            offset += 4
            if getfh_status != NFS4_OK:
                raise RPCError(f"GETFH failed: {getfh_status}")
            
            # Get file handle
            fh_length = struct.unpack('!I', response[offset:offset+4])[0]
            offset += 4
            file_handle = response[offset:offset+fh_length]
            
            return file_handle
            
        except Exception as e:
            logging.error(f"Lookup failed for {name}: {e}")
            raise
    
    def readdir(self, path="/"):
        """Read directory contents using READDIR operation"""
        logging.info(f"Reading directory: {path}")
        
        if not self.connected:
            raise RuntimeError("Not connected to NFSv4 server")
        
        # Get directory file handle
        dir_fh = self._lookup_path(path)
        
        try:
            # Build COMPOUND request: PUTFH + READDIR
            operations = []
            
            # PUTFH operation
            operations.append(
                struct.pack('!I', OP_PUTFH) +
                struct.pack('!I', len(dir_fh)) + dir_fh
            )
            
            # READDIR operation
            cookie = 0
            cookievf = b'\x00' * 8  # verifier
            dircount = 4096
            maxcount = 4096
            
            # Requested attributes (basic set)
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
            
            response = self._send_compound(operations)
            
            # Parse directory entries
            return self._parse_readdir_response(response)
            
        except Exception as e:
            logging.error(f"Readdir failed: {e}")
            raise
    
    def _parse_readdir_response(self, data):
        """Parse READDIR response"""
        try:
            # Parse COMPOUND response header
            parsed = self._parse_compound_response(data)
            offset = parsed['data_offset']
            
            # Parse PUTFH result (opcode + status)
            putfh_opcode = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            putfh_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            if putfh_status != NFS4_OK:
                raise RPCError(f"PUTFH failed: {putfh_status}")
            
            # Parse READDIR result (opcode + status)
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
            
            # Parse entries - NFSv4 READDIR response structure
            while True:
                # Check if we have enough data for value_follows
                if offset + 4 > len(data):
                    logging.debug(f"End of data reached at offset {offset}, data length {len(data)}")
                    break
                
                value_follows = struct.unpack('!I', data[offset:offset+4])[0]
                offset += 4
                logging.debug(f"Value follows: {value_follows}")
                
                if value_follows == 0:
                    logging.debug("No more entries marker found")
                    break  # No more entries
                
                # Check if we have enough data for cookie (8 bytes)
                if offset + 8 > len(data):
                    logging.debug(f"Insufficient data for cookie at offset {offset}")
                    break
                
                # Parse entry cookie
                cookie = struct.unpack('!Q', data[offset:offset+8])[0]
                offset += 8
                logging.debug(f"Cookie: {cookie}")
                
                # Check if we have enough data for name length (4 bytes)
                if offset + 4 > len(data):
                    logging.debug(f"Insufficient data for name length at offset {offset}")
                    break
                
                # Parse name length and name
                name_len = struct.unpack('!I', data[offset:offset+4])[0]
                offset += 4
                logging.debug(f"Name length: {name_len}")
                
                # Check if we have enough data for the name itself
                if offset + name_len > len(data):
                    logging.debug(f"Insufficient data for name at offset {offset}, name_len {name_len}")
                    break
                
                try:
                    name = data[offset:offset+name_len].decode('utf-8')
                except UnicodeDecodeError:
                    # Fallback for non-UTF-8 filenames (use latin-1 to preserve bytes)
                    name = data[offset:offset+name_len].decode('latin-1')
                    logging.debug(f"Non-UTF-8 filename encountered: {name}")
                
                offset += name_len
                # Apply XDR padding to 4-byte boundary
                padding = (4 - (name_len % 4)) % 4
                offset += padding
                logging.debug(f"Name: '{name}', applied {padding} bytes padding")
                
                # Parse NFSv4 attributes - they consist of bitmap + attribute data
                # First, read the attribute bitmap (number of words)
                if offset + 4 > len(data):
                    logging.debug(f"Insufficient data for attribute bitmap length at offset {offset}")
                    break
                
                bitmap_words = struct.unpack('!I', data[offset:offset+4])[0]
                offset += 4
                logging.debug(f"Attribute bitmap words: {bitmap_words}")
                
                # Skip bitmap words (4 bytes each)
                bitmap_bytes = bitmap_words * 4
                if offset + bitmap_bytes > len(data):
                    logging.debug(f"Insufficient data for bitmap at offset {offset}, need {bitmap_bytes} bytes")
                    break
                offset += bitmap_bytes
                logging.debug(f"Skipped {bitmap_bytes} bytes of bitmap")
                
                # Read attribute data length
                if offset + 4 > len(data):
                    logging.debug(f"Insufficient data for attribute data length at offset {offset}")
                    break
                
                attr_data_len = struct.unpack('!I', data[offset:offset+4])[0]
                offset += 4
                logging.debug(f"Attribute data length: {attr_data_len}")
                
                # Check if we have enough data for the attribute data
                if offset + attr_data_len > len(data):
                    logging.debug(f"Insufficient data for attribute data at offset {offset}, need {attr_data_len} bytes")
                    break
                
                # Skip attribute data for now - focus on getting all names
                offset += attr_data_len
                logging.debug(f"Skipped {attr_data_len} bytes of attribute data, new offset: {offset}")
                
                entries.append({
                    'name': name,
                    'cookie': cookie,
                    'type': 'unknown'  # Would parse from attributes
                })
                
                logging.debug(f"Successfully parsed entry: '{name}' (cookie: {cookie})")
            
            logging.info(f"Found {len(entries)} directory entries")
            return entries
            
        except Exception as e:
            logging.error(f"Failed to parse readdir response: {e}")
            raise
    
    def read_file(self, path, offset=0, size=None):
        """Read file contents using READ operation"""
        logging.info(f"Reading file: {path}")
        
        if not self.connected:
            raise RuntimeError("Not connected to NFSv4 server")
        
        # Get file handle
        file_fh = self._lookup_path(path)
        
        # Determine read size
        if size is None:
            size = self.chunk_size
        
        try:
            # Build COMPOUND request: PUTFH + READ
            operations = []
            
            # PUTFH operation
            operations.append(
                struct.pack('!I', OP_PUTFH) +
                struct.pack('!I', len(file_fh)) + file_fh
            )
            
            # READ operation
            read_op = (
                struct.pack('!I', OP_READ) +
                struct.pack('!I', 0) +  # stateid sequence
                b'\x00' * 12 +  # stateid other
                struct.pack('!Q', offset) +
                struct.pack('!I', size)
            )
            operations.append(read_op)
            
            response = self._send_compound(operations)
            
            # Parse read data
            return self._parse_read_response(response)
            
        except Exception as e:
            logging.error(f"Read failed: {e}")
            raise
    
    def _parse_read_response(self, data):
        """Parse READ response"""
        try:
            # Parse COMPOUND response header
            parsed = self._parse_compound_response(data)
            offset = parsed['data_offset']
            
            # Parse PUTFH result (opcode + status)
            putfh_opcode = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            putfh_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            if putfh_status != NFS4_OK:
                raise RPCError(f"PUTFH failed: {putfh_status}")
            
            # Parse READ result (opcode + status)
            read_opcode = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            read_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            if read_status != NFS4_OK:
                raise RPCError(f"read failed: {read_status}")
            
            # Parse read data
            eof = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            data_len = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            file_data = data[offset:offset+data_len]
            
            logging.info(f"Read {len(file_data)} bytes")
            return file_data
            
        except Exception as e:
            logging.error(f"Failed to parse read response: {e}")
            raise
    
    def write_file(self, path, data, offset=0):
        """Write data to file - delegated to isolated writer module"""
        from .nfsv4_file_writer import NFSv4FileWriter
        
        writer = NFSv4FileWriter(self)
        return writer.write_file(path, data)
    

    
    def check_access(self, path, access_mask):
        """Check access permissions using ACCESS operation"""
        # Get file handle
        file_fh = self._lookup_path(path)
        
        try:
            # Build COMPOUND request: PUTFH + ACCESS
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
            
            response = self._send_compound(operations)
            
            # Parse access result
            return self._parse_access_response(response)
            
        except Exception as e:
            logging.error(f"Access check failed: {e}")
            raise
    
    def _parse_access_response(self, data):
        """Parse ACCESS response"""
        try:
            # Parse COMPOUND response header
            parsed = self._parse_compound_response(data)
            offset = parsed['data_offset']
            
            # Parse PUTFH result (opcode + status)
            putfh_opcode = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            putfh_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            if putfh_status != NFS4_OK:
                raise RPCError(f"PUTFH failed: {putfh_status}")
            
            # Parse ACCESS result (opcode + status)
            access_opcode = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            access_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            if access_status != NFS4_OK:
                raise RPCError(f"ACCESS failed: {access_status}")
            
            # Parse supported and access masks
            supported = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            access = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            return access
            
        except Exception as e:
            logging.error(f"Failed to parse access response: {e}")
            raise
    
    def getattr(self, path):
        """Get file attributes using GETATTR operation"""
        # Get file handle
        file_fh = self._lookup_path(path)
        
        try:
            # Build COMPOUND request: PUTFH + GETATTR
            operations = []
            
            # PUTFH operation
            operations.append(
                struct.pack('!I', OP_PUTFH) +
                struct.pack('!I', len(file_fh)) + file_fh
            )
            
            # GETATTR operation
            attr_request = pack_bitmap([
                FATTR4_TYPE, FATTR4_SIZE, FATTR4_MODE,
                FATTR4_NUMLINKS, FATTR4_OWNER, FATTR4_OWNER_GROUP,
                FATTR4_TIME_ACCESS, FATTR4_TIME_MODIFY, FATTR4_TIME_METADATA
            ])
            
            operations.append(
                struct.pack('!I', OP_GETATTR) +
                attr_request
            )
            
            response = self._send_compound(operations)
            
            # Parse attributes
            return self._parse_getattr_response(response)
            
        except Exception as e:
            logging.error(f"Getattr failed: {e}")
            raise
    
    def _parse_getattr_response(self, data):
        """Parse GETATTR response"""
        try:
            # Parse COMPOUND response header
            parsed = self._parse_compound_response(data)
            offset = parsed['data_offset']
            
            # Parse PUTFH result (opcode + status)
            putfh_opcode = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            putfh_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            if putfh_status != NFS4_OK:
                raise RPCError(f"PUTFH failed: {putfh_status}")
            
            # Parse GETATTR result (opcode + status)
            getattr_opcode = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            getattr_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            if getattr_status != NFS4_OK:
                raise RPCError(f"GETATTR failed: {getattr_status}")
            
            # Parse attributes from NFSv4 response
            attrs = {}
            
            # Read attribute bitmap (2 words for our request)
            bitmap_len = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            # Skip bitmap data
            offset += bitmap_len * 4
            
            # Read attribute data length
            attr_data_len = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            # Parse attribute data (in order of bitmap)
            attr_start = offset
            
            # Type (FATTR4_TYPE)
            if offset + 4 <= attr_start + attr_data_len:
                attrs['type'] = struct.unpack('!I', data[offset:offset+4])[0]
                offset += 4
                logging.debug(f"File type: {attrs['type']}")
            
            # Size (FATTR4_SIZE) 
            if offset + 8 <= attr_start + attr_data_len:
                attrs['size'] = struct.unpack('!Q', data[offset:offset+8])[0]
                offset += 8
            
            # Mode (FATTR4_MODE)
            if offset + 4 <= attr_start + attr_data_len:
                attrs['mode'] = struct.unpack('!I', data[offset:offset+4])[0]
                offset += 4
                logging.debug(f"Mode: 0{attrs['mode']:o}")
            
            # NumLinks (FATTR4_NUMLINKS)
            if offset + 4 <= attr_start + attr_data_len:
                attrs['nlink'] = struct.unpack('!I', data[offset:offset+4])[0]
                offset += 4
            
            # Owner (FATTR4_OWNER) - string format
            if offset + 4 <= attr_start + attr_data_len:
                owner_len = struct.unpack('!I', data[offset:offset+4])[0]
                offset += 4
                if offset + owner_len <= attr_start + attr_data_len:
                    owner_str = data[offset:offset+owner_len].decode('utf-8')
                    attrs['uid'] = int(owner_str) if owner_str.isdigit() else owner_str
                    offset += owner_len
                    # XDR padding
                    padding = (4 - (owner_len % 4)) % 4
                    offset += padding
            
            # Owner_Group (FATTR4_OWNER_GROUP) - string format  
            if offset + 4 <= attr_start + attr_data_len:
                group_len = struct.unpack('!I', data[offset:offset+4])[0]
                offset += 4
                if offset + group_len <= attr_start + attr_data_len:
                    group_str = data[offset:offset+group_len].decode('utf-8')
                    attrs['gid'] = int(group_str) if group_str.isdigit() else group_str
                    offset += group_len
            
            # Set defaults for missing attributes
            attrs.setdefault('type', 1)
            attrs.setdefault('size', 0) 
            attrs.setdefault('mode', 0o644)
            attrs.setdefault('uid', -1)
            attrs.setdefault('gid', -1)
            attrs.setdefault('nlink', 1)
            
            return attrs
            
        except Exception as e:
            logging.error(f"Failed to parse getattr response: {e}")
            raise
    
    def clone_with_credentials(self, uid, gid, gids=None):
        """Create a clone with different credentials"""
        return NFSv4Client(
            self.target_host,
            self.export_path,
            self.proxy_type,
            self.proxy_host,
            self.proxy_port,
            self.nfs_port,
            self.nfs_program,
            self.auth_manager.hostname,
            uid, gid, gids,
            self.timeout,
            self.chunk_size
        )
    
    def disconnect(self):
        """Disconnect from NFSv4 server"""
        logging.info("Disconnecting from NFSv4 server")
        self.connected = False
    
    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()

class RPCError(Exception):
    """RPC operation error"""
    pass
