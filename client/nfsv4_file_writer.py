import struct
import logging
import xdrlib
from .nfs_constants import *
from .rpc_transport import RPCError, RPCTransport
from .socks_socket import ProxySocket
# No longer needed - using manual parsing like working client

# NFSv4 Write stability constants
UNSTABLE = 0
DATA_SYNC = 1
FILE_SYNC = 2

def pack_xdr_string(s):
    """Pack a string in XDR format"""
    if isinstance(s, str):
        b = s.encode('utf-8')
    else:
        b = s
    pad = (4 - (len(b) % 4)) % 4
    return struct.pack('!I', len(b)) + b + (b'\x00' * pad)

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

# NFSv4 constants (copied from nfs_constants.py)
OP_PUTFH = 22
OP_OPEN = 18
OP_GETFH = 10

# NFSv4 OPEN constants
OPEN4_CREATE_UNCHECKED = 0
OPEN4_OPEN_CREATE = 1
OPEN4_SHARE_ACCESS_WRITE = 2
OPEN4_SHARE_DENY_NONE = 0

# NFSv4 Status codes
NFS4_OK = 0

class NFSv4FileWriter:
    """
    Isolated NFSv4 file writing operations
    """

    def __init__(self, nfs_client):
        """
        Initialize with reference to main NFSv4 client

        :param nfs_client: Main NFSv4Client instance
        """
        self.client = nfs_client

    def write_file(self, path, data):
        """
        Write data to a file on NFSv4 server

        :param path: path to file
        :param data: data to write
        :return: number of bytes written
        """
        logging.info(f"Writing {len(data)} bytes to {path}")

        if not self.client.connected:
            raise RuntimeError("Not connected to NFSv4 server")

        try:
            # Try to lookup existing file
            try:
                file_fh = self.client._lookup_path(path)
                logging.debug(f"File exists, using existing handle")
            except Exception:
                # File doesn't exist, create it
                logging.debug(f"File doesn't exist, creating new file")
                file_fh = self._create_file_with_open(path)

            # Write data to file
            return self._write_to_file(file_fh, data)

        except Exception as e:
            logging.error(f"Write failed: {e}")
            raise

    def _get_client_id(self):
        """
        Get valid client ID using SETCLIENTID operation
        """
        logging.debug("Obtaining client ID via SETCLIENTID")

        # Build complete COMPOUND4args manually (RFC 3530 Section 14.2)
        compound_packer = xdrlib.Packer()

        # COMPOUND4args structure:
        # utf8str_cs tag (empty string)
        compound_packer.pack_string(b"")  # empty tag

        # uint32_t minorversion (0 for NFSv4.0)
        compound_packer.pack_uint(0)

        # uint32_t argarray_len (number of operations = 1)
        compound_packer.pack_uint(1)

        # nfs_argop4 argarray<> - SETCLIENTID operation
        # Pack operation opcode
        compound_packer.pack_uint(35)  # OP_SETCLIENTID

        # Pack SETCLIENTID operation data (RFC 3530 Section 14.2.33)
        # client4.verifier (8 bytes)
        compound_packer.pack_uhyper(0x1234567890ABCDEF)

        # client4.id (opaque string) - use hostname parameter
        hostname = getattr(self.client, 'hostname', 'nfsclient')
        client_id_data = hostname.encode('utf-8')
        compound_packer.pack_bytes(client_id_data)

        # cb_client4.cb_program (4 bytes) - 0 for no callback
        compound_packer.pack_uint(0)  # 0 = no callback

        # cb_client4.cb_location per no callback (RFC 3530 Section 14.2.33)
        # When cb_program is 0, r_netid and r_addr should be empty strings
        compound_packer.pack_string(b"")  # r_netid: empty for no callback
        compound_packer.pack_string(b"")  # r_addr: empty for no callback

        # uint32_t callback_ident (RFC 3530 Section 14.2.33)
        # Required field after cb_client4 - can be 0 for no callback
        compound_packer.pack_uint(0)  # callback_ident

        compound_data = compound_packer.get_buffer()

        # Send COMPOUND request directly via RPC
        response = self._send_rpc_compound(compound_data)

        # Parse response
        parsed = self.client._parse_compound_response(response)
        offset = parsed['data_offset']

        # Parse SETCLIENTID response
        opcode = struct.unpack('!I', response[offset:offset+4])[0]
        offset += 4
        op_status = struct.unpack('!I', response[offset:offset+4])[0]
        offset += 4

        if op_status != 0:
            raise Exception(f"SETCLIENTID operation failed with status {op_status}")

        # Extract client ID
        client_id = struct.unpack('!Q', response[offset:offset+8])[0]
        offset += 8

        # Extract verifier for SETCLIENTID_CONFIRM
        confirm_verifier = response[offset:offset+8]

        logging.debug(f"Got client ID: {client_id:016x}")

        # Now confirm the client ID
        self._confirm_client_id(client_id, confirm_verifier)

        return client_id

    def _send_rpc_compound(self, compound_data):
        """
        Send COMPOUND request directly via RPC (procedure 1)
        """
        try:
            # Connect to NFS service
            sock = ProxySocket(
                self.client.target_host, self.client.nfs_port,
                self.client.proxy_host, self.client.proxy_port,
                self.client.proxy_type, self.client.timeout
            ).connect()

            rpc_transport = RPCTransport(sock)

            # Get credentials
            credentials = self.client.auth_manager.get_auth_unix_credentials()
            verifier = self.client.auth_manager.get_default_verifier()

            # Send COMPOUND request (procedure 1 = COMPOUND)
            _, response = rpc_transport.send_rpc_request(
                self.client.nfs_program, self.client.nfs_version, 1,  # procedure 1 = COMPOUND
                compound_data, credentials, verifier
            )

            sock.close()
            return response

        except Exception as e:
            logging.error(f"RPC COMPOUND request failed: {e}")
            raise

    def _confirm_client_id(self, client_id, verifier):
        """
        Confirm client ID using SETCLIENTID_CONFIRM operation
        """
        logging.debug(f"Confirming client ID: {client_id:016x}")

        # Build SETCLIENTID_CONFIRM request
        operations = []

        # SETCLIENTID_CONFIRM operation
        confirm_op = struct.pack('!I', 36)  # OP_SETCLIENTID_CONFIRM
        confirm_op += struct.pack('!Q', client_id)  # client ID
        confirm_op += verifier  # verifier

        operations.append(confirm_op)

        # Send request
        response = self.client._send_compound(operations)

        # Parse response
        parsed = self.client._parse_compound_response(response)
        offset = parsed['data_offset']

        # Parse SETCLIENTID_CONFIRM response
        opcode = struct.unpack('!I', response[offset:offset+4])[0]
        offset += 4
        op_status = struct.unpack('!I', response[offset:offset+4])[0]
        offset += 4

        if op_status != 0:
            raise Exception(f"SETCLIENTID_CONFIRM failed with status {op_status}")

        logging.debug("Client ID confirmed successfully")

    def _create_file_with_open(self, path):
        """
        Create a new file using NFSv4 OPEN operation with CREATE flag

        :param path: path to file to create
        :return: file handle for created file
        """
        import os

        # Split path into directory and filename
        dirname = os.path.dirname(path) if path.startswith('/') else '/'
        filename = os.path.basename(path)

        # Get directory handle
        if dirname == '/':
            dir_fh = self.client._lookup_path('/')
        else:
            dir_fh = self.client._lookup_path(dirname)

        logging.debug(f"Creating file '{filename}' in directory")

        try:
            # Get valid client ID first
            client_id = self._get_client_id()

            # Build COMPOUND request following RFC 7530 Section 16.16 exactly
            operations = []

            # PUTFH operation (directory)
            putfh_op = struct.pack('!I', OP_PUTFH)
            putfh_op += struct.pack('!I', len(dir_fh)) + dir_fh
            operations.append(putfh_op)

            # OPEN operation following RFC 7530 XDR structure exactly
            filename_bytes = filename.encode('utf-8')
            filename_padding = (4 - (len(filename_bytes) % 4)) % 4

            # Start OPEN operation
            open_op = struct.pack('!I', OP_OPEN)  # opcode

            # OPEN4args structure (RFC 7530 Section 16.16)
            open_op += struct.pack('!I', 0)  # seqid4 seqid
            open_op += struct.pack('!I', OPEN4_SHARE_ACCESS_WRITE)  # uint32_t share_access  
            open_op += struct.pack('!I', OPEN4_SHARE_DENY_NONE)  # uint32_t share_deny

            # open_owner4 owner
            open_op += struct.pack('!Q', client_id)  # clientid4 clientid (valid from SETCLIENTID)
            owner_data = b'nfsclient'
            owner_padding = (4 - (len(owner_data) % 4)) % 4
            open_op += struct.pack('!I', len(owner_data)) + owner_data + b'\x00' * owner_padding  # opaque owner<>

            # openflag4 openhow (union with discriminator)
            open_op += struct.pack('!I', OPEN4_OPEN_CREATE)  # opentype4 opentype (discriminator)
            # Since opentype == OPEN4_CREATE, include createhow4 how
            open_op += struct.pack('!I', OPEN4_CREATE_UNCHECKED)  # createhow4.mode (discriminator)
            # Since mode == UNCHECKED4, include createattrs (RFC 3530 Section 9.1.1 - attribute mask required)
            open_op += struct.pack('!I', 2)  # bitmap4 length = 2 words (for bit 33)
            open_op += struct.pack('!I', 0x00000000)  # bitmap word 0 (bits 0-31)
            open_op += struct.pack('!I', 0x00000002)  # bitmap word 1 (bit 33 = 0x02 in word 1)
            open_op += struct.pack('!I', 4)  # attribute data length (4 bytes for mode)
            open_op += struct.pack('!I', 0o644)  # mode value (rw-r--r--)

            # open_claim4 claim (union with discriminator)  
            open_op += struct.pack('!I', 0)  # open_claim_type4 claim = CLAIM_NULL (discriminator)
            # Since claim == CLAIM_NULL, include component4 file
            open_op += struct.pack('!I', len(filename_bytes)) + filename_bytes + b'\x00' * filename_padding

            operations.append(open_op)

            # GETFH operation to get file handle
            getfh_op = struct.pack('!I', OP_GETFH)
            operations.append(getfh_op)

            response = self.client._send_compound(operations)

            # Use EXISTING parser that WORKS - NO CHANGES
            parsed = self.client._parse_compound_response(response)
            offset = parsed['data_offset']
            
            try:
                # Use EXACT same approach as working client  
                logging.debug(f"Using working parser - Operations count: {parsed['num_results']}")
                
                # Manual parsing like working client does
                if parsed['num_results'] != 3:
                    raise RPCError(f"Expected 3 operations, got {parsed['num_results']}")
                
                # Parse PUTFH result - EXACT same as working client
                putfh_opcode = struct.unpack('!I', response[offset:offset+4])[0]
                offset += 4
                putfh_status = struct.unpack('!I', response[offset:offset+4])[0]
                offset += 4
                logging.debug(f"PUTFH opcode: {putfh_opcode}, status: {putfh_status}")
                if putfh_status != NFS4_OK:
                    raise RPCError(f"PUTFH failed: {putfh_status}")
                
                # Parse OPEN result - EXACT same as working client
                open_opcode = struct.unpack('!I', response[offset:offset+4])[0]
                offset += 4
                open_status = struct.unpack('!I', response[offset:offset+4])[0]
                offset += 4
                logging.debug(f"OPEN opcode: {open_opcode}, status: {open_status}")
                if open_status != NFS4_OK:
                    if open_status == 10036:
                        raise RPCError(f"OPEN failed: NFS4ERR_BADXDR (malformed XDR)")
                    elif open_status == 17:
                        raise RPCError(f"OPEN failed: NFS4ERR_EXIST (file exists)")
                    elif open_status == 13:
                        raise RPCError(f"OPEN failed: NFS4ERR_ACCESS (permission denied)")
                    else:
                        raise RPCError(f"OPEN failed: {open_status}")
                
                # Parse OPEN4resok structure carefully from Wireshark data
                logging.debug(f"Parsing OPEN result at offset {offset}, remaining bytes: {len(response) - offset}")
                logging.debug(f"Response length: {len(response)}")
                
                # Skip stateid (16 bytes)
                if offset + 16 > len(response):
                    raise ValueError(f"Not enough data for stateid at offset {offset}, need 16 bytes, have {len(response) - offset}")
                logging.debug(f"Skipping stateid: offset {offset} -> {offset + 16}")
                offset += 16
                
                # Skip change_info4: atomic(bool=4) + before(8) + after(8) = 20 bytes total  
                if offset + 20 > len(response):
                    raise ValueError(f"Not enough data for change_info at offset {offset}, need 20 bytes, have {len(response) - offset}")
                logging.debug(f"Skipping change_info: offset {offset} -> {offset + 20}")
                offset += 20
                
                # Skip rflags (4 bytes)
                if offset + 4 > len(response):
                    raise ValueError(f"Not enough data for rflags at offset {offset}")
                offset += 4
                
                # Parse attrset bitmap length carefully
                if offset + 4 > len(response):
                    raise ValueError(f"Not enough data for bitmap length at offset {offset}")
                bitmap_len = struct.unpack('!I', response[offset:offset+4])[0]
                offset += 4
                logging.debug(f"Bitmap length: {bitmap_len}")
                
                # Skip bitmap words
                bitmap_bytes = bitmap_len * 4
                if offset + bitmap_bytes > len(response):
                    raise ValueError(f"Not enough data for bitmap at offset {offset}")
                offset += bitmap_bytes
                
                # Skip delegation type (4 bytes for OPEN_DELEGATE_NONE=0)
                if offset + 4 > len(response):
                    raise ValueError(f"Not enough data for delegation at offset {offset}")
                delegation_type = struct.unpack('!I', response[offset:offset+4])[0]
                offset += 4
                logging.debug(f"Delegation type: {delegation_type}")
                
                # No additional delegation data for OPEN_DELEGATE_NONE (type 0)
                
                # Parse GETFH result with bounds checking
                logging.debug(f"Parsing GETFH at offset {offset}, remaining bytes: {len(response) - offset}")
                
                if offset + 8 > len(response):
                    raise ValueError(f"Not enough data for GETFH header at offset {offset}")
                
                getfh_opcode = struct.unpack('!I', response[offset:offset+4])[0]
                offset += 4
                getfh_status = struct.unpack('!I', response[offset:offset+4])[0]
                offset += 4
                logging.debug(f"GETFH opcode: {getfh_opcode}, status: {getfh_status}")
                
                if getfh_status != NFS4_OK:
                    raise RPCError(f"GETFH failed: {getfh_status}")
                
                # Extract file handle with bounds checking
                if offset + 4 > len(response):
                    raise ValueError(f"Not enough data for file handle length at offset {offset}")
                
                fh_len = struct.unpack('!I', response[offset:offset+4])[0]
                offset += 4
                logging.debug(f"File handle length: {fh_len}")
                
                if offset + fh_len > len(response):
                    raise ValueError(f"Not enough data for file handle at offset {offset}")
                
                file_fh = response[offset:offset+fh_len]
                logging.debug(f"Manual parsed file handle: {len(file_fh)} bytes")
                
                return file_fh
                
            except Exception as e:
                logging.error(f"Manual parsing failed: {e}")
                import traceback
                logging.error(f"Traceback: {traceback.format_exc()}")
                raise RPCError(f"Failed to parse COMPOUND response: {e}")

        except Exception as e:
            logging.error(f"File creation failed: {e}")
            raise

    def _write_to_file(self, file_fh, data):
        """
        Write data to an existing file handle

        :param file_fh: file handle
        :param data: data to write
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

            # WRITE operation
            offset = 0
            stateid = b'\x00' * 16  # All zeros stateid (for anonymous/simple writes)
            stable = FILE_SYNC  # Write synchronously

            write_op = (
                struct.pack('!I', OP_WRITE) +
                stateid +
                struct.pack('!Q', offset) +
                struct.pack('!I', stable) +
                struct.pack('!I', len(data)) + data +
                (b'\x00' * ((4 - len(data) % 4) % 4))  # XDR padding
            )
            operations.append(write_op)

            response = self.client._send_compound(operations)

            # Parse response
            parsed = self.client._parse_compound_response(response)
            offset = parsed['data_offset']

            # Parse PUTFH result
            putfh_opcode = struct.unpack('!I', response[offset:offset+4])[0]
            offset += 4
            putfh_status = struct.unpack('!I', response[offset:offset+4])[0]
            offset += 4
            if putfh_status != NFS4_OK:
                raise RPCError(f"PUTFH failed: {putfh_status}")

            # Parse WRITE result
            write_opcode = struct.unpack('!I', response[offset:offset+4])[0]
            offset += 4
            write_status = struct.unpack('!I', response[offset:offset+4])[0]
            offset += 4
            if write_status != NFS4_OK:
                error_name = "UNKNOWN_ERROR"
                if write_status == 13:
                    error_name = "NFS4ERR_ACCESS"
                elif write_status == 1:
                    error_name = "NFS4ERR_PERM"
                elif write_status == 28:
                    error_name = "NFS4ERR_NOSPC"
                raise RPCError(f"WRITE failed: {error_name} ({write_status})")

            # Get bytes written
            bytes_written = struct.unpack('!I', response[offset:offset+4])[0]
            offset += 4

            # Skip committed field
            offset += 4

            # Skip write verifier
            offset += 8

            logging.info(f"Successfully wrote {bytes_written} bytes")
            return bytes_written

        except Exception as e:
            logging.error(f"Write operation failed: {e}")
            raise
