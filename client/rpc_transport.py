"""
RPC transport layer implementation
"""

import struct
import random
import logging
import time
from .nfs_constants import *


class RPCTransport:
    """
    Handles RPC communication over TCP
    """
    
    def __init__(self, socket_obj):
        """
        Initialize RPC transport
        
        :param socket_obj: connected socket object
        """
        self.sock = socket_obj
        self.last_xid = random.randint(1, 0x7FFFFFFF)
        
    def next_xid(self):
        """
        Generate next XID
        
        :return: next transaction ID
        """
        self.last_xid += 1
        return self.last_xid
    
    def build_rpc_call(self, xid, program, version, procedure,
                      credentials=None, verifier=None, payload=b''):
        """
        Build an RPC call packet
        
        :param xid: transaction ID
        :param program: RPC program number
        :param version: program version
        :param procedure: procedure number
        :param credentials: authentication credentials tuple (flavor, data)
        :param verifier: authentication verifier tuple (flavor, data)
        :param payload: procedure-specific payload
        :return: complete RPC packet bytes
        """
        logging.debug(f"Building RPC call: XID={xid}, program={program}, "
                     f"version={version}, procedure={procedure}")
        
        # Default to AUTH_NULL if not specified
        if credentials is None:
            credentials = (AUTH_NULL, b'')
        if verifier is None:
            verifier = (AUTH_NULL, b'')
        
        cred_flavor, cred_data = credentials
        verf_flavor, verf_data = verifier
        
        # Build credential and verifier structures
        cred_struct = struct.pack('!II', cred_flavor, len(cred_data)) + cred_data
        # Add padding for XDR alignment
        cred_pad = (4 - (len(cred_data) % 4)) % 4
        cred_struct += b'\x00' * cred_pad
        
        verf_struct = struct.pack('!II', verf_flavor, len(verf_data)) + verf_data
        # Add padding for XDR alignment
        verf_pad = (4 - (len(verf_data) % 4)) % 4
        verf_struct += b'\x00' * verf_pad
        
        # Build RPC call header
        rpc_header = struct.pack('!IIIIII',
                                xid,        # Transaction ID
                                RPC_CALL,   # Message type (CALL)
                                2,          # RPC version (always 2)
                                program,    # Program number
                                version,    # Program version
                                procedure   # Procedure number
                                )
        
        return rpc_header + cred_struct + verf_struct + payload
    
    def send_rpc_request(self, program, version, procedure,
                        payload=b'', credentials=None, verifier=None):
        """
        Send an RPC request and return the response
        
        :param program: RPC program number
        :param version: program version
        :param procedure: procedure number
        :param payload: procedure-specific payload
        :param credentials: authentication credentials
        :param verifier: authentication verifier
        :return: tuple (XID, response_data)
        """
        xid = self.next_xid()
        
        # Build the RPC call
        rpc_packet = self.build_rpc_call(xid, program, version, procedure,
                                        credentials, verifier, payload)
        
        # Frame the packet for TCP transport
        length = len(rpc_packet)
        framed_packet = struct.pack('!I', 0x80000000 | length) + rpc_packet
        
        try:
            logging.debug(f"Sending RPC request: length={length}, XID={xid}")
            self.sock.sendall(framed_packet)
            
            # Receive response
            response_data = self.receive_rpc_response(xid)
            
            return xid, response_data
            
        except Exception as e:
            logging.error(f"RPC request failed: {e}")
            raise
    
    def receive_rpc_response(self, expected_xid):
        """
        Receive and parse an RPC response
        
        :param expected_xid: expected transaction ID
        :return: response data bytes
        """
        try:
            data = b''
            
            # Handle TCP framing - may have multiple fragments
            while True:
                # Read fragment header
                header_data = self._recv_exactly(4)
                if len(header_data) < 4:
                    raise RuntimeError("Incomplete RPC response header")
                
                fragment_header = struct.unpack('!I', header_data)[0]
                is_last_fragment = bool(fragment_header & 0x80000000)
                fragment_length = fragment_header & 0x7FFFFFFF
                
                # Read fragment data
                fragment_data = self._recv_exactly(fragment_length)
                if len(fragment_data) < fragment_length:
                    raise RuntimeError("Incomplete RPC response fragment")
                
                data += fragment_data
                
                if is_last_fragment:
                    break
            
            # Verify XID
            if len(data) < 4:
                raise RuntimeError("RPC response too short")
            
            response_xid = struct.unpack('!I', data[:4])[0]
            if response_xid != expected_xid:
                logging.warning(f"XID mismatch: expected {expected_xid}, got {response_xid}")
            
            logging.debug(f"Received RPC response: XID={response_xid}, length={len(data)}")
            return data
            
        except Exception as e:
            logging.error(f"Failed to receive RPC response: {e}")
            raise
    
    def _recv_exactly(self, length):
        """
        Receive exactly the specified number of bytes
        
        :param length: number of bytes to receive
        :return: received data
        """
        data = b''
        while len(data) < length:
            chunk = self.sock.recv(length - len(data))
            if not chunk:
                raise RuntimeError("Connection closed prematurely")
            data += chunk
        return data
    
    def parse_rpc_response(self, data):
        """
        Parse RPC response header
        
        :param data: response data
        :return: dict with parsed response fields
        """
        if len(data) < 12:
            raise ValueError("Response too short for RPC header")
        
        offset = 0
        
        # Parse basic RPC response header
        xid, msg_type, reply_stat = struct.unpack('!III', data[offset:offset+12])
        offset += 12
        
        result = {
            'xid': xid,
            'msg_type': msg_type,
            'reply_stat': reply_stat,
            'verifier': None,
            'accept_stat': None,
            'status': None,
            'data_offset': offset
        }
        
        if reply_stat == MSG_ACCEPTED:
            # Parse verifier
            if offset + 8 > len(data):
                raise ValueError("Truncated verifier")
            
            verf_flavor, verf_length = struct.unpack('!II', data[offset:offset+8])
            offset += 8
            
            if offset + verf_length > len(data):
                raise ValueError("Truncated verifier data")
            
            verf_data = data[offset:offset+verf_length]
            offset += verf_length
            
            # Handle XDR padding
            pad = (4 - (verf_length % 4)) % 4
            offset += pad
            
            result['verifier'] = (verf_flavor, verf_data)
            
            # Parse accept status
            if offset + 4 > len(data):
                raise ValueError("Missing accept status")
            
            accept_stat = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            result['accept_stat'] = accept_stat
            result['data_offset'] = offset
            
            if accept_stat == SUCCESS:
                # For successful responses, the rest is program-specific data
                pass
            else:
                # Handle RPC-level errors
                error_msg = self._get_rpc_error_message(accept_stat)
                logging.error(f"RPC accept error: {error_msg}")
        
        else:
            # MSG_DENIED - handle authentication failures, etc.
            logging.error(f"RPC request denied: {reply_stat}")
        
        return result
    
    def _get_rpc_error_message(self, accept_stat):
        """
        Get human-readable error message for RPC accept status
        
        :param accept_stat: RPC accept status code
        :return: error message string
        """
        error_messages = {
            SUCCESS: "Success",
            PROG_UNAVAIL: "Program unavailable",
            PROG_MISMATCH: "Program version mismatch",
            PROC_UNAVAIL: "Procedure unavailable",
            GARBAGE_ARGS: "Garbage arguments",
            SYSTEM_ERR: "System error"
        }
        
        return error_messages.get(accept_stat, f"Unknown error ({accept_stat})")
    
    def close(self):
        """
        Close the transport connection
        """
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None


class RPCError(Exception):
    """
    RPC-specific error
    """
    
    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


class RPCTimeoutError(RPCError):
    """
    RPC timeout error
    """
    pass


class RPCAuthenticationError(RPCError):
    """
    RPC authentication error
    """
    pass


class RPCProgramError(RPCError):
    """
    RPC program error
    """
    pass
