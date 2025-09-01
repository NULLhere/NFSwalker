#!/usr/bin/env python3
"""
NFSv4.1 Session Manager - Gestione sessioni per NFSv4.1+
Modulo isolato per implementare CREATE_SESSION e gestione stato sessioni
"""

import struct
import logging
import socket
import random
from client.socks_socket import ProxySocket
from client.auth import AuthManager
from client.nfs_constants import *

# Constants for session manager
AUTH_NULL = 0
AUTH_UNIX = 1
RPC_CALL = 0
RPC_REPLY = 1
MSG_ACCEPTED = 0
MSG_DENIED = 1
SUCCESS = 0

# NFSv4 Error codes
NFS4_ERROR_CODES = {
    0: "NFS4_OK",
    1: "NFS4ERR_PERM",
    2: "NFS4ERR_NOENT", 
    5: "NFS4ERR_IO",
    13: "NFS4ERR_ACCESS",
    17: "NFS4ERR_EXIST",
    20: "NFS4ERR_NOTDIR",
    21: "NFS4ERR_ISDIR",
    22: "NFS4ERR_INVAL",
    27: "NFS4ERR_FBIG",
    28: "NFS4ERR_NOSPC",
    30: "NFS4ERR_ROFS",
    63: "NFS4ERR_NAMETOOLONG",
    66: "NFS4ERR_NOTEMPTY",
    69: "NFS4ERR_DQUOT",
    70: "NFS4ERR_STALE",
    10001: "NFS4ERR_BADHANDLE",
    10003: "NFS4ERR_BAD_COOKIE",
    10004: "NFS4ERR_NOTSUPP",
    10005: "NFS4ERR_TOOSMALL",
    10006: "NFS4ERR_SERVERFAULT",
    10007: "NFS4ERR_BADTYPE",
    10008: "NFS4ERR_DELAY",
    10013: "NFS4ERR_SAME",
    10014: "NFS4ERR_DENIED",
    10015: "NFS4ERR_EXPIRED",
    10016: "NFS4ERR_LOCKED",
    10017: "NFS4ERR_GRACE",
    10018: "NFS4ERR_FHEXPIRED",
    10019: "NFS4ERR_SHARE_DENIED",
    10020: "NFS4ERR_WRONGSEC",
    10021: "NFS4ERR_MINOR_VERS_MISMATCH",
    10022: "NFS4ERR_STALE_CLIENTID",
    10023: "NFS4ERR_STALE_STATEID",
    10024: "NFS4ERR_OLD_STATEID",
    10025: "NFS4ERR_BAD_STATEID",
    10026: "NFS4ERR_BAD_SEQID",
    10027: "NFS4ERR_NOT_SAME",
    10028: "NFS4ERR_LOCK_RANGE",
    10029: "NFS4ERR_SYMLINK",
    10030: "NFS4ERR_RESTOREFH",
    10031: "NFS4ERR_LEASE_MOVED",
    10032: "NFS4ERR_ATTRNOTSUPP",
    10033: "NFS4ERR_NO_GRACE",
    10034: "NFS4ERR_RECLAIM_BAD",
    10035: "NFS4ERR_RECLAIM_CONFLICT",
    10036: "NFS4ERR_BADXDR",
    10037: "NFS4ERR_LOCKS_HELD",
    10038: "NFS4ERR_OPENMODE",
    10039: "NFS4ERR_BADOWNER",
    10040: "NFS4ERR_BADCHAR",
    10041: "NFS4ERR_BADNAME",
    10042: "NFS4ERR_BAD_RANGE",
    10043: "NFS4ERR_LOCK_NOTSUPP",
    10044: "NFS4ERR_OP_ILLEGAL",
    10045: "NFS4ERR_DEADLOCK",
    10046: "NFS4ERR_FILE_OPEN",
    10047: "NFS4ERR_ADMIN_REVOKED",
    10048: "NFS4ERR_CB_PATH_DOWN",
    10071: "NFS4ERR_OP_NOT_IN_SESSION"
}

class SessionRPCTransport:
    """Dedicated RPC transport for NFSv4.1+ session management"""
    
    def __init__(self, socket_obj, auth_manager=None):
        self.sock = socket_obj
        self.auth_manager = auth_manager
        self.last_xid = random.randint(1, 0x7FFFFFFF)
        
    def next_xid(self):
        self.last_xid += 1
        return self.last_xid
    
    def call(self, program, version, procedure, data=b''):
        """Send RPC call and return response data"""
        xid = self.next_xid()
        
        # Build credentials
        if self.auth_manager:
            credentials = self.auth_manager.get_auth_unix_credentials()
        else:
            credentials = (AUTH_NULL, b'')
        
        # Build RPC call
        rpc_packet = self._build_rpc_call(xid, program, version, procedure, credentials, data)
        
        # Frame for TCP
        length = len(rpc_packet)
        framed_packet = struct.pack('!I', 0x80000000 | length) + rpc_packet
        
        logging.debug(f"Sending RPC request: length={length}, XID={xid}")
        self.sock.sendall(framed_packet)
        
        # Receive response
        response_data = self._receive_response(xid)
        
        # Parse and return just the data portion
        return self._extract_data(response_data)
    
    def _build_rpc_call(self, xid, program, version, procedure, credentials, payload):
        """Build RPC call packet"""
        cred_flavor, cred_data = credentials
        
        # Build credential structure
        cred_struct = struct.pack('!II', cred_flavor, len(cred_data)) + cred_data
        cred_pad = (4 - (len(cred_data) % 4)) % 4
        cred_struct += b'\x00' * cred_pad
        
        # Verifier (AUTH_NULL)
        verf_struct = struct.pack('!II', AUTH_NULL, 0)
        
        # RPC header
        rpc_header = struct.pack('!IIIIII',
                                xid, RPC_CALL, 2, program, version, procedure)
        
        return rpc_header + cred_struct + verf_struct + payload
    
    def _receive_response(self, expected_xid):
        """Receive RPC response"""
        data = b''
        
        while True:
            # Read fragment header
            header_data = self._recv_exactly(4)
            fragment_header = struct.unpack('!I', header_data)[0]
            is_last_fragment = bool(fragment_header & 0x80000000)
            fragment_length = fragment_header & 0x7FFFFFFF
            
            # Read fragment data
            fragment_data = self._recv_exactly(fragment_length)
            data += fragment_data
            
            if is_last_fragment:
                break
        
        # Verify XID
        response_xid = struct.unpack('!I', data[:4])[0]
        logging.debug(f"Received RPC response: XID={response_xid}, length={len(data)}")
        
        return data
    
    def _extract_data(self, response_data):
        """Extract data portion from RPC response"""
        offset = 0
        
        logging.debug(f"[TRACE] SessionRPCTransport._extract_data: called with {len(response_data)} bytes")
        logging.debug(f"Parsing RPC response: {len(response_data)} bytes, hex: {response_data[:16].hex()}")
        
        # Skip XID (4 bytes)
        xid = struct.unpack('!I', response_data[offset:offset+4])[0]
        offset += 4
        logging.debug(f"XID: {xid}")
        
        # Check msg_type (should be 1 for reply)
        msg_type = struct.unpack('!I', response_data[offset:offset+4])[0]
        offset += 4
        logging.debug(f"msg_type: {msg_type} (should be 1 for reply)")
        
        if msg_type != 1:  # RPC_REPLY
            raise RuntimeError(f"Invalid RPC message type: {msg_type} (expected 1 for RPC_REPLY)")
        
        # Check reply_stat (0 = MSG_ACCEPTED, 1 = MSG_DENIED)
        reply_stat = struct.unpack('!I', response_data[offset:offset+4])[0]
        offset += 4
        logging.debug(f"reply_stat: {reply_stat} (0=ACCEPTED, 1=DENIED)")
        
        if reply_stat == 1:  # MSG_DENIED
            # Read reject_stat to determine the reason
            reject_stat = struct.unpack('!I', response_data[offset:offset+4])[0]
            if reject_stat == 0:  # RPC_MISMATCH
                raise RuntimeError("RPC version mismatch")
            elif reject_stat == 1:  # AUTH_ERROR
                auth_stat = struct.unpack('!I', response_data[offset+4:offset+8])[0]
                raise RuntimeError(f"RPC request denied: {auth_stat}")
            else:
                raise RuntimeError(f"RPC request denied: unknown reject_stat {reject_stat}")
        
        # MSG_ACCEPTED (reply_stat == 0)
        # Skip verifier
        verf_flavor, verf_length = struct.unpack('!II', response_data[offset:offset+8])
        offset += 8 + verf_length + ((4 - (verf_length % 4)) % 4)
        logging.debug(f"Skipped verifier: flavor={verf_flavor}, length={verf_length}")
        
        # Check accept_stat (0 = SUCCESS)
        accept_stat = struct.unpack('!I', response_data[offset:offset+4])[0]
        offset += 4
        logging.debug(f"accept_stat: {accept_stat} (should be 0 for SUCCESS)")
        
        if accept_stat != 0:  # SUCCESS
            raise RuntimeError(f"RPC call failed: accept_stat {accept_stat}")
        
        # Return remaining data
        data_portion = response_data[offset:]
        logging.debug(f"Extracted data portion: {len(data_portion)} bytes")
        return data_portion
    
    def _recv_exactly(self, length):
        """Receive exactly length bytes"""
        data = b''
        while len(data) < length:
            chunk = self.sock.recv(length - len(data))
            if not chunk:
                raise RuntimeError("Connection closed prematurely")
            data += chunk
        return data

class NFSv4SessionManager:
    """Gestisce sessioni NFSv4.1+ separate dal client principale"""
    
    def __init__(self, target_host, nfs_port, proxy_host=None, proxy_port=None, 
                 proxy_type='socks5', timeout=10, auth_manager=None, use_privileged_ports=False):
        self.target_host = target_host
        self.nfs_port = nfs_port
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_type = proxy_type
        self.timeout = timeout
        self.use_privileged_ports = use_privileged_ports
        self.auth_manager = auth_manager or AuthManager()
        
        # NFSv4.1+ session state
        self.session_id = None
        self.sequenceid = 0
        self.clientid = None
        self.exchange_id_sequenceid = None  # Sequence ID da EXCHANGE_ID response
        self.session_established = False
        self.minor_version = 1  # Default to 4.1
        
        # Persistent connection for NFSv4.1 sessions
        self.persistent_transport = None
        self.persistent_socket = None
        
    def _create_persistent_connection(self):
        """Creates persistent connection for NFSv4.1 sessions"""
        # Create socket using ProxySocket class
        proxy_socket = ProxySocket(
            self.target_host, self.nfs_port,
            self.proxy_host, self.proxy_port,
            self.proxy_type, self.timeout,
            use_privileged_port=self.use_privileged_ports
        )
        
        # Connect and get the actual socket
        self.persistent_socket = proxy_socket.connect()
        
        # Create persistent transport
        self.persistent_transport = SessionRPCTransport(self.persistent_socket, self.auth_manager)
        logging.info(f"Successfully connected to {self.target_host}:{self.nfs_port} (persistent)")
        
    def call(self, program, version, procedure, data=b''):
        """Use persistent transport for all calls"""
        if not self.persistent_transport:
            raise RuntimeError("No persistent connection established")
        return self.persistent_transport.call(program, version, procedure, data)
        
    def establish_session(self, minor_version=1):
        """Stabilisce una sessione NFSv4.1+ completa"""
        logging.info(f"Establishing NFSv4.{minor_version} session...")
        self.minor_version = minor_version
        
        try:
            # Create persistent connection for session
            self._create_persistent_connection()
            
            # Step 1: EXCHANGE_ID (per ottenere clientid e sequenceid)
            self.clientid, self.exchange_id_sequenceid = self._exchange_id()
            logging.info(f"Exchange ID successful, clientid: {self.clientid}, sequenceid: {self.exchange_id_sequenceid}")
            
            # Step 2: CREATE_SESSION (usando il sequenceid da EXCHANGE_ID)
            self.session_id = self._create_session()
            logging.info(f"Session created successfully, session_id: {self.session_id}")
            
            self.session_established = True
            return True
            
        except Exception as e:
            logging.error(f"Failed to establish NFSv4.{minor_version} session: {e}")
            return False
    
    def _exchange_id(self):
        """Implementa EXCHANGE_ID per NFSv4.1+"""
        logging.debug("Performing EXCHANGE_ID operation...")
        
        # Build COMPOUND request with EXCHANGE_ID
        operations = []
        
        # EXCHANGE_ID operation (opcode 42)
        operations.append(struct.pack('!I', 42))  # OP_EXCHANGE_ID
        
        # client_owner4 structure per RFC 5661:
        # struct client_owner4 {
        #     verifier4 co_verifier;     // 8 bytes fissi (senza lunghezza)
        #     opaque co_ownerid<>;       // lunghezza + dati + padding
        # };
        co_ownerid = b"NFSv4.1_client_" + str(self.auth_manager.uid).encode()
        co_verifier = struct.pack('!Q', 0x1234567890ABCDEF)  # 8-byte verifier fisso
        
        # Pack client_owner4 correttamente
        exchange_id_data = (
            co_verifier +                                        # co_verifier: 8 bytes diretti
            struct.pack('!I', len(co_ownerid)) + co_ownerid +    # co_ownerid: lunghezza + dati
            self._pad_to_4(co_ownerid)                           # padding XDR
        )
        
        # flags (0 = no flags)
        exchange_id_data += struct.pack('!I', 0)
        
        # state_protect (SP4_NONE = 0)
        exchange_id_data += struct.pack('!I', 0)
        
        # client_impl_id (array length 0 = no implementation info)
        exchange_id_data += struct.pack('!I', 0)
        
        operations.append(exchange_id_data)
        
        # Send compound request (EXCHANGE_ID deve essere l'unica operazione)
        response = self._send_compound(operations, num_operations=1)
        
        # Parse EXCHANGE_ID response
        return self._parse_exchange_id_response(response)
    
    def _create_session(self):
        """Implementa CREATE_SESSION per NFSv4.1+"""
        logging.debug("Performing CREATE_SESSION operation...")
        
        # Build COMPOUND request with CREATE_SESSION
        operations = []
        
        # CREATE_SESSION operation (opcode 43)
        operations.append(struct.pack('!I', 43))  # OP_CREATE_SESSION
        
        # clientid (from EXCHANGE_ID)
        create_session_data = struct.pack('!Q', self.clientid)
        
        # sequenceid (dal EXCHANGE_ID response)
        create_session_data += struct.pack('!I', self.exchange_id_sequenceid)
        
        # flags (0 = no special flags)
        create_session_data += struct.pack('!I', 0)
        
        # fore_chan_attrs (channel attributes) - seguendo PyNFS esatto:
        # channel_attrs4(0, 8192, 8192, 8192, 128, 8, [])
        fore_chan_attrs = (
            struct.pack('!I', 0) +       # ca_headerpadsize = 0
            struct.pack('!I', 8192) +    # ca_maxrequestsize = 8192  
            struct.pack('!I', 8192) +    # ca_maxresponsesize = 8192
            struct.pack('!I', 8192) +    # ca_maxresponsesize_cached = 8192
            struct.pack('!I', 128) +     # ca_maxoperations = 128
            struct.pack('!I', 8) +       # ca_maxrequests = 8
            struct.pack('!I', 0)         # ca_rdma_ird (array length 0)
        )
        create_session_data += fore_chan_attrs
        
        # back_chan_attrs (identico a fore_chan_attrs come in PyNFS)
        create_session_data += fore_chan_attrs
        
        # cb_program (123 come in PyNFS per callback)
        create_session_data += struct.pack('!I', 123)
        
        # sec_parms (array length 1 con callback_sec_parms4(0))
        create_session_data += struct.pack('!I', 1)     # array length = 1
        create_session_data += struct.pack('!I', 0)     # callback_sec_parms4(0) = AUTH_NONE
        
        operations.append(create_session_data)
        
        # Send compound request (CREATE_SESSION deve essere l'unica operazione)
        response = self._send_compound(operations, num_operations=1)
        
        # Parse CREATE_SESSION response
        return self._parse_create_session_response(response)
    
    def get_root_filehandle_with_session(self):
        """Ottiene root filehandle usando la sessione NFSv4.1+"""
        if not self.session_established:
            raise Exception("Session not established - call establish_session() first")
        
        logging.debug("Getting root filehandle with session...")
        
        # Build COMPOUND with SEQUENCE + PUTROOTFH + GETFH
        operations = []
        
        # SEQUENCE operation (required for all NFSv4.1+ operations)
        operations.append(struct.pack('!I', 53))  # OP_SEQUENCE
        
        # SEQUENCE arguments per RFC 5661 - sequenceid deve iniziare da 1 per primi slot usage
        current_seq = 1  # RFC 5661: primo SEQUENCE su slot deve iniziare da 1
        sequence_data = (
            self.session_id +                        # sessionid4 (16 bytes fissi, NO lunghezza)
            struct.pack('!I', current_seq) +         # sequenceid4 (4 bytes) 
            struct.pack('!I', 0) +                   # slotid4 (4 bytes)
            struct.pack('!I', 0) +                   # highest_slotid4 (4 bytes) 
            struct.pack('!I', 1)                     # sa_cachethis bool (4 bytes) = True
        )
        operations.append(sequence_data)
        
        # PUTROOTFH operation
        operations.append(struct.pack('!I', OP_PUTROOTFH))
        
        # GETFH operation
        operations.append(struct.pack('!I', OP_GETFH))
        
        # Send compound request (SEQUENCE + PUTROOTFH + GETFH = 3 operazioni)
        response = self._send_compound(operations, num_operations=3)
        
        # Parse response to get file handle
        return self._parse_getfh_with_session_response(response)
    
    def _send_compound(self, operations, num_operations=None):
        """Invia richiesta COMPOUND NFSv4.1+ usando connessione persistente"""
        if not self.persistent_transport:
            raise RuntimeError("No persistent connection established - call establish_session() first")
        
        # Calculate actual number of operations (operations array ha opcode+data in coppie)
        if num_operations is None:
            num_operations = len(operations) // 2
        
        # Build COMPOUND payload
        payload = (
            struct.pack('!I', 0) +                    # tag length (empty)
            struct.pack('!I', self.minor_version) +   # minor version
            struct.pack('!I', num_operations)         # number of operations (calcolato correttamente)
        )
        
        # Add all operations
        for op in operations:
            payload += op
        
        # Use persistent transport for all operations
        response_data = self.persistent_transport.call(
            program=100003,  # NFS_PROGRAM
            version=4,       # NFSv4
            procedure=1,     # COMPOUND
            data=payload
        )
        
        return response_data
    
    def _parse_exchange_id_response(self, data):
        """Analizza risposta EXCHANGE_ID"""
        try:
            offset = 0
            
            # Parse COMPOUND response header
            status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if status != 0:  # NFS4_OK
                error_name = NFS4_ERROR_CODES.get(status, f"UNKNOWN_ERROR")
                raise Exception(f"EXCHANGE_ID failed: {error_name} ({status})")
            
            # Skip tag
            tag_len = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4 + tag_len + self._pad_len(tag_len)
            
            # Number of operations
            num_ops = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            # Parse EXCHANGE_ID response
            opcode = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            op_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if op_status != 0:
                error_name = NFS4_ERROR_CODES.get(op_status, f"UNKNOWN_ERROR")
                raise Exception(f"EXCHANGE_ID operation failed: {error_name} ({op_status})")
            
            # Extract clientid (8 bytes)
            clientid = struct.unpack('!Q', data[offset:offset+8])[0]
            offset += 8
            
            # Extract sequenceid (4 bytes) - eir_sequenceid per RFC 5661
            sequenceid = struct.unpack('!I', data[offset:offset+4])[0]
            
            return clientid, sequenceid
            
        except Exception as e:
            logging.error(f"Failed to parse EXCHANGE_ID response: {e}")
            raise
    
    def _parse_create_session_response(self, data):
        """Analizza risposta CREATE_SESSION"""
        try:
            offset = 0
            
            # Parse COMPOUND response header
            status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if status != 0:  # NFS4_OK
                error_name = NFS4_ERROR_CODES.get(status, f"UNKNOWN_ERROR")
                raise Exception(f"CREATE_SESSION failed: {error_name} ({status})")
            
            # Skip tag
            tag_len = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4 + tag_len + self._pad_len(tag_len)
            
            # Number of operations
            num_ops = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            # Parse CREATE_SESSION response
            opcode = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            op_status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if op_status != 0:
                error_name = NFS4_ERROR_CODES.get(op_status, f"UNKNOWN_ERROR")
                raise Exception(f"CREATE_SESSION operation failed: {error_name} ({op_status})")
            
            # Extract session ID (sempre 16 bytes fissi per RFC 5661)
            session_id = data[offset:offset+16]
            
            return session_id
            
        except Exception as e:
            logging.error(f"Failed to parse CREATE_SESSION response: {e}")
            raise
    
    def _parse_getfh_with_session_response(self, data):
        """Analizza risposta GETFH con sessione"""
        try:
            offset = 0
            
            # Parse COMPOUND response header
            status = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            if status != 0:  # NFS4_OK
                error_name = NFS4_ERROR_CODES.get(status, f"UNKNOWN_ERROR")
                raise Exception(f"COMPOUND with session failed: {error_name} ({status})")
            
            # Skip tag
            tag_len = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4 + tag_len + self._pad_len(tag_len)
            
            # Number of operations
            num_ops = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            
            # Parse each operation response
            filehandle = None
            
            for i in range(num_ops):
                opcode = struct.unpack('!I', data[offset:offset+4])[0]
                offset += 4
                
                op_status = struct.unpack('!I', data[offset:offset+4])[0]
                offset += 4
                
                if op_status != 0:
                    error_name = NFS4_ERROR_CODES.get(op_status, f"UNKNOWN_ERROR")
                    raise Exception(f"Operation {opcode} failed: {error_name} ({op_status})")
                
                # Handle specific operations
                if opcode == 53:  # OP_SEQUENCE
                    # Skip SEQUENCE response data per RFC 5661
                    # sessionid (16 bytes fissi), sequenceid (4), slotid (4), highest_slotid (4), target_highest_slotid (4), status_flags (4)
                    offset += 16  # sessionid4 sempre 16 bytes fissi
                    offset += 20  # sequenceid + slotid + highest_slotid + target_highest_slotid + status_flags
                    
                elif opcode == OP_PUTROOTFH:  # PUTROOTFH
                    # No response data for PUTROOTFH
                    pass
                    
                elif opcode == OP_GETFH:  # GETFH
                    # Extract file handle
                    fh_len = struct.unpack('!I', data[offset:offset+4])[0]
                    offset += 4
                    
                    filehandle = data[offset:offset+fh_len]
                    offset += fh_len + self._pad_len(fh_len)
            
            if filehandle is None:
                raise Exception("No file handle found in response")
            
            return filehandle
            
        except Exception as e:
            logging.error(f"Failed to parse GETFH with session response: {e}")
            raise
    
    def _pad_to_4(self, data):
        """Aggiungi padding XDR a 4 byte"""
        pad_len = (4 - (len(data) % 4)) % 4
        return b'\0' * pad_len
    
    def _pad_len(self, length):
        """Calcola lunghezza padding XDR"""
        return (4 - (length % 4)) % 4

def test_nfsv4_session():
    """Test del session manager"""
    logging.basicConfig(level=logging.DEBUG)
    
    # Configurazione test
    target = "10.10.10.180"
    auth = AuthManager(hostname="nfsclient", uid=2017, gid=33)
    
    # Crea session manager
    session_mgr = NFSv4SessionManager(
        target_host=target,
        nfs_port=2049,
        auth_manager=auth
    )
    
    try:
        # Testa stabilimento sessione
        if session_mgr.establish_session(minor_version=1):
            print("✅ Sessione NFSv4.1 stabilita con successo")
            
            # Testa ottenimento root filehandle
            root_fh = session_mgr.get_root_filehandle_with_session()
            print(f"✅ Root filehandle ottenuto: {root_fh.hex()}")
            
        else:
            print("❌ Fallimento stabilimento sessione")
            
    except Exception as e:
        print(f"❌ Errore test: {e}")

if __name__ == "__main__":
    test_nfsv4_session()
