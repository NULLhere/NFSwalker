"""
NFSv4 Response Parser - PyNFS-style implementation
"""

import struct
import xdrlib
import logging

class COMPOUND4res:
    """NFSv4 COMPOUND response structure"""
    def __init__(self, status, tag, resarray):
        self.status = status
        self.tag = tag
        self.resarray = resarray

class nfs_resop4:
    """NFSv4 operation result"""
    def __init__(self, resop, result):
        self.resop = resop  # operation code
        self.result = result  # operation-specific result

class OPEN4resok:
    """NFSv4 OPEN success result"""
    def __init__(self, stateid, cinfo, rflags, attrset, delegation):
        self.stateid = stateid
        self.cinfo = cinfo
        self.rflags = rflags
        self.attrset = attrset
        self.delegation = delegation

class change_info4:
    """NFSv4 change info structure"""
    def __init__(self, atomic, before, after):
        self.atomic = atomic
        self.before = before
        self.after = after

class PyNFSUnpacker(xdrlib.Unpacker):
    """PyNFS-style unpacker for NFSv4 responses"""
    
    def __init__(self, data):
        super().__init__(data)
    
    def unpack_COMPOUND4res(self):
        """Unpack COMPOUND4 response like PyNFS"""
        # 1. Status
        status = self.unpack_uint()
        
        # 2. Tag (opaque string)
        tag = self.unpack_opaque()
        
        # 3. Results array
        resarray_count = self.unpack_uint()
        resarray = []
        
        for i in range(resarray_count):
            # Each result has: opcode + status + operation-specific data
            opcode = self.unpack_uint()
            op_status = self.unpack_uint()
            
            # Create operation result
            op_result = {'opcode': opcode, 'status': op_status}
            
            # Parse operation-specific data based on status
            if op_status == 0:  # NFS4_OK
                if opcode == 22:  # OP_PUTFH
                    # PUTFH has no additional data on success
                    pass
                elif opcode == 18:  # OP_OPEN
                    op_result['open_result'] = self.unpack_OPEN4resok()
                elif opcode == 10:  # OP_GETFH
                    # File handle
                    fh_len = self.unpack_uint()
                    fh_data = self.unpack_fopaque(fh_len)
                    op_result['filehandle'] = fh_data
                elif opcode == 2:   # OP_ACCESS
                    supported = self.unpack_uint()
                    access = self.unpack_uint()
                    op_result['access_result'] = {'supported': supported, 'access': access}
                elif opcode == 4:   # OP_CLOSE
                    # stateid4
                    stateid = self.unpack_fstring(16)
                    op_result['stateid'] = stateid
                elif opcode == 25:  # OP_READ
                    eof = self.unpack_bool()
                    data_len = self.unpack_uint()
                    data = self.unpack_fopaque(data_len)
                    op_result['read_result'] = {'eof': eof, 'data': data}
                elif opcode == 38:  # OP_WRITE
                    count = self.unpack_uint()
                    committed = self.unpack_uint()
                    verf = self.unpack_fstring(8)
                    op_result['write_result'] = {'count': count, 'committed': committed, 'verf': verf}
            
            resarray.append(op_result)
        
        return COMPOUND4res(status, tag, resarray)
    
    def unpack_OPEN4resok(self):
        """Unpack OPEN4 success result"""
        # stateid4 (16 bytes)
        stateid = self.unpack_fstring(16)
        
        # change_info4
        atomic = self.unpack_bool()
        before = self.unpack_uhyper()
        after = self.unpack_uhyper()
        cinfo = change_info4(atomic, before, after)
        
        # rflags
        rflags = self.unpack_uint()
        
        # attrset (bitmap4)
        bitmap_len = self.unpack_uint()
        attrset = []
        for i in range(bitmap_len):
            attrset.append(self.unpack_uint())
        
        # delegation (union)
        delegation_type = self.unpack_uint()
        delegation = {'type': delegation_type}
        
        if delegation_type == 1:  # OPEN_DELEGATE_READ
            # Read delegation data would be here
            pass
        elif delegation_type == 2:  # OPEN_DELEGATE_WRITE  
            # Write delegation data would be here
            pass
        # OPEN_DELEGATE_NONE (0) has no additional data
        
        return OPEN4resok(stateid, cinfo, rflags, attrset, delegation)

def parse_nfsv4_response(response_data, rpc_offset):
    """
    Parse NFSv4 COMPOUND response using PyNFS-style unpacker
    
    :param response_data: Raw response bytes
    :param rpc_offset: Offset where NFSv4 data starts (after RPC header)
    :return: Parsed COMPOUND4res object
    """
    nfs_data = response_data[rpc_offset:]
    unpacker = PyNFSUnpacker(nfs_data)
    
    try:
        result = unpacker.unpack_COMPOUND4res()
        unpacker.done()
        return result
    except Exception as e:
        logging.error(f"Failed to parse NFSv4 response: {e}")
        raise