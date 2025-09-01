"""
NFS client factory for automatic version selection
"""

import logging
from .nfs_client import NFSClient
from .nfsv4_client import NFSv4Client
from .nfsv41_client import NFSv41Client

def create_nfs_client(target_host, export_path="/", proxy_type="direct",
                     proxy_host=None, proxy_port=None, nfs_version=3,
                     nfs_port=2049, mount_port=2049, nfs_program=100003,
                     mount_program=100005, hostname=None, uid=None,
                     gid=None, gids=None, timeout=10, chunk_size=8192,
                     use_privileged_ports=False):
    """
    Factory function to create appropriate NFS client based on version
    
    :param target_host: NFS server hostname or IP
    :param export_path: NFS export path
    :param proxy_type: proxy type (direct, socks4, socks5)
    :param proxy_host: proxy host
    :param proxy_port: proxy port  
    :param nfs_version: NFS version (2, 3, 4)
    :param nfs_port: NFS service port
    :param mount_port: Mount service port
    :param nfs_program: NFS RPC program number
    :param mount_program: Mount RPC program number
    :param hostname: hostname for authentication
    :param uid: user ID
    :param gid: group ID
    :param gids: additional group IDs
    :param timeout: connection timeout
    :param chunk_size: chunk size for large operations
    :param use_privileged_ports: use privileged ports (<1024) for connections
    :return: appropriate NFS client instance
    """
    
    logging.info(f"Creating NFS client (version {nfs_version})")
    
    if nfs_version == 4:
        # NFSv4 client with automatic version detection
        logging.info("Using NFSv4 client with COMPOUND operations")
        
        # Try NFSv4.0 first, then auto-detect if NFSv4.1+ needed
        try:
            client = NFSv4Client(
                target_host=target_host,
                export_path=export_path,
                proxy_type=proxy_type,
                proxy_host=proxy_host,
                proxy_port=proxy_port,
                nfs_port=nfs_port,
                nfs_program=nfs_program,
                hostname=hostname,
                uid=uid,
                gid=gid,
                gids=gids,
                timeout=timeout,
                chunk_size=chunk_size,
                use_privileged_ports=use_privileged_ports
            )
            
            # Test connection to determine if NFSv4.1+ needed
            try:
                client.connect()
                # Check if NFSv4Client established sessions internally
                if hasattr(client, 'session_manager') and client.session_manager is not None:
                    logging.info("NFSv4Client used sessions internally, switching to dedicated NFSv41Client")
                    # Create dedicated NFSv41Client for better session handling
                    nfsv41_client = NFSv41Client(
                        target_host=target_host,
                        export_path=export_path,
                        proxy_type=proxy_type,
                        proxy_host=proxy_host,
                        proxy_port=proxy_port,
                        nfs_port=nfs_port,
                        nfs_program=nfs_program,
                        hostname=hostname,
                        uid=uid,
                        gid=gid,
                        gids=gids,
                        timeout=timeout,
                        chunk_size=chunk_size,
                        use_privileged_ports=use_privileged_ports
                    )
                    # Connect the NFSv4.1 client
                    nfsv41_client.connect()
                    return nfsv41_client
                else:
                    return client
            except Exception as e:
                logging.debug(f"NFSv4Client connection failed with: {str(e)}")
                if "UNKNOWN_ERROR (10071)" in str(e) or "NFS4ERR_OP_NOT_IN_SESSION" in str(e):
                    # NFSv4.1+ session required
                    logging.info("NFSv4.1+ session required, switching to NFSv41Client")
                    nfsv41_client = NFSv41Client(
                        target_host=target_host,
                        export_path=export_path,
                        proxy_type=proxy_type,
                        proxy_host=proxy_host,
                        proxy_port=proxy_port,
                        nfs_port=nfs_port,
                        nfs_program=nfs_program,
                        hostname=hostname,
                        uid=uid,
                        gid=gid,
                        gids=gids,
                        timeout=timeout,
                        chunk_size=chunk_size,
                        use_privileged_ports=use_privileged_ports
                    )
                    # Connect the NFSv4.1 client
                    nfsv41_client.connect()
                    return nfsv41_client
                else:
                    # Other error, re-raise
                    raise
                    
        except Exception as e:
            # If all fails, try NFSv41Client directly
            logging.info("Trying NFSv41Client as fallback")
            nfsv41_client = NFSv41Client(
                target_host=target_host,
                export_path=export_path,
                proxy_type=proxy_type,
                proxy_host=proxy_host,
                proxy_port=proxy_port,
                nfs_port=nfs_port,
                nfs_program=nfs_program,
                hostname=hostname,
                uid=uid,
                gid=gid,
                gids=gids,
                timeout=timeout,
                chunk_size=chunk_size,
                use_privileged_ports=use_privileged_ports
            )
            # Connect the NFSv4.1 client
            nfsv41_client.connect()
            return nfsv41_client
    
    elif nfs_version in [2, 3]:
        # NFSv2/v3 client (existing implementation)
        logging.info(f"Using NFSv{nfs_version} client with traditional RPC")
        return NFSClient(
            target_host=target_host,
            export_path=export_path,
            proxy_type=proxy_type,
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            nfs_version=nfs_version,
            nfs_port=nfs_port,
            mount_port=mount_port,
            nfs_program=nfs_program,
            mount_program=mount_program,
            hostname=hostname,
            uid=uid,
            gid=gid,
            gids=gids,
            timeout=timeout,
            chunk_size=chunk_size,
            use_privileged_ports=use_privileged_ports
        )
    
    else:
        raise ValueError(f"Unsupported NFS version: {nfs_version}")

def get_nfs_capabilities(nfs_version):
    """
    Get capabilities for a specific NFS version
    
    :param nfs_version: NFS version (2, 3, 4)
    :return: dict with capability information
    """
    
    capabilities = {
        2: {
            'mount_protocol': True,
            'compound_operations': False,
            'stateful': False,
            'file_locking': False,
            'acls': False,
            'create_file': True,
            'remove_file': True,
            'write_file': True,
            'read_file': True,
            'readdir': True,
            'getattr': True,
            'setattr': True,
            'access_check': False,
            'max_file_size': '2GB',
            'description': 'NFSv2 with basic file operations'
        },
        
        3: {
            'mount_protocol': True,
            'compound_operations': False,
            'stateful': False,
            'file_locking': False,
            'acls': False,
            'create_file': True,
            'remove_file': True,
            'write_file': True,
            'read_file': True,
            'readdir': True,
            'getattr': True,
            'setattr': True,
            'access_check': True,
            'max_file_size': '8EB',
            'description': 'NFSv3 with extended features and better performance'
        },
        
        4: {
            'mount_protocol': False,
            'compound_operations': True,
            'stateful': True,
            'file_locking': True,
            'acls': True,
            'create_file': True,
            'remove_file': True,
            'write_file': True,
            'read_file': True,
            'readdir': True,
            'getattr': True,
            'setattr': True,
            'access_check': True,
            'max_file_size': '8EB',
            'delegation': True,
            'security': 'Enhanced (Kerberos, LIPKEY)',
            'description': 'NFSv4 with stateful operations, compound procedures, and enhanced security'
        }
    }
    
    return capabilities.get(nfs_version, {})

def compare_nfs_versions():
    """
    Compare features across NFS versions
    
    :return: comparison matrix
    """
    
    comparison = {
        'feature': [
            'Mount Protocol Required',
            'Compound Operations',
            'Stateful Protocol', 
            'File Locking',
            'ACL Support',
            'Max File Size',
            'Network Efficiency',
            'Security Features',
            'Error Recovery'
        ],
        
        'nfsv2': [
            'Yes',
            'No',
            'No',
            'No',
            'No',
            '2GB',
            'Basic',
            'AUTH_UNIX only',
            'Limited'
        ],
        
        'nfsv3': [
            'Yes',
            'No',
            'No',
            'No',
            'No',
            '8EB',
            'Good',
            'AUTH_UNIX only',
            'Better'
        ],
        
        'nfsv4': [
            'No',
            'Yes',
            'Yes',
            'Yes',
            'Yes',
            '8EB',
            'Excellent',
            'Kerberos, LIPKEY',
            'Advanced'
        ]
    }
    
    return comparison

def recommend_nfs_version(use_case):
    """
    Recommend NFS version based on use case
    
    :param use_case: use case description
    :return: recommended version and reasoning
    """
    
    recommendations = {
        'penetration_testing': {
            'version': 3,
            'reason': 'Better compatibility with older systems, simpler authentication bypass'
        },
        
        'modern_deployment': {
            'version': 4,
            'reason': 'Enhanced security, better performance, advanced features'
        },
        
        'legacy_compatibility': {
            'version': 2,
            'reason': 'Maximum compatibility with very old systems'
        },
        
        'high_security': {
            'version': 4,
            'reason': 'Kerberos authentication, ACLs, delegation'
        },
        
        'simple_file_sharing': {
            'version': 3,
            'reason': 'Good balance of features and simplicity'
        }
    }
    
    return recommendations.get(use_case.lower(), {
        'version': 3,
        'reason': 'General purpose - good balance of compatibility and features'
    })
