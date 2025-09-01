import argparse
import logging
import sys
import os
from client.nfs_client_factory import create_nfs_client, get_nfs_capabilities
from client.bruteforce import BruteForceManager


def configure_logging(verbosity):
    """Configure logging based on verbosity level"""
    level = logging.DEBUG if verbosity else logging.INFO
    logging.basicConfig(
        format='[%(levelname)s] %(message)s', 
        level=level,
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="NFSwalker is a User-space NFS client with SOCKS proxy support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.100 ls / --nfs-version 4 --portnfs 2049 --export /site_backups
  %(prog)s 192.168.1.100 read /file.txt --nfs-version 4 --portnfs 2049 --export /site_backups
  %(prog)s 192.168.1.100 write /remote/file.txt --file local_file.txt --export /site_backups
  %(prog)s 192.168.1.100 perms / --export /site_backups --nfs-version 4 --portnfs 2049 --os windows
  %(prog)s 192.168.1.100 ls /somedir --socks 172.x.x.x:9050 --export /site_backups --nfs-version 4 --portnfs 2049 
  %(prog)s 192.168.1.100 bruteforce --uid-range 1-2000 --gid-range 1-100 --export /site_backups --nfs-version 4 --portnfs 2049 
  %(prog)s 192.168.1.100 bruteforce --uid-range 2016-2019 --gid-range 31-33 --sleep 0.5 --priv --export /site_backups --nfs-version 4 --portnfs 2049 
  sudo %(prog)s 192.168.1.100 write /file.txt --file local.txt --priv --export /site_backups --nfs-version 4 --portnfs 2049 
        """
    )

    # Target and basic options
    parser.add_argument("target", help="NFS server IP or hostname")
    parser.add_argument("command", 
                       choices=["ls", "read", "write", "perms", "bruteforce"], 
                       help="Command to execute")
    parser.add_argument("path", nargs="?", 
                       help="Path for ls/read/write/perms operations")

    # NFS configuration
    parser.add_argument("--export", 
                       help="NFS export path (default: /)", 
                       default="/")
    parser.add_argument("--nfs-version", 
                       choices=["2 - NOT IMPLEMENTED YET", "3", "4"], 
                       default="3",
                       help="NFS version to use (default: 3)")
    parser.add_argument("--portnfs", 
                       type=int, 
                       default=2049,
                       help="NFS service port (default: 2049)")
    parser.add_argument("--portmnt", 
                       type=int, 
                       default=2049,
                       help="Mount service port (default: 2049)")
    parser.add_argument("--rpcport", 
                       type=int, 
                       default=111,
                       help="RPC Portmapper port (default: 111)")
    
    # RPC Program Numbers
    parser.add_argument("--nfs-program", 
                       type=int, 
                       default=100003,
                       help="NFS RPC program number (default: 100003)")
    parser.add_argument("--mount-program", 
                       type=int, 
                       default=100005,
                       help="Mount RPC program number (default: 100005)")
    parser.add_argument("--pmap-program", 
                       type=int, 
                       default=100000,
                       help="Portmapper RPC program number (default: 100000)")
    parser.add_argument("--hostname", 
                       help="Hostname to spoof (default: localhost)",
                       default="localhost")

    # Proxy configuration
    parser.add_argument("--socks", 
                       help="SOCKS proxy in format host:port (e.g., 127.0.0.1:9050)")
    parser.add_argument("--proxy-type", 
                       choices=["socks4", "socks5", "direct"], 
                       default="socks5",
                       help="Proxy type (default: socks5)")

    # Authentication
    #parser.add_argument("--user", 
    #                   help="Username for authentication")
    #parser.add_argument("--psw", 
    #                   help="Password for authentication")
    parser.add_argument("--uid", 
                       type=int, 
                       default=65534,
                       help="User ID for AUTH_UNIX (default: 65534)")
    parser.add_argument("--gid", 
                       type=int, 
                       default=65534,
                       help="Group ID for AUTH_UNIX (default: 65534)")
    parser.add_argument("--gids", 
                       help="Additional group IDs (comma-separated)")

    # Brute force options
    parser.add_argument("--bruteforce", 
                       action="store_true",
                       help="Enable brute force mode to guess valid credentials")
    parser.add_argument("--uid-range", 
                       default="1-2000",
                       help="UID range for brute force (default: 1-2000)")
    parser.add_argument("--gid-range", 
                       default="1-100",
                       help="GID range for brute force (default: 1-100)")
    parser.add_argument("--threads", 
                       type=int, 
                       default=10,
                       help="Number of threads for brute force (default: 10)")
    parser.add_argument("--sleep", 
                       type=float, 
                       default=2.0,
                       help="Sleep time in seconds between bruteforce attempts (default: 2.0)")

    # Write operation options
    parser.add_argument("--file", 
                       help="Local file to upload (required for write command)")
    parser.add_argument("--chunk-size", 
                       type=int, 
                       default=8192,
                       help="Chunk size for large operations (default: 8192)")

    # General options
    parser.add_argument("-v", "--verbose", 
                       action="store_true",
                       help="Enable verbose debug output")
    parser.add_argument("--timeout", 
                       type=int, 
                       default=10,
                       help="Connection timeout in seconds (default: 10)")
    parser.add_argument("--os", 
                      choices=["linux", "windows"], 
                      default="linux",
                      help="Target NFS server OS type (default: linux)")
    parser.add_argument("--priv", 
                       action="store_true",
                       help="Use privileged ports (<1024) to bypass root squashing")

    return parser.parse_args()


def validate_args(args):
    """Validate command line arguments"""
    # Check if --priv requires root privileges
    if args.priv:
        #import os
        if os.getuid() != 0:
            logging.error("--priv requires root privileges. Run with sudo.")
            sys.exit(1)
    
    if args.command in ["read", "write", "perms"] and not args.path:
        logging.error("Path is required for read/write/perms operations")
        sys.exit(1)
    
    if args.command == "write":
        if not args.file:
            logging.error("--file is required for write operations")
            sys.exit(1)
        if not os.path.exists(args.file):
            logging.error(f"Local file not found: {args.file}")
            sys.exit(1)
    
    if args.socks:
        try:
            host, port = args.socks.split(':')
            args.proxy_host = host
            args.proxy_port = int(port)
        except ValueError:
            logging.error("Invalid SOCKS proxy format. Use host:port")
            sys.exit(1)
    else:
        args.proxy_host = None
        args.proxy_port = None
        args.proxy_type = "direct"
    
    if args.gids:
        try:
            args.gids = [int(gid.strip()) for gid in args.gids.split(',')]
        except ValueError:
            logging.error("Invalid GIDs format. Use comma-separated integers")
            sys.exit(1)
    else:
        args.gids = []


def main():
    """Main entry point"""
    args = parse_args()
    validate_args(args)
    configure_logging(args.verbose)
    
    logging.info(f"Connecting to {args.target}")
    
    # Show configuration
    nfs_version = int(args.nfs_version)
    logging.info(f"[CONFIG] NFS Program: {args.nfs_program}")
    logging.info(f"[CONFIG] Mount Program: {args.mount_program}")
    logging.info(f"[CONFIG] Portmapper Program: {args.pmap_program}")
    logging.info(f"[CONFIG] RPC Port: {args.rpcport}")
    logging.info(f"[CONFIG] NFS Port: {args.portnfs}")
    logging.info(f"[CONFIG] Mount Port: {args.portmnt}")
    
    # Show NFS version capabilities
    capabilities = get_nfs_capabilities(nfs_version)
    if capabilities:
        logging.info(f"[VERSION] Using NFS v{nfs_version}: {capabilities.get('description', '')}")
        if nfs_version == 4:
            logging.info("[NFSv4] ")
        elif nfs_version == 3:
            logging.info("[NFSv3] ")
        elif nfs_version == 2:
            logging.info("[NFSv2] ")
    
    # Create appropriate NFS client based on version
    client = create_nfs_client(
        target_host=args.target,
        export_path=args.export,
        proxy_type=args.proxy_type,
        proxy_host=args.proxy_host,
        proxy_port=args.proxy_port,
        nfs_version=nfs_version,
        nfs_port=args.portnfs,
        mount_port=args.portmnt,
        nfs_program=args.nfs_program,
        mount_program=args.mount_program,
        hostname=args.hostname,
        uid=args.uid,
        gid=args.gid,
        gids=args.gids,
        timeout=args.timeout,
        chunk_size=args.chunk_size,
        use_privileged_ports=args.priv
    )
    
    # DEBUG: Show which client type was created
    client_type = type(client).__name__
    logging.info(f"[DEBUG] Factory returned client type: {client_type}")
    if hasattr(client, 'session_manager'):
        logging.info(f"[DEBUG] Client has session_manager: {client.session_manager is not None}")
    if hasattr(client, 'minor_version'):
        logging.info(f"[DEBUG] Client minor_version: {getattr(client, 'minor_version', 'Not set')}")
    if hasattr(client, 'connected'):
        logging.info(f"[DEBUG] Client connected status: {getattr(client, 'connected', 'Not set')}")
    
    try:
        if args.command == "bruteforce":
            # Brute force mode
            bf_manager = BruteForceManager(
                client=client,
                uid_range=args.uid_range,
                gid_range=args.gid_range,
                threads=args.threads,
                sleep_time=args.sleep
            )
            results = bf_manager.run()
            
            print("\n=== BRUTE FORCE RESULTS ===")
            if results['successful']:
                print(f"Found {len(results['successful'])} working combinations:")
                for result in results['successful']:
                    print(f"  UID: {result['uid']}, GID: {result['gid']}, "
                          f"GIDs: {result['gids']}, Access: {result['access']}")
            else:
                print("No working combinations found")
                
        else:
            # Normal operation mode
            # DEBUG: Show client type before connect
            client_type = type(client).__name__
            logging.info(f"[DEBUG] About to call connect() on client type: {client_type}")
            
            client.connect()
            
            # DEBUG: Show client state after connect
            logging.info(f"[DEBUG] After connect() - client type: {client_type}")
            if hasattr(client, 'connected'):
                logging.info(f"[DEBUG] Client connected status: {getattr(client, 'connected', 'Not set')}")
            if hasattr(client, 'session_id'):
                session_id = getattr(client, 'session_id', None)
                if session_id:
                    logging.info(f"[DEBUG] Client has session_id: {session_id.hex() if isinstance(session_id, bytes) else session_id}")
                else:
                    logging.info(f"[DEBUG] Client session_id: None")
            
            if args.command == "ls":
                path = args.path if args.path else "/"
                try:
                    entries = client.readdir(path)
                    print(f"\nDirectory listing for '{path}':")
                    print("-" * 60)
                    for entry in entries:
                        # Handle different entry formats between NFS versions
                        fileid = entry.get('fileid', 0)  # Default to 0 for NFSv4
                        name = entry.get('name', 'unknown')
                        print(f"{fileid:016x}  {name}")
                except Exception as e:
                    logging.error(f"Failed to list directory: {e}")
                    sys.exit(1)
                    
            elif args.command == "read":
                try:
                    content = client.read_file(args.path)
                    print(content.decode('utf-8', errors='replace'))
                except Exception as e:
                    logging.error(f"Failed to read file: {e}")
                    sys.exit(1)
                    
            elif args.command == "write":
                try:
                    with open(args.file, 'rb') as f:
                        data = f.read()
                    
                    print(f"Uploading {args.file} ({len(data)} bytes) to {args.path}")
                    success = client.write_file(args.path, data)
                    if success:
                        print(f"Successfully uploaded {args.file} to {args.path}")
                    else:
                        print(f"Failed to upload {args.file} to {args.path}")
                        sys.exit(1)
                except Exception as e:
                    logging.error(f"Failed to write file: {e}")
                    sys.exit(1)
                    
            elif args.command == "perms":
                try:
                    # DEBUG: Show client type before perms command
                    client_type = type(client).__name__
                    logging.info(f"[DEBUG] Executing perms command with client type: {client_type}")
                    if hasattr(client, 'session_id'):
                        session_id = getattr(client, 'session_id', None)
                        if session_id:
                            logging.info(f"[DEBUG] Using session_id: {session_id.hex() if isinstance(session_id, bytes) else session_id}")
                        else:
                            logging.info(f"[DEBUG] No session_id available")
                    
                    print(f"\nChecking permissions for: {args.path}")
                    print("=" * 60)
                    
                    # Get file attributes
                    attrs = client.getattr(args.path)
                    print(f"File type: {attrs['type']}")
                    print(f"Mode: 0{attrs['mode']:o}")
                    
                    # Check if we're using NFSv4.1 client for owner format
                    is_nfsv41 = type(client).__name__ == 'NFSv41Client'
                    
                    if is_nfsv41:
                        # NFSv4.1 RFC 5661: FATTR4_OWNER and FATTR4_OWNER_GROUP (UTF-8 strings)
                        if args.os == 'windows':
                            # Windows format: parse user@domain or fallback to string
                            owner = attrs['owner']
                            owner_group = attrs['owner_group']
                            print(f"Owner: {owner}")
                            print(f"Owner Group: {owner_group}")
                        else:
                            # Linux format: expect numeric strings that can be converted
                            try:
                                uid = int(attrs['owner'])
                                gid = int(attrs['owner_group'])
                                print(f"UID: {uid}")
                                print(f"GID: {gid}")
                            except ValueError:
                                # Fallback if not numeric
                                print(f"Owner: {attrs['owner']}")
                                print(f"Owner Group: {attrs['owner_group']}")
                    else:
                        # NFSv3/NFSv4.0: uid/gid (integers)
                        print(f"UID: {attrs['uid']}")
                        print(f"GID: {attrs['gid']}")
                    
                    # Display ACL information for NFSv4.1 if available
                    if is_nfsv41 and 'acl' in attrs and attrs['acl']:
                        print(f"\nAccess Control List (ACL):")
                        print("=" * 40)
                        for i, ace in enumerate(attrs['acl']):
                            print(f"ACE {i+1}:")
                            print(f"  Type: {ace['type']}")
                            print(f"  Principal: {ace['principal']}")
                            print(f"  Access: {ace['access']}")
                            print()
                    
                    # Check access permissions
                    access_mask = 0x3F  # All permissions
                    access_result = client.check_access(args.path, access_mask)
                    
                    # Check if we're using NFSv4.1 client
                    is_nfsv41 = type(client).__name__ == 'NFSv41Client'
                    
                    if is_nfsv41:
                        # NFSv4.1 format: {'supported': X, 'access': Y, 'requested': Z}
                        granted = access_result['access']
                        supported = access_result['supported']
                        requested = access_result['requested']
                        
                        print(f"\nAccess check results:")
                        print(f"Requested: 0x{requested:02x} (all permissions)")
                        print(f"Supported: 0x{supported:02x}")
                        print(f"Granted:   0x{granted:02x}")
                    else:
                        # NFSv3/NFSv4.0 format: integer
                        granted = access_result
                        print(f"\nAccess check results:")
                        print(f"Requested: 0x{access_mask:02x} (all permissions)")
                        print(f"Granted:   0x{granted:02x}")
                    
                    print(f"\nPermission breakdown:")
                    print(f"READ:    {'✓' if granted & 0x01 else '✗'}")
                    print(f"LOOKUP:  {'✓' if granted & 0x02 else '✗'}")
                    print(f"MODIFY:  {'✓' if granted & 0x04 else '✗'}")
                    print(f"EXTEND:  {'✓' if granted & 0x08 else '✗'}")
                    print(f"DELETE:  {'✓' if granted & 0x10 else '✗'}")
                    print(f"EXECUTE: {'✓' if granted & 0x20 else '✗'}")
                    
                    # Interpret results
                    if granted & 0x04 or granted & 0x08:  # MODIFY or EXTEND
                        print(f"\n🟢 WRITABLE: Path appears to be writable")
                    else:
                        print(f"\n🔴 READ-ONLY: Path appears to be read-only")
                        
                except Exception as e:
                    logging.error(f"Failed to check permissions: {e}")
                    sys.exit(1)
                    
    except KeyboardInterrupt:
        logging.info("Operation interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
