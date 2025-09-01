"""
SOCKS proxy socket implementation
"""

import socks
import socket
import logging
import platform


class ProxySocket:
    """
    Wrapper for socket connections through SOCKS proxy
    """
    
    def __init__(self, target_host, target_port,
                 proxy_host=None, proxy_port=None,
                 proxy_type="socks5", timeout=10, use_privileged_port=False):
        """
        Initialize proxy socket
        
        :param target_host: final destination host
        :param target_port: final destination port
        :param proxy_host: SOCKS proxy host (optional)
        :param proxy_port: SOCKS proxy port
        :param proxy_type: proxy type (socks4, socks5, direct)
        :param timeout: connection timeout in seconds
        :param use_privileged_port: use privileged source port (<1024)
        """
        self.target_host = target_host
        self.target_port = target_port
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_type = proxy_type.lower()
        self.timeout = timeout
        self.use_privileged_port = use_privileged_port
        self.sock = None
        self.bound_port = None  # Track bound port for debugging
        
    def connect(self):
        """
        Establish connection through proxy or direct
        
        :return: connected socket object
        """
        logging.debug(f"Connecting to {self.target_host}:{self.target_port} "
                     f"via {self.proxy_type}")
        
        try:
            if self.proxy_type in ["socks5", "socks4"]:
                if not self.proxy_host or not self.proxy_port:
                    raise ValueError("Proxy host and port required for SOCKS connection")
                
                proxy_type_enum = socks.SOCKS5 if self.proxy_type == "socks5" else socks.SOCKS4
                self.sock = socks.socksocket()
                self.sock.set_proxy(proxy_type_enum, self.proxy_host, self.proxy_port)
                
                logging.debug(f"Using {self.proxy_type.upper()} proxy at "
                             f"{self.proxy_host}:{self.proxy_port}")
                
            else:
                # Direct connection
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                logging.debug("Using direct connection")
            
            # Set timeout
            self.sock.settimeout(self.timeout)
            
            # Bind to privileged port if requested (only for direct connections)
            if self.use_privileged_port and self.proxy_type == "direct":
                self._bind_privileged_port()
            
            # Connect to target
            self.sock.connect((self.target_host, self.target_port))
            
            # Get actual source port used
            if not self.bound_port:
                try:
                    local_address = self.sock.getsockname()
                    self.bound_port = local_address[1]
                except:
                    self.bound_port = "UNKNOWN"
            
            logging.info(f"Successfully connected to {self.target_host}:{self.target_port}")
            return self.sock
            
        except Exception as e:
            logging.error(f"Connection failed: {e}")
            if self.sock:
                try:
                    self.sock.close()
                except:
                    pass
                self.sock = None
            raise
    
    def close(self):
        """
        Close the socket connection
        """
        if self.sock:
            try:
                self.sock.close()
                logging.debug("Socket closed")
            except Exception as e:
                logging.warning(f"Error closing socket: {e}")
            finally:
                self.sock = None
    
    def is_connected(self):
        """
        Check if socket is connected
        
        :return: True if connected, False otherwise
        """
        return self.sock is not None
    
    def _bind_privileged_port(self):
        """
        Bind socket to a privileged port (<1024) to bypass root squashing
        """
        import os
        
        # Check if running as root
        if os.getuid() != 0:
            logging.warning("Cannot bind to privileged port: not running as root")
            return
        
        # Try to bind to a privileged port (512-1023)
        for port in range(512, 1024):
            try:
                self.sock.bind(('', port))
                logging.info(f"Bound to privileged port {port}")
                # Store the port for debugging
                self.bound_port = port
                return
            except OSError:
                continue
        
        # If no privileged port is available, continue without binding
        logging.warning("No privileged ports available, continuing with default port assignment")
    
    def get_socket(self):
        """
        Get the underlying socket object
        
        :return: socket object
        """
        return self.sock
    
    def __enter__(self):
        """
        Context manager entry
        
        :return: connected socket
        """
        return self.connect()
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Context manager exit
        """
        self.close()


class ProxySocketManager:
    """
    Manages multiple proxy socket connections
    """
    
    def __init__(self, target_host, proxy_host=None, proxy_port=None,
                 proxy_type="socks5", timeout=10):
        """
        Initialize proxy socket manager
        
        :param target_host: target host
        :param proxy_host: proxy host
        :param proxy_port: proxy port
        :param proxy_type: proxy type
        :param timeout: connection timeout
        """
        self.target_host = target_host
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_type = proxy_type
        self.timeout = timeout
        self.connections = {}
    
    def get_connection(self, port):
        """
        Get or create a connection to a specific port
        
        :param port: target port
        :return: ProxySocket instance
        """
        if port not in self.connections:
            self.connections[port] = ProxySocket(
                target_host=self.target_host,
                target_port=port,
                proxy_host=self.proxy_host,
                proxy_port=self.proxy_port,
                proxy_type=self.proxy_type,
                timeout=self.timeout
            )
        
        return self.connections[port]
    
    def close_all(self):
        """
        Close all managed connections
        """
        for connection in self.connections.values():
            connection.close()
        self.connections.clear()
    
    def test_connection(self, port):
        """
        Test connection to a specific port
        
        :param port: target port
        :return: True if connection successful, False otherwise
        """
        try:
            conn = self.get_connection(port)
            sock = conn.connect()
            conn.close()
            return True
        except Exception as e:
            logging.debug(f"Connection test failed for port {port}: {e}")
            return False


def test_proxy_connectivity(proxy_host, proxy_port, proxy_type="socks5"):
    """
    Test SOCKS proxy connectivity
    
    :param proxy_host: proxy host
    :param proxy_port: proxy port
    :param proxy_type: proxy type
    :return: True if proxy is accessible, False otherwise
    """
    try:
        # Test connection to a known service (Google DNS)
        test_socket = ProxySocket(
            target_host="8.8.8.8",
            target_port=53,
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            proxy_type=proxy_type,
            timeout=5
        )
        
        sock = test_socket.connect()
        test_socket.close()
        
        logging.info(f"SOCKS proxy {proxy_host}:{proxy_port} is accessible")
        return True
        
    except Exception as e:
        logging.error(f"SOCKS proxy test failed: {e}")
        return False
    


def get_system_proxy_settings():
    """
    Attempt to detect system proxy settings
    
    :return: dict with proxy settings or None
    """
    try:
        import urllib.request
        
        # Check for system proxy
        proxy_handler = urllib.request.ProxyHandler()
        opener = urllib.request.build_opener(proxy_handler)
        
        # This is a basic implementation - more sophisticated detection
        # would require platform-specific code
        return None
        
    except Exception:
        return None
