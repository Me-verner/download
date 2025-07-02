#!/usr/bin/env python3

"""
Complete SSH Tunnel Manager with Built-in SOCKS5 Proxies - Single File Solution
All-in-one solution that replaces Trojan with SOCKS5 proxies

Just run this file and everything works automatically!
"""

import subprocess
import time
import sys
import os
import signal
import logging
import threading
import json
import socket
import psutil
import asyncio
import re
import struct
import select
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed

# Rich library for beautiful terminal output
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.panel import Panel
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "rich", "psutil"])
        from rich.console import Console
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
        from rich.table import Table
        from rich.panel import Panel
        RICH_AVAILABLE = True
    except Exception:
        RICH_AVAILABLE = False

# ================================================================
# BUILT-IN SOCKS5 PROXY IMPLEMENTATION
# ================================================================

class SOCKS5Status(Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    FAILED = "failed"
    UNHEALTHY = "unhealthy"

class AuthMethod(Enum):
    NO_AUTH = 0x00
    USERNAME_PASSWORD = 0x02
    NO_ACCEPTABLE = 0xFF

class CommandType(Enum):
    CONNECT = 0x01
    BIND = 0x02
    UDP_ASSOCIATE = 0x03

class AddressType(Enum):
    IPV4 = 0x01
    DOMAIN = 0x03
    IPV6 = 0x04

class ReplyCode(Enum):
    SUCCESS = 0x00
    GENERAL_FAILURE = 0x01
    CONNECTION_NOT_ALLOWED = 0x02
    NETWORK_UNREACHABLE = 0x03
    HOST_UNREACHABLE = 0x04
    CONNECTION_REFUSED = 0x05
    TTL_EXPIRED = 0x06
    COMMAND_NOT_SUPPORTED = 0x07
    ADDRESS_TYPE_NOT_SUPPORTED = 0x08

@dataclass
class ConnectionStats:
    start_time: datetime
    client_addr: str
    target_addr: str
    target_port: int
    bytes_sent: int = 0
    bytes_received: int = 0
    active: bool = True
    end_time: Optional[datetime] = None
    
    @property
    def duration(self) -> timedelta:
        end = self.end_time or datetime.now()
        return end - self.start_time
    
    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_received

@dataclass
class ProxyStats:
    start_time: datetime = field(default_factory=datetime.now)
    total_connections: int = 0
    active_connections: int = 0
    failed_connections: int = 0
    total_bytes_transferred: int = 0
    connections_history: List[ConnectionStats] = field(default_factory=list)
    
    def add_connection(self, conn_stats: ConnectionStats):
        self.connections_history.append(conn_stats)
        self.total_connections += 1
        self.active_connections += 1
    
    def close_connection(self, conn_stats: ConnectionStats):
        conn_stats.active = False
        conn_stats.end_time = datetime.now()
        self.active_connections -= 1
        self.total_bytes_transferred += conn_stats.total_bytes
    
    def fail_connection(self):
        self.failed_connections += 1
    
    @property
    def uptime(self) -> timedelta:
        return datetime.now() - self.start_time
    
    @property
    def success_rate(self) -> float:
        total = self.total_connections + self.failed_connections
        if total == 0:
            return 100.0
        return (self.total_connections / total) * 100.0

class SOCKS5Exception(Exception):
    def __init__(self, message: str, reply_code: ReplyCode = ReplyCode.GENERAL_FAILURE):
        super().__init__(message)
        self.reply_code = reply_code

class SOCKS5Proxy:
    def __init__(self, host: str = "127.0.0.1", port: int = 1080, 
                 auth_required: bool = False, username: str = None, password: str = None,
                 max_connections: int = 100, buffer_size: int = 8192):
        self.host = host
        self.port = port
        self.auth_required = auth_required
        self.username = username
        self.password = password
        self.max_connections = max_connections
        self.buffer_size = buffer_size
        
        self.status = SOCKS5Status.STOPPED
        self.server_socket = None
        self.running = False
        self.connections: Dict[int, ConnectionStats] = {}
        self.stats = ProxyStats()
        
        self.logger = logging.getLogger(f"SOCKS5-{port}")
        self.logger.setLevel(logging.WARNING)
        
        self.accept_thread = None
        self.connection_threads = []
        self.connection_counter = 0
    
    def start(self) -> bool:
        try:
            self.status = SOCKS5Status.STARTING
            
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(self.max_connections)
            
            self.running = True
            self.status = SOCKS5Status.RUNNING
            
            self.accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
            self.accept_thread.start()
            
            return True
            
        except Exception as e:
            self.status = SOCKS5Status.FAILED
            return False
    
    def stop(self):
        self.running = False
        self.status = SOCKS5Status.STOPPED
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        if self.accept_thread and self.accept_thread.is_alive():
            self.accept_thread.join(timeout=2)
        
        for conn_id in list(self.connections.keys()):
            self._close_connection(conn_id)
    
    def _accept_loop(self):
        while self.running:
            try:
                ready, _, _ = select.select([self.server_socket], [], [], 1.0)
                if not ready:
                    continue
                
                client_socket, client_addr = self.server_socket.accept()
                
                if len(self.connections) >= self.max_connections:
                    client_socket.close()
                    self.stats.fail_connection()
                    continue
                
                conn_id = self.connection_counter
                self.connection_counter += 1
                
                conn_thread = threading.Thread(
                    target=self._handle_connection,
                    args=(client_socket, client_addr, conn_id),
                    daemon=True
                )
                conn_thread.start()
                self.connection_threads.append(conn_thread)
                
                self.connection_threads = [t for t in self.connection_threads if t.is_alive()]
                
            except Exception as e:
                if self.running:
                    time.sleep(0.1)
    
    def _handle_connection(self, client_socket: socket.socket, client_addr: tuple, conn_id: int):
        try:
            client_socket.settimeout(30)
            
            if not self._handle_handshake(client_socket, conn_id):
                return
            
            target_socket = self._handle_request(client_socket, conn_id)
            if not target_socket:
                return
            
            conn_stats = ConnectionStats(
                start_time=datetime.now(),
                client_addr=f"{client_addr[0]}:{client_addr[1]}",
                target_addr="",
                target_port=0
            )
            self.connections[conn_id] = conn_stats
            self.stats.add_connection(conn_stats)
            
            self._relay_data(client_socket, target_socket, conn_id)
            
        except Exception as e:
            self.stats.fail_connection()
        finally:
            self._close_connection(conn_id)
            try:
                client_socket.close()
            except:
                pass
    
    def _handle_handshake(self, client_socket: socket.socket, conn_id: int) -> bool:
        try:
            data = client_socket.recv(256)
            if len(data) < 3:
                return False
            
            version, nmethods = struct.unpack('!BB', data[:2])
            if version != 5:
                return False
            
            methods = struct.unpack('!' + 'B' * nmethods, data[2:2+nmethods])
            
            if self.auth_required:
                if AuthMethod.USERNAME_PASSWORD.value in methods:
                    chosen_method = AuthMethod.USERNAME_PASSWORD
                else:
                    chosen_method = AuthMethod.NO_ACCEPTABLE
            else:
                if AuthMethod.NO_AUTH.value in methods:
                    chosen_method = AuthMethod.NO_AUTH
                else:
                    chosen_method = AuthMethod.NO_ACCEPTABLE
            
            response = struct.pack('!BB', 5, chosen_method.value)
            client_socket.send(response)
            
            if chosen_method == AuthMethod.NO_ACCEPTABLE:
                return False
            
            if chosen_method == AuthMethod.USERNAME_PASSWORD:
                if not self._handle_username_password_auth(client_socket, conn_id):
                    return False
            
            return True
            
        except Exception as e:
            return False
    
    def _handle_username_password_auth(self, client_socket: socket.socket, conn_id: int) -> bool:
        try:
            data = client_socket.recv(256)
            if len(data) < 2:
                return False
            
            version = data[0]
            if version != 1:
                return False
            
            username_len = data[1]
            if len(data) < 2 + username_len + 1:
                return False
            
            username = data[2:2+username_len].decode('utf-8')
            password_len = data[2+username_len]
            
            if len(data) < 2 + username_len + 1 + password_len:
                return False
            
            password = data[2+username_len+1:2+username_len+1+password_len].decode('utf-8')
            
            auth_success = (username == self.username and password == self.password)
            
            status = 0 if auth_success else 1
            response = struct.pack('!BB', 1, status)
            client_socket.send(response)
            
            return auth_success
            
        except Exception as e:
            return False
    
    def _handle_request(self, client_socket: socket.socket, conn_id: int) -> Optional[socket.socket]:
        try:
            data = client_socket.recv(1024)
            if len(data) < 4:
                return None
            
            version, cmd, reserved, addr_type = struct.unpack('!BBBB', data[:4])
            
            if version != 5:
                return None
            
            if cmd != CommandType.CONNECT.value:
                return None
            
            if addr_type == AddressType.IPV4.value:
                if len(data) < 10:
                    return None
                addr = socket.inet_ntoa(data[4:8])
                port = struct.unpack('!H', data[8:10])[0]
                
            elif addr_type == AddressType.DOMAIN.value:
                if len(data) < 5:
                    return None
                domain_len = data[4]
                if len(data) < 5 + domain_len + 2:
                    return None
                addr = data[5:5+domain_len].decode('utf-8')
                port = struct.unpack('!H', data[5+domain_len:7+domain_len])[0]
                
            else:
                return None
            
            if conn_id in self.connections:
                self.connections[conn_id].target_addr = addr
                self.connections[conn_id].target_port = port
            
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.settimeout(10)
            
            try:
                target_socket.connect((addr, port))
            except:
                return None
            
            response = struct.pack('!BBBB', 5, ReplyCode.SUCCESS.value, 0, AddressType.IPV4.value)
            response += socket.inet_aton('0.0.0.0')
            response += struct.pack('!H', 0)
            
            client_socket.send(response)
            
            return target_socket
            
        except Exception as e:
            return None
    
    def _relay_data(self, client_socket: socket.socket, target_socket: socket.socket, conn_id: int):
        try:
            client_socket.settimeout(300)
            target_socket.settimeout(300)
            
            sockets = [client_socket, target_socket]
            
            while self.running:
                ready, _, error = select.select(sockets, [], sockets, 1.0)
                
                if error:
                    break
                
                if not ready:
                    continue
                
                for sock in ready:
                    try:
                        data = sock.recv(self.buffer_size)
                        if not data:
                            return
                        
                        if sock is client_socket:
                            target_socket.send(data)
                            if conn_id in self.connections:
                                self.connections[conn_id].bytes_sent += len(data)
                        else:
                            client_socket.send(data)
                            if conn_id in self.connections:
                                self.connections[conn_id].bytes_received += len(data)
                        
                    except socket.timeout:
                        continue
                    except socket.error:
                        return
                    
        except Exception as e:
            pass
        finally:
            try:
                target_socket.close()
            except:
                pass
    
    def _close_connection(self, conn_id: int):
        if conn_id in self.connections:
            conn_stats = self.connections[conn_id]
            self.stats.close_connection(conn_stats)
            del self.connections[conn_id]
    
    def is_healthy(self) -> bool:
        return (self.status == SOCKS5Status.RUNNING and 
                self.running and 
                self.server_socket is not None)

class SOCKS5HealthChecker:
    def __init__(self, proxy_host: str = "127.0.0.1", proxy_port: int = 1080):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
    
    def check_basic_connectivity(self) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.proxy_host, self.proxy_port))
            sock.close()
            return result == 0
        except:
            return False
    
    def run_health_check(self) -> Dict[str, any]:
        results = {
            "basic_connectivity": self.check_basic_connectivity(),
            "overall_healthy": False
        }
        results["overall_healthy"] = results["basic_connectivity"]
        return results

# ================================================================
# SSH TUNNEL MANAGER WITH INTEGRATED SOCKS5
# ================================================================

class TunnelStatus(Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    FAILED = "failed"
    RECOVERING = "recovering"
    UNHEALTHY = "unhealthy"

@dataclass
class TunnelInfo:
    port: int
    status: TunnelStatus = TunnelStatus.STOPPED
    pid: Optional[int] = None
    process: Optional[subprocess.Popen] = None
    start_time: Optional[datetime] = None
    last_health_check: Optional[datetime] = None
    failure_count: int = 0
    last_error: Optional[str] = None
    
    socks5_proxy: Optional[SOCKS5Proxy] = None
    socks5_port: Optional[int] = None
    socks5_status: SOCKS5Status = SOCKS5Status.STOPPED
    socks5_health_checker: Optional[SOCKS5HealthChecker] = None
    
    @property
    def uptime_str(self) -> str:
        if self.start_time:
            uptime = datetime.now() - self.start_time
            hours = int(uptime.total_seconds() // 3600)
            minutes = int((uptime.total_seconds() % 3600) // 60)
            return f"{hours:02d}:{minutes:02d}"
        return "00:00"

class CompleteSSHTunnelSOCKS5Manager:
    def __init__(self, config_string: str = None):
        if config_string:
            self._parse_config_string(config_string)
        else:
            self.iranian_ip = None
            self.iranian_pass = None
            self.telegram_token = None
            self.telegram_admins = []
        
        self.iranian_user = "root"
        self.ssh_port = 22
        self.base_socks5_port = 8880
        self.log_file = Path("/var/log/ssh_socks5_manager.log")
        self.pid_dir = Path("/var/run/ssh_socks5_manager")
        
        self.default_ports = [1080, 1081, 1082]
        self.tunnels: Dict[int, TunnelInfo] = {}
        self.use_key_auth = False
        self.monitoring = False
        self.monitor_thread = None
        
        self.socks5_auth_required = False
        self.health_check_interval = 30
        self.max_failure_count = 5
        self.recovery_delay = 10
        
        self.console = Console() if RICH_AVAILABLE else None
        
        self.setup_logging()
        self.setup_signal_handlers()
    
    def _parse_config_string(self, config_string: str):
        try:
            parts = config_string.split(',')
            if len(parts) < 2:
                raise ValueError("Invalid config format")
            
            self.iranian_ip = parts[0].strip()
            self.iranian_pass = parts[1].strip()
            
            if len(parts) >= 3 and parts[2].strip():
                self.telegram_token = parts[2].strip()
            else:
                self.telegram_token = None
            
            self.telegram_admins = []
            if len(parts) >= 4:
                for admin_part in parts[3:]:
                    admin_id = admin_part.strip()
                    if admin_id.isdigit():
                        self.telegram_admins.append(int(admin_id))
            
            print(f"✅ Configuration loaded: {self.iranian_ip}")
            
        except Exception as e:
            print(f"❌ Error parsing config: {e}")
            print("Expected format: ip,password,bottoken,admin1,admin2,...")
            sys.exit(1)
    
    def prompt_for_config(self):
        print("🔧 SSH + SOCKS5 Tunnel Manager Configuration")
        print("=" * 50)
        print()
        print("Please provide configuration in this format:")
        print("server_ip,ssh_password,telegram_bot_token,admin_id1,admin_id2,...")
        print()
        print("Example:")
        print("94.182.150.195,mypassword,7624988827:AAGb36v5sUG5aKGU,434418436,5043926051")
        print()
        print("Notes:")
        print("- Leave telegram_bot_token empty if you don't want Telegram notifications")
        print("- You can add multiple admin IDs separated by commas")
        print("- SSH user is assumed to be 'root' on port 22")
        print()
        
        while True:
            try:
                config_input = input("Enter configuration: ").strip()
                if config_input:
                    self._parse_config_string(config_input)
                    break
                else:
                    print("❌ Configuration cannot be empty. Please try again.")
            except KeyboardInterrupt:
                print("\n👋 Configuration cancelled.")
                sys.exit(0)
            except Exception as e:
                print(f"❌ Invalid configuration: {e}")
                print("Please try again with the correct format.")
    
    def setup_logging(self):
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='[%(asctime)s] %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler() if not RICH_AVAILABLE else logging.NullHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def setup_signal_handlers(self):
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        self.log("info", "🛑 Shutdown signal received")
        self.stop_monitoring()
        self.stop_all_tunnels()
        sys.exit(0)
    
    def log(self, level: str, message: str, tunnel_port: Optional[int] = None):
        prefix = f"[Port {tunnel_port}] " if tunnel_port else ""
        full_message = f"{prefix}{message}"
        
        log_level = "info" if level == "success" else level
        getattr(self.logger, log_level.lower())(full_message)
        
        if RICH_AVAILABLE and self.console:
            color = {
                "info": "cyan",
                "warning": "yellow", 
                "error": "red",
                "success": "green",
                "debug": "dim"
            }.get(level, "white")
            
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.console.print(f"[dim]{timestamp}[/dim] [{color}]{full_message}[/{color}]")
    
    def detect_auth_method(self):
        if RICH_AVAILABLE:
            with self.console.status("[bold blue]🔍 Detecting authentication method..."):
                self.use_key_auth = self._test_key_auth()
        else:
            print("🔍 Detecting authentication method...")
            self.use_key_auth = self._test_key_auth()
        
        auth_method = "SSH key" if self.use_key_auth else "password"
        self.log("info", f"✅ Using {auth_method} authentication")
    
    def _test_key_auth(self) -> bool:
        try:
            cmd = [
                "ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no",
                "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
                f"{self.iranian_user}@{self.iranian_ip}", "echo test"
            ]
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            return result.returncode == 0
        except:
            return False
    
    def check_dependencies(self):
        missing_deps = []
        
        if not self.use_key_auth and not shutil.which("sshpass"):
            missing_deps.append("sshpass")
        
        if not shutil.which("autossh"):
            missing_deps.append("autossh")
        
        if missing_deps:
            print(f"📦 Installing dependencies: {', '.join(missing_deps)}")
            self._install_packages(missing_deps)
    
    def _install_packages(self, packages: List[str]):
        try:
            if shutil.which("apt-get"):
                subprocess.run(["apt-get", "update", "-qq"], check=True)
                subprocess.run(["apt-get", "install", "-y"] + packages, check=True)
            elif shutil.which("yum"):
                subprocess.run(["yum", "install", "-y"] + packages, check=True)
            elif shutil.which("dnf"):
                subprocess.run(["dnf", "install", "-y"] + packages, check=True)
            else:
                raise Exception("No supported package manager found")
        except Exception as e:
            self.log("error", f"Failed to install packages: {e}")
            sys.exit(1)
    
    def create_socks5_proxy(self, tunnel_port: int) -> bool:
        tunnel = self.tunnels[tunnel_port]
        socks5_port = self.base_socks5_port + (tunnel_port - 1080)
        
        try:
            self.log("info", f"Creating SOCKS5 proxy on port {socks5_port}", tunnel_port)
            
            socks5_proxy = SOCKS5Proxy(
                host="127.0.0.1",
                port=socks5_port,
                auth_required=self.socks5_auth_required,
                max_connections=50,
                buffer_size=8192
            )
            
            if socks5_proxy.start():
                tunnel.socks5_proxy = socks5_proxy
                tunnel.socks5_port = socks5_port
                tunnel.socks5_status = SOCKS5Status.RUNNING
                tunnel.socks5_health_checker = SOCKS5HealthChecker("127.0.0.1", socks5_port)
                
                self.log("success", f"SOCKS5 proxy started on port {socks5_port}", tunnel_port)
                
                time.sleep(1)
                if self.test_socks5_health(tunnel_port):
                    self.log("success", f"SOCKS5 proxy health check passed", tunnel_port)
                    return True
                else:
                    self.log("warning", f"SOCKS5 proxy health check failed", tunnel_port)
                    return False
            else:
                tunnel.socks5_status = SOCKS5Status.FAILED
                self.log("error", f"Failed to start SOCKS5 proxy on port {socks5_port}", tunnel_port)
                return False
                
        except Exception as e:
            tunnel.socks5_status = SOCKS5Status.FAILED
            self.log("error", f"Error creating SOCKS5 proxy: {e}", tunnel_port)
            return False
    
    def test_socks5_health(self, tunnel_port: int) -> bool:
        tunnel = self.tunnels.get(tunnel_port)
        if not tunnel or not tunnel.socks5_health_checker:
            return False
        
        try:
            results = tunnel.socks5_health_checker.run_health_check()
            return results["overall_healthy"]
        except Exception as e:
            return False
    
    def create_tunnel(self, port: int) -> bool:
        tunnel = self.tunnels[port]
        tunnel.status = TunnelStatus.STARTING
        
        try:
            if not self.create_socks5_proxy(port):
                tunnel.status = TunnelStatus.FAILED
                tunnel.failure_count += 1
                return False
            
            self.pid_dir.mkdir(parents=True, exist_ok=True)
            pid_file = self.pid_dir / f"tunnel_{port}.pid"
            
            socks5_port = tunnel.socks5_port
            ssh_opts = [
                "-o", "ConnectTimeout=30",
                "-o", "ServerAliveInterval=5",
                "-o", "ServerAliveCountMax=3",
                "-o", "TCPKeepAlive=yes",
                "-o", "ExitOnForwardFailure=yes",
                "-o", "StrictHostKeyChecking=no",
                "-o", "Compression=yes",
                "-N",
                "-R", f"127.0.0.1:{port}:127.0.0.1:{socks5_port}",
                "-p", str(self.ssh_port),
                f"{self.iranian_user}@{self.iranian_ip}"
            ]
            
            if self.use_key_auth:
                cmd = ["autossh", "-M", "0"] + ssh_opts
            else:
                cmd = ["sshpass", "-p", self.iranian_pass, "autossh", "-M", "0"] + ssh_opts
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL
            )
            
            tunnel.process = process
            tunnel.pid = process.pid
            tunnel.start_time = datetime.now()
            
            with open(pid_file, 'w') as f:
                f.write(str(process.pid))
            
            time.sleep(3)
            
            if process.poll() is not None:
                stdout, stderr = process.communicate(timeout=5)
                error_msg = stderr.decode().strip() if stderr else "Process died immediately"
                tunnel.last_error = error_msg
                tunnel.status = TunnelStatus.FAILED
                tunnel.failure_count += 1
                return False
            
            for attempt in range(3):
                ssh_healthy = self.test_tunnel_health(port)
                socks5_healthy = self.test_socks5_health(port)
                
                if ssh_healthy and socks5_healthy:
                    tunnel.status = TunnelStatus.RUNNING
                    tunnel.last_health_check = datetime.now()
                    tunnel.failure_count = 0
                    tunnel.last_error = None
                    
                    self.log("success", f"Tunnel and SOCKS5 proxy are running successfully", port)
                    return True
                    
                time.sleep(2)
            
            tunnel.last_error = "Tunnel created but health checks failed"
            tunnel.status = TunnelStatus.UNHEALTHY
            tunnel.failure_count += 1
            return False
            
        except Exception as e:
            tunnel.last_error = str(e)
            tunnel.status = TunnelStatus.FAILED
            tunnel.failure_count += 1
            return False
    
    def test_tunnel_health(self, port: int) -> bool:
        try:
            if self.use_key_auth:
                cmd = [
                    "ssh", "-o", "ConnectTimeout=3", "-o", "StrictHostKeyChecking=no",
                    f"{self.iranian_user}@{self.iranian_ip}",
                    f"timeout 2 bash -c '</dev/tcp/127.0.0.1/{port}' 2>/dev/null"
                ]
            else:
                cmd = [
                    "sshpass", "-p", self.iranian_pass, "ssh",
                    "-o", "ConnectTimeout=3", "-o", "StrictHostKeyChecking=no",
                    f"{self.iranian_user}@{self.iranian_ip}",
                    f"timeout 2 bash -c '</dev/tcp/127.0.0.1/{port}' 2>/dev/null"
                ]
            
            result = subprocess.run(cmd, capture_output=True, timeout=8)
            return result.returncode == 0
        except:
            return False
    
    def test_ssh_connectivity(self) -> bool:
        for attempt in range(3):
            try:
                if self.use_key_auth:
                    cmd = [
                        "ssh", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no",
                        "-o", "BatchMode=yes", f"{self.iranian_user}@{self.iranian_ip}",
                        "echo 'SSH_TEST_SUCCESS'"
                    ]
                else:
                    cmd = [
                        "sshpass", "-p", self.iranian_pass, "ssh",
                        "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no",
                        f"{self.iranian_user}@{self.iranian_ip}", "echo 'SSH_TEST_SUCCESS'"
                    ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                
                if result.returncode == 0 and "SSH_TEST_SUCCESS" in result.stdout:
                    return True
                
                if attempt < 2:
                    self.log("warning", f"SSH test failed (attempt {attempt + 1}/3), retrying...")
                    time.sleep(2)
                
            except Exception as e:
                if attempt < 2:
                    self.log("warning", f"SSH test error (attempt {attempt + 1}/3): {e}")
                    time.sleep(2)
        
        return False
    
    def stop_tunnel(self, port: int) -> bool:
        tunnel = self.tunnels.get(port)
        if not tunnel:
            return False
        
        try:
            if tunnel.process and tunnel.process.poll() is None:
                tunnel.process.terminate()
                try:
                    tunnel.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    tunnel.process.kill()
                    tunnel.process.wait()
            
            if tunnel.socks5_proxy:
                tunnel.socks5_proxy.stop()
                tunnel.socks5_proxy = None
                tunnel.socks5_status = SOCKS5Status.STOPPED
            
            pid_file = self.pid_dir / f"tunnel_{port}.pid"
            pid_file.unlink(missing_ok=True)
            
            tunnel.status = TunnelStatus.STOPPED
            tunnel.process = None
            tunnel.pid = None
            tunnel.start_time = None
            tunnel.socks5_port = None
            tunnel.socks5_health_checker = None
            
            return True
        except Exception as e:
            self.log("error", f"Error stopping tunnel: {e}", port)
            return False
    
    def start_tunnels(self, ports: List[int]) -> bool:
        self.check_dependencies()
        self.detect_auth_method()
        
        for port in ports:
            self.tunnels[port] = TunnelInfo(port)
        
        self.log("info", f"Starting SSH tunnels with SOCKS5 proxies on ports: {', '.join(map(str, ports))}")
        
        if RICH_AVAILABLE:
            return self._start_tunnels_with_progress(ports)
        else:
            return self._start_tunnels_simple(ports)
    
    def _start_tunnels_with_progress(self, ports: List[int]) -> bool:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            
            connect_task = progress.add_task("🔗 Testing SSH connectivity...", total=1)
            if not self.test_ssh_connectivity():
                progress.update(connect_task, completed=1)
                self.console.print("[red]❌ SSH connectivity test failed[/red]")
                return False
            progress.update(connect_task, completed=1)
            
            tunnel_task = progress.add_task(f"🚇🧦 Creating {len(ports)} tunnels with SOCKS5 proxies...", total=len(ports))
            
            success_count = 0
            for port in ports:
                progress.console.print(f"[yellow]🔄 Creating tunnel {port} with SOCKS5 proxy...[/yellow]")
                
                if self.create_tunnel(port):
                    success_count += 1
                    progress.console.print(f"[green]✅ Tunnel {port} + SOCKS5 proxy created successfully[/green]")
                else:
                    tunnel = self.tunnels[port]
                    progress.console.print(f"[red]❌ Tunnel {port} failed: {tunnel.last_error}[/red]")
                
                progress.advance(tunnel_task)
        
        return success_count > 0
    
    def _start_tunnels_simple(self, ports: List[int]) -> bool:
        print("🔗 Testing SSH connectivity...")
        if not self.test_ssh_connectivity():
            print("❌ SSH connectivity test failed")
            return False
        
        print(f"🚇🧦 Creating {len(ports)} tunnels with SOCKS5 proxies...")
        success_count = 0
        
        for i, port in enumerate(ports, 1):
            print(f"  [{i}/{len(ports)}] Creating tunnel {port} with SOCKS5 proxy...")
            if self.create_tunnel(port):
                print(f"  ✅ Tunnel {port} + SOCKS5 proxy created successfully")
                success_count += 1
            else:
                tunnel = self.tunnels[port]
                print(f"  ❌ Tunnel {port} failed: {tunnel.last_error}")
        
        return success_count > 0
    
    def start_monitoring(self):
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        self.log("info", "🔍 Tunnel and SOCKS5 monitoring started")
    
    def stop_monitoring(self):
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.log("info", "🔍 Monitoring stopped")
    
    def _monitor_loop(self):
        while self.monitoring:
            try:
                healthy_count = 0
                total_count = len(self.tunnels)
                
                for port, tunnel in self.tunnels.items():
                    if not self.monitoring:
                        break
                    
                    ssh_healthy = False
                    if tunnel.process and tunnel.process.poll() is None:
                        ssh_healthy = self.test_tunnel_health(port)
                    
                    socks5_healthy = self.test_socks5_health(port)
                    
                    if ssh_healthy and socks5_healthy:
                        tunnel.status = TunnelStatus.RUNNING
                        tunnel.socks5_status = SOCKS5Status.RUNNING
                        tunnel.last_health_check = datetime.now()
                        tunnel.failure_count = max(0, tunnel.failure_count - 1)
                        healthy_count += 1
                    else:
                        tunnel.failure_count += 1
                        if tunnel.failure_count >= self.max_failure_count:
                            self._recover_tunnel(port)
                
                time.sleep(self.health_check_interval)
                
            except Exception as e:
                self.log("error", f"Monitor loop error: {e}")
                time.sleep(10)
    
    def _recover_tunnel(self, port: int):
        tunnel = self.tunnels[port]
        tunnel.status = TunnelStatus.RECOVERING
        
        try:
            self.log("info", f"Starting recovery process for port {port}", port)
            
            self.stop_tunnel(port)
            time.sleep(self.recovery_delay)
            
            if self.create_tunnel(port):
                self.log("success", "Recovery successful", port)
            else:
                self.log("error", f"Recovery failed: {tunnel.last_error}", port)
                
        except Exception as e:
            tunnel.last_error = f"Recovery error: {e}"
            tunnel.status = TunnelStatus.FAILED
            self.log("error", f"Recovery error: {e}", port)
    
    def stop_all_tunnels(self):
        if RICH_AVAILABLE:
            with self.console.status("[bold red]🛑 Stopping all tunnels and SOCKS5 proxies..."):
                for port in list(self.tunnels.keys()):
                    self.stop_tunnel(port)
        else:
            print("🛑 Stopping all tunnels and SOCKS5 proxies...")
            for port in list(self.tunnels.keys()):
                self.stop_tunnel(port)
        
        self.tunnels.clear()
        self.log("info", "All tunnels and SOCKS5 proxies stopped")
    
    def show_status(self):
        if RICH_AVAILABLE and self.console:
            table = Table(title="🚇🧦 SSH Tunnels + SOCKS5 Proxies Status", show_header=True, header_style="bold magenta")
            table.add_column("Tunnel Port", style="cyan", width=12)
            table.add_column("SSH Status", width=12)
            table.add_column("SOCKS5 Port", style="yellow", width=12)
            table.add_column("SOCKS5 Status", width=15)
            table.add_column("Uptime", style="green", width=10)
            
            for port, tunnel in sorted(self.tunnels.items()):
                ssh_status_color = {
                    TunnelStatus.RUNNING: "green",
                    TunnelStatus.STARTING: "yellow",
                    TunnelStatus.FAILED: "red",
                    TunnelStatus.UNHEALTHY: "orange1",
                    TunnelStatus.RECOVERING: "blue",
                    TunnelStatus.STOPPED: "dim"
                }.get(tunnel.status, "white")
                
                ssh_status_text = f"[{ssh_status_color}]{tunnel.status.value.title()}[/{ssh_status_color}]"
                
                socks5_status_color = {
                    SOCKS5Status.RUNNING: "green",
                    SOCKS5Status.STARTING: "yellow",
                    SOCKS5Status.FAILED: "red",
                    SOCKS5Status.UNHEALTHY: "orange1",
                    SOCKS5Status.STOPPED: "dim"
                }.get(tunnel.socks5_status, "white")
                
                socks5_status_text = f"[{socks5_status_color}]{tunnel.socks5_status.value.title()}[/{socks5_status_color}]"
                
                table.add_row(
                    str(port),
                    ssh_status_text,
                    str(tunnel.socks5_port) if tunnel.socks5_port else "N/A",
                    socks5_status_text,
                    tunnel.uptime_str
                )
            
            self.console.print(table)
        else:
            print("🚇🧦 SSH Tunnels + SOCKS5 Proxies Status:")
            print("=" * 60)
            
            for port, tunnel in sorted(self.tunnels.items()):
                ssh_status = tunnel.status.value.title()
                socks5_status = tunnel.socks5_status.value.title()
                uptime = tunnel.uptime_str
                
                print(f"Tunnel {port}: SSH={ssh_status}, SOCKS5={socks5_status} (Port {tunnel.socks5_port})")
                print(f"  Uptime: {uptime}")
    
    def show_connection_info(self):
        if not self.tunnels:
            return
        
        tunnel_ports = sorted(self.tunnels.keys())
        socks5_ports = [str(t.socks5_port) for t in self.tunnels.values() if t.socks5_port]
        
        if RICH_AVAILABLE:
            info_text = f"""
[bold cyan]SSH + SOCKS5 Configuration:[/bold cyan]
- Iranian Server: {self.iranian_ip}:{self.ssh_port}
- SSH Tunnel Ports: {' '.join(map(str, tunnel_ports))}
- Local SOCKS5 Ports: {' '.join(socks5_ports)}
- Active Tunnels: {len(self.tunnels)}

[bold cyan]Client Configuration:[/bold cyan]
Configure your applications to use SOCKS5 proxy:
- Host: {self.iranian_ip}
- Ports: {' '.join(map(str, tunnel_ports))}
- Type: SOCKS5
- Authentication: None

[bold green]✨ SSH Tunnels + SOCKS5 Proxies are ready![/bold green]
"""
            
            panel = Panel(
                info_text,
                title="🚇🧦 Complete SSH + SOCKS5 Manager",
                border_style="green",
                padding=(1, 2)
            )
            self.console.print(panel)
        else:
            print(f"""
🚇🧦 Complete SSH + SOCKS5 Manager - Connection Info
{'=' * 60}

SSH + SOCKS5 Configuration:
- Iranian Server: {self.iranian_ip}:{self.ssh_port}
- SSH Tunnel Ports: {' '.join(map(str, tunnel_ports))}
- Local SOCKS5 Ports: {' '.join(socks5_ports)}
- Active Tunnels: {len(self.tunnels)}

Client Configuration:
Configure your applications to use SOCKS5 proxy:
- Host: {self.iranian_ip}
- Ports: {' '.join(map(str, tunnel_ports))}
- Type: SOCKS5
- Authentication: None

✨ SSH Tunnels + SOCKS5 Proxies are ready!
""")

def parse_ports(args: List[str]) -> List[int]:
    if not args:
        return [1080, 1081, 1082]
    
    ports = []
    for arg in args:
        try:
            port = int(arg)
            if 1024 <= port <= 65535:
                ports.append(port)
            else:
                print(f"⚠️  Invalid port {port} (must be 1024-65535)")
        except ValueError:
            print(f"⚠️  Invalid port '{arg}' (not a number)")
    
    return ports or [1080, 1081, 1082]

def main():
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help', 'help']:
        show_usage()
        return
    
    config_string = None
    
    if len(sys.argv) > 1 and ',' in sys.argv[1]:
        config_string = sys.argv[1]
        sys.argv = [sys.argv[0]] + sys.argv[2:]
    
    command = sys.argv[1] if len(sys.argv) > 1 else "start"
    args = sys.argv[2:] if len(sys.argv) > 2 else []
    
    if command in args:
        args.remove(command)
    
    if command not in ["start", "stop", "restart", "status", "test", "monitor", "config"]:
        args = [command] + args
        command = "start"
    
    if command == "config":
        print("🔧 SSH + SOCKS5 Tunnel Manager Configuration")
        print("=" * 50)
        print()
        print("Format: server_ip,ssh_password,telegram_bot_token,admin_id1,admin_id2,...")
        print("Example: 94.182.150.195,mypassword,7624988827:AAGb36v5sUG,434418436")
        return
    
    manager = CompleteSSHTunnelSOCKS5Manager(config_string)
    
    if not config_string:
        manager.prompt_for_config()
    
    try:
        if command == "start":
            ports = parse_ports(args)
            
            print("🚀 Initializing Complete SSH + SOCKS5 Manager...")
            
            if manager.start_tunnels(ports):
                manager.show_connection_info()
                manager.start_monitoring()
                
                try:
                    if RICH_AVAILABLE:
                        with Live(refresh_per_second=0.5, console=manager.console) as live:
                            while manager.monitoring:
                                live.update(manager.show_status())
                                time.sleep(2)
                    else:
                        manager.log("info", "🔍 Monitoring started. Press Ctrl+C to stop.")
                        while manager.monitoring:
                            time.sleep(30)
                            manager.show_status()
                            
                except KeyboardInterrupt:
                    manager.log("info", "👋 Shutting down gracefully...")
                
            else:
                manager.log("error", "❌ Failed to start tunnels")
                sys.exit(1)
        
        elif command == "stop":
            manager.stop_monitoring()
            manager.stop_all_tunnels()
            print("✅ All tunnels and SOCKS5 proxies stopped")
        
        elif command == "status":
            manager.show_status()
        
        elif command == "test":
            print("🧪 Running connectivity tests...")
            ssh_ok = manager.test_ssh_connectivity()
            print(f"SSH Connectivity: {'✅ OK' if ssh_ok else '❌ Failed'}")
        
        else:
            print(f"❌ Unknown command: {command}")
            show_usage()
            sys.exit(1)
    
    except KeyboardInterrupt:
        print(f"\n👋 Interrupted by user")
        manager.stop_monitoring()
        manager.stop_all_tunnels()
    except Exception as e:
        manager.log("error", f"Fatal error: {e}")
        sys.exit(1)

def show_usage():
    print("""
🚇🧦 Complete SSH Tunnel Manager with Built-in SOCKS5 Proxies
⚡ Single File Solution - No External Dependencies!

Usage:
  python3 complete_ssh_socks5_manager.py [CONFIG] [COMMAND] [PORT1] [PORT2] ...

Configuration (Interactive):
  Just run the script and it will prompt you for configuration:
  python3 complete_ssh_socks5_manager.py

Configuration (Single Line):
  server_ip,ssh_password,telegram_bot_token,admin_id1,admin_id2,...
  
  Examples:
  python3 complete_ssh_socks5_manager.py 94.182.150.195,mypass123
  python3 complete_ssh_socks5_manager.py 94.182.150.195,mypass,bottoken,434418436

Commands:
  start     - Start SSH reverse tunnels with SOCKS5 proxies (default)
  stop      - Stop all SSH tunnels and SOCKS5 proxies
  status    - Check status of tunnels and proxies
  test      - Test SSH connectivity
  config    - Show configuration format help

Quick Start Examples:
  # Interactive setup
  python3 complete_ssh_socks5_manager.py
  
  # Quick start with config
  python3 complete_ssh_socks5_manager.py 94.182.150.195,mypassword
  
  # Custom ports
  python3 complete_ssh_socks5_manager.py 94.182.150.195,mypass start 1080 1081 1082

Client Configuration:
  • Host: YOUR_SERVER_IP
  • Port: 1080, 1081, or 1082
  • Type: SOCKS5
  • Authentication: None

No Setup Required!
Just download this file and run it - everything else is automatic!
""")

if __name__ == "__main__":
    main()
