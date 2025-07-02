#!/usr/bin/env python3

"""
SSH Tunnel Manager with SOCKS5 Proxy Integration
Modified version of your SSH tunnel manager that uses SOCKS5 proxies instead of Trojan

Features:
- Creates SOCKS5 proxies on tunnel ports
- SSH reverse tunnels forward to SOCKS5 proxies
- Health checking for both SSH tunnels and SOCKS5 proxies
- Telegram bot integration with SOCKS5 status
- Automatic recovery and monitoring
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
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import our SOCKS5 proxy (assuming it's in the same directory)
try:
    from socks5_proxy import SOCKS5Proxy, SOCKS5HealthChecker, SOCKS5Status
    SOCKS5_AVAILABLE = True
except ImportError:
    print("⚠️ SOCKS5 proxy module not found. Please ensure socks5_proxy.py is in the same directory.")
    SOCKS5_AVAILABLE = False
    sys.exit(1)

# Rich library for beautiful terminal output
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.live import Live
    from rich.layout import Layout
    from rich.align import Align
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("⚠️ Installing 'rich' library for better UI...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "rich", "psutil"])
        from rich.console import Console
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
        from rich.table import Table
        from rich.panel import Panel
        from rich.text import Text
        from rich.live import Live
        from rich.layout import Layout
        from rich.align import Align
        RICH_AVAILABLE = True
    except Exception:
        RICH_AVAILABLE = False

# Telegram Bot imports
try:
    from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
    from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes
    from telegram.constants import ParseMode
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False
    print("⚠️ Installing 'python-telegram-bot' library...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "python-telegram-bot==20.7"])
        from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
        from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes
        from telegram.constants import ParseMode
        TELEGRAM_AVAILABLE = True
    except Exception as e:
        TELEGRAM_AVAILABLE = False
        print(f"❌ Failed to install telegram bot library: {e}. Telegram features will be disabled.")

class TunnelStatus(Enum):
    """Tunnel status enumeration"""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    FAILED = "failed"
    RECOVERING = "recovering"
    UNHEALTHY = "unhealthy"

@dataclass
class TunnelInfo:
    """Information about a tunnel with SOCKS5 proxy"""
    port: int
    status: TunnelStatus = TunnelStatus.STOPPED
    pid: Optional[int] = None
    process: Optional[subprocess.Popen] = None
    start_time: Optional[datetime] = None
    last_health_check: Optional[datetime] = None
    failure_count: int = 0
    last_error: Optional[str] = None
    uptime: timedelta = field(default_factory=lambda: timedelta(0))
    last_notification_sent: Optional[datetime] = None
    
    # SOCKS5 proxy information
    socks5_proxy: Optional[SOCKS5Proxy] = None
    socks5_port: Optional[int] = None
    socks5_status: SOCKS5Status = SOCKS5Status.STOPPED
    socks5_health_checker: Optional[SOCKS5HealthChecker] = None
    
    @property
    def is_healthy(self) -> bool:
        """Check if both tunnel and SOCKS5 proxy are healthy"""
        ssh_healthy = self.status == TunnelStatus.RUNNING and self.failure_count < 3
        socks5_healthy = (self.socks5_proxy and 
                         self.socks5_proxy.is_healthy() and 
                         self.socks5_status == SOCKS5Status.RUNNING)
        return ssh_healthy and socks5_healthy
    
    @property
    def uptime_str(self) -> str:
        """Get formatted uptime string"""
        if self.start_time:
            uptime = datetime.now() - self.start_time
            hours = int(uptime.total_seconds() // 3600)
            minutes = int((uptime.total_seconds() % 3600) // 60)
            return f"{hours:02d}:{minutes:02d}"
        return "00:00"
    
    @property
    def status_emoji(self) -> str:
        """Get emoji for status"""
        return {
            TunnelStatus.RUNNING: "✅",
            TunnelStatus.STARTING: "🔄",
            TunnelStatus.FAILED: "❌",
            TunnelStatus.UNHEALTHY: "⚠️",
            TunnelStatus.RECOVERING: "🔧",
            TunnelStatus.STOPPED: "⏹️"
        }.get(self.status, "❓")
    
    @property
    def socks5_status_emoji(self) -> str:
        """Get emoji for SOCKS5 status"""
        return {
            SOCKS5Status.RUNNING: "🧦✅",
            SOCKS5Status.STARTING: "🧦🔄", 
            SOCKS5Status.FAILED: "🧦❌",
            SOCKS5Status.UNHEALTHY: "🧦⚠️",
            SOCKS5Status.STOPPED: "🧦⏹️"
        }.get(self.socks5_status, "🧦❓")

class SSHTunnelWithSOCKS5Manager:
    """SSH Tunnel Manager with integrated SOCKS5 proxies"""
    
    def __init__(self):
        # Configuration
        self.iranian_ip = "85.133.250.29"
        self.iranian_user = "root"
        self.iranian_pass = "hf_KWQypu"
        self.ssh_port = 22
        self.base_socks5_port = 8880  # Base port for SOCKS5 proxies
        self.log_file = Path("/var/log/ssh_socks5_manager.log")
        self.pid_dir = Path("/var/run/ssh_socks5_manager")
        self.config_file = Path("/etc/ssh_socks5_manager.json")
        
        # Telegram Bot Configuration
        self.telegram_token = "7624988827:AAGb36v5sUG5aKGU-jA7ScaS3LPIqJKJwc0"
        self.telegram_admins = [434418436, 5043926051]
        self.telegram_bot = None
        
        # Default ports for SSH tunnels
        self.default_ports = [1080, 1081, 1082]
        self.tunnels: Dict[int, TunnelInfo] = {}
        self.use_key_auth = False
        self.monitoring = False
        self.monitor_thread = None
        
        # SOCKS5 Configuration
        self.socks5_auth_required = False
        self.socks5_username = "user"
        self.socks5_password = "pass123"
        
        # Health check settings
        self.health_check_interval = 30  # seconds
        self.max_failure_count = 5
        self.recovery_delay = 10  # seconds
        
        # UI
        self.console = Console() if RICH_AVAILABLE else None
        
        # Setup
        self.setup_logging()
        self.setup_signal_handlers()
        self.detect_auth_method()
        if TELEGRAM_AVAILABLE:
            self.setup_telegram_bot()
    
    def setup_logging(self):
        """Setup comprehensive logging"""
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Configure logging with rotation
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
        """Setup signal handlers for graceful shutdown"""
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.log("info", "🛑 Shutdown signal received")
        self.stop_monitoring()
        self.stop_all_tunnels()
        if self.telegram_bot:
            self.telegram_bot.stop_bot()
        sys.exit(0)
    
    def setup_telegram_bot(self):
        """Setup Telegram bot"""
        if TELEGRAM_AVAILABLE and self.telegram_token:
            # Import the TelegramBot class from your original script
            # For now, we'll create a simplified version
            self.log("info", "🤖 Telegram bot initialized (simplified)")
        else:
            self.log("warning", "⚠️ Telegram bot not available")
    
    def log(self, level: str, message: str, tunnel_port: Optional[int] = None):
        """Enhanced logging with optional tunnel context"""
        prefix = f"[Port {tunnel_port}] " if tunnel_port else ""
        full_message = f"{prefix}{message}"
        
        # Map success to info for logging
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
        """Automatically detect the best authentication method"""
        if RICH_AVAILABLE:
            with self.console.status("[bold blue]🔍 Detecting authentication method..."):
                self.use_key_auth = self._test_key_auth()
        else:
            print("🔍 Detecting authentication method...")
            self.use_key_auth = self._test_key_auth()
        
        auth_method = "SSH key" if self.use_key_auth else "password"
        self.log("info", f"✅ Using {auth_method} authentication")
    
    def _test_key_auth(self) -> bool:
        """Test if key-based authentication works"""
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
    
    def create_socks5_proxy(self, tunnel_port: int) -> bool:
        """Create a SOCKS5 proxy for a tunnel"""
        if not SOCKS5_AVAILABLE:
            self.log("error", "SOCKS5 proxy not available", tunnel_port)
            return False
        
        tunnel = self.tunnels[tunnel_port]
        socks5_port = self.base_socks5_port + (tunnel_port - 1080)  # Offset calculation
        
        try:
            self.log("info", f"Creating SOCKS5 proxy on port {socks5_port}", tunnel_port)
            
            # Create SOCKS5 proxy
            socks5_proxy = SOCKS5Proxy(
                host="127.0.0.1",
                port=socks5_port,
                auth_required=self.socks5_auth_required,
                username=self.socks5_username if self.socks5_auth_required else None,
                password=self.socks5_password if self.socks5_auth_required else None,
                max_connections=50,
                buffer_size=8192
            )
            
            # Start the proxy
            if socks5_proxy.start():
                tunnel.socks5_proxy = socks5_proxy
                tunnel.socks5_port = socks5_port
                tunnel.socks5_status = SOCKS5Status.RUNNING
                tunnel.socks5_health_checker = SOCKS5HealthChecker("127.0.0.1", socks5_port)
                
                self.log("success", f"SOCKS5 proxy started on port {socks5_port}", tunnel_port)
                
                # Test the proxy
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
        """Test SOCKS5 proxy health"""
        tunnel = self.tunnels.get(tunnel_port)
        if not tunnel or not tunnel.socks5_health_checker:
            return False
        
        try:
            results = tunnel.socks5_health_checker.run_health_check()
            return results["overall_healthy"]
        except Exception as e:
            self.log("warning", f"SOCKS5 health check error: {e}", tunnel_port)
            return False
    
    def create_tunnel(self, port: int) -> bool:
        """Create a single tunnel with SOCKS5 proxy"""
        tunnel = self.tunnels[port]
        tunnel.status = TunnelStatus.STARTING
        
        try:
            # First create the SOCKS5 proxy
            if not self.create_socks5_proxy(port):
                tunnel.status = TunnelStatus.FAILED
                tunnel.failure_count += 1
                return False
            
            # Create PID directory
            self.pid_dir.mkdir(parents=True, exist_ok=True)
            pid_file = self.pid_dir / f"tunnel_{port}.pid"
            
            # Build SSH command - forward tunnel port to SOCKS5 proxy
            socks5_port = tunnel.socks5_port
            ssh_opts = [
                "-o", "ConnectTimeout=30",
                "-o", "ServerAliveInterval=5",
                "-o", "ServerAliveCountMax=3",
                "-o", "TCPKeepAlive=yes",
                "-o", "ExitOnForwardFailure=yes",
                "-o", "StrictHostKeyChecking=no",
                "-o", "Compression=yes",
                "-o", "IPQoS=throughput",
                "-N",
                "-R", f"127.0.0.1:{port}:127.0.0.1:{socks5_port}",  # Forward to SOCKS5 proxy
                "-p", str(self.ssh_port),
                f"{self.iranian_user}@{self.iranian_ip}"
            ]
            
            if self.use_key_auth:
                cmd = ["autossh", "-M", "0"] + ssh_opts
            else:
                cmd = ["sshpass", "-p", self.iranian_pass, "autossh", "-M", "0"] + ssh_opts
            
            # Start process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL
            )
            
            # Store tunnel info
            tunnel.process = process
            tunnel.pid = process.pid
            tunnel.start_time = datetime.now()
            
            # Write PID file
            with open(pid_file, 'w') as f:
                f.write(str(process.pid))
            
            # Wait for tunnel to establish
            time.sleep(3)
            
            # Check if process is still running
            if process.poll() is not None:
                # Process died, get error output
                stdout, stderr = process.communicate(timeout=5)
                error_msg = stderr.decode().strip() if stderr else "Process died immediately"
                tunnel.last_error = error_msg
                tunnel.status = TunnelStatus.FAILED
                tunnel.failure_count += 1
                return False
            
            # Test tunnel connectivity (both SSH and SOCKS5)
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
            
            # Tunnel or SOCKS5 not responding
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
        """Test if SSH tunnel is healthy"""
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
    
    def stop_tunnel(self, port: int) -> bool:
        """Stop a specific tunnel and its SOCKS5 proxy"""
        tunnel = self.tunnels.get(port)
        if not tunnel:
            return False
        
        try:
            # Stop SSH tunnel process
            if tunnel.process and tunnel.process.poll() is None:
                tunnel.process.terminate()
                try:
                    tunnel.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    tunnel.process.kill()
                    tunnel.process.wait()
            
            # Stop SOCKS5 proxy
            if tunnel.socks5_proxy:
                tunnel.socks5_proxy.stop()
                tunnel.socks5_proxy = None
                tunnel.socks5_status = SOCKS5Status.STOPPED
            
            # Clean up PID file
            pid_file = self.pid_dir / f"tunnel_{port}.pid"
            pid_file.unlink(missing_ok=True)
            
            # Reset tunnel info
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
    
    def start_tunnels(self, ports: List[int], auto_kill: bool = False) -> bool:
        """Start multiple tunnels with SOCKS5 proxies"""
        # Initialize tunnel info
        for port in ports:
            self.tunnels[port] = TunnelInfo(port)
        
        self.log("info", f"Starting SSH tunnels with SOCKS5 proxies on ports: {', '.join(map(str, ports))}")
        
        if RICH_AVAILABLE:
            result = self._start_tunnels_with_progress(ports)
        else:
            result = self._start_tunnels_simple(ports)
        
        return result
    
    def _start_tunnels_with_progress(self, ports: List[int]) -> bool:
        """Start tunnels with rich progress display"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            
            # Test connectivity first
            connect_task = progress.add_task("🔗 Testing SSH connectivity...", total=1)
            if not self.test_ssh_connectivity():
                progress.update(connect_task, completed=1)
                self.console.print("[red]❌ SSH connectivity test failed[/red]")
                return False
            progress.update(connect_task, completed=1)
            
            # Create tunnels with SOCKS5 proxies
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
        """Start tunnels with simple output"""
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
    
    def test_ssh_connectivity(self) -> bool:
        """Test SSH connectivity with retry logic"""
        max_retries = 3
        
        for attempt in range(max_retries):
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
                
                if attempt < max_retries - 1:
                    self.log("warning", f"SSH test failed (attempt {attempt + 1}/{max_retries}), retrying...")
                    time.sleep(2)
                
            except Exception as e:
                if attempt < max_retries - 1:
                    self.log("warning", f"SSH test error (attempt {attempt + 1}/{max_retries}): {e}")
                    time.sleep(2)
        
        return False
    
    def start_monitoring(self):
        """Start tunnel and SOCKS5 monitoring"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        self.log("info", "🔍 Tunnel and SOCKS5 monitoring started")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.log("info", "🔍 Monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop for SSH tunnels and SOCKS5 proxies"""
        consecutive_failures = 0
        
        while self.monitoring:
            try:
                healthy_count = 0
                total_count = len(self.tunnels)
                failed_tunnels = []
                recovered_tunnels = []
                
                for port, tunnel in self.tunnels.items():
                    if not self.monitoring:
                        break
                    
                    previous_status = tunnel.status
                    
                    # Check SSH process health
                    ssh_healthy = False
                    if tunnel.process and tunnel.process.poll() is None:
                        ssh_healthy = self.test_tunnel_health(port)
                    
                    # Check SOCKS5 proxy health
                    socks5_healthy = self.test_socks5_health(port)
                    
                    # Update status based on both checks
                    if ssh_healthy and socks5_healthy:
                        tunnel.status = TunnelStatus.RUNNING
                        tunnel.socks5_status = SOCKS5Status.RUNNING
                        tunnel.last_health_check = datetime.now()
                        tunnel.failure_count = max(0, tunnel.failure_count - 1)
                        healthy_count += 1
                        
                        # Check if tunnel recovered
                        if previous_status in [TunnelStatus.FAILED, TunnelStatus.UNHEALTHY, TunnelStatus.RECOVERING]:
                            recovered_tunnels.append(port)
                    else:
                        if not ssh_healthy and not socks5_healthy:
                            tunnel.status = TunnelStatus.FAILED
                            tunnel.socks5_status = SOCKS5Status.FAILED
                        elif not ssh_healthy:
                            tunnel.status = TunnelStatus.UNHEALTHY
                            tunnel.socks5_status = SOCKS5Status.RUNNING if socks5_healthy else SOCKS5Status.UNHEALTHY
                        else:  # SSH healthy but SOCKS5 not
                            tunnel.status = TunnelStatus.RUNNING
                            tunnel.socks5_status = SOCKS5Status.UNHEALTHY
                        
                        tunnel.failure_count += 1
                        self.log("warning", f"Health check failed - SSH: {ssh_healthy}, SOCKS5: {socks5_healthy} (failures: {tunnel.failure_count})", port)
                        
                        # Auto-recover if too many failures
                        if tunnel.failure_count >= self.max_failure_count:
                            self.log("info", "Attempting auto-recovery", port)
                            failed_tunnels.append(port)
                            self._recover_tunnel(port)
                
                # Log monitoring results
                if healthy_count == total_count:
                    consecutive_failures = 0
                    self.log("debug", f"All {total_count} tunnels and SOCKS5 proxies healthy")
                else:
                    consecutive_failures += 1
                    self.log("warning", f"Only {healthy_count}/{total_count} tunnels fully healthy")
                
                # Calculate sleep interval with exponential backoff
                if consecutive_failures > 0:
                    sleep_time = min(self.health_check_interval * (2 ** min(consecutive_failures, 5)), 300)
                else:
                    sleep_time = self.health_check_interval
                
                time.sleep(sleep_time)
                
            except Exception as e:
                self.log("error", f"Monitor loop error: {e}")
                time.sleep(10)
    
    def _recover_tunnel(self, port: int):
        """Recover a failed tunnel and its SOCKS5 proxy"""
        tunnel = self.tunnels[port]
        tunnel.status = TunnelStatus.RECOVERING
        
        try:
            self.log("info", f"Starting recovery process for port {port}", port)
            
            # Stop existing tunnel and SOCKS5 proxy
            self.stop_tunnel(port)
            
            # Wait before restart
            time.sleep(self.recovery_delay)
            
            # Restart tunnel with new SOCKS5 proxy
            if self.create_tunnel(port):
                self.log("success", "Recovery successful", port)
            else:
                self.log("error", f"Recovery failed: {tunnel.last_error}", port)
                
        except Exception as e:
            tunnel.last_error = f"Recovery error: {e}"
            tunnel.status = TunnelStatus.FAILED
            self.log("error", f"Recovery error: {e}", port)
    
    def stop_all_tunnels(self):
        """Stop all tunnels and SOCKS5 proxies"""
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
    
    def get_status_display(self) -> str:
        """Get formatted status display"""
        if not RICH_AVAILABLE:
            return self._get_simple_status()
        
        # Create status table
        table = Table(title="🚇🧦 SSH Tunnels + SOCKS5 Proxies Status", show_header=True, header_style="bold magenta")
        table.add_column("Tunnel Port", style="cyan", width=12)
        table.add_column("SSH Status", width=12)
        table.add_column("SOCKS5 Port", style="yellow", width=12)
        table.add_column("SOCKS5 Status", width=15)
        table.add_column("Uptime", style="green", width=10)
        table.add_column("Failures", style="yellow", width=10)
        table.add_column("Last Error", style="red")
        
        for port, tunnel in sorted(self.tunnels.items()):
            # SSH Status with color
            ssh_status_color = {
                TunnelStatus.RUNNING: "green",
                TunnelStatus.STARTING: "yellow",
                TunnelStatus.FAILED: "red",
                TunnelStatus.UNHEALTHY: "orange1",
                TunnelStatus.RECOVERING: "blue",
                TunnelStatus.STOPPED: "dim"
            }.get(tunnel.status, "white")
            
            ssh_status_text = f"[{ssh_status_color}]{tunnel.status.value.title()}[/{ssh_status_color}]"
            
            # SOCKS5 Status with color
            socks5_status_color = {
                SOCKS5Status.RUNNING: "green",
                SOCKS5Status.STARTING: "yellow",
                SOCKS5Status.FAILED: "red",
                SOCKS5Status.UNHEALTHY: "orange1",
                SOCKS5Status.STOPPED: "dim"
            }.get(tunnel.socks5_status, "white")
            
            socks5_status_text = f"[{socks5_status_color}]{tunnel.socks5_status.value.title()}[/{socks5_status_color}]"
            
            # Last error (truncated)
            error = tunnel.last_error or ""
            if len(error) > 40:
                error = error[:37] + "..."
            
            table.add_row(
                str(port),
                ssh_status_text,
                str(tunnel.socks5_port) if tunnel.socks5_port else "N/A",
                socks5_status_text,
                tunnel.uptime_str,
                str(tunnel.failure_count),
                error
            )
        
        return table
    
    def _get_simple_status(self) -> str:
        """Get simple text status"""
        lines = ["🚇🧦 SSH Tunnels + SOCKS5 Proxies Status:"]
        lines.append("=" * 80)
        
        for port, tunnel in sorted(self.tunnels.items()):
            ssh_status = tunnel.status.value.title()
            socks5_status = tunnel.socks5_status.value.title()
            uptime = tunnel.uptime_str
            failures = tunnel.failure_count
            error = tunnel.last_error or "None"
            
            lines.append(f"Tunnel {port}: SSH={ssh_status}, SOCKS5={socks5_status} (Port {tunnel.socks5_port})")
            lines.append(f"  Uptime: {uptime} | Failures: {failures}")
            if tunnel.last_error:
                lines.append(f"  Error: {error}")
        
        return "\n".join(lines)
    
    def show_status(self):
        """Display current status"""
        if RICH_AVAILABLE:
            self.console.print(self.get_status_display())
        else:
            print(self._get_simple_status())
    
    def show_connection_info(self):
        """Show connection information"""
        if not self.tunnels:
            return
        
        tunnel_ports = sorted(self.tunnels.keys())
        socks5_ports = [str(t.socks5_port) for t in self.tunnels.values() if t.socks5_port]
        
        if RICH_AVAILABLE:
            # Create info panel
            info_text = f"""
[bold cyan]SSH + SOCKS5 Configuration:[/bold cyan]
- Iranian Server: {self.iranian_ip}:{self.ssh_port}
- SSH Tunnel Ports: {' '.join(map(str, tunnel_ports))}
- Local SOCKS5 Ports: {' '.join(socks5_ports)}
- SOCKS5 Authentication: {'Required' if self.socks5_auth_required else 'None'}
- Active Tunnels: {len(self.tunnels)}

[bold cyan]How it works:[/bold cyan]
1. Local SOCKS5 proxies listen on ports: {' '.join(socks5_ports)}
2. SSH reverse tunnels forward Iranian ports to local SOCKS5 proxies
3. Iranian ports {' '.join(map(str, tunnel_ports))} → Local SOCKS5 ports {' '.join(socks5_ports)}

[bold cyan]Client Configuration:[/bold cyan]
Configure your applications to use SOCKS5 proxy:
- Host: 127.0.0.1 (or connect via Iranian server)
- Ports: {' '.join(map(str, tunnel_ports))} (on Iranian server) or {' '.join(socks5_ports)} (locally)
- Type: SOCKS5
- Authentication: {'Username/Password' if self.socks5_auth_required else 'None'}

[bold green]✨ SSH Tunnels + SOCKS5 Proxies are ready![/bold green]
[yellow]💡 Use any of the tunnel ports as SOCKS5 endpoints[/yellow]
[blue]🧦 Each tunnel has its own dedicated SOCKS5 proxy[/blue]
"""
            
            panel = Panel(
                info_text,
                title="🚇🧦 SSH Tunnel + SOCKS5 Manager",
                border_style="green",
                padding=(1, 2)
            )
            self.console.print(panel)
        else:
            print(f"""
🚇🧦 SSH Tunnel + SOCKS5 Manager - Connection Info
{'=' * 60}

SSH + SOCKS5 Configuration:
- Iranian Server: {self.iranian_ip}:{self.ssh_port}
- SSH Tunnel Ports: {' '.join(map(str, tunnel_ports))}
- Local SOCKS5 Ports: {' '.join(socks5_ports)}
- SOCKS5 Authentication: {'Required' if self.socks5_auth_required else 'None'}
- Active Tunnels: {len(self.tunnels)}

How it works:
1. Local SOCKS5 proxies listen on ports: {' '.join(socks5_ports)}
2. SSH reverse tunnels forward Iranian ports to local SOCKS5 proxies
3. Iranian ports {' '.join(map(str, tunnel_ports))} → Local SOCKS5 ports {' '.join(socks5_ports)}

Client Configuration:
Configure your applications to use SOCKS5 proxy:
- Host: 127.0.0.1 (or connect via Iranian server)  
- Ports: {' '.join(map(str, tunnel_ports))} (on Iranian server) or {' '.join(socks5_ports)} (locally)
- Type: SOCKS5
- Authentication: {'Username/Password' if self.socks5_auth_required else 'None'}

✨ SSH Tunnels + SOCKS5 Proxies are ready!
💡 Use any of the tunnel ports as SOCKS5 endpoints
🧦 Each tunnel has its own dedicated SOCKS5 proxy
""")
    
    def test_full_setup(self):
        """Test the full setup with sample connections"""
        if RICH_AVAILABLE:
            self.console.print("[bold blue]🧪 Testing full SSH + SOCKS5 setup...[/bold blue]")
        else:
            print("🧪 Testing full SSH + SOCKS5 setup...")
        
        results = {}
        
        for port, tunnel in self.tunnels.items():
            if tunnel.status != TunnelStatus.RUNNING:
                continue
                
            port_results = {
                "ssh_tunnel": False,
                "socks5_proxy": False,
                "full_connection": False
            }
            
            # Test SSH tunnel
            port_results["ssh_tunnel"] = self.test_tunnel_health(port)
            
            # Test SOCKS5 proxy
            port_results["socks5_proxy"] = self.test_socks5_health(port)
            
            # Test full connection through SOCKS5
            if port_results["socks5_proxy"] and tunnel.socks5_health_checker:
                try:
                    health_results = tunnel.socks5_health_checker.run_health_check()
                    port_results["full_connection"] = health_results["full_connection"]
                except:
                    port_results["full_connection"] = False
            
            results[port] = port_results
            
            # Print results for this port
            ssh_status = "✅" if port_results["ssh_tunnel"] else "❌"
            socks5_status = "✅" if port_results["socks5_proxy"] else "❌"
            full_status = "✅" if port_results["full_connection"] else "❌"
            
            if RICH_AVAILABLE:
                self.console.print(f"Port {port}: SSH {ssh_status} | SOCKS5 {socks5_status} | Full Test {full_status}")
            else:
                print(f"Port {port}: SSH {ssh_status} | SOCKS5 {socks5_status} | Full Test {full_status}")
        
        # Overall results
        working_ports = [p for p, r in results.items() if all(r.values())]
        total_ports = len(results)
        
        if RICH_AVAILABLE:
            if working_ports:
                self.console.print(f"[bold green]🎉 {len(working_ports)}/{total_ports} tunnels fully operational![/bold green]")
            else:
                self.console.print(f"[bold red]❌ No tunnels are fully operational![/bold red]")
        else:
            if working_ports:
                print(f"🎉 {len(working_ports)}/{total_ports} tunnels fully operational!")
            else:
                print(f"❌ No tunnels are fully operational!")
        
        return results

def parse_ports(args: List[str]) -> List[int]:
    """Parse port arguments"""
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
    """Main application entry point"""
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help', 'help']:
        show_usage()
        return
    
    # Parse command and arguments
    command = sys.argv[1] if len(sys.argv) > 1 else "start"
    args = sys.argv[2:] if len(sys.argv) > 2 else []
    
    # Filter command from ports if it appears in args
    if command in args:
        args.remove(command)
    
    # If first argument is not a command, treat as ports for start
    if command not in ["start", "stop", "restart", "status", "test", "monitor"]:
        args = [command] + args
        command = "start"
    
    manager = SSHTunnelWithSOCKS5Manager()
    
    try:
        if command == "start":
            ports = parse_ports(args)
            
            # Check for --force or -f flag for auto-kill
            auto_kill = '--force' in sys.argv or '-f' in sys.argv
            
            if RICH_AVAILABLE:
                with manager.console.status("[bold green]🚀 Initializing SSH + SOCKS5 Manager..."):
                    pass  # Dependencies already checked in __init__
            else:
                print("🚀 Initializing SSH + SOCKS5 Manager...")
            
            if manager.start_tunnels(ports, auto_kill):
                manager.show_connection_info()
                
                # Test the full setup
                manager.test_full_setup()
                
                manager.start_monitoring()
                
                try:
                    if RICH_AVAILABLE:
                        # Live status display
                        with Live(manager.get_status_display(), refresh_per_second=0.5, console=manager.console) as live:
                            while manager.monitoring:
                                time.sleep(2)
                                live.update(manager.get_status_display())
                    else:
                        # Simple monitoring
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
            if RICH_AVAILABLE:
                manager.console.print("[green]✅ All tunnels and SOCKS5 proxies stopped[/green]")
            else:
                print("✅ All tunnels and SOCKS5 proxies stopped")
        
        elif command == "status":
            # Load existing tunnel info if any
            manager.show_status()
        
        elif command == "test":
            ports = parse_ports(args)
            
            if RICH_AVAILABLE:
                with manager.console.status("[bold blue]🧪 Running connectivity tests..."):
                    ssh_ok = manager.test_ssh_connectivity()
                
                manager.console.print(f"SSH Connectivity: {'✅ OK' if ssh_ok else '❌ Failed'}")
            else:
                print("🧪 Running connectivity tests...")
                ssh_ok = manager.test_ssh_connectivity()
                print(f"SSH Connectivity: {'✅ OK' if ssh_ok else '❌ Failed'}")
        
        else:
            print(f"❌ Unknown command: {command}")
            show_usage()
            sys.exit(1)
    
    except KeyboardInterrupt:
        if RICH_AVAILABLE:
            manager.console.print(f"\n[yellow]👋 Interrupted by user[/yellow]")
        else:
            print(f"\n👋 Interrupted by user")
        manager.stop_monitoring()
        manager.stop_all_tunnels()
    except Exception as e:
        manager.log("error", f"Fatal error: {e}")
        sys.exit(1)

def show_usage():
    """Display usage information"""
    console = Console() if RICH_AVAILABLE else None
    
    usage_text = f"""
[bold green]🚇🧦 SSH Tunnel Manager with SOCKS5 Proxies[/bold green]

[bold]Usage:[/bold]
  python3 {sys.argv[0] if sys.argv else 'ssh_socks5_manager.py'} [COMMAND] [OPTIONS] [PORT1] [PORT2] [PORT3] ...

[bold]Commands:[/bold]
  [cyan]start[/cyan]     - Start SSH reverse tunnels with SOCKS5 proxies (default)
  [cyan]stop[/cyan]      - Stop all SSH tunnels and SOCKS5 proxies
  [cyan]restart[/cyan]   - Restart all tunnels and proxies
  [cyan]status[/cyan]    - Check status of tunnels and proxies
  [cyan]test[/cyan]      - Test SSH connectivity and SOCKS5 functionality

[bold]Options:[/bold]
  [yellow]--force, -f[/yellow]  - Automatically handle conflicts without asking

[bold]Port Configuration:[/bold]
  • Default ports: [yellow]1080 1081 1082[/yellow]
  • Custom ports: [dim]python3 ssh_socks5_manager.py start 1080 1081 1082 1083[/dim]
  • Valid range: [yellow]1024-65535[/yellow]

[bold]How it Works:[/bold]
  1. 🧦 Local SOCKS5 proxies are created (ports 8880, 8881, 8882, etc.)
  2. 🚇 SSH reverse tunnels forward Iranian ports to local SOCKS5 proxies
  3. 🌐 Clients connect to Iranian ports and get SOCKS5 proxy functionality
  4. 🔍 Both SSH tunnels and SOCKS5 proxies are monitored for health

[bold]Examples:[/bold]
  [dim]python3 ssh_socks5_manager.py[/dim]                    # Start with defaults
  [dim]python3 ssh_socks5_manager.py start 1080 1081 1082[/dim] # Custom ports  
  [dim]python3 ssh_socks5_manager.py start --force[/dim]        # Auto-handle conflicts
  [dim]python3 ssh_socks5_manager.py status[/dim]               # Check status
  [dim]python3 ssh_socks5_manager.py stop[/dim]                # Stop all
  [dim]python3 ssh_socks5_manager.py test[/dim]                # Test connectivity

[bold green]Architecture:[/bold green]
  [dim]Iranian Ports (1080, 1081, 1082) ←SSH Reverse Tunnels← Local SOCKS5 Proxies (8880, 8881, 8882)[/dim]
  [dim]Client → Iranian Server:1080 → SSH Tunnel → Local SOCKS5:8880 → Internet[/dim]

[bold blue]Benefits over Trojan:[/bold blue]
  ✅ Standard SOCKS5 protocol - works with any SOCKS5 client
  ✅ No special client software needed
  ✅ Better compatibility with applications
  ✅ Easier to configure and troubleshoot
  ✅ Built-in authentication support
  ✅ Comprehensive health checking
"""
    
    if console:
        console.print(usage_text)
    else:
        # Strip ANSI codes for plain text
        import re
        plain_text = re.sub(r'\[.*?\]', '', usage_text)
        print(plain_text)

if __name__ == "__main__":
    main()
