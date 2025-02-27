#!/usr/bin/env python3
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll, Center
from textual.widgets import Header, Footer, Static, DataTable, Button, Label
from textual.widgets.data_table import ColumnKey
from textual.coordinate import Coordinate
from textual import events
from textual.binding import Binding
from textual.screen import ModalScreen
from textual.css.query import NoMatches
from rich.text import Text
from rich.syntax import Syntax
import subprocess
from collections import defaultdict
import re
import socket
import asyncio
import os
from typing import Optional, List, Dict, TYPE_CHECKING
from datetime import datetime, timedelta
import urllib.request
from urllib.error import URLError
from html.parser import HTMLParser
import netifaces
import ipaddress

if TYPE_CHECKING:
    from typing import Type
    from textual.widgets import DataTable

class ConnectionTable:  # Forward declaration
    pass

# Configuration
MONITORED_PORTS = ["80", "443"]
MONITORED_STATES = ["ESTABLISHED", "TIME_WAIT", "SYN_RECV"]
PORTS_DISPLAY = "/".join(MONITORED_PORTS)
APACHE_STATUS_URL = "http://127.0.0.1/whm-server-status"

def get_server_addresses():
    """Get all IP addresses (IPv4 and IPv6) of the server."""
    try:
        server_ips = set()
        
        # Get all interfaces
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            
            # Get IPv4 addresses
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    server_ips.add(addr['addr'])
                    
            # Get IPv6 addresses
            if netifaces.AF_INET6 in addrs:
                for addr in addrs[netifaces.AF_INET6]:
                    # Remove scope id if present (e.g., %eth0)
                    ip = addr['addr'].split('%')[0]
                    server_ips.add(ip)
        
        return server_ips
    except ImportError:
        return set(['127.0.0.1', '::1'])  # Fallback to basic loopback addresses
    except Exception:
        return set(['127.0.0.1', '::1'])  # Fallback on any error

# Initialize server addresses
SERVER_ADDRESSES = get_server_addresses()

# Test mode configuration
TEST_MODE = False  # Set to False to use real netstat
TEST_DATA_FILE = os.path.join(os.path.dirname(__file__), "test_data", "netstat_sample.txt")

# Global state for CSF status
ip_csf_status = {}

def is_excluded_ip(ip: str) -> bool:
    """Check if an IP should be excluded from monitoring."""
    import ipaddress
    
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        # Check if it's a loopback address
        if ip_obj.is_loopback:
            return True
            
        # Check if it's one of our server addresses
        if ip in SERVER_ADDRESSES:
            return True
            
        return False
    except ValueError:
        return False  # If IP is invalid, don't exclude it

def get_netstat_output():
    """Get netstat output either from test file or real command."""
    if TEST_MODE:
        try:
            with open(TEST_DATA_FILE, 'r') as f:
                return f.read()
        except FileNotFoundError:
            return ""
    
    try:
        cmd = ["netstat", "-tn"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError:
        return ""

def get_connection_data():
    """Fetch and aggregate network connection data."""
    try:
        output = get_netstat_output()
        
        # Initialize aggregation dictionary
        connections = {}
        
        # Process each line
        for line in output.splitlines():
            if "tcp" not in line.lower():
                continue
                
            parts = line.split()
            if len(parts) < 6:
                continue
                
            # Extract remote IP and local port
            local_addr = parts[3]
            remote_addr = parts[4]
            
            # Handle IPv4 (format: 192.168.1.1:80)
            if "." in local_addr:
                local_port = local_addr.split(":")[-1]
                remote_ip = remote_addr.rsplit(":", 1)[0]  # Use rsplit to handle IPv4 port
            # Handle IPv6 (format: 2a01:4f9:2b:1f2d::56508)
            else:
                try:
                    local_port = local_addr.rsplit(":", 1)[1]  # Get port after last colon
                    remote_ip = remote_addr.rsplit(":", 1)[0]  # Get IP without port
                except (IndexError, ValueError):
                    continue
            
            # Skip if it's a server address or loopback
            if is_excluded_ip(remote_ip):
                continue
                
            if local_port not in MONITORED_PORTS:
                continue
                
            state = parts[5]
            if state in MONITORED_STATES:
                if remote_ip not in connections:
                    connections[remote_ip] = {
                        'ESTABLISHED': 0,
                        'TIME_WAIT': 0,
                        'SYN_RECV': 0,
                        'csf_status': ''
                    }
                connections[remote_ip][state] += 1
        
        return connections
    except subprocess.CalledProcessError as e:
        return {}

def format_block_time(until_time: datetime) -> str:
    """Format block time in a human-readable format."""
    now = datetime.now()
    if until_time < now:
        return "Block expired"
    
    time_str = until_time.strftime("%H:%M")
    
    # If it's tomorrow, add the day
    if until_time.date() > now.date():
        time_str = until_time.strftime("%b %d %H:%M")
    
    return f"Blocked until {time_str}"

def check_csf(ip: str) -> str:
    """Check if IP is in CSF."""
    try:
        result = subprocess.check_output(["csf", "-g", ip], text=True)
        if "DENY" in result:
            # Try to extract if it's temporary and when it expires
            if "Temporary Block" in result:
                for line in result.splitlines():
                    if "expires at" in line.lower():
                        try:
                            # Extract and parse the expiry time
                            time_str = line.split("expires at")[1].strip()
                            expiry = datetime.strptime(time_str, "%a %b %d %H:%M:%S %Y")
                            return format_block_time(expiry)
                        except (ValueError, IndexError):
                            pass
                return "Temporarily blocked"
            return "Permanently blocked"
        return "Not blocked"
    except subprocess.CalledProcessError:
        return "Not blocked"
    except FileNotFoundError:
        return "CSF not installed"

def block_in_csf(ip: str, is_temporary: bool = True, duration: int = 600) -> str:
    """Block IP in CSF."""
    global ip_csf_status
    
    if is_temporary:
        cmd = ["csf", "-td", ip, str(duration)]
        status = format_block_time(datetime.now() + timedelta(seconds=duration))
    else:
        cmd = ["csf", "-d", ip]
        status = "Permanently blocked"
        
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        ip_csf_status[ip] = status
        return "Success"
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr}"
    except FileNotFoundError:
        return "CSF not installed"

def perform_ptr_lookup(ip):
    """Perform PTR lookup for an IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "No PTR record found"

def perform_whois_lookup(ip):
    """Perform WHOIS lookup for an IP address."""
    try:
        result = subprocess.check_output(["whois", ip], text=True)
        return result
    except subprocess.CalledProcessError:
        return "WHOIS lookup failed"

def get_subnet(ip: str) -> str:
    """Convert an IP address to its subnet with default mask (/24 for IPv4, /64 for IPv6)."""
    try:
        # Check if it's IPv6
        if ":" in ip:
            # Split the IPv6 address into segments
            segments = ip.split(":")
            # Take first 4 segments (64 bits) and pad with zeros
            subnet = ":".join(segments[:4]) + "::" + "/64"
            return subnet
        else:
            # For IPv4, take first 3 octets
            segments = ip.split(".")
            if len(segments) == 4:
                return ".".join(segments[:3]) + ".0/24"
            return ip + "/24"  # Fallback
    except Exception:
        return ip  # Return original IP if parsing fails

class ApacheStatusParser(HTMLParser):
    """Parser for Apache server-status page."""
    
    def __init__(self):
        super().__init__()
        self.in_table = False
        self.in_tr = False
        self.in_td = False
        self.current_row = []
        self.current_cell = []
        self.connections = []
        self.is_header = False
        self.column_indices = {}  # Maps column names to indices
        
    def handle_starttag(self, tag, attrs):
        if tag == 'table':
            self.in_table = True
        elif tag == 'tr':
            self.in_tr = True
            self.current_row = []
        elif tag == 'th':
            self.is_header = True
            self.in_td = True
            self.current_cell = []
        elif tag == 'td':
            self.in_td = True
            self.current_cell = []
            
    def handle_endtag(self, tag):
        if tag == 'table':
            self.in_table = False
        elif tag == 'tr':
            self.in_tr = False
            if self.is_header:
                # Process header row to get column indices
                self.process_header_row(self.current_row)
                self.is_header = False
            else:
                # Process data row
                self.process_data_row(self.current_row)
        elif tag in ('th', 'td'):
            self.in_td = False
            cell_content = ''.join(self.current_cell).strip()
            self.current_row.append(cell_content)
            self.current_cell = []
            
    def handle_data(self, data):
        if self.in_td:
            self.current_cell.append(data)
            
    def process_header_row(self, row):
        """Process the header row to map column names to indices."""
        for i, header in enumerate(row):
            self.column_indices[header.lower()] = i
            
    def process_data_row(self, row):
        """Process a data row and extract connection information."""
        if not row or len(row) < len(self.column_indices):
            return
            
        try:
            conn = {
                'client_ip': row[self.column_indices['client']],
                'protocol': row[self.column_indices['protocol']],
                'vhost': row[self.column_indices['vhost']],
                'request': row[self.column_indices['request']],
                'srv': row[self.column_indices['srv']],
                'pid': row[self.column_indices['pid']],
                'cpu': row[self.column_indices['cpu']],
                'ss': row[self.column_indices['ss']],  # Seconds since beginning of most recent request
                'acc': row[self.column_indices['acc']],  # Number of accesses this connection / this child / this slot
                'status': row[self.column_indices['m']],  # Status of the connection
                'conn': row[self.column_indices['conn']]  # Kilobytes transferred this connection
            }
            
            # Parse the request field into method, path, and protocol
            request_parts = conn['request'].split()
            if len(request_parts) >= 3:
                conn['method'] = request_parts[0]
                conn['path'] = request_parts[1]
                conn['protocol_version'] = request_parts[2]
            else:
                conn['method'] = ''
                conn['path'] = ''
                conn['protocol_version'] = ''
                
            # Only add connections that have actual client data
            if conn['client_ip'] and conn['client_ip'] not in ('-', ''):
                self.connections.append(conn)
                
        except (KeyError, IndexError) as e:
            # Skip malformed rows
            pass
            
    def get_connections(self) -> List[Dict[str, str]]:
        """Return the list of parsed connections."""
        return self.connections

def get_apache_status(ip: str) -> List[Dict[str, str]]:
    """Fetch and parse Apache status page for connections from specific IP."""
    try:
        with urllib.request.urlopen(APACHE_STATUS_URL) as response:
            html = response.read().decode('utf-8')
            
        parser = ApacheStatusParser()
        parser.feed(html)
        
        # Filter connections for specific IP
        return [conn for conn in parser.get_connections() if conn['client_ip'] == ip]
    except URLError as e:
        return []
    except Exception as e:
        return []

class TitleBox(Static):
    """Title and welcome message widget."""
    DEFAULT_CSS = """
    TitleBox {
        height: 3;
        content-align: center middle;
        background: $boost;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("Network Connection Monitor", classes="title")
        yield Button("Refresh", variant="primary", id="refresh_btn")

class WhoisScreen(ModalScreen[None]):
    """Modal screen for displaying WHOIS information."""
    
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Close"),
        Binding("q", "app.pop_screen", "Close"),
    ]
    
    DEFAULT_CSS = """
    ApacheStatusScreen {
        align: center middle;
    }
    
    #whois-container {
        width: 90%;
        height: 90%;
        border: thick $primary;
        background: $surface;
        padding: 1;
    }
    
    #whois-content {
        width: 100%;
        height: 100%;
        background: $surface;
        overflow-y: scroll;
    }
    
    #whois-header {
        background: $accent;
        color: $text;
        padding: 1;
        text-align: center;
        width: 100%;
    }
    
    #close-button {
        dock: bottom;
        width: 100%;
        margin: 1;
    }
    
    #refresh-message {
        color: $success;
        text-align: center;
        margin: 1;
    }
    """
    
    def __init__(self, ip: str, connections: List[Dict[str, str]], connection_table: 'ConnectionTable'):
        super().__init__()
        self.ip = ip
        self.connections = connections
        self.refresh_message = Static("", id="refresh-message")
        self.connection_table = connection_table
        
    def compose(self) -> ComposeResult:
        with Container(id="whois-container"):
            yield Label(f"WHOIS Information - {self.ip}", id="whois-header")
            with VerticalScroll(id="whois-content"):
                # Format WHOIS data with syntax highlighting
                syntax = Syntax(
                    self.whois_data,
                    "whois",
                    theme="monokai",
                    word_wrap=True,
                    padding=(0, 1),
                )
                yield Static(syntax)
            with Center():
                yield Button("Close (ESC/Q)", variant="primary", id="close-button")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "close-button":
            self.app.pop_screen()

class ApacheStatusScreen(ModalScreen):
    """Modal screen for displaying Apache status information."""
    
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Close"),
        Binding("q", "app.pop_screen", "Close"),
        Binding("r", "refresh", "Refresh", show=True),
    ]
    
    DEFAULT_CSS = """
    ApacheStatusScreen {
        align: center middle;
    }
    
    #status-container {
        width: 95%;
        height: 95%;
        border: thick $primary;
        background: $surface;
        padding: 1;
    }
    
    #status-header {
        background: $accent;
        color: $text;
        padding: 1;
        text-align: center;
        width: 100%;
    }
    
    #status-table {
        width: 100%;
        height: 85%;
    }
    
    #close-button {
        dock: bottom;
        width: 100%;
        margin: 1;
    }
    
    #refresh-message {
        color: $success;
        text-align: center;
        margin: 1;
    }
    """
    
    def __init__(self, ip: str, connections: List[Dict[str, str]], connection_table: 'ConnectionTable'):
        super().__init__()
        self.ip = ip
        self.connections = connections
        self.refresh_message = Static("", id="refresh-message")
        self.connection_table = connection_table
        
    def compose(self) -> ComposeResult:
        with Container(id="status-container"):
            yield Label(f"Apache Status for {self.ip}", id="status-header")
            yield self.refresh_message
            
            # Create DataTable
            table = DataTable(id="status-table")
            table.add_columns(
                "Server",
                "Status",
                "VHost",
                "Method",
                "Path",
                "Protocol",
                "CPU%",
                "Accesses",
                "Traffic(KB)",
                "Time(s)"
            )
            
            # Add rows to table
            if self.connections:
                for conn in self.connections:
                    table.add_row(
                        conn['srv'],
                        conn['status'] or '.',
                        conn['vhost'],
                        conn['method'],
                        conn['path'],
                        f"{conn['protocol']} {conn['protocol_version']}",
                        conn['cpu'],
                        conn['acc'],
                        conn['conn'],
                        conn['ss']
                    )
            else:
                table.add_row(
                    "No active connections found",
                    "", "", "", "", "", "", "", "", ""
                )
                
            yield table
            yield Button("Close", variant="primary", id="close-button")
            
    async def action_refresh(self) -> None:
        """Refresh the Apache status data."""
        self.refresh_message.update("Refreshing...")
        
        # Get fresh connection data
        try:
            new_connections = await self.connection_table.run_in_thread(
                get_apache_status, self.ip
            )
            
            # Clear existing table data
            table = self.query_one(DataTable)
            table.clear()
            
            # Add new data
            if new_connections:
                for conn in new_connections:
                    table.add_row(
                        conn['srv'],
                        conn['status'] or '.',
                        conn['vhost'],
                        conn['method'],
                        conn['path'],
                        f"{conn['protocol']} {conn['protocol_version']}",
                        conn['cpu'],
                        conn['acc'],
                        conn['conn'],
                        conn['ss']
                    )
                self.refresh_message.update(f"Refreshed: {len(new_connections)} connections found")
            else:
                table.add_row(
                    "No active connections found",
                    "", "", "", "", "", "", "", "", ""
                )
                self.refresh_message.update("Refreshed: No active connections found")
                
            self.connections = new_connections
            
        except Exception as e:
            self.refresh_message.update(f"Error refreshing: {str(e)}")
            
        # Schedule the message to clear after 3 seconds
        self.set_timer(3.0, self.clear_refresh_message)
            
    def clear_refresh_message(self) -> None:
        """Clear the refresh message."""
        self.refresh_message.update("")
            
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close-button":
            self.app.pop_screen()

class ActivityLog(VerticalScroll):
    """A widget to display application activity and messages."""

    DEFAULT_CSS = """
    ActivityLog {
        height: 8;
        dock: bottom;
        background: $surface;
        border-top: solid $primary;
        padding: 0 1 1 1;
        margin-bottom: 1;
    }

    ActivityLog > .log-entry {
        color: $text;
        height: 1;
    }

    ActivityLog > .log-entry.info {
        color: $text;
    }

    ActivityLog > .log-entry.warning {
        color: $warning;
    }

    ActivityLog > .log-entry.error {
        color: $error;
    }

    ActivityLog > .log-entry.success {
        color: $success;
    }
    """

    def __init__(self):
        super().__init__()
        self.max_entries = 100
        self.entries = []

    def log_message(self, message: str, level: str = "info") -> None:
        """Add a new message to the log."""
        entry = Static(message, classes=f"log-entry {level}")
        self.entries.append(entry)
        
        # Remove old entries if we exceed max_entries
        while len(self.entries) > self.max_entries:
            self.entries.pop(0)
            if self.entries[0] in self.children:
                self.entries[0].remove()

        # Add the new entry and scroll to it
        self.mount(entry)
        self.scroll_end(animate=False)

class AttackAnalyzer:
    """Analyzes connection patterns to detect potential attacks."""
    
    def __init__(self):
        self.SYN_ATTACK_THRESHOLD = 30
        self.CONN_LIMIT_THRESHOLD = 30
        self.HTTP_EXHAUSTION_THRESHOLD = 10
        
    def analyze_connections(self, connections: dict, apache_connections: List[Dict[str, str]] = None) -> Dict[str, List[str]]:
        """
        Analyze connections for attack patterns.
        Returns a dictionary mapping IP addresses to lists of detected attack types.
        """
        results = defaultdict(list)
        
        # Group Apache connections by IP and VHost for WordPress attack detection
        wp_connections = defaultdict(lambda: defaultdict(int))
        if apache_connections:
            for conn in apache_connections:
                if 'wp-login' in conn.get('request', '').lower() or 'xmlrpc' in conn.get('request', '').lower():
                    wp_connections[conn['client_ip']][conn['vhost']] += 1
        
        # Analyze each IP's connections
        for ip, data in connections.items():
            # SYN Attack Detection
            if int(data.get('SYN_RECV', 0)) > self.SYN_ATTACK_THRESHOLD:
                results[ip].append("SYN Attack")
            
            # Connection Limit Attack Detection
            if int(data.get('ESTABLISHED', 0)) > self.CONN_LIMIT_THRESHOLD:
                results[ip].append("ConnLimit Attack")
            
            # WordPress Attack Detection
            if ip in wp_connections:
                vhosts = wp_connections[ip]
                total_wp_requests = sum(vhosts.values())
                
                if len(vhosts) > 1 and total_wp_requests > 5:
                    results[ip].append("WP Distributed BruteForce")
                elif len(vhosts) == 1 and total_wp_requests > 10:
                    results[ip].append("WP Directed BruteForce")
            
            # HTTP Exhaustion Attack Detection
            if apache_connections:
                request_count = sum(1 for conn in apache_connections if conn['client_ip'] == ip)
                if request_count > self.HTTP_EXHAUSTION_THRESHOLD:
                    results[ip].append("HTTP Exhaustion")
        
        return results

class ConnectionTable(DataTable):
    """A custom DataTable for displaying network connections."""

    BINDINGS = [
        Binding("p", "ptr_lookup", "PTR Lookup", show=True),
        Binding("w", "whois_lookup", "WHOIS", show=True),
        Binding("c", "csf_check", "CSF Check", show=True),
        Binding("t", "block_temp", "Temp Block IP", show=True),
        Binding("s", "block_subnet", "Temp Block Subnet", show=True),
        Binding("b", "block_perm", "Perm Block IP", show=True),
        Binding("a", "apache_status", "Apache Status", show=True),
        Binding("x", "analyze_attacks", "Analyze Attacks", show=True),
        Binding("1", "sort(0)", "Sort by IP", show=True),
        Binding("2", "sort(1)", "Sort by CSF Status", show=True),
        Binding("3", "sort(2)", "Sort by Established", show=True),
        Binding("4", "sort(3)", "Sort by Time Wait", show=True),
        Binding("5", "sort(4)", "Sort by SYN Recv", show=True),
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.current_data = []
        self.sorted_column = None
        self.sort_reverse = False

    def on_mount(self) -> None:
        """Set up the data table."""
        self.cursor_type = "row"
        self.selected_row_index = None
        self._sort_column = 0  # Track current sort column
        self._sort_reverse = False  # Track sort direction
        self._raw_data = {}  # Store raw connection data
        
    def update_data(self):
        """Update table with fresh connection data."""
        self._raw_data = get_connection_data()
        self._refresh_table_display()
            
    def _get_sort_key(self, ip, data):
        """Get the sort key for the given IP and data."""
        if self._sort_column == 0:
            return ip
        elif self._sort_column == 1:
            return data.get('csf_status', 'Unknown')
        elif self._sort_column == 2:
            return int(data.get('ESTABLISHED', 0))
        elif self._sort_column == 3:
            return int(data.get('TIME_WAIT', 0))
        elif self._sort_column == 4:
            return int(data.get('SYN_RECV', 0))
        else:
            return ""
        
    def _refresh_table_display(self, preserve_selection: bool = True) -> None:
        """Refresh the table display using current data without fetching new connections."""
        # Store current selection before clearing
        current_ip = self.get_selected_ip() if preserve_selection else None
        
        self.clear()
        # analyzer = AttackAnalyzer()
        # attack_results = analyzer.analyze_connections(self._raw_data)
        
        # Format the data for display
        rows_data = []
        for ip, data in self._raw_data.items():
            csf_status = data.get('csf_status', '')
            established = str(data.get('ESTABLISHED', 0))
            time_wait = str(data.get('TIME_WAIT', 0))
            syn_recv = str(data.get('SYN_RECV', 0))
            # attacks = attack_results.get(ip, [])
            attacks = False
            attack_text = ", ".join(attacks) if attacks else ""
            
            rows_data.append((ip, csf_status, established, time_wait, syn_recv, attack_text, bool(attacks)))
        
        # Sort the data if needed
        if self._sort_column is not None:
            rows_data.sort(
                key=lambda x: (
                    int(x[self._sort_column]) if self._sort_column in [2, 3, 4] and x[self._sort_column].isdigit()
                    else x[self._sort_column]
                ),
                reverse=self._sort_reverse
            )
        
        # Add rows to the table
        for i, row_data in enumerate(rows_data):
            row = self.add_row(*row_data[:-1], key=str(i))
            if row_data[-1]:  # If has attacks
                for cell in self.get_row_at(i):
                    cell.style = "color: red"
                
        # Restore selection if possible and desired
        if current_ip:
            for i, row_data in enumerate(rows_data):
                if row_data[0] == current_ip:
                    self.move_cursor(row=i)
                    break
                    
    async def run_in_thread(self, func, *args):
        """Run a function in a thread pool."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, func, *args)

    async def action_ptr_lookup(self) -> None:
        """Perform PTR lookup for selected IP."""
        ip = self.get_selected_ip()
        if ip:
            log = self.app.query_one(ActivityLog)
            log.log_message(f"Performing PTR lookup for {ip}...", "info")
            result = await self.run_in_thread(perform_ptr_lookup, ip)
            log.log_message(f"PTR Lookup for {ip}: {result}", "success")

    async def action_whois_lookup(self) -> None:
        """Perform WHOIS lookup for selected IP."""
        ip = self.get_selected_ip()
        if ip:
            self.app.query_one(ActivityLog).log_message(f"Fetching WHOIS information for {ip}...", "info")
            result = await self.run_in_thread(perform_whois_lookup, ip)
            self.app.push_screen(WhoisScreen(ip, result))

    async def action_csf_check(self) -> None:
        """Check if IP is in CSF."""
        ip = self.get_selected_ip()
        if not ip:
            return
            
        log = self.app.query_one(ActivityLog)
        try:
            csf_status = await self.run_in_thread(check_csf, ip)
            # Update the CSF status in the raw data
            if ip in self._raw_data:
                self._raw_data[ip]['csf_status'] = csf_status
            log.log_message(f"CSF Status for {ip}: {csf_status}", "info")
            # Refresh display to show updated status
            self._refresh_table_display()
        except Exception as e:
            log.log_message(f"Error checking CSF status: {str(e)}", "error")

    async def action_block_temp(self) -> None:
        """Block IP temporarily in CSF."""
        ip = self.get_selected_ip()
        if not ip:
            return
            
        log = self.app.query_one(ActivityLog)
        log.log_message(f"Blocking {ip} temporarily...", "warning")
        result = await self.run_in_thread(block_in_csf, ip, True)
        csf_status = await self.run_in_thread(check_csf, ip)
        if ip in self._raw_data:
            self._raw_data[ip]['csf_status'] = csf_status
        log.log_message(f"Temporary block for {ip}: {result}", "success")
        self._refresh_table_display()

    async def action_block_subnet(self) -> None:
        """Block the subnet of the selected IP temporarily."""
        ip = self.get_selected_ip()
        if not ip:
            return
            
        log = self.app.query_one(ActivityLog)
        subnet = get_subnet(ip)
        
        if subnet == ip:
            log.log_message(f"Failed to calculate subnet for {ip}", "error")
            return
            
        log.log_message(f"Blocking subnet {subnet} temporarily...", "info")
        result = await self.run_in_thread(block_in_csf, subnet, True)
        log.log_message(f"Temporary block for subnet {subnet}: {result}", "success")
        self._refresh_table_display()

    async def action_block_perm(self) -> None:
        """Block IP permanently in CSF."""
        ip = self.get_selected_ip()
        if not ip:
            return
            
        log = self.app.query_one(ActivityLog)
        log.log_message(f"Blocking {ip} permanently...", "warning")
        result = await self.run_in_thread(block_in_csf, ip, False)
        csf_status = await self.run_in_thread(check_csf, ip)
        if ip in self._raw_data:
            self._raw_data[ip]['csf_status'] = csf_status
        log.log_message(f"Permanent block for {ip}: {result}", "success")
        self._refresh_table_display()

    async def action_apache_status(self) -> None:
        """Show Apache status information for selected IP."""
        ip = self.get_selected_ip()
        if not ip:
            return
            
        log = self.app.query_one(ActivityLog)
        log.log_message(f"Fetching Apache status for {ip}...", "info")
        
        # Fetch Apache status in a thread to avoid blocking
        connections = await self.run_in_thread(get_apache_status, ip)
        
        if connections:
            log.log_message(f"Found {len(connections)} Apache connections for {ip}", "success")
        else:
            log.log_message(f"No Apache connections found for {ip}", "warning")
            
        self.app.push_screen(ApacheStatusScreen(ip, connections, self))

    async def action_analyze_attacks(self) -> None:
        """Analyze connections for potential attacks."""
        log = self.app.query_one(ActivityLog)
        log.log_message("Analyzing connections for potential attacks...", "info")
        
        try:
            # Use current connection data
            connections = self._raw_data
            if not connections:
                log.log_message("No connection data available for analysis", "warning")
                return

            # Only fetch Apache status for IPs with high connection counts
            apache_connections = []
            suspicious_ips = [
                ip for ip, data in connections.items()
                if (int(data.get('ESTABLISHED', 0)) > 50 or 
                    int(data.get('TIME_WAIT', 0)) > 50)
            ]
            
            if suspicious_ips:
                log.log_message(f"Checking Apache status for {len(suspicious_ips)} suspicious IPs...", "info")
                for ip in suspicious_ips:
                    try:
                        apache_conn = await self.run_in_thread(get_apache_status, ip)
                        if apache_conn:
                            apache_connections.extend(apache_conn)
                    except Exception as e:
                        log.log_message(f"Error fetching Apache status for {ip}: {str(e)}", "error")
            
            # Run attack analysis
            analyzer = AttackAnalyzer()
            results = analyzer.analyze_connections(connections, apache_connections)
            
            # Log results and update display
            attack_count = 0
            for ip, attacks in results.items():
                if attacks:
                    attack_count += 1
                    log.log_message(f"Potential attacks detected from {ip}: {', '.join(attacks)}", "warning")
                    if ip in self._raw_data:
                        self._raw_data[ip]['attack_text'] = ', '.join(attacks)
                        self._raw_data[ip]['attacks'] = True
            if attack_count == 0:
                log.log_message("No attacks detected in current connections", "success")
            else:
                log.log_message(f"Found potential attacks from {attack_count} IPs", "warning")
            
            # Refresh the table display to show attack results
            self._refresh_table_display()
            
        except Exception as e:
            log.log_message(f"Error during attack analysis: {str(e)}", "error")

    def action_sort(self, column_index: int) -> None:
        """Sort the table by the specified column."""
        if self._sort_column == column_index:
            # If already sorting by this column, toggle direction
            self._sort_reverse = not self._sort_reverse
        else:
            # If sorting by a new column, set it and default to ascending
            self._sort_column = column_index
            self._sort_reverse = False
            
        # Refresh without preserving selection for sort operations
        self._refresh_table_display(preserve_selection=False)
        
        # Log the sort action
        direction = "descending" if self._sort_reverse else "ascending"
        column_names = ["IP", "CSF Status", "ESTABLISHED", "TIME_WAIT", "SYN_RECV", "Attack Analysis"]
        message = f"Sorted by {column_names[column_index]} ({direction})"
        self.app.query_one(ActivityLog).log_message(message, "info")
        
    def on_mount(self) -> None:
        """Set up the table columns."""
        self.add_columns(
            "IP Address",
            "CSF Status",
            "ESTABLISHED",
            "TIME_WAIT", 
            "SYN_RECV",
            "Attack Analysis"
        )
        self.update_data()
        
    def on_data_table_row_selected(self, event) -> None:
        """Handle row selection."""
        self.selected_row_index = event.cursor_row
        ip = self.get_row_at(event.cursor_row)[0]
        self.app.query_one(ActivityLog).log_message(f"Selected IP: {ip}", "info")

    def on_data_table_row_highlighted(self, event) -> None:
        """Handle row highlight from keyboard navigation."""
        self.selected_row_index = event.cursor_row
        ip = self.get_row_at(event.cursor_row)[0]
        self.app.query_one(ActivityLog).log_message(f"Selected IP: {ip}", "info")

    def get_selected_ip(self) -> Optional[str]:
        """Get the currently selected IP address."""
        try:
            if self.cursor_row is None:
                self.app.query_one(ActivityLog).log_message("Please select an IP address first", "warning")
                return None
            return self.get_cell_at(Coordinate(self.cursor_row, 0))
        except Exception:
            return None

class NetworkApp(App):
    """The main network monitoring application."""
    
    CSS = """
    Screen {
        align: center middle;
    }
    
    DataTable {
        height: 1fr;
        border: solid green;
    }
    
    WhoisScreen {
        align: center middle;
    }
    
    .whois {
        width: 80%;
        height: 80%;
        border: thick $background 80%;
        background: $surface;
    }
    """
    
    BINDINGS = [
        ("r", "refresh", "Refresh data"),
        ("q", "quit", "Quit"),
    ]
    
    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header()
        yield ConnectionTable()
        yield ActivityLog()
        yield Footer()

    def on_mount(self) -> None:
        """Handle app mount event."""
        # Initial data load
        self.query_one(ActivityLog).log_message("Application started", "info")
        self.query_one(ConnectionTable).update_data()
        self.query_one(ActivityLog).log_message("Initial data loaded", "success")

    def action_refresh(self) -> None:
        """Refresh the connection data."""
        self.query_one(ActivityLog).log_message("Refreshing connection data...", "info")
        self.query_one(ConnectionTable).update_data()
        self.query_one(ActivityLog).log_message("Data refreshed", "success")

def main():
    app = NetworkApp()
    app.run()

if __name__ == "__main__":
    main()
