#!/usr/bin/env python3
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll, Center
from textual.widgets import Header, Footer, Static, DataTable, Button, Label
from textual.widgets.data_table import ColumnKey
from textual.coordinate import Coordinate
from textual import events
from textual.binding import Binding
from textual.screen import ModalScreen
from rich.text import Text
from rich.syntax import Syntax
import subprocess
from collections import defaultdict
import re
import socket
import asyncio
import os
from typing import Optional
from datetime import datetime, timedelta

# Configuration
MONITORED_PORTS = ["80", "443"]
MONITORED_STATES = ["ESTABLISHED", "TIME_WAIT", "SYN_RECV"]
PORTS_DISPLAY = "/".join(MONITORED_PORTS)

# Test mode configuration
TEST_MODE = True  # Set to False to use real netstat
TEST_DATA_FILE = os.path.join(os.path.dirname(__file__), "test_data", "netstat_sample.txt")

# Global state for CSF status
ip_csf_status = {}

def get_netstat_output():
    """Get netstat output either from test file or real command."""
    if TEST_MODE:
        try:
            with open(TEST_DATA_FILE, 'r') as f:
                return f.read()
        except FileNotFoundError:
            return ""
    else:
        try:
            # Build netstat command with state filtering
            state_filter = " || ".join(f"$6 ~ /^{state}$/" for state in MONITORED_STATES)
            port_filter = " || ".join(f"$4 ~ /:{port}/" for port in MONITORED_PORTS)
            cmd = f"netstat -ant | awk '({port_filter}) && ({state_filter})'"
            return subprocess.check_output(cmd, shell=True, text=True)
        except subprocess.CalledProcessError:
            return ""

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
            if "Temporary block" in result:
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

def get_connection_data():
    """Fetch and aggregate network connection data."""
    try:
        output = get_netstat_output()
        
        # Initialize aggregation dictionary
        connections = defaultdict(lambda: {port: defaultdict(int) for port in MONITORED_PORTS})
        
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
                
            if local_port not in MONITORED_PORTS:
                continue
                
            state = parts[5]
            if state in MONITORED_STATES:
                connections[remote_ip][local_port][state] += 1
        
        # Format data for table
        table_data = []
        for remote_ip, ports in connections.items():
            row = [
                remote_ip,
                ip_csf_status.get(remote_ip, "")  # Add CSF status column
            ]
            # Add counts for each monitored state
            for state in MONITORED_STATES:
                state_count = sum(ports[port].get(state, 0) for port in MONITORED_PORTS)
                row.append(state_count)
            table_data.append(row)
            
        return table_data
    except subprocess.CalledProcessError as e:
        return []

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
    WhoisScreen {
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
    """

    def __init__(self, ip: str, whois_data: str):
        super().__init__()
        self.ip = ip
        self.whois_data = whois_data

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

class ConnectionTable(DataTable):
    """A table showing network connections."""
    
    BINDINGS = [
        Binding("p", "ptr_lookup", "PTR Lookup", show=True),
        Binding("w", "whois_lookup", "WHOIS", show=True),
        Binding("c", "csf_check", "CSF Check", show=True),
        Binding("t", "block_temp", "Temp Block IP", show=True),
        Binding("s", "block_subnet", "Temp Block Subnet", show=True),
        Binding("b", "block_perm", "Perm Block IP", show=True),
        Binding("1", "sort(0)", "Sort by IP", show=True),
        Binding("2", "sort(1)", "Sort by CSF Status", show=True),
        Binding("3", "sort(2)", "Sort by Established", show=True),
        Binding("4", "sort(3)", "Sort by Time Wait", show=True),
        Binding("5", "sort(4)", "Sort by SYN Recv", show=True),
    ]
    
    def __init__(self):
        super().__init__()
        self.cursor_type = "row"
        self.selected_row_index = None
        self._sort_column = 0  # Track current sort column
        self._sort_reverse = False  # Track sort direction
        
    def update_data(self):
        """Update table with fresh connection data."""
        # Clear existing rows
        self.clear()
        
        # Get fresh data
        data = get_connection_data()
        
        # Sort data if needed
        if self._sort_column is not None:
            data.sort(key=lambda x: x[self._sort_column], reverse=self._sort_reverse)
        
        # Add rows
        for row in data:
            self.add_row(*row)
            
    def action_sort(self, column_index: int) -> None:
        """Sort the table by the specified column."""
        if self._sort_column == column_index:
            # If already sorting by this column, toggle direction
            self._sort_reverse = not self._sort_reverse
        else:
            # New column, sort ascending
            self._sort_column = column_index
            self._sort_reverse = False
            
        # Update the table with new sorting
        self.update_data()
        
        # Log the sort action
        direction = "descending" if self._sort_reverse else "ascending"
        column_names = ["IP", "CSF Status", "ESTABLISHED", "TIME_WAIT", "SYN_RECV"]
        message = f"Sorted by {column_names[column_index]} ({direction})"
        self.app.query_one(ActivityLog).log_message(message, "info")
        
    def get_selected_ip(self) -> Optional[str]:
        """Get the currently selected IP address."""
        if self.selected_row_index is None:
            self.app.query_one(ActivityLog).log_message("Please select an IP address first", "warning")
            return None
        return self.get_row_at(self.selected_row_index)[0]

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
        log.log_message(f"Checking CSF status for {ip}...", "info")
        status = await self.run_in_thread(check_csf, ip)
        log.log_message(f"CSF status for {ip}: {status}", "info")
        
        # Update status in global state and refresh table
        global ip_csf_status
        ip_csf_status[ip] = status
        self.update_data()

    async def action_block_temp(self) -> None:
        """Block IP temporarily in CSF."""
        ip = self.get_selected_ip()
        if not ip:
            return
            
        log = self.app.query_one(ActivityLog)
        log.log_message(f"Blocking {ip} temporarily...", "warning")
        result = await self.run_in_thread(block_in_csf, ip, True)
        log.log_message(f"Temporary block for {ip}: {result}", "success")
        self.update_data()

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
        self.update_data()

    async def action_block_perm(self) -> None:
        """Block IP permanently in CSF."""
        ip = self.get_selected_ip()
        if not ip:
            return
            
        log = self.app.query_one(ActivityLog)
        log.log_message(f"Blocking {ip} permanently...", "warning")
        result = await self.run_in_thread(block_in_csf, ip, False)
        log.log_message(f"Permanent block for {ip}: {result}", "success")
        self.update_data()

    def on_mount(self) -> None:
        """Set up the table columns."""
        self.add_column("Remote IP", width=30)
        self.add_column("CSF Status", width=25)
        self.add_column("ESTABLISHED", width=12)
        self.add_column("TIME_WAIT", width=12)
        self.add_column("SYN_RECV", width=12)
        
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
