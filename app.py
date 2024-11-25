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
TEST_MODE = False  # Set to False to use real netstat
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
    """A custom DataTable for displaying network connections."""

    BINDINGS = [
        ("p", "ptr_lookup", "PTR Lookup"),
        ("w", "whois_lookup", "WHOIS Lookup"),
        ("c", "csf_check", "CSF Check"),
        ("t", "temp_block", "Temp Block IP"),
        ("s", "temp_block_subnet", "Temp Block Subnet"),
        ("b", "perm_block", "Perm Block IP"),
        ("1", "sort(0)", "Sort IP"),
        ("2", "sort(1)", "Sort CSF"),
        *[
            (str(i + 3), f"sort({i + 2})", f"Sort {state}")
            for i, state in enumerate(MONITORED_STATES)
        ],
        ("r", "refresh", "Refresh Data"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.current_data = []
        self.sorted_column = None
        self.sort_reverse = False

    def on_mount(self) -> None:
        """Set up the data table."""
        self.cursor_type = "row"
        
        # Add columns: Remote IP, CSF Status, and monitored states
        self.add_column("Remote IP", width=30)
        self.add_column("CSF Status", width=25)
        for state in MONITORED_STATES:
            self.add_column(state, width=12)
            
        self.update_data()

    def update_data(self) -> None:
        """Update the table with fresh connection data."""
        self.current_data = get_connection_data()
        self.refresh_view()

    def refresh_view(self) -> None:
        """Refresh the table view using current data."""
        # Clear existing rows
        self.clear()
        
        # Sort data if needed
        if self.sorted_column is not None:
            self.current_data.sort(
                key=lambda x: x[self.sorted_column],
                reverse=self.sort_reverse
            )

        # Add rows with current data
        for row_data in self.current_data:
            self.add_row(*row_data)

    def action_sort(self, column_index: int) -> None:
        """Sort the table by the specified column."""
        if self.sorted_column == column_index:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sorted_column = column_index
            self.sort_reverse = False
        
        self.refresh_view()

    def action_refresh(self) -> None:
        """Refresh the connection data."""
        self.update_data()

    def action_ptr_lookup(self) -> None:
        """Perform PTR lookup for the selected IP."""
        if self.cursor_row is not None:
            ip = self.get_row_at(self.cursor_row)[0]
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                self.notify(f"PTR lookup for {ip}: {hostname}")
            except (socket.herror, socket.gaierror) as e:
                self.notify(f"PTR lookup failed for {ip}: {str(e)}")

    def action_whois_lookup(self) -> None:
        """Perform WHOIS lookup for the selected IP."""
        if self.cursor_row is not None:
            ip = self.get_row_at(self.cursor_row)[0]
            try:
                result = subprocess.run(["whois", ip], capture_output=True, text=True)
                self.notify(f"WHOIS lookup for {ip}:\n{result.stdout[:500]}...")
            except subprocess.CalledProcessError as e:
                self.notify(f"WHOIS lookup failed for {ip}: {str(e)}")

    def action_csf_check(self) -> None:
        """Check if the selected IP is blocked in CSF."""
        if self.cursor_row is not None:
            ip = self.get_row_at(self.cursor_row)[0]
            try:
                result = subprocess.run(["csf", "-g", ip], capture_output=True, text=True)
                status = "Blocked" if "DENY" in result.stdout else "Not blocked"
                self.notify(f"CSF status for {ip}: {status}")
                
                # Update the CSF status in current_data
                row_data = list(self.get_row_at(self.cursor_row))
                row_data[1] = status  # CSF Status is the second column
                self.current_data[self.cursor_row] = tuple(row_data)
                
                # Refresh the view
                self.refresh_view()
                
            except subprocess.CalledProcessError as e:
                self.notify(f"CSF check failed for {ip}: {str(e)}")

    def _block_ip(self, ip: str, temp: bool = True, subnet: bool = False) -> None:
        """Helper function to block an IP address."""
        try:
            if subnet:
                # For IPv4, block /24, for IPv6, block /64
                if ":" in ip:
                    ip = f"{ip}/64"
                else:
                    ip = f"{ip}/24"

            cmd = ["csf", "-td" if temp else "-d", ip]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                duration = "temporarily" if temp else "permanently"
                target = "subnet" if subnet else "IP"
                self.notify(f"{target} {ip} {duration} blocked")
                
                # Update the CSF status in current_data for all matching IPs
                block_prefix = ip.split("/")[0]
                for i, row in enumerate(self.current_data):
                    if row[0].startswith(block_prefix):
                        row_data = list(row)
                        row_data[1] = f"Blocked ({'temp' if temp else 'perm'})"  # CSF Status is the second column
                        self.current_data[i] = tuple(row_data)
                
                # Refresh the view
                self.refresh_view()
                
            else:
                self.notify(f"Failed to block {ip}: {result.stderr}")
        except subprocess.CalledProcessError as e:
            self.notify(f"Failed to block {ip}: {str(e)}")

    def action_temp_block(self) -> None:
        """Temporarily block the selected IP."""
        if self.cursor_row is not None:
            ip = self.get_row_at(self.cursor_row)[0]
            self._block_ip(ip, temp=True)

    def action_temp_block_subnet(self) -> None:
        """Temporarily block the subnet of the selected IP."""
        if self.cursor_row is not None:
            ip = self.get_row_at(self.cursor_row)[0]
            self._block_ip(ip, temp=True, subnet=True)

    def action_perm_block(self) -> None:
        """Permanently block the selected IP."""
        if self.cursor_row is not None:
            ip = self.get_row_at(self.cursor_row)[0]
            self._block_ip(ip, temp=False)

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
