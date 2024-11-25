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

# Configuration
MONITORED_PORTS = ["80", "443"]
MONITORED_STATES = ["ESTABLISHED", "TIME_WAIT", "SYN_RECV"]
PORTS_DISPLAY = "/".join(MONITORED_PORTS)

# Test mode configuration
TEST_MODE = True  # Set to False to use real netstat
TEST_DATA_FILE = os.path.join(os.path.dirname(__file__), "test_data", "netstat_sample.txt")

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
            remote_addr = parts[4].split(":")[0]
            local_port = local_addr.split(":")[-1]
            
            if local_port not in MONITORED_PORTS:
                continue
                
            state = parts[5]
            if state in MONITORED_STATES:
                connections[remote_addr][local_port][state] += 1
        
        # Format data for table
        table_data = []
        for remote_ip, ports in connections.items():
            row = [
                remote_ip,
                PORTS_DISPLAY
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

def check_csf(ip):
    """Check if IP is in CSF."""
    try:
        # Check both allow and deny lists
        allow_result = subprocess.check_output(["csf", "-g", ip], text=True)
        deny_result = subprocess.check_output(["csf", "-c", ip], text=True)
        return f"Allow: {allow_result}\nDeny: {deny_result}"
    except subprocess.CalledProcessError:
        return "IP not found in CSF"
    except FileNotFoundError:
        return "CSF not installed"

def block_in_csf(ip: str, is_temporary: bool = True, duration: int = 600) -> str:
    """Block IP in CSF."""
    try:
        if is_temporary:
            result = subprocess.check_output(["csf", "-td", ip, str(duration)], text=True)
            return f"Temporarily blocked for {duration} seconds"
        else:
            result = subprocess.check_output(["csf", "-d", ip], text=True)
            return "Permanently blocked"
    except subprocess.CalledProcessError as e:
        return f"Failed to block IP: {str(e)}"
    except FileNotFoundError:
        return "CSF not installed"

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

class ConnectionTable(DataTable):
    """A table showing network connections."""
    
    BINDINGS = [
        Binding("p", "ptr_lookup", "PTR Lookup", show=True),
        Binding("w", "whois_lookup", "WHOIS", show=True),
        Binding("c", "csf_check", "CSF Check", show=True),
        Binding("t", "block_temp", "Temp Block", show=True),
        Binding("b", "block_perm", "Block", show=True),
    ]
    
    def __init__(self):
        super().__init__()
        self.cursor_type = "row"
        self.selected_row_index = None
    
    def update_data(self):
        """Update table with fresh connection data."""
        self.clear()
        self.selected_row_index = None
        for row in get_connection_data():
            self.add_row(*row)

    def get_selected_ip(self) -> Optional[str]:
        """Get the currently selected IP address."""
        if self.selected_row_index is None:
            self.app.notify("Please select an IP address first")
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
            self.app.notify("Performing PTR lookup...")
            result = await self.run_in_thread(perform_ptr_lookup, ip)
            self.app.notify(f"PTR Lookup for {ip}: {result}")

    async def action_whois_lookup(self) -> None:
        """Perform WHOIS lookup for selected IP."""
        ip = self.get_selected_ip()
        if ip:
            self.app.notify("Fetching WHOIS information...")
            result = await self.run_in_thread(perform_whois_lookup, ip)
            self.app.push_screen(WhoisScreen(ip, result))

    async def action_csf_check(self) -> None:
        """Check if IP is in CSF."""
        ip = self.get_selected_ip()
        if ip:
            self.app.notify("Checking CSF...")
            result = await self.run_in_thread(check_csf, ip)
            self.app.notify(f"CSF Check for {ip}: {result}")

    async def action_block_temp(self) -> None:
        """Block IP temporarily in CSF."""
        ip = self.get_selected_ip()
        if ip:
            self.app.notify("Blocking IP temporarily...")
            result = await self.run_in_thread(block_in_csf, ip, True)
            self.app.notify(f"Temporary block for {ip}: {result}")

    async def action_block_perm(self) -> None:
        """Block IP permanently in CSF."""
        ip = self.get_selected_ip()
        if ip:
            self.app.notify("Blocking IP permanently...")
            result = await self.run_in_thread(block_in_csf, ip, False)
            self.app.notify(f"Permanent block for {ip}: {result}")

    def on_mount(self) -> None:
        """Set up the table columns."""
        self.add_columns(
            "Remote IP", 
            PORTS_DISPLAY,
            "ESTABLISHED",
            "TIME_WAIT",
            "SYN_RECV"
        )

    def on_data_table_row_selected(self, event) -> None:
        """Handle row selection."""
        self.selected_row_index = event.cursor_row
        ip = self.get_row_at(event.cursor_row)[0]
        self.app.notify(f"Selected IP: {ip}")

class TUIApp(App):
    """A Textual TUI application."""
    
    CSS = """
    Screen {
        align: center middle;
    }
    """
    
    BINDINGS = [
        ("d", "toggle_dark", "Toggle dark mode"),
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh data"),
    ]

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        table = ConnectionTable()
        yield TitleBox()
        yield table
        yield Footer()

    def on_mount(self) -> None:
        """Handle app mount event."""
        # Initial data load
        self.query_one(ConnectionTable).update_data()

    def action_toggle_dark(self) -> None:
        """An action to toggle dark mode."""
        self.dark = not self.dark
        
    def action_refresh(self) -> None:
        """Refresh the connection data."""
        self.query_one(ConnectionTable).update_data()
        
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press events."""
        if event.button.id == "refresh_btn":
            self.action_refresh()

def main():
    app = TUIApp()
    app.run()

if __name__ == "__main__":
    main()
