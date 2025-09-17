# HEIMER - Network Security Monitor

*Named after Professor Cecil B. Heimerdinger, the Revered Inventor*

A terminal-based network connection monitoring tool with advanced IP management capabilities.

## Features

- Real-time network connection monitoring
- IPv4 and IPv6 support
- CSF (ConfigServer Firewall) integration
- IP lookup and blocking capabilities
- Terminal-based UI with sorting and filtering

## Installation
For CloudLinux\CentOS 7:
```
cd ~
wget https://github.com/libyanspiderllc/HEIMER/releases/latest/download/heimer_centos7 -O heimer_centos7
mv -f heimer_centos7 /usr/local/bin/heimer
chmod +x /usr/local/bin/heimer
```

For CloudLinux\AlmaLinux 8+:
```
cd ~
wget https://github.com/libyanspiderllc/HEIMER/releases/latest/download/heimer_alma8 -O heimer_alma8
mv -f heimer_alma8 /usr/local/bin/heimer
chmod +x /usr/local/bin/heimer
```

## Building the Application

### Option 1: Docker Build (Recommended)

This method ensures compatibility with AlmaLinux 8 and similar systems (RHEL 8, CentOS 8).

Prerequisites:
- Docker

Steps:
1. Build using the provided script:
   ```bash
   ./docker-build.sh
   ```

The binary will be created at `dist/heimer`.

### Option 2: Direct Build

Prerequisites:
- Python 3.8+
- zlib development libraries
  - AlmaLinux/RHEL: `sudo dnf install -y zlib zlib-devel`
  - Ubuntu/Debian: `sudo apt-get install -y zlib1g zlib1g-dev`

Steps:
1. Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Build the binary:
   ```bash
   pyinstaller build.spec --clean
   ```

## Running the Application

### Running the Binary

Prerequisites:
- zlib libraries
  - AlmaLinux/RHEL: `sudo dnf install -y zlib`
  - Ubuntu/Debian: `sudo apt-get install -y zlib1g`

Run the binary:
```bash
./dist/heimer
```

### Running from Source

1. Activate the virtual environment:
   ```bash
   source venv/bin/activate
   ```

2. Run the application:
   ```bash
   python app.py
   ```

## Key Bindings

- `r` - Refresh data
- `h` - Toggle help
- `q` - Quit
- `p` - IP PTR Lookup
- `w` - IP WHOIS Lookup
- `c` - Check IP status in CSF
- `a` - List IP connections in Apache Status Page
- `t` - Temporary Block IP in CSF
- `y` - Temporary Block IP in CSF Cluster
- `b` - Permanent Block IP in CSF
- `z` - Permanent Block IP in CSF Cluster
- `s` - Temporary Block Subnet in CSF
- `n` - Temporary Block Subnet in CSF Cluster
- `x` -  Attempt Automatic Attack Pattern Analysis
- `1~5` - Sort table by column

## Development

### Setting up Development Environment

1. Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running Tests

```bash
python -m pytest tests/
```

### Code Style

Follow PEP 8 guidelines. Use `black` for code formatting:
```bash
black .
```

## Troubleshooting

### Common Issues

1. "libz.so.1: failed to map segment from shared object"
   - Solution: Install zlib
     ```bash
     # AlmaLinux/RHEL
     sudo dnf install -y zlib
     
     # Ubuntu/Debian
     sudo apt-get install -y zlib1g
     ```

2. GLIBC version issues
   - Solution: Use the Docker build method which ensures compatibility

3. Whois is not installed
   - Solution: Install whois
     ```bash
     sudo dns install whois
     ```

## License

MIT License

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request
