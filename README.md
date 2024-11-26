# HEIMER - Network Security Monitor

*Named after Professor Cecil B. Heimerdinger, the Revered Inventor*

A terminal-based network connection monitoring tool with advanced IP management capabilities.

## Features

- Real-time network connection monitoring
- IPv4 and IPv6 support
- CSF (ConfigServer Firewall) integration
- IP lookup and blocking capabilities
- Terminal-based UI with sorting and filtering

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

The binary will be created at `dist/arcane`.

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
./dist/arcane
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

- `p`: PTR Lookup
- `w`: WHOIS Lookup
- `c`: CSF Check
- `t`: Temporary Block IP
- `s`: Temporary Block Subnet
- `b`: Permanent Block IP
- `1-5`: Column Sorting
- `r`: Refresh Data
- `q`: Quit

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

## License

MIT License

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request
