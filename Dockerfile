FROM almalinux:8

# Install system dependencies
RUN dnf install -y \
    python38 \
    python38-devel \
    zlib \
    zlib-devel \
    gcc \
    make \
    && dnf clean all

# Set Python 3.8 as default
RUN alternatives --set python3 /usr/bin/python3.8

WORKDIR /app

# Copy only requirements first to leverage Docker cache
COPY requirements.txt .

# Install dependencies directly with python
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --no-cache-dir "textual>=0.32.0,<0.33.0" && \
    /app/venv/bin/python -m pip install --no-cache-dir "pyinstaller>=5.13.0,<6.0.0"

# Copy the rest of the application
COPY . .

# Build the binary using python -m
RUN /app/venv/bin/python -m PyInstaller build.spec --clean --name heimer

# Create artifacts directory with correct permissions
RUN mkdir -p /artifacts && \
    cp -r dist/* /artifacts/ && \
    chmod -R 777 /artifacts
