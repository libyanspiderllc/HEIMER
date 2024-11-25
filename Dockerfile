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
RUN python3 -m venv venv && \
    . venv/bin/activate && \
    pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Build the binary
RUN . venv/bin/activate && \
    pyinstaller build.spec --clean

# Create artifacts directory with correct permissions
RUN mkdir -p /artifacts && \
    cp -r dist/* /artifacts/ && \
    chmod -R 777 /artifacts
