# Use Ubuntu 22.04 as a base image
FROM ubuntu:22.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies required for Python, PyQt6, X11, and the VNC setup
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    xvfb \
    x11vnc \
    novnc \
    websockify \
    supervisor \
    fluxbox \
    xterm \
    # Qt6 dependencies based on research
    libgl1-mesa-glx \
    libxkbcommon-x11-0 \
    libxcb-icccm4 \
    libxcb-image0 \
    libxcb-keysyms1 \
    libxcb-randr0 \
    libxcb-render-util0 \
    libxcb-render0 \
    libxcb-shape0 \
    libxcb-sync1 \
    libxcb-xfixes0 \
    libxcb-xinerama0 \
    libxcb-xkb1 \
    libxcb1 \
    libxrender1 \
    libxi6 \
    libdbus-1-3 \
    libxcb-cursor0 \
    libegl1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file and install Python dependencies
COPY requirements.txt .
RUN python3 -m pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application source code
COPY . .

# Copy the supervisor configuration and startup script
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY docker/startup.sh /app/docker/startup.sh

# Make the startup script executable
RUN chmod +x /app/docker/startup.sh

# Expose the port for the noVNC web interface
EXPOSE 8080

# The command to run when the container starts
CMD ["/usr/bin/supervisord"]
