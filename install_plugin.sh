#!/bin/bash

# Wireshark K-means Analyzer Plugin Installation Script
# This script sets up the plugin and its dependencies

echo "=== Wireshark K-means Analyzer Plugin Setup ==="

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed. Please install Python 3 first."
    exit 1
fi

# Check if pip is available
if ! command -v pip3 &> /dev/null; then
    echo "Error: pip3 is not installed. Please install pip first."
    exit 1
fi

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

echo "Script directory: $SCRIPT_DIR"

# Install Python dependencies
echo "Installing Python dependencies..."

# Create a virtual environment for the plugin
VENV_DIR="$SCRIPT_DIR/venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to create virtual environment."
        echo "Trying with --break-system-packages as fallback..."
        pip3 install -r "$SCRIPT_DIR/requirements.txt" --break-system-packages --user
        if [ $? -ne 0 ]; then
            echo "Error: Failed to install Python dependencies even with fallback method."
            echo "Please try one of these solutions:"
            echo "1. Install dependencies manually: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
            echo "2. Use pipx: brew install pipx && pipx install -r requirements.txt"
            echo "3. Use Homebrew: brew install python-pandas python-scikit-learn"
            exit 1
        fi
    else
        echo "Activating virtual environment and installing dependencies..."
        source "$VENV_DIR/bin/activate"
        pip install -r "$SCRIPT_DIR/requirements.txt"
        
        if [ $? -ne 0 ]; then
            echo "Error: Failed to install dependencies in virtual environment."
            echo "Trying system installation with --user flag..."
            deactivate
            pip3 install -r "$SCRIPT_DIR/requirements.txt" --user
            if [ $? -ne 0 ]; then
                echo "Error: Failed to install Python dependencies."
                exit 1
            fi
        fi
        
        # Update the Python backend to use the virtual environment
        if [ -f "$VENV_DIR/bin/python" ]; then
            sed -i '' '1s|.*|#!'"$VENV_DIR"'/bin/python|' "$SCRIPT_DIR/wireshark_kmeans_backend.py"
            echo "Updated Python backend to use virtual environment."
        fi
    fi
else
    echo "Virtual environment already exists, using it..."
    source "$VENV_DIR/bin/activate"
    pip install -r "$SCRIPT_DIR/requirements.txt"
    if [ $? -ne 0 ]; then
        echo "Warning: Failed to update dependencies in existing virtual environment."
    fi
fi

# Find Wireshark plugin directory
PLUGIN_DIR=""

# Common Wireshark plugin directories on macOS
WIRESHARK_DIRS=(
    "$HOME/.local/lib/wireshark/plugins"
    "$HOME/.wireshark/plugins"
    "/Applications/Wireshark.app/Contents/PlugIns/wireshark"
    "/usr/local/lib/wireshark/plugins"
    "/opt/local/lib/wireshark/plugins"
)

# Try to find Wireshark installation
for dir in "${WIRESHARK_DIRS[@]}"; do
    if [ -d "$(dirname "$dir")" ]; then
        PLUGIN_DIR="$dir"
        break
    fi
done

# If no standard directory found, create user plugin directory
if [ -z "$PLUGIN_DIR" ]; then
    PLUGIN_DIR="$HOME/.local/lib/wireshark/plugins"
    echo "Creating Wireshark plugin directory: $PLUGIN_DIR"
    mkdir -p "$PLUGIN_DIR"
fi

echo "Using Wireshark plugin directory: $PLUGIN_DIR"

# Copy Lua plugin file
echo "Installing Lua plugin..."
cp "$SCRIPT_DIR/kmeans_analyzer.lua" "$PLUGIN_DIR/"

if [ $? -ne 0 ]; then
    echo "Error: Failed to copy Lua plugin file."
    exit 1
fi

# Copy Python backend script
echo "Installing Python backend..."
cp "$SCRIPT_DIR/wireshark_kmeans_backend.py" "$PLUGIN_DIR/"

if [ $? -ne 0 ]; then
    echo "Error: Failed to copy Python backend script."
    exit 1
fi

# Make Python script executable
chmod +x "$PLUGIN_DIR/wireshark_kmeans_backend.py"

# Create a symbolic link to the backend script in a common location
BACKEND_LINK="/usr/local/bin/wireshark_kmeans_backend"
if [ -w "/usr/local/bin" ]; then
    ln -sf "$PLUGIN_DIR/wireshark_kmeans_backend.py" "$BACKEND_LINK"
    echo "Created symbolic link: $BACKEND_LINK"
fi

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Plugin files installed to: $PLUGIN_DIR"
echo ""
echo "To use the plugin:"
echo "1. Start Wireshark"
echo "2. Capture or open a packet capture file"
echo "3. Go to Tools > K-means Analyzer to access the plugin features"
echo ""
echo "Plugin features:"
echo "- Real-time packet analysis and clustering"
echo "- Anomaly detection based on K-means clustering"
echo "- Configurable number of clusters"
echo "- Statistics and analysis reports"
echo ""
echo "Note: The plugin will automatically analyze packets as they are captured."
echo "For large captures, consider using the sampling feature."

# Test Python backend
echo ""
echo "Testing Python backend..."
python3 "$PLUGIN_DIR/wireshark_kmeans_backend.py" --help > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo "✓ Python backend is working correctly"
else
    echo "⚠ Warning: Python backend test failed. Check dependencies."
fi

echo ""
echo "Setup complete! Restart Wireshark to load the plugin."
