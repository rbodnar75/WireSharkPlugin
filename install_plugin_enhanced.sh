#!/bin/bash

# Enhanced Wireshark K-means Analyzer Plugin Installation Script
# Handles various Python environment configurations including externally-managed environments

echo "=== Wireshark K-means Analyzer Plugin Setup ==="

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
echo "Script directory: $SCRIPT_DIR"

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed. Please install Python 3 first."
    echo "On macOS: brew install python"
    exit 1
fi

echo "Python version: $(python3 --version)"

# Function to test if packages are available
test_python_packages() {
    python3 -c "import pandas, numpy, sklearn; print('All required packages are available')" 2>/dev/null
    return $?
}

# Function to install via virtual environment
install_with_venv() {
    echo "Installing dependencies using virtual environment..."
    
    VENV_DIR="$SCRIPT_DIR/venv"
    
    # Create virtual environment
    if [ ! -d "$VENV_DIR" ]; then
        echo "Creating virtual environment at $VENV_DIR..."
        python3 -m venv "$VENV_DIR"
        if [ $? -ne 0 ]; then
            echo "Error: Failed to create virtual environment."
            return 1
        fi
    fi
    
    # Activate and install
    echo "Installing packages in virtual environment..."
    source "$VENV_DIR/bin/activate"
    pip install --upgrade pip
    pip install -r "$SCRIPT_DIR/requirements.txt"
    
    if [ $? -eq 0 ]; then
        echo "✓ Successfully installed packages in virtual environment"
        
        # Update the Python backend shebang to use venv
        if [ -f "$VENV_DIR/bin/python" ]; then
            cp "$SCRIPT_DIR/wireshark_kmeans_backend.py" "$SCRIPT_DIR/wireshark_kmeans_backend.py.backup"
            sed "1s|.*|#!$VENV_DIR/bin/python|" "$SCRIPT_DIR/wireshark_kmeans_backend.py.backup" > "$SCRIPT_DIR/wireshark_kmeans_backend.py"
            chmod +x "$SCRIPT_DIR/wireshark_kmeans_backend.py"
            echo "✓ Updated Python backend to use virtual environment"
        fi
        
        deactivate
        return 0
    else
        echo "Error: Failed to install packages in virtual environment"
        deactivate
        return 1
    fi
}

# Function to install with --user flag
install_with_user_flag() {
    echo "Installing dependencies with --user flag..."
    pip3 install --user -r "$SCRIPT_DIR/requirements.txt"
    return $?
}

# Function to install with --break-system-packages
install_with_break_system() {
    echo "Installing dependencies with --break-system-packages flag..."
    pip3 install --break-system-packages -r "$SCRIPT_DIR/requirements.txt"
    return $?
}

# Function to suggest manual installation
suggest_manual_installation() {
    echo ""
    echo "=== Manual Installation Required ==="
    echo ""
    echo "The automatic installation failed. Please try one of these methods:"
    echo ""
    echo "Method 1 - Virtual Environment (Recommended):"
    echo "  cd $SCRIPT_DIR"
    echo "  python3 -m venv venv"
    echo "  source venv/bin/activate"
    echo "  pip install -r requirements.txt"
    echo ""
    echo "Method 2 - User Installation:"
    echo "  pip3 install --user pandas numpy scikit-learn matplotlib"
    echo ""
    echo "Method 3 - Homebrew (macOS):"
    echo "  brew install python-pandas"
    echo "  brew install python-scikit-learn"
    echo "  brew install python-matplotlib"
    echo ""
    echo "Method 4 - pipx (for isolated installation):"
    echo "  brew install pipx"
    echo "  pipx install pandas"
    echo "  pipx install scikit-learn"
    echo "  pipx install matplotlib"
    echo ""
    echo "After installing dependencies manually, run this script again or proceed with manual plugin installation."
}

# Check if packages are already available
echo "Checking for existing Python packages..."
if test_python_packages; then
    echo "✓ All required Python packages are already available!"
    DEPENDENCIES_OK=true
else
    echo "Installing required Python packages..."
    DEPENDENCIES_OK=false
    
    # Try different installation methods in order of preference
    if install_with_venv; then
        DEPENDENCIES_OK=true
    elif install_with_user_flag; then
        echo "✓ Successfully installed packages with --user flag"
        DEPENDENCIES_OK=true
    elif install_with_break_system; then
        echo "✓ Successfully installed packages with --break-system-packages flag"
        echo "⚠️  Warning: Using --break-system-packages may affect your system Python"
        DEPENDENCIES_OK=true
    else
        suggest_manual_installation
        exit 1
    fi
fi

# Verify installation
if [ "$DEPENDENCIES_OK" = true ]; then
    echo "Verifying package installation..."
    if test_python_packages; then
        echo "✓ Package verification successful"
    else
        echo "⚠️  Warning: Package verification failed, but continuing installation"
    fi
fi

# Find Wireshark plugin directory
PLUGIN_DIR=""

# Common Wireshark plugin directories on macOS (prioritize user directories)
WIRESHARK_DIRS=(
    "$HOME/.local/lib/wireshark/plugins"
    "$HOME/.wireshark/plugins"
    "$HOME/Library/Application Support/Wireshark/plugins"
    "/usr/local/lib/wireshark/plugins"
    "/opt/local/lib/wireshark/plugins"
    "/Applications/Wireshark.app/Contents/PlugIns/wireshark"
)

# Try to find a writable Wireshark directory
for dir in "${WIRESHARK_DIRS[@]}"; do
    parent_dir=$(dirname "$dir")
    if [ -d "$parent_dir" ] && [ -w "$parent_dir" ]; then
        PLUGIN_DIR="$dir"
        break
    elif [ -d "$dir" ] && [ -w "$dir" ]; then
        PLUGIN_DIR="$dir"
        break
    fi
done

# If no writable directory found, create user plugin directory
if [ -z "$PLUGIN_DIR" ]; then
    PLUGIN_DIR="$HOME/.local/lib/wireshark/plugins"
    echo "Creating Wireshark plugin directory: $PLUGIN_DIR"
    mkdir -p "$PLUGIN_DIR"
    
    # If that fails, try alternative user directory
    if [ ! -d "$PLUGIN_DIR" ]; then
        PLUGIN_DIR="$HOME/.wireshark/plugins"
        echo "Creating alternative plugin directory: $PLUGIN_DIR"
        mkdir -p "$PLUGIN_DIR"
    fi
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

# Copy virtual environment if it exists
if [ -d "$SCRIPT_DIR/venv" ]; then
    echo "Copying virtual environment..."
    cp -r "$SCRIPT_DIR/venv" "$PLUGIN_DIR/"
    echo "✓ Virtual environment copied to plugin directory"
fi

# Create a wrapper script for easier execution
WRAPPER_SCRIPT="$PLUGIN_DIR/run_kmeans_analysis.sh"
cat > "$WRAPPER_SCRIPT" << 'EOF'
#!/bin/bash
# Wrapper script for K-means analysis

PLUGIN_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Try to use virtual environment first
if [ -f "$PLUGIN_DIR/venv/bin/python" ]; then
    "$PLUGIN_DIR/venv/bin/python" "$PLUGIN_DIR/wireshark_kmeans_backend.py" "$@"
elif command -v python3 &> /dev/null; then
    python3 "$PLUGIN_DIR/wireshark_kmeans_backend.py" "$@"
else
    echo "Error: Python 3 not found"
    exit 1
fi
EOF
chmod +x "$WRAPPER_SCRIPT"

# Create a symbolic link to the wrapper script in a common location
BACKEND_LINK="/usr/local/bin/wireshark_kmeans_backend"
if [ -w "/usr/local/bin" ]; then
    ln -sf "$WRAPPER_SCRIPT" "$BACKEND_LINK"
    echo "Created symbolic link: $BACKEND_LINK"
elif [ -w "$HOME/.local/bin" ]; then
    mkdir -p "$HOME/.local/bin"
    ln -sf "$WRAPPER_SCRIPT" "$HOME/.local/bin/wireshark_kmeans_backend"
    echo "Created symbolic link: $HOME/.local/bin/wireshark_kmeans_backend"
    echo "Note: Make sure $HOME/.local/bin is in your PATH"
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
if [ -f "$PLUGIN_DIR/venv/bin/python" ]; then
    TEST_CMD="$PLUGIN_DIR/venv/bin/python $PLUGIN_DIR/wireshark_kmeans_backend.py --help"
else
    TEST_CMD="python3 $PLUGIN_DIR/wireshark_kmeans_backend.py --help"
fi

$TEST_CMD > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo "✓ Python backend is working correctly"
else
    echo "⚠️ Warning: Python backend test failed. Check dependencies."
    echo "You can test manually with: $TEST_CMD"
fi

echo ""
echo "Setup complete! Restart Wireshark to load the plugin."
echo ""
echo "If you encounter issues:"
echo "1. Check that Wireshark supports Lua plugins"
echo "2. Verify Python dependencies are installed"
echo "3. Check the plugin directory permissions"
echo "4. Review the troubleshooting section in README.md"
