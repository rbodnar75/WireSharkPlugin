#!/bin/bash

# Fixed Wireshark K-means Analyzer Plugin Installation Script
# This version avoids matplotlib conflicts and uses compatible Lua functions

echo "=== Wireshark K-means Analyzer Plugin Setup (Fixed) ==="

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

# Remove existing virtual environment to avoid matplotlib conflicts
if [ -d "$SCRIPT_DIR/venv" ]; then
    echo "Removing existing virtual environment to avoid matplotlib conflicts..."
    rm -rf "$SCRIPT_DIR/venv"
fi

# Create a clean virtual environment
echo "Creating clean virtual environment..."
python3 -m venv "$SCRIPT_DIR/venv_clean"
if [ $? -ne 0 ]; then
    echo "Error: Failed to create virtual environment."
    exit 1
fi

# Activate and install minimal dependencies (no matplotlib)
echo "Installing minimal dependencies (avoiding matplotlib conflicts)..."
source "$SCRIPT_DIR/venv_clean/bin/activate"
pip install --upgrade pip
pip install -r "$SCRIPT_DIR/requirements_minimal.txt"

if [ $? -ne 0 ]; then
    echo "Error: Failed to install dependencies in virtual environment."
    deactivate
    exit 1
fi

echo "✓ Successfully installed minimal packages without matplotlib"
deactivate

# Find Wireshark plugin directory
PLUGIN_DIR=""

# Common Wireshark plugin directories on macOS (prioritize user directories)
WIRESHARK_DIRS=(
    "$HOME/.local/lib/wireshark/plugins"
    "$HOME/.wireshark/plugins"
    "$HOME/Library/Application Support/Wireshark/plugins"
    "/usr/local/lib/wireshark/plugins"
    "/opt/local/lib/wireshark/plugins"
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

# Install the fixed Lua plugin
echo "Installing fixed Lua plugin..."
cp "$SCRIPT_DIR/kmeans_analyzer_v2.lua" "$PLUGIN_DIR/kmeans_analyzer.lua"

if [ $? -ne 0 ]; then
    echo "Error: Failed to copy Lua plugin file."
    exit 1
fi

# Install the minimal Python backend
echo "Installing minimal Python backend..."
cp "$SCRIPT_DIR/wireshark_kmeans_backend_minimal.py" "$PLUGIN_DIR/wireshark_kmeans_backend.py"

if [ $? -ne 0 ]; then
    echo "Error: Failed to copy Python backend script."
    exit 1
fi

# Make Python script executable
chmod +x "$PLUGIN_DIR/wireshark_kmeans_backend.py"

# Copy the clean virtual environment
echo "Copying clean virtual environment..."
cp -r "$SCRIPT_DIR/venv_clean" "$PLUGIN_DIR/venv"
echo "✓ Clean virtual environment copied to plugin directory"

# Update the Python backend shebang to use the clean venv
if [ -f "$PLUGIN_DIR/venv/bin/python" ]; then
    sed -i '' '1s|.*|#!'"$PLUGIN_DIR"'/venv/bin/python|' "$PLUGIN_DIR/wireshark_kmeans_backend.py"
    echo "✓ Updated Python backend to use clean virtual environment"
fi

# Create a wrapper script for easier execution
WRAPPER_SCRIPT="$PLUGIN_DIR/run_kmeans_analysis.sh"
cat > "$WRAPPER_SCRIPT" << EOF
#!/bin/bash
# Wrapper script for K-means analysis

PLUGIN_DIR="\$( cd "\$( dirname "\${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Try to use clean virtual environment first
if [ -f "\$PLUGIN_DIR/venv/bin/python" ]; then
    "\$PLUGIN_DIR/venv/bin/python" "\$PLUGIN_DIR/wireshark_kmeans_backend.py" "\$@"
elif command -v python3 &> /dev/null; then
    python3 "\$PLUGIN_DIR/wireshark_kmeans_backend.py" "\$@"
else
    echo "Error: Python 3 not found"
    exit 1
fi
EOF
chmod +x "$WRAPPER_SCRIPT"

# Clean up temporary venv
rm -rf "$SCRIPT_DIR/venv_clean"

echo ""
echo "=== Installation Complete ==="
echo ""
echo "✅ Fixed plugin installed successfully!"
echo ""
echo "Plugin files installed to: $PLUGIN_DIR"
echo ""
echo "🔧 Key fixes applied:"
echo "- Removed matplotlib to avoid Lua conflicts"
echo "- Used compatible Wireshark Lua API functions"
echo "- Created clean virtual environment"
echo "- Added better error handling and logging"
echo ""
echo "To use the plugin:"
echo "1. Start Wireshark"
echo "2. Check the console for 'K-means Analyzer plugin loaded successfully!'"
echo "3. Use console commands:"
echo "   - run_kmeans_analysis() for full analysis"
echo "   - show_kmeans_stats() for statistics"
echo "   - clear_kmeans_data() to clear data"
echo ""
echo "Or access via Tools menu if available in your Wireshark version."

# Test the minimal Python backend
echo ""
echo "Testing minimal Python backend..."
"$PLUGIN_DIR/venv/bin/python" "$PLUGIN_DIR/wireshark_kmeans_backend.py" --help > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo "✓ Minimal Python backend is working correctly"
else
    echo "⚠️ Warning: Python backend test failed. Check dependencies."
fi

echo ""
echo "🎉 Setup complete! Restart Wireshark to load the fixed plugin."
echo ""
echo "The plugin should now load without Lua errors!"
