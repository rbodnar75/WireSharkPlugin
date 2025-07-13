#!/bin/bash

# Script to permanently fix matplotlib Lua conflicts with Wireshark
# This removes the problematic Lua files that matplotlib installs

echo "🧹 Fixing matplotlib Lua conflicts with Wireshark..."

# Find matplotlib installation directory in the virtual environment
VENV_DIR="/Users/rbodnar/.local/lib/wireshark/plugins/venv"
MATPLOTLIB_LUA_DIR="$VENV_DIR/lib/python3.13/site-packages/matplotlib/mpl-data"

if [ -d "$MATPLOTLIB_LUA_DIR" ]; then
    echo "📁 Found matplotlib Lua directory: $MATPLOTLIB_LUA_DIR"
    
    # List problematic Lua files
    LUA_FILES=$(find "$MATPLOTLIB_LUA_DIR" -name "*.lua" 2>/dev/null)
    
    if [ -n "$LUA_FILES" ]; then
        echo "🔍 Found problematic Lua files:"
        echo "$LUA_FILES" | while read -r file; do
            echo "   - $(basename "$file")"
        done
        
        echo ""
        echo "⚠️  These files cause conflicts with Wireshark's Lua environment"
        echo "🗑️  Removing problematic Lua files..."
        
        # Remove or rename the problematic Lua files
        find "$MATPLOTLIB_LUA_DIR" -name "*.lua" -exec mv {} {}.disabled \; 2>/dev/null
        
        echo "✅ Matplotlib Lua conflicts fixed!"
        echo "   Lua files renamed to .disabled extension"
        echo ""
        echo "🎉 You should no longer see the matplotlib Lua error in Wireshark!"
    else
        echo "ℹ️  No problematic Lua files found in matplotlib"
    fi
else
    echo "⚠️  Matplotlib directory not found in virtual environment"
    echo "   This is normal if using system Python or different environment"
fi

echo ""
echo "💡 Alternative solutions:"
echo "   1. Use ./run_wireshark_clean.sh to start Wireshark"
echo "   2. Use ./tshark_clean.sh for command-line operations"
echo "   3. The analysis script now uses clean tshark automatically"
