#!/bin/bash

# Quick troubleshooting script for Wireshark K-means plugin
echo "=== Wireshark K-means Plugin Troubleshooting ==="

# Check if plugin files exist
PLUGIN_DIR="/Users/$USER/.local/lib/wireshark/plugins"
LUA_PLUGIN="$PLUGIN_DIR/kmeans_analyzer.lua"
PYTHON_BACKEND="$PLUGIN_DIR/wireshark_kmeans_backend.py"

echo ""
echo "1. Checking plugin installation..."

if [ -f "$LUA_PLUGIN" ]; then
    echo "✓ Lua plugin found"
    
    # Check for the fixed version
    if grep -q "table_size" "$LUA_PLUGIN" && grep -q "force_collect_packets" "$LUA_PLUGIN"; then
        echo "✓ Plugin appears to be the fixed version"
    else
        echo "⚠️  Plugin may be outdated - consider reinstalling"
    fi
else
    echo "✗ Lua plugin not found at $LUA_PLUGIN"
    exit 1
fi

if [ -f "$PYTHON_BACKEND" ]; then
    echo "✓ Python backend found"
else
    echo "✗ Python backend not found at $PYTHON_BACKEND"
    exit 1
fi

echo ""
echo "2. Checking Python environment..."

VENV_PYTHON="$PLUGIN_DIR/venv/bin/python"
if [ -x "$VENV_PYTHON" ]; then
    echo "✓ Virtual environment found"
    
    # Test Python backend
    if "$VENV_PYTHON" "$PYTHON_BACKEND" --help >/dev/null 2>&1; then
        echo "✓ Python backend is functional"
    else
        echo "✗ Python backend test failed"
    fi
else
    echo "✗ Virtual environment not found"
fi

echo ""
echo "3. Common solutions for typical issues:"
echo ""

echo "📋 If you see 'table.maxn' error:"
echo "   → Reinstall with: ./install_plugin_fixed.sh"
echo ""

echo "📋 If you see '0 packets' error:"
echo "   → In Wireshark Lua console, run:"
echo "     force_collect_packets()"
echo "     run_kmeans_analysis()"
echo ""

echo "📋 If plugin doesn't load:"
echo "   → Check Wireshark console for error messages"
echo "   → Restart Wireshark after installation"
echo ""

echo "📋 If analysis fails:"
echo "   → Try manual CSV export:"
echo "     File > Export Packet Dissections > As CSV..."
echo "   → Then run: ./export_and_analyze.sh"
echo ""

echo "4. Quick test commands for Wireshark Lua console:"
echo ""
echo "   show_kmeans_stats()          # Check plugin status"
echo "   force_collect_packets()      # Collect from current capture"
echo "   run_kmeans_analysis()        # Run full analysis"
echo "   set_kmeans_clusters(3)       # Change cluster count"
echo ""

echo "5. Manual analysis command:"
echo ""
echo "   # Export capture and analyze directly"
echo "   tshark -r capture.pcap -T csv -E header=y > export.csv"
echo "   $VENV_PYTHON $PYTHON_BACKEND export.csv --clusters 5"
echo ""

echo "=== Troubleshooting Complete ==="
echo ""
echo "For more help, check the README.md troubleshooting section."
