#!/bin/bash

# Debug script to test Wireshark file detection
echo "🔧 Debugging Wireshark File Detection"
echo "===================================="

# Find Wireshark process
WIRESHARK_PID=$(pgrep -f -i "wireshark" | head -1)

if [ -z "$WIRESHARK_PID" ]; then
    WIRESHARK_PID=$(ps aux | grep -i wireshark | grep -v grep | awk '{print $2}' | head -1)
fi

if [ -n "$WIRESHARK_PID" ]; then
    echo "✅ Found Wireshark PID: $WIRESHARK_PID"
    echo ""
    
    echo "📊 Raw lsof output for capture files:"
    lsof -p "$WIRESHARK_PID" 2>/dev/null | grep -E '\.(pcap|pcapng|cap)$'
    echo ""
    
    echo "📁 Extracted filenames (method 1 - last column):"
    lsof -p "$WIRESHARK_PID" 2>/dev/null | grep -E '\.(pcap|pcapng|cap)$' | awk '{print $NF}'
    echo ""
    
    echo "📁 Extracted paths (method 2 - columns 9+):"
    lsof -p "$WIRESHARK_PID" 2>/dev/null | grep -E '\.(pcap|pcapng|cap)$' | awk '{for(i=9;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/[[:space:]]*$//'
    echo ""
    
    echo "🔍 Testing file existence:"
    lsof -p "$WIRESHARK_PID" 2>/dev/null | grep -E '\.(pcap|pcapng|cap)$' | awk '{for(i=9;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/[[:space:]]*$//' | while read -r file; do
        if [ -f "$file" ]; then
            echo "   ✅ EXISTS: $file"
        else
            echo "   ❌ NOT FOUND: $file"
            # Try to find it
            filename=$(basename "$file")
            echo "      🔍 Searching for: $filename"
            for search_dir in "$HOME/Documents" "$HOME/Desktop" "$HOME/Downloads" "$HOME/Documents/pyshark" "/tmp" "/var/tmp"; do
                if [ -d "$search_dir" ]; then
                    found=$(find "$search_dir" -name "$filename" -type f 2>/dev/null | head -1)
                    if [ -n "$found" ]; then
                        echo "      ✅ FOUND AT: $found"
                    fi
                fi
            done
        fi
    done
else
    echo "❌ Wireshark is not running"
    echo "💡 Please open Wireshark with a capture file and run this script again"
fi
