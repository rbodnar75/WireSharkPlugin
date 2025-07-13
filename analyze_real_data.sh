#!/bin/bash

# Quick real data analysis for Wireshark K-means plugin
echo "=== Wireshark K-means Real Data Analysis ==="

# Check if user provided a capture file
if [ $# -eq 1 ]; then
    CAPTURE_FILE="$1"
    if [ ! -f "$CAPTURE_FILE" ]; then
        echo "Error: File not found: $CAPTURE_FILE"
        exit 1
    fi
else
    # Look for recent capture files
    echo "Looking for recent capture files..."
    
    SEARCH_DIRS=(
        "$HOME/Downloads"
        "$HOME/Desktop"
        "$(pwd)"
    )
    
    LATEST_FILE=""
    LATEST_TIME=0
    
    for dir in "${SEARCH_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            for file in "$dir"/*.pcap "$dir"/*.pcapng; do
                if [ -f "$file" ]; then
                    FILE_TIME=$(stat -f %m "$file" 2>/dev/null || stat -c %Y "$file" 2>/dev/null)
                    if [ "$FILE_TIME" -gt "$LATEST_TIME" ]; then
                        LATEST_TIME="$FILE_TIME"
                        LATEST_FILE="$file"
                    fi
                fi
            done
        fi
    done
    
    if [ -n "$LATEST_FILE" ]; then
        echo "Found recent capture: $LATEST_FILE"
        CAPTURE_FILE="$LATEST_FILE"
    else
        echo "No capture files found. Please provide a path:"
        echo "Usage: $0 /path/to/capture.pcap"
        echo ""
        echo "Or create a capture file in Wireshark:"
        echo "1. Start packet capture in Wireshark"
        echo "2. Let it run for a few seconds"
        echo "3. Stop capture and save as .pcap file"
        echo "4. Run this script again"
        exit 1
    fi
fi

# Get file info
echo ""
echo "Analyzing capture file: $CAPTURE_FILE"
echo "File size: $(ls -lh "$CAPTURE_FILE" | awk '{print $5}')"

# Count packets with tshark
TSHARK_PATH="/Applications/Wireshark.app/Contents/MacOS/tshark"
if [ -x "$TSHARK_PATH" ]; then
    PACKET_COUNT=$("$TSHARK_PATH" -r "$CAPTURE_FILE" -T fields -e frame.number | wc -l | tr -d ' ')
    echo "Total packets: $PACKET_COUNT"
elif command -v tshark &> /dev/null; then
    PACKET_COUNT=$(tshark -r "$CAPTURE_FILE" -T fields -e frame.number | wc -l | tr -d ' ')
    echo "Total packets: $PACKET_COUNT"
else
    echo "Warning: tshark not found, cannot count packets"
    PACKET_COUNT="unknown"
fi

echo ""
echo "Converting to CSV for analysis..."

# Create temporary CSV file
TEMP_CSV="/tmp/real_capture_$(date +%s).csv"
echo "Creating CSV file with proper format..."

if [ -x "$TSHARK_PATH" ]; then
    # Create CSV header
    echo "No.,Time,Source,Destination,Protocol,Length,Info" > "$TEMP_CSV"
    
    # Extract packet data and format as CSV
    "$TSHARK_PATH" -r "$CAPTURE_FILE" -T fields \
        -e frame.number \
        -e frame.time_epoch \
        -e ip.src \
        -e ip.dst \
        -e _ws.col.Protocol \
        -e frame.len \
        -e _ws.col.Info \
        -E header=n -E separator=, -E quote=d -E occurrence=f >> "$TEMP_CSV"
        
elif command -v tshark &> /dev/null; then
    # Create CSV header
    echo "No.,Time,Source,Destination,Protocol,Length,Info" > "$TEMP_CSV"
    
    # Extract packet data and format as CSV
    tshark -r "$CAPTURE_FILE" -T fields \
        -e frame.number \
        -e frame.time_epoch \
        -e ip.src \
        -e ip.dst \
        -e _ws.col.Protocol \
        -e frame.len \
        -e _ws.col.Info \
        -E header=n -E separator=, -E quote=d -E occurrence=f >> "$TEMP_CSV"
else
    echo "Error: tshark not found"
    exit 1
fi

if [ $? -eq 0 ] && [ -f "$TEMP_CSV" ]; then
    CSV_LINES=$(wc -l < "$TEMP_CSV")
    echo "✓ CSV created with $CSV_LINES lines"
    
    echo ""
    echo "Running K-means analysis on REAL packet data..."
    
    # Find Python backend
    PYTHON_BACKEND="/Users/$USER/.local/lib/wireshark/plugins/wireshark_kmeans_backend.py"
    VENV_PYTHON="/Users/$USER/.local/lib/wireshark/plugins/venv/bin/python"
    
    if [ -x "$VENV_PYTHON" ] && [ -f "$PYTHON_BACKEND" ]; then
        echo "Using: $VENV_PYTHON"
        
        # Run analysis
        "$VENV_PYTHON" "$PYTHON_BACKEND" "$TEMP_CSV" --clusters 5 --format json
        
        echo ""
        echo "=== Real Data Analysis Complete ==="
        echo "✓ Analyzed $PACKET_COUNT real packets from $CAPTURE_FILE"
        echo ""
        echo "This is REAL network traffic data, not sample data!"
        
    else
        echo "Error: Python backend not found"
        echo "Please run ./install_plugin_fixed.sh first"
    fi
    
    # Clean up
    rm -f "$TEMP_CSV"
    
else
    echo "Error: Failed to create CSV file"
    echo "Make sure tshark is installed and the capture file is valid"
fi
