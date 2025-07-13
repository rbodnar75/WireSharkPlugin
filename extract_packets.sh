#!/bin/bash

# Simple packet extraction script for the plugin
CAPTURE_FILE="$1"
OUTPUT_CSV="$2"

# Check parameters
if [ -z "$CAPTURE_FILE" ] || [ -z "$OUTPUT_CSV" ]; then
    echo "Usage: $0 <capture_file> <output_csv>"
    exit 1
fi

# Find tshark
TSHARK_PATH=""
if [ -x "/Applications/Wireshark.app/Contents/MacOS/tshark" ]; then
    TSHARK_PATH="/Applications/Wireshark.app/Contents/MacOS/tshark"
elif command -v tshark &> /dev/null; then
    TSHARK_PATH="tshark"
else
    echo "Error: tshark not found"
    exit 1
fi

# Disable Wireshark plugins to avoid interference
export WIRESHARK_LUA_DISABLE=1

# Create CSV header
echo "No.,Time,Source,Destination,Protocol,Length,Info" > "$OUTPUT_CSV"

# Extract packet data
"$TSHARK_PATH" -r "$CAPTURE_FILE" -T fields \
    -e frame.number \
    -e frame.time_epoch \
    -e ip.src \
    -e ip.dst \
    -e _ws.col.Protocol \
    -e frame.len \
    -e _ws.col.Info \
    -E header=n -E separator=, -E quote=d -E occurrence=f >> "$OUTPUT_CSV"

# Check if extraction succeeded
if [ $? -eq 0 ] && [ -s "$OUTPUT_CSV" ]; then
    LINES=$(wc -l < "$OUTPUT_CSV")
    echo "Success: Extracted $((LINES - 1)) packets"
    exit 0
else
    echo "Error: Failed to extract packets"
    exit 1
fi
