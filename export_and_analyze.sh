#!/bin/bash

# Wireshark Capture Export Helper
# This script helps export the current capture for K-means analysis

TEMP_DIR="${TMPDIR:-/tmp}"
TIMESTAMP=$(date +%s)
CSV_FILE="$TEMP_DIR/wireshark_capture_$TIMESTAMP.csv"

echo "=== Wireshark K-means Export Helper ==="
echo "Temporary CSV file: $CSV_FILE"

# Function to export current capture using tshark
export_with_tshark() {
    echo "Attempting to export current capture using tshark..."
    
    # Try to find a running Wireshark capture file
    WIRESHARK_TEMP_FILES=$(find "$TEMP_DIR" -name "wireshark*" -type f 2>/dev/null | head -1)
    
    if [ -n "$WIRESHARK_TEMP_FILES" ]; then
        echo "Found Wireshark temp file: $WIRESHARK_TEMP_FILES"
        tshark -r "$WIRESHARK_TEMP_FILES" -T csv -E header=y > "$CSV_FILE"
    else
        echo "No Wireshark temp files found. Please save your capture first."
        return 1
    fi
}

# Function to create CSV from most recent pcap/pcapng file
export_recent_capture() {
    echo "Looking for recent capture files..."
    
    # Common capture locations
    CAPTURE_DIRS=(
        "$HOME/Downloads"
        "$HOME/Desktop"
        "$(pwd)"
        "/tmp"
    )
    
    LATEST_FILE=""
    LATEST_TIME=0
    
    for dir in "${CAPTURE_DIRS[@]}"; do
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
        echo "Found recent capture file: $LATEST_FILE"
        echo "Exporting to CSV..."
        tshark -r "$LATEST_FILE" -T csv -E header=y > "$CSV_FILE"
        return 0
    else
        echo "No capture files found in common locations"
        return 1
    fi
}

# Function to analyze the exported CSV
analyze_csv() {
    if [ ! -f "$CSV_FILE" ]; then
        echo "Error: CSV file not found: $CSV_FILE"
        return 1
    fi
    
    # Check if CSV has content
    LINE_COUNT=$(wc -l < "$CSV_FILE" 2>/dev/null)
    if [ "$LINE_COUNT" -lt 2 ]; then
        echo "Error: CSV file is empty or only has headers"
        return 1
    fi
    
    echo "CSV exported successfully: $LINE_COUNT lines"
    echo "Running K-means analysis..."
    
    # Find the Python backend
    BACKEND_LOCATIONS=(
        "/Users/$USER/.local/lib/wireshark/plugins/wireshark_kmeans_backend.py"
        "./wireshark_kmeans_backend.py"
        "./wireshark_kmeans_backend_minimal.py"
    )
    
    BACKEND_SCRIPT=""
    for location in "${BACKEND_LOCATIONS[@]}"; do
        if [ -f "$location" ]; then
            BACKEND_SCRIPT="$location"
            break
        fi
    done
    
    if [ -z "$BACKEND_SCRIPT" ]; then
        echo "Error: Python backend not found"
        echo "Expected locations:"
        for location in "${BACKEND_LOCATIONS[@]}"; do
            echo "  $location"
        done
        return 1
    fi
    
    echo "Using backend: $BACKEND_SCRIPT"
    
    # Try virtual environment first, then system python
    VENV_PYTHON="/Users/$USER/.local/lib/wireshark/plugins/venv/bin/python"
    if [ -x "$VENV_PYTHON" ]; then
        echo "Using virtual environment Python"
        "$VENV_PYTHON" "$BACKEND_SCRIPT" "$CSV_FILE" --clusters 5 --format json
    else
        echo "Using system Python"
        python3 "$BACKEND_SCRIPT" "$CSV_FILE" --clusters 5 --format json
    fi
    
    # Clean up
    echo "Cleaning up temporary file: $CSV_FILE"
    rm -f "$CSV_FILE"
}

# Main execution
main() {
    echo "Choose export method:"
    echo "1. Export from most recent capture file"
    echo "2. Manual file path"
    echo "3. Help with Wireshark export"
    
    read -p "Enter choice (1-3): " choice
    
    case $choice in
        1)
            if export_recent_capture; then
                analyze_csv
            else
                echo "Failed to export recent capture"
                exit 1
            fi
            ;;
        2)
            read -p "Enter path to capture file: " capture_file
            if [ -f "$capture_file" ]; then
                echo "Exporting $capture_file to CSV..."
                tshark -r "$capture_file" -T csv -E header=y > "$CSV_FILE"
                analyze_csv
            else
                echo "Error: File not found: $capture_file"
                exit 1
            fi
            ;;
        3)
            echo ""
            echo "=== How to Export from Wireshark ==="
            echo "1. In Wireshark, open your capture file"
            echo "2. Go to File > Export Packet Dissections > As CSV..."
            echo "3. Save the CSV file"
            echo "4. Run this script and choose option 2"
            echo "5. Enter the path to your saved CSV file"
            echo ""
            echo "=== Alternative: Use tshark directly ==="
            echo "tshark -r your_capture.pcap -T csv -E header=y > export.csv"
            echo ""
            ;;
        *)
            echo "Invalid choice"
            exit 1
            ;;
    esac
}

# Check if tshark is available
if ! command -v tshark &> /dev/null; then
    echo "Error: tshark not found. Please install Wireshark command-line tools."
    echo "On macOS: brew install wireshark"
    echo "On Ubuntu: sudo apt-get install tshark"
    exit 1
fi

main "$@"
