#!/bin/bash

# Enhanced Wireshark K-means Analysis with Auto-Detection
# This script can detect opened capture files and analyze them directly

echo "🔬 Wireshark K-means Analysis - Auto-Detection Mode"
echo "=================================================="

# Function to find Wireshark processes and their opened files
find_wireshark_capture() {
    echo "🔍 Looking for Wireshark processes and opened capture files..."
    
    # Check if Wireshark is running
    WIRESHARK_PID=$(pgrep -f "Wireshark")
    
    if [ -n "$WIRESHARK_PID" ]; then
        echo "✅ Found Wireshark running (PID: $WIRESHARK_PID)"
        
        # Try to find opened capture files using lsof
        CAPTURE_FILES=$(lsof -p "$WIRESHARK_PID" 2>/dev/null | grep -E '\.(pcap|pcapng|cap)$' | awk '{print $NF}' | sort -u)
        
        if [ -n "$CAPTURE_FILES" ]; then
            echo "📁 Found opened capture files:"
            echo "$CAPTURE_FILES" | nl -w2 -s'. '
            
            # If multiple files, let user choose
            CAPTURE_ARRAY=($CAPTURE_FILES)
            if [ ${#CAPTURE_ARRAY[@]} -eq 1 ]; then
                SELECTED_FILE="${CAPTURE_ARRAY[0]}"
                echo "📌 Using: $(basename "$SELECTED_FILE")"
            else
                echo ""
                read -p "Select file number [1-${#CAPTURE_ARRAY[@]}]: " choice
                if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#CAPTURE_ARRAY[@]} ]; then
                    SELECTED_FILE="${CAPTURE_ARRAY[$((choice-1))]}"
                    echo "📌 Selected: $(basename "$SELECTED_FILE")"
                else
                    echo "❌ Invalid selection"
                    return 1
                fi
            fi
            
            echo "$SELECTED_FILE"
            return 0
        else
            echo "⚠️  No capture files currently opened in Wireshark"
        fi
    else
        echo "⚠️  Wireshark is not currently running"
    fi
    
    return 1
}

# Function to find recent capture files
find_recent_captures() {
    echo "🔍 Looking for recent capture files..."
    
    local search_dirs=(
        "$HOME/Downloads"
        "$HOME/Desktop" 
        "$(pwd)"
        "/tmp"
    )
    
    local files=()
    for dir in "${search_dirs[@]}"; do
        if [ -d "$dir" ]; then
            while IFS= read -r -d '' file; do
                # Skip files larger than 100MB for performance
                local size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null)
                if [ "$size" -lt 104857600 ]; then  # 100MB limit
                    files+=("$file")
                fi
            done < <(find "$dir" -maxdepth 2 -type f \( -name "*.pcap" -o -name "*.pcapng" -o -name "*.cap" \) -print0 2>/dev/null)
        fi
    done
    
    # Sort by modification time (newest first)
    if [ ${#files[@]} -gt 0 ]; then
        printf '%s\n' "${files[@]}" | while IFS= read -r file; do
            printf '%s\t%s\n' "$(stat -f%m "$file" 2>/dev/null || stat -c%Y "$file" 2>/dev/null)" "$file"
        done | sort -nr | cut -f2 | head -5
    fi
}

# Function to display file info
show_file_info() {
    local file="$1"
    local size=$(ls -lh "$file" | awk '{print $5}')
    local mod_time=$(ls -l "$file" | awk '{print $6, $7, $8}')
    
    echo "📁 File: $(basename "$file")"
    echo "📏 Size: $size"
    echo "📅 Modified: $mod_time"
    
    # Quick packet count check
    if command -v /Applications/Wireshark.app/Contents/MacOS/tshark &> /dev/null; then
        local packet_count=$(/Applications/Wireshark.app/Contents/MacOS/tshark -r "$file" -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' ')
        echo "📦 Packets: $packet_count"
    fi
    echo ""
}

# Main logic
CAPTURE_FILE=""

# Method 1: Check command line argument
if [ $# -eq 1 ]; then
    if [ -f "$1" ]; then
        CAPTURE_FILE="$1"
        echo "✅ Using specified file:"
        show_file_info "$CAPTURE_FILE"
    else
        echo "❌ File not found: $1"
        exit 1
    fi

# Method 2: Try to detect opened file in Wireshark
elif WIRESHARK_FILE=$(find_wireshark_capture); then
    CAPTURE_FILE="$WIRESHARK_FILE"
    echo ""
    echo "✅ Using file opened in Wireshark:"
    show_file_info "$CAPTURE_FILE"

# Method 3: Look for recent capture files
else
    echo ""
    echo "🔎 Searching for recent capture files..."
    # Create temporary file for results
    TEMP_FILE_LIST="/tmp/capture_files_$(date +%s).txt"
    find_recent_captures > "$TEMP_FILE_LIST"
    
    if [ ! -s "$TEMP_FILE_LIST" ]; then
        rm -f "$TEMP_FILE_LIST"
        echo "❌ No capture files found!"
        echo ""
        echo "💡 Options:"
        echo "   1. Open a capture file in Wireshark first"
        echo "   2. Specify a file: $0 /path/to/capture.pcap"
        echo "   3. Place a .pcap/.pcapng file in Downloads or Desktop"
        exit 1
    elif [ $(wc -l < "$TEMP_FILE_LIST") -eq 1 ]; then
        CAPTURE_FILE=$(cat "$TEMP_FILE_LIST")
        rm -f "$TEMP_FILE_LIST"
        echo "✅ Found recent capture file:"
        show_file_info "$CAPTURE_FILE"
    else
        echo "🎯 Found $(wc -l < "$TEMP_FILE_LIST") recent capture files:"
        echo ""
        local i=1
        while IFS= read -r file; do
            local size=$(ls -lh "$file" | awk '{print $5}')
            local basename=$(basename "$file")
            printf "   [%2d] %-40s (%s)\n" "$i" "$basename" "$size"
            i=$((i+1))
        done < "$TEMP_FILE_LIST"
        
        echo ""
        read -p "🎯 Select file number [1-$(wc -l < "$TEMP_FILE_LIST")]: " choice
        
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le $(wc -l < "$TEMP_FILE_LIST") ]; then
            CAPTURE_FILE=$(sed -n "${choice}p" "$TEMP_FILE_LIST")
            rm -f "$TEMP_FILE_LIST"
            echo ""
            echo "✅ Selected:"
            show_file_info "$CAPTURE_FILE"
        else
            rm -f "$TEMP_FILE_LIST"
            echo "❌ Invalid selection"
            exit 1
        fi
    fi
fi

# Validate the capture file
echo "🔍 Validating capture file..."
if ! /Applications/Wireshark.app/Contents/MacOS/tshark -r "$CAPTURE_FILE" -c 1 &> /dev/null; then
    echo "❌ Error: Invalid or corrupted capture file"
    echo "   File: $CAPTURE_FILE"
    exit 1
fi

# Get detailed file info
PACKET_COUNT=$(/Applications/Wireshark.app/Contents/MacOS/tshark -r "$CAPTURE_FILE" -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' ')
echo "✅ Valid capture file with $PACKET_COUNT packets"
echo ""

# Convert to CSV for analysis
echo "🔄 Converting to CSV format..."
TEMP_CSV="/tmp/wireshark_analysis_$(date +%s).csv"

# Create CSV header
echo "No.,Time,Source,Destination,Protocol,Length,Info" > "$TEMP_CSV"

# Extract packet data
WIRESHARK_LUA_DISABLE=1 /Applications/Wireshark.app/Contents/MacOS/tshark -r "$CAPTURE_FILE" -T fields \
    -e frame.number \
    -e frame.time_epoch \
    -e ip.src \
    -e ip.dst \
    -e _ws.col.Protocol \
    -e frame.len \
    -e _ws.col.Info \
    -E header=n -E separator=, -E quote=d -E occurrence=f >> "$TEMP_CSV"

CSV_LINES=$(wc -l < "$TEMP_CSV")
echo "✅ CSV created with $(printf "%8d" $((CSV_LINES))) lines"
echo ""

# Run K-means analysis
echo "🧠 Running K-means analysis on REAL packet data..."

# Find Python environment
PYTHON_PATH=""
if [ -f "/Users/rbodnar/.local/lib/wireshark/plugins/venv/bin/python" ]; then
    PYTHON_PATH="/Users/rbodnar/.local/lib/wireshark/plugins/venv/bin/python"
elif command -v python3 &> /dev/null; then
    PYTHON_PATH="python3"
else
    echo "❌ Error: Python not found"
    exit 1
fi

echo "🐍 Using: $PYTHON_PATH"

# Find backend script
if [ -f "/Users/rbodnar/.local/lib/wireshark/plugins/wireshark_kmeans_backend_enhanced.py" ]; then
    BACKEND="/Users/rbodnar/.local/lib/wireshark/plugins/wireshark_kmeans_backend_enhanced.py"
elif [ -f "wireshark_kmeans_backend_enhanced.py" ]; then
    BACKEND="wireshark_kmeans_backend_enhanced.py"
elif [ -f "/Users/rbodnar/.local/lib/wireshark/plugins/wireshark_kmeans_backend.py" ]; then
    BACKEND="/Users/rbodnar/.local/lib/wireshark/plugins/wireshark_kmeans_backend.py"
else
    echo "❌ Error: Python backend not found"
    exit 1
fi

echo "📊 Backend: $(basename "$BACKEND")"
echo ""

# Execute analysis
"$PYTHON_PATH" "$BACKEND" "$TEMP_CSV"

# Cleanup
echo ""
echo "🧹 Cleaning up temporary files..."
rm -f "$TEMP_CSV"

echo ""
echo "🎉 === Analysis Complete ==="
echo "✅ Analyzed $PACKET_COUNT real packets from $(basename "$CAPTURE_FILE")"
echo ""
echo "🔬 This analysis used REAL network traffic data!"
echo ""
echo "💡 Next time:"
echo "   • Keep the file open in Wireshark for auto-detection"
echo "   • Or specify directly: $0 /path/to/capture.pcap"
