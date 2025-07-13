#!/bin/bash

# Enhanced real data analysis for Wireshark K-means plugin
echo "🔍 Wireshark K-means Real Data Analysis (Enhanced)"
echo "=================================================="

# Function to find capture files
find_capture_files() {
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
        done | sort -nr | cut -f2
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

# Check for command line argument first
if [ $# -eq 1 ]; then
    if [ -f "$1" ]; then
        CAPTURE_FILE="$1"
        echo "✅ Using specified file:"
        show_file_info "$CAPTURE_FILE"
    else
        echo "❌ Error: File '$1' not found"
        echo ""
        echo "Usage examples:"
        echo "  $0 capture.pcap"
        echo "  $0 /path/to/file.pcapng"
        echo "  $0                    # Auto-detect files"
        exit 1
    fi
else
    # Auto-detect capture files
    echo "🔎 Searching for capture files..."
    echo "   Locations: ~/Downloads, ~/Desktop, current directory, /tmp"
    echo "   Formats: .pcap, .pcapng, .cap (max 100MB)"
    echo ""
    
    readarray -t CAPTURE_FILES < <(find_capture_files)
    
    if [ ${#CAPTURE_FILES[@]} -eq 0 ]; then
        echo "❌ No capture files found!"
        echo ""
        echo "💡 To create a capture file:"
        echo "   1. Open Wireshark"
        echo "   2. Start capturing on your network interface"
        echo "   3. Generate some network traffic"
        echo "   4. Stop capture and save as .pcap/.pcapng"
        echo "   5. Run this script again"
        echo ""
        echo "💡 Or specify a file directly:"
        echo "   $0 /path/to/your/capture.pcap"
        exit 1
    elif [ ${#CAPTURE_FILES[@]} -eq 1 ]; then
        CAPTURE_FILE="${CAPTURE_FILES[0]}"
        echo "✅ Found one capture file:"
        show_file_info "$CAPTURE_FILE"
    else
        echo "🎯 Found ${#CAPTURE_FILES[@]} capture files:"
        echo ""
        for i in "${!CAPTURE_FILES[@]}"; do
            local size=$(ls -lh "${CAPTURE_FILES[$i]}" | awk '{print $5}')
            local basename=$(basename "${CAPTURE_FILES[$i]}")
            printf "   [%2d] %-40s (%s)\n" "$((i+1))" "$basename" "$size"
        done
        echo ""
        echo "0️⃣  [0] Exit"
        echo ""
        read -p "🎯 Select file number [0-${#CAPTURE_FILES[@]}]: " choice
        
        if [ "$choice" = "0" ]; then
            echo "👋 Exiting..."
            exit 0
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#CAPTURE_FILES[@]} ]; then
            CAPTURE_FILE="${CAPTURE_FILES[$((choice-1))]}"
            echo ""
            echo "✅ Selected:"
            show_file_info "$CAPTURE_FILE"
        else
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
TEMP_CSV="/tmp/real_capture_$(date +%s).csv"

# Detect tshark location
TSHARK_PATH=""
if [ -x "/Applications/Wireshark.app/Contents/MacOS/tshark" ]; then
    TSHARK_PATH="/Applications/Wireshark.app/Contents/MacOS/tshark"
elif command -v tshark &> /dev/null; then
    TSHARK_PATH="tshark"
else
    echo "❌ Error: tshark not found"
    echo "   Please install Wireshark or ensure tshark is in PATH"
    exit 1
fi

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

# Run analysis
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
echo "🎉 === Real Data Analysis Complete ==="
echo "✅ Analyzed $PACKET_COUNT real packets from $(basename "$CAPTURE_FILE")"
echo ""
echo "🔬 This is REAL network traffic data, not sample data!"
echo "   You can now use these analysis results to understand your network patterns."
echo ""
echo "💡 Next steps:"
echo "   - Review the cluster analysis results above"
echo "   - Look for high anomaly scores (> 0.7) indicating suspicious activity"
echo "   - Check small clusters for potential security incidents"
echo "   - Use the Wireshark plugin console commands for interactive analysis"
