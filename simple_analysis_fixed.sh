#!/bin/bash

# Simple Wireshark K-means Analysis with Enhanced Lua Conflict Prevention
echo "🔬 Wireshark K-means Analysis v4.1.0"
echo "======================================"
echo "✅ Enhanced with Lua conflict prevention"
echo ""

# Function to find Wireshark's currently opened capture file
find_wireshark_capture() {
    echo "🔍 Checking for Wireshark's opened capture file..." >&2
    
    # Check if Wireshark is running (multiple possible process names)
    WIRESHARK_PID=$(pgrep -f -i "wireshark" | head -1)
    
    if [ -z "$WIRESHARK_PID" ]; then
        # Try alternative process detection for macOS app bundle
        WIRESHARK_PID=$(ps aux | grep -i wireshark | grep -v grep | awk '{print $2}' | head -1)
    fi
    
    if [ -n "$WIRESHARK_PID" ]; then
        echo "✅ Found Wireshark running (PID: $WIRESHARK_PID)" >&2
        
        # Method 1: Use lsof to find opened capture files
        OPENED_FILES=$(lsof -p "$WIRESHARK_PID" 2>/dev/null | grep -E '\.(pcap|pcapng|cap)$' | awk '{for(i=9;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/[[:space:]]*$//' | sort -u)
        
        if [ -n "$OPENED_FILES" ]; then
            echo "📁 Found opened capture files:" >&2
            echo "$OPENED_FILES" | while read -r file; do
                if [ -f "$file" ]; then
                    size=$(ls -lh "$file" | awk '{print $5}')
                    echo "   📄 $(basename "$file") ($size) - $file" >&2
                fi
            done
            
            # Return the first valid file
            echo "$OPENED_FILES" | while read -r file; do
                if [ -f "$file" ]; then
                    echo "$file"
                    return 0
                fi
            done | head -1
            
            return 0
        fi
    fi
    
    return 1
}

# Function to get clean tshark command
get_clean_tshark() {
    if [ -f "/Users/rbodnar/.local/lib/wireshark/plugins/tshark_clean.sh" ]; then
        echo "/Users/rbodnar/.local/lib/wireshark/plugins/tshark_clean.sh"
    elif [ -f "tshark_clean.sh" ]; then
        echo "./tshark_clean.sh"
    else
        echo "/Applications/Wireshark.app/Contents/MacOS/tshark"
    fi
}

# Function to analyze a file
analyze_file() {
    local file="$1"
    
    echo "📁 Analyzing: $(basename "$file")"
    
    # Get clean tshark command
    local tshark_cmd=$(get_clean_tshark)
    
    # Validate file
    if ! "$tshark_cmd" -r "$file" -c 1 &> /dev/null; then
        echo "❌ Invalid capture file"
        return 1
    fi
    
    # Get packet count
    local packet_count=$("$tshark_cmd" -r "$file" -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' ')
    echo "📦 Packets: $packet_count"
    
    # Convert to CSV
    echo "🔄 Extracting features..."
    local temp_csv="/tmp/analysis_$(date +%s).csv"
    
    echo "No.,Time,Source,Destination,Protocol,Length,Info" > "$temp_csv"
    
    # Use clean tshark to avoid all Lua conflicts
    "$tshark_cmd" -r "$file" -T fields \
        -e frame.number \
        -e frame.time_epoch \
        -e ip.src \
        -e ip.dst \
        -e _ws.col.Protocol \
        -e frame.len \
        -e _ws.col.Info \
        -E header=n -E separator=, -E quote=d -E occurrence=f >> "$temp_csv"
    
    # Run analysis with isolated environment
    echo "🧠 Running K-means analysis..."
    
    local isolated_runner=""
    if [ -f "/Users/rbodnar/.local/lib/wireshark/plugins/run_analysis_isolated.sh" ]; then
        isolated_runner="/Users/rbodnar/.local/lib/wireshark/plugins/run_analysis_isolated.sh"
    elif [ -f "run_analysis_isolated.sh" ]; then
        isolated_runner="./run_analysis_isolated.sh"
    fi
    
    if [ -n "$isolated_runner" ]; then
        # Use isolated runner to avoid Lua conflicts
        LUA_PATH="" LUA_CPATH="" "$isolated_runner" "$temp_csv" --graphs
    else
        # Fallback to direct Python execution
        local python_cmd=""
        if [ -f "/Users/rbodnar/.local/lib/wireshark/plugins/venv/bin/python" ]; then
            python_cmd="/Users/rbodnar/.local/lib/wireshark/plugins/venv/bin/python"
        elif command -v python3 &> /dev/null; then
            python_cmd="python3"
        else
            echo "❌ Python not found"
            rm -f "$temp_csv"
            return 1
        fi
        
        local backend=""
        if [ -f "/Users/rbodnar/.local/lib/wireshark/plugins/wireshark_kmeans_backend_enhanced.py" ]; then
            backend="/Users/rbodnar/.local/lib/wireshark/plugins/wireshark_kmeans_backend_enhanced.py"
        elif [ -f "wireshark_kmeans_backend_enhanced.py" ]; then
            backend="wireshark_kmeans_backend_enhanced.py"
        else
            echo "❌ Analysis backend not found"
            rm -f "$temp_csv"
            return 1
        fi
        
        LUA_PATH="" LUA_CPATH="" "$python_cmd" "$backend" "$temp_csv" --graphs
    fi
    
    # Cleanup
    rm -f "$temp_csv"
    
    echo ""
    echo "✅ Analysis complete for $(basename "$file")"
    echo ""
}

# Function to find capture files in common locations
find_capture_files() {
    local search_paths=(
        "$HOME/Downloads"
        "$HOME/Desktop"
        "$HOME/Documents"
        "."
    )
    
    local files=()
    for search_path in "${search_paths[@]}"; do
        if [ -d "$search_path" ]; then
            while IFS= read -r -d '' file; do
                files+=("$file")
            done < <(find "$search_path" -maxdepth 2 -type f \( -name "*.pcap" -o -name "*.pcapng" -o -name "*.cap" \) -print0 2>/dev/null)
        fi
    done
    
    printf '%s\n' "${files[@]}"
}

# Main execution logic
main() {
    if [ $# -eq 1 ]; then
        # File specified as argument
        if [ -f "$1" ]; then
            analyze_file "$1"
        else
            echo "❌ File not found: $1"
            exit 1
        fi
    else
        # Method 1: Check if Wireshark has a file open
        echo "🎯 Priority 1: Checking Wireshark's opened capture files..."
        if WIRESHARK_FILE=$(find_wireshark_capture); then
            echo ""
            echo "✅ Using file currently opened in Wireshark:"
            echo "📁 File: $(basename "$WIRESHARK_FILE")"
            
            # Show file info
            size=$(ls -lh "$WIRESHARK_FILE" | awk '{print $5}')
            mod_time=$(ls -l "$WIRESHARK_FILE" | awk '{print $6, $7, $8}')
            echo "📏 Size: $size"
            echo "📅 Modified: $mod_time"
            
            # Quick packet count check
            local tshark_cmd=$(get_clean_tshark)
            if command -v "$tshark_cmd" &> /dev/null; then
                packet_count=$("$tshark_cmd" -r "$WIRESHARK_FILE" -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' ')
                echo "📦 Packets: $packet_count"
            fi
            echo ""
            
            analyze_file "$WIRESHARK_FILE"
        else
            # Method 2: Look for files in common locations
            echo ""
            echo "🎯 Priority 2: Searching for capture files in common locations..."
            
            # Find capture files
            mapfile -t capture_files < <(find_capture_files)
            
            if [ ${#capture_files[@]} -eq 0 ]; then
                echo ""
                echo "❌ No capture files found in common locations:"
                echo "   - ~/Downloads"
                echo "   - ~/Desktop"  
                echo "   - ~/Documents"
                echo "   - Current directory"
                echo ""
                echo "💡 Try:"
                echo "   1. Open a capture file in Wireshark first"
                echo "   2. Place a .pcap/.pcapng file in Downloads or Desktop"
                echo "   3. Run: $0 /path/to/your/file.pcap"
                exit 1
            fi
            
            echo "📋 Found ${#capture_files[@]} capture files:"
            echo ""
            
            # Display files with index
            for i in "${!capture_files[@]}"; do
                file="${capture_files[$i]}"
                size=$(ls -lh "$file" 2>/dev/null | awk '{print $5}' || echo "?")
                printf "   [%d] %s (%s)\n" $((i+1)) "$(basename "$file")" "$size"
            done
            
            echo ""
            read -p "Select file [1-${#capture_files[@]}]: " choice
            
            if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#capture_files[@]} ]; then
                selected_file="${capture_files[$((choice-1))]}"
                echo ""
                analyze_file "$selected_file"
            else
                echo "❌ Invalid selection"
                exit 1
            fi
        fi
    fi
}

# Run main function
main "$@"

echo "🎉 All done!"
