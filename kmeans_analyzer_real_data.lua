-- K-means Anomaly Detection Plugin for Wireshark
-- Enhanced version that works with REAL packet data from capture files

-- Check Wireshark version compatibility
local version_str = get_version()
print("K-means Analyzer: Plugin loaded successfully!")
print("K-means Analyzer: Wireshark version: " .. version_str)

-- Plugin information
local plugin_info = {
    name = "K-means Anomaly Analyzer",
    version = "3.0.0",
    description = "Analyzes network traffic using K-means clustering to detect anomalies - NOW WITH REAL DATA SUPPORT",
    author = "Wireshark K-means Plugin"
}

-- Create a new protocol for our analysis
local kmeans_proto = Proto("kmeans_analyzer", "K-means Anomaly Analyzer")

-- Define fields for our analysis
local f_cluster_id = ProtoField.uint8("kmeans.cluster_id", "Cluster ID", base.DEC)
local f_anomaly_score = ProtoField.float("kmeans.anomaly_score", "Anomaly Score", base.DEC)
local f_packet_features = ProtoField.string("kmeans.features", "Packet Features")
local f_analysis_result = ProtoField.string("kmeans.result", "Analysis Result")

-- Add fields to the protocol
kmeans_proto.fields = {f_cluster_id, f_anomaly_score, f_packet_features, f_analysis_result}

-- Global variables for analysis
local packet_data = {}
local analysis_results = {}
local config = {
    num_clusters = 5,
    enable_realtime = false,
    min_packets = 10,  -- Lowered from 50 for small captures
    python_script_path = "",
    use_real_data = true  -- NEW: Enable real data collection
}

-- Safe table size function (replacement for deprecated table.maxn)
local function table_size(t)
    if not t then return 0 end
    local count = 0
    for _ in pairs(t) do
        count = count + 1
    end
    return count
end

-- Create safe directory function
local function get_safe_temp_dir()
    local temp_dirs = {"/tmp", "/var/tmp", os.getenv("TMPDIR") or "/tmp"}
    for _, dir in ipairs(temp_dirs) do
        if dir and io.open(dir, "r") then
            return dir
        end
    end
    return "/tmp"
end

-- Enhanced real packet collection using tshark
local function collect_real_packets_with_tshark()
    print("K-means Analyzer: Attempting to collect REAL packets using tshark...")
    
    -- Clear existing data
    packet_data = {}
    
    -- Try to get the current capture file path
    local capture_file = nil
    
    -- Method 1: Check if there's a capture file loaded
    if get_capture_file and get_capture_file() then
        capture_file = get_capture_file()
        print("K-means Analyzer: Found loaded capture file")
    end
    
    -- Method 2: Look for recent capture files if no file is loaded
    if not capture_file then
        print("K-means Analyzer: No capture file loaded, looking for recent files...")
        local search_dirs = {
            os.getenv("HOME") .. "/Downloads",
            os.getenv("HOME") .. "/Desktop",
            "/tmp"
        }
        
        local find_cmd = "find " .. table.concat(search_dirs, " ") .. 
                        " -name '*.pcap' -o -name '*.pcapng' -o -name '*.cap' 2>/dev/null | head -1"
        
        local handle = io.popen(find_cmd)
        if handle then
            capture_file = handle:read("*l")
            handle:close()
            if capture_file and capture_file ~= "" then
                print("K-means Analyzer: Found recent capture file: " .. capture_file)
            end
        end
    end
    
    if not capture_file or capture_file == "" then
        print("K-means Analyzer: No capture file found")
        return false
    end
    
    -- Use tshark to extract real packet data
    local temp_dir = get_safe_temp_dir()
    local csv_file = temp_dir .. "/wireshark_real_packets_" .. os.time() .. ".csv"
    
    -- Find tshark executable
    local tshark_paths = {
        "/Applications/Wireshark.app/Contents/MacOS/tshark",
        "/usr/bin/tshark",
        "/usr/local/bin/tshark"
    }
    
    local tshark_cmd = nil
    for _, path in ipairs(tshark_paths) do
        local test_cmd = "test -x " .. path .. " && echo 'found'"
        local handle = io.popen(test_cmd)
        if handle then
            local result = handle:read("*l")
            handle:close()
            if result == "found" then
                tshark_cmd = path
                break
            end
        end
    end
    
    if not tshark_cmd then
        print("K-means Analyzer: tshark not found")
        return false
    end
    
    -- Use external extraction script to avoid Lua plugin interference
    local script_path = os.getenv("HOME") .. "/.local/lib/wireshark/plugins/extract_packets.sh"
    local extract_cmd = script_path .. ' "' .. capture_file .. '" "' .. csv_file .. '"'
    
    print("K-means Analyzer: Using extraction script:")
    print("  " .. extract_cmd)
    
    local extract_handle = io.popen(extract_cmd .. " 2>&1")
    if not extract_handle then
        print("K-means Analyzer: Failed to start extraction script")
        return false
    end
    
    local output = extract_handle:read("*a")
    local success = extract_handle:close()
    
    print("K-means Analyzer: Extraction output:")
    print("  " .. output)
    
    if not success then
        print("K-means Analyzer: Extraction script failed")
        return false
    end
    
    -- Read the CSV file and parse packets
    local file = io.open(csv_file, "r")
    if not file then
        print("K-means Analyzer: Failed to open CSV file")
        return false
    end
    
    -- Skip header line
    file:read("*l")
    
    local packet_count = 0
    for line in file:lines() do
        if line and line ~= "" then
            -- Parse CSV line (basic parsing)
            local fields = {}
            for field in string.gmatch(line .. ',', '([^,]*),') do
                table.insert(fields, field:gsub('"', ''))
            end
            
            if #fields >= 6 then
                local packet = {
                    frame_number = tonumber(fields[1]) or packet_count + 1,
                    timestamp = tonumber(fields[2]) or (packet_count * 0.001),
                    src_ip = fields[3] or "",
                    dst_ip = fields[4] or "",
                    protocol = fields[5] or "unknown",
                    length = tonumber(fields[6]) or 64,
                    info = fields[7] or "",
                    -- Additional computed fields
                    protocol_num = (fields[5] == "TCP") and 6 or (fields[5] == "UDP") and 17 or 1,
                    src_local = (string.match(fields[3] or "", "^192%.168%.") or 
                                string.match(fields[3] or "", "^10%.") or 
                                string.match(fields[3] or "", "^172%.1[6-9]%.") or
                                string.match(fields[3] or "", "^172%.2[0-9]%.") or
                                string.match(fields[3] or "", "^172%.3[0-1]%.")) and 1 or 0,
                    dst_local = (string.match(fields[4] or "", "^192%.168%.") or 
                                string.match(fields[4] or "", "^10%.") or 
                                string.match(fields[4] or "", "^172%.1[6-9]%.") or
                                string.match(fields[4] or "", "^172%.2[0-9]%.") or
                                string.match(fields[4] or "", "^172%.3[0-1]%.")) and 1 or 0
                }
                
                table.insert(packet_data, packet)
                packet_count = packet_count + 1
            end
        end
    end
    
    file:close()
    
    -- Clean up temporary file
    os.remove(csv_file)
    
    print("K-means Analyzer: Successfully collected " .. packet_count .. " REAL packets")
    print("K-means Analyzer: Protocols found: " .. get_protocol_summary())
    
    return packet_count > 0
end

-- Get protocol summary from collected packets
function get_protocol_summary()
    local protocol_count = {}
    for _, packet in ipairs(packet_data) do
        local proto = packet.protocol or "unknown"
        protocol_count[proto] = (protocol_count[proto] or 0) + 1
    end
    
    local summary = {}
    for proto, count in pairs(protocol_count) do
        table.insert(summary, proto .. "(" .. count .. ")")
    end
    
    return table.concat(summary, ", ")
end

-- Enhanced force packet collection function
function force_collect_packets()
    print("K-means Analyzer: Force collecting packets...")
    
    if config.use_real_data then
        print("K-means Analyzer: Attempting REAL packet collection...")
        local success = collect_real_packets_with_tshark()
        if success then
            print("✓ Collected " .. #packet_data .. " REAL packets")
            print("✓ Protocols: " .. get_protocol_summary())
            return true
        else
            print("✗ Real packet collection failed, falling back to sample data")
        end
    end
    
    -- Fallback to sample data if real collection fails
    print("K-means Analyzer: Generating sample data for demonstration...")
    return collect_sample_packets()
end

-- Original sample packet generation (fallback)
function collect_sample_packets()
    packet_data = {}
    
    local protocols = {"TCP", "UDP", "HTTP", "DNS", "HTTPS", "FTP", "SSH", "ICMP"}
    local local_ips = {"192.168.1.100", "192.168.1.101", "192.168.1.102", "10.0.0.50"}
    local external_ips = {"8.8.8.8", "172.217.14.110", "151.101.193.140", "17.253.144.10"}
    
    for i = 1, 100 do -- Generate 100 sample packets
        local protocol = protocols[1 + (i % #protocols)]
        local is_external = (i % 3) == 0
        
        local packet = {
            frame_number = i,
            timestamp = os.time() + (i * 0.1),
            src_ip = is_external and external_ips[1 + (i % #external_ips)] or local_ips[1 + (i % #local_ips)],
            dst_ip = is_external and local_ips[1 + (i % #local_ips)] or external_ips[1 + (i % #external_ips)],
            protocol = protocol,
            length = 64 + (i * 10 % 1400),
            protocol_num = (protocol == "TCP") and 6 or (protocol == "UDP") and 17 or 1,
            src_local = is_external and 0 or 1,
            dst_local = is_external and 1 or 0
        }
        
        table.insert(packet_data, packet)
    end
    
    print("K-means Analyzer: Generated " .. #packet_data .. " sample packets")
    return true
end

-- Export packets to CSV for Python analysis
local function export_packets_to_csv()
    local temp_dir = get_safe_temp_dir()
    local csv_file = temp_dir .. "/wireshark_export_" .. os.time() .. ".csv"
    
    local file = io.open(csv_file, "w")
    if not file then
        return nil, "Could not create CSV file"
    end
    
    -- Write CSV header
    file:write("No.,Time,Source,Destination,Protocol,Length,Info\n")
    
    -- Write packet data
    for _, packet in ipairs(packet_data) do
        local line = string.format("%d,%f,%s,%s,%s,%d,%s\n",
            packet.frame_number or 0,
            packet.timestamp or 0,
            packet.src_ip or "",
            packet.dst_ip or "",
            packet.protocol or "unknown",
            packet.length or 0,
            packet.info or ""
        )
        file:write(line)
    end
    
    file:close()
    
    -- Check if file was created and has content
    local file_check = io.open(csv_file, "r")
    if file_check then
        local content = file_check:read("*a")
        file_check:close()
        if string.len(content) > 100 then  -- Header + at least one packet
            return csv_file, nil
        else
            return nil, "CSV file is empty or too small"
        end
    else
        return nil, "Could not verify CSV file creation"
    end
end

-- Get Python script path
local function get_python_script_path()
    if config.python_script_path and config.python_script_path ~= "" then
        return config.python_script_path
    end
    
    local possible_paths = {
        os.getenv("HOME") .. "/.local/lib/wireshark/plugins/wireshark_kmeans_backend_enhanced.py",
        os.getenv("HOME") .. "/.local/lib/wireshark/plugins/wireshark_kmeans_backend.py",
        "./wireshark_kmeans_backend_enhanced.py",
        "./wireshark_kmeans_backend.py"
    }
    
    for _, path in ipairs(possible_paths) do
        local file = io.open(path, "r")
        if file then
            file:close()
            config.python_script_path = path
            return path
        end
    end
    
    return nil
end

-- Run K-means analysis
function run_kmeans_analysis()
    print("K-means Analyzer: Starting analysis...")
    print("K-means Analyzer: Real data mode: " .. (config.use_real_data and "ENABLED" or "DISABLED"))
    
    if table_size(packet_data) == 0 then
        print("K-means Analyzer: No packets collected, attempting collection...")
        if not force_collect_packets() then
            print("K-means Analyzer: Failed to collect packets")
            return false
        end
    end
    
    local packet_count = table_size(packet_data)
    print("K-means Analyzer: Analyzing " .. packet_count .. " packets")
    
    if packet_count < config.min_packets then
        print("K-means Analyzer: Not enough packets (" .. packet_count .. " < " .. config.min_packets .. ")")
        print("K-means Analyzer: Lowering threshold for small captures...")
        config.min_packets = math.max(5, packet_count)
    end
    
    -- Export packets to CSV
    local csv_file, error_msg = export_packets_to_csv()
    if not csv_file then
        print("K-means Analyzer: Failed to export packets: " .. (error_msg or "unknown error"))
        return false
    end
    
    print("K-means Analyzer: Exported packets to " .. csv_file)
    
    -- Find Python script
    local python_script = get_python_script_path()
    if not python_script then
        print("K-means Analyzer: Python backend not found")
        return false
    end
    
    -- Find Python executable
    local python_paths = {
        os.getenv("HOME") .. "/.local/lib/wireshark/plugins/venv/bin/python",
        "/usr/bin/python3",
        "/usr/local/bin/python3",
        "python3"
    }
    
    local python_cmd = nil
    for _, path in ipairs(python_paths) do
        local test_cmd = "which " .. path .. " 2>/dev/null"
        local handle = io.popen(test_cmd)
        if handle then
            local result = handle:read("*l")
            handle:close()
            if result and result ~= "" then
                python_cmd = path
                break
            end
        end
    end
    
    if not python_cmd then
        print("K-means Analyzer: Python not found")
        return false
    end
    
    -- Run analysis
    local analysis_cmd = python_cmd .. " " .. python_script .. " " .. csv_file .. " --clusters " .. config.num_clusters
    print("K-means Analyzer: Running: " .. analysis_cmd)
    
    local success = os.execute(analysis_cmd)
    
    -- Clean up
    os.remove(csv_file)
    
    if success == 0 then
        print("K-means Analyzer: Analysis completed successfully")
        return true
    else
        print("K-means Analyzer: Analysis failed")
        return false
    end
end

-- Toggle real data mode
function toggle_real_data_mode()
    config.use_real_data = not config.use_real_data
    print("K-means Analyzer: Real data mode " .. (config.use_real_data and "ENABLED" or "DISABLED"))
    if config.use_real_data then
        print("K-means Analyzer: Will attempt to use actual packet data from captures")
    else
        print("K-means Analyzer: Will use sample/synthetic data for demonstration")
    end
    return config.use_real_data
end

-- Show statistics
function show_kmeans_stats()
    print("=== K-means Analyzer Statistics ===")
    print("Plugin version: " .. plugin_info.version)
    print("Packets collected: " .. table_size(packet_data))
    print("Real data mode: " .. (config.use_real_data and "ENABLED" or "DISABLED"))
    print("Clusters: " .. config.num_clusters)
    print("Min packets: " .. config.min_packets)
    if table_size(packet_data) > 0 then
        print("Protocol summary: " .. get_protocol_summary())
    end
    print("=====================================")
end

-- Clear packet data
function clear_kmeans_data()
    packet_data = {}
    analysis_results = {}
    print("K-means Analyzer: Data cleared")
end

-- Show configuration
function show_kmeans_config()
    print("=== K-means Configuration ===")
    print("Number of clusters: " .. config.num_clusters)
    print("Real data mode: " .. (config.use_real_data and "ENABLED" or "DISABLED"))
    print("Enable real-time: " .. (config.enable_realtime and "yes" or "no"))
    print("Minimum packets: " .. config.min_packets)
    print("Python script: " .. (config.python_script_path or "auto-detect"))
    print("============================")
end

-- Set number of clusters
function set_kmeans_clusters(n)
    if type(n) == "number" and n >= 2 and n <= 20 then
        config.num_clusters = n
        print("K-means Analyzer: Clusters set to " .. n)
        return true
    else
        print("K-means Analyzer: Invalid cluster count (must be 2-20)")
        return false
    end
end

-- Toggle real-time analysis
function toggle_kmeans_realtime()
    config.enable_realtime = not config.enable_realtime
    print("K-means Analyzer: Real-time analysis " .. (config.enable_realtime and "enabled" or "disabled"))
    return config.enable_realtime
end

-- Menu registration (if supported by Wireshark version)
local function register_menu_items()
    -- Try to register menu items, but don't fail if not supported
    pcall(function()
        if register_menu then
            register_menu("K-means Analyzer/Run Analysis", run_kmeans_analysis, MENU_TOOLS_UNSORTED)
            register_menu("K-means Analyzer/Show Statistics", show_kmeans_stats, MENU_TOOLS_UNSORTED)
            register_menu("K-means Analyzer/Clear Data", clear_kmeans_data, MENU_TOOLS_UNSORTED)
            register_menu("K-means Analyzer/Configuration", show_kmeans_config, MENU_TOOLS_UNSORTED)
            register_menu("K-means Analyzer/Force Collect Packets", force_collect_packets, MENU_TOOLS_UNSORTED)
            register_menu("K-means Analyzer/Toggle Real Data Mode", toggle_real_data_mode, MENU_TOOLS_UNSORTED)
            print("K-means Analyzer: Menu items registered")
        end
    end)
end

-- Initialize plugin
local function init_plugin()
    print("K-means Analyzer: Plugin initialization complete")
    print("K-means Analyzer: Version " .. plugin_info.version)
    print("K-means Analyzer: *** NOW WITH REAL DATA SUPPORT! ***")
    print("K-means Analyzer: Use console commands:")
    print("  run_kmeans_analysis() - Perform full analysis")
    print("  show_kmeans_stats() - View packet statistics")
    print("  clear_kmeans_data() - Clear collected data")
    print("  show_kmeans_config() - Show configuration")
    print("  set_kmeans_clusters(N) - Set number of clusters (2-20)")
    print("  toggle_kmeans_realtime() - Enable/disable real-time analysis")
    print("  force_collect_packets() - Force collection from current capture")
    print("  toggle_real_data_mode() - Enable/disable real packet data")
    
    -- Try to register menu items
    register_menu_items()
    
    -- Auto-detect Python backend
    local script_path = get_python_script_path()
    if script_path then
        print("K-means Analyzer: Found Python backend at " .. script_path)
    else
        print("K-means Analyzer: Warning - Python backend not found")
        print("K-means Analyzer: Expected location: ~/.local/lib/wireshark/plugins/wireshark_kmeans_backend.py")
    end
    
    print("K-means Analyzer: Real data mode is " .. (config.use_real_data and "ENABLED" or "DISABLED"))
    print("K-means Analyzer: Ready for analysis!")
end

-- Initialize the plugin
init_plugin()

print("K-means Analyzer: Enhanced plugin loaded with real data support!")
