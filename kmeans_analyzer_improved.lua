-- K-means Anomaly Detection Plugin for Wireshark
-- Improved version that works with opened packet captures

-- Check Wireshark version compatibility
local version_str = get_version()
print("K-means Analyzer: Plugin loaded successfully!")
print("K-means Analyzer: Wireshark version: " .. version_str)

-- Plugin information
local plugin_info = {
    name = "K-means Anomaly Analyzer",
    version = "2.0.0",
    description = "Analyzes network traffic using K-means clustering to detect anomalies",
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
    min_packets = 50,
    python_script_path = ""
}

-- Create safe directory function
local function get_safe_temp_dir()
    local temp_dirs = {
        "/tmp",
        os.getenv("TMPDIR"),
        os.getenv("TEMP"),
        os.getenv("TMP"),
        "."
    }
    
    for _, dir in ipairs(temp_dirs) do
        if dir and dir ~= "" then
            return dir
        end
    end
    return "/tmp"
end

-- File existence check
local function safe_file_exists(path)
    local file = io.open(path, "r")
    if file then
        file:close()
        return true
    end
    return false
end

-- Get Python script path
local function get_python_script_path()
    if config.python_script_path and config.python_script_path ~= "" then
        return config.python_script_path
    end
    
    -- Try to find the script in common locations
    local possible_paths = {
        -- Plugin directory (most likely)
        "/Users/" .. os.getenv("USER") .. "/.local/lib/wireshark/plugins/wireshark_kmeans_backend.py",
        -- Current directory
        "./wireshark_kmeans_backend.py",
        -- Common plugin locations
        os.getenv("HOME") .. "/.wireshark/plugins/wireshark_kmeans_backend.py",
        "/usr/lib/wireshark/plugins/wireshark_kmeans_backend.py"
    }
    
    for _, path in ipairs(possible_paths) do
        if safe_file_exists(path) then
            config.python_script_path = path
            return path
        end
    end
    
    return nil
end

-- Extract features from packet info
local function extract_packet_features(pinfo, tvb)
    local features = {}
    
    -- Basic packet information
    features.frame_number = pinfo.number
    features.timestamp = tonumber(tostring(pinfo.abs_ts))
    features.length = pinfo.len
    features.protocol = tostring(pinfo.cols.protocol)
    
    -- Network layer information
    features.src_ip = tostring(pinfo.src)
    features.dst_ip = tostring(pinfo.dst)
    
    -- Transport layer information
    features.src_port = pinfo.src_port or 0
    features.dst_port = pinfo.dst_port or 0
    
    -- Protocol encoding
    local protocol_map = {
        TCP = 6, UDP = 17, ICMP = 1, ARP = 2054, 
        HTTP = 80, HTTPS = 443, DNS = 53, SSH = 22
    }
    features.protocol_num = protocol_map[features.protocol] or 0
    
    -- IP address features (check for local addresses)
    features.src_local = 0
    features.dst_local = 0
    
    if features.src_ip and features.src_ip ~= "" then
        if string.match(features.src_ip, "^192%.168%.") or 
           string.match(features.src_ip, "^10%.") or 
           string.match(features.src_ip, "^172%.1[6-9]%.") or
           string.match(features.src_ip, "^172%.2[0-9]%.") or
           string.match(features.src_ip, "^172%.3[0-1]%.") then
            features.src_local = 1
        end
    end
    
    if features.dst_ip and features.dst_ip ~= "" then
        if string.match(features.dst_ip, "^192%.168%.") or 
           string.match(features.dst_ip, "^10%.") or 
           string.match(features.dst_ip, "^172%.1[6-9]%.") or
           string.match(features.dst_ip, "^172%.2[0-9]%.") or
           string.match(features.dst_ip, "^172%.3[0-1]%.") then
            features.dst_local = 1
        end
    end
    
    -- Time-based features
    if #packet_data > 0 then
        local prev_time = packet_data[#packet_data].timestamp or 0
        features.time_delta = features.timestamp - prev_time
    else
        features.time_delta = 0
    end
    
    return features
end

-- Export current capture to CSV using tshark
local function export_current_capture_to_csv()
    local temp_dir = get_safe_temp_dir()
    local csv_file = temp_dir .. "/wireshark_export_" .. os.time() .. ".csv"
    
    print("K-means Analyzer: Exporting current capture to CSV...")
    
    -- Use tshark to export the current capture to CSV
    -- This works with whatever is currently loaded in Wireshark
    local tshark_cmd = string.format(
        'tshark -r - -T csv -E header=y > "%s" 2>/dev/null',
        csv_file
    )
    
    -- Alternative: Use Wireshark's built-in export if available
    local export_cmd = string.format(
        'echo "frame.number,frame.time_epoch,ip.src,ip.dst,_ws.col.Protocol,frame.len,_ws.col.Info" > "%s"',
        csv_file
    )
    
    -- For now, create a CSV from our collected packet data
    local file = io.open(csv_file, "w")
    if not file then
        return nil, "Could not create CSV file: " .. csv_file
    end
    
    -- Write CSV header (compatible with the Python backend)
    file:write("No.,Time,Source,Destination,Protocol,Length,Info\n")
    
    -- Write packet data
    for i, packet in ipairs(packet_data) do
        local info = (packet.protocol or "Unknown")
        if packet.src_port and packet.src_port > 0 then
            info = info .. " " .. packet.src_port .. " -> " .. packet.dst_port
        end
        
        -- Escape quotes in info field
        info = string.gsub(info, '"', '""')
        
        file:write(string.format('%d,%.6f,"%s","%s","%s",%d,"%s"\n',
            packet.frame_number or i,
            packet.timestamp or 0,
            packet.src_ip or "",
            packet.dst_ip or "",
            packet.protocol or "Unknown",
            packet.length or 0,
            info
        ))
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

-- Run Python analysis on CSV data
local function run_python_analysis(csv_file)
    local script_path = get_python_script_path()
    if not script_path then
        return false, "Python backend script not found"
    end
    
    local temp_dir = get_safe_temp_dir()
    
    -- Check if we have a virtual environment
    local plugin_dir = string.match(script_path, "(.+)/[^/]+$") or ""
    local venv_python = plugin_dir .. "/venv/bin/python"
    local cmd
    
    if safe_file_exists(venv_python) then
        -- Use virtual environment Python
        cmd = string.format('"%s" "%s" "%s" --clusters %d --format json --output "%s/kmeans_results.json" 2>&1',
            venv_python, script_path, csv_file, config.num_clusters, temp_dir)
    else
        -- Fall back to system Python
        cmd = string.format('python3 "%s" "%s" --clusters %d --format json --output "%s/kmeans_results.json" 2>&1',
            script_path, csv_file, config.num_clusters, temp_dir)
    end
    
    print("K-means Analyzer: Running analysis with command: " .. cmd)
    
    -- Run Python analysis
    local handle = io.popen(cmd)
    local result_output = ""
    if handle then
        result_output = handle:read("*a") or ""
        handle:close()
    end
    
    print("K-means Analyzer: Python output: " .. result_output)
    
    -- Clean up temporary CSV file
    os.remove(csv_file)
    
    if string.find(result_output, "Analysis complete") or string.find(result_output, "Total packets") or string.find(result_output, "Analyzed") then
        return true, result_output
    else
        return false, "Python analysis failed: " .. result_output
    end
end

-- Full analysis function
local function run_full_analysis()
    print("K-means Analyzer: Starting full analysis...")
    
    if #packet_data < config.min_packets then
        local msg = string.format("Need at least %d packets for analysis. Currently have %d packets.", 
                                 config.min_packets, #packet_data)
        print("K-means Analyzer: " .. msg)
        return false, msg
    end
    
    -- Export current data to CSV
    local csv_file, err = export_current_capture_to_csv()
    if not csv_file then
        print("K-means Analyzer: Failed to export CSV: " .. (err or "unknown error"))
        return false, "Failed to export packet data: " .. (err or "unknown error")
    end
    
    print("K-means Analyzer: Exported " .. #packet_data .. " packets to " .. csv_file)
    
    -- Run analysis
    local success, result = run_python_analysis(csv_file)
    if success then
        print("K-means Analyzer: Analysis completed successfully")
        print("K-means Analyzer: " .. result)
        return true, "Analysis completed successfully"
    else
        print("K-means Analyzer: Analysis failed - " .. result)
        return false, result
    end
end

-- Packet dissector function
function kmeans_proto.dissector(tvb, pinfo, tree)
    -- Extract features and store packet data
    local features = extract_packet_features(pinfo, tvb)
    table.insert(packet_data, features)
    
    -- Create analysis tree
    local analysis_tree = tree:add(kmeans_proto, tvb(), "K-means Analysis")
    
    -- Add basic packet information
    analysis_tree:add(f_packet_features, tvb(), 
        string.format("Features: len=%d, proto=%s, src=%s:%d, dst=%s:%d",
            features.length, features.protocol, features.src_ip, features.src_port,
            features.dst_ip, features.dst_port))
    
    -- If we have analysis results for this packet, show them
    if analysis_results[features.frame_number] then
        local result = analysis_results[features.frame_number]
        analysis_tree:add(f_cluster_id, tvb(), result.cluster_id or 0)
        analysis_tree:add(f_anomaly_score, tvb(), result.anomaly_score or 0.0)
        analysis_tree:add(f_analysis_result, tvb(), result.analysis or "No analysis")
    end
    
    -- Auto-analysis for real-time mode
    if config.enable_realtime and #packet_data % 500 == 0 and #packet_data >= config.min_packets then
        print("K-means Analyzer: Auto-running analysis (real-time mode)")
        run_full_analysis()
    end
end

-- Console command functions for user interaction
function run_kmeans_analysis()
    print("K-means Analyzer: Manual analysis triggered")
    local success, message = run_full_analysis()
    if success then
        print("✓ Analysis completed: " .. message)
    else
        print("✗ Analysis failed: " .. message)
    end
    return success, message
end

function show_kmeans_stats()
    local stats = string.format([[
K-means Analyzer Statistics:
- Total packets collected: %d
- Minimum packets for analysis: %d
- Current clusters setting: %d
- Real-time analysis: %s
- Analysis results available: %d packets
- Python backend: %s
]], 
        #packet_data,
        config.min_packets,
        config.num_clusters,
        config.enable_realtime and "Enabled" or "Disabled",
        table.maxn(analysis_results or {}),
        get_python_script_path() and "Found" or "Not found"
    )
    print(stats)
    return stats
end

function clear_kmeans_data()
    packet_data = {}
    analysis_results = {}
    print("K-means Analyzer: All data cleared")
end

function show_kmeans_config()
    local config_str = string.format([[
K-means Analyzer Configuration:
- Number of clusters: %d
- Minimum packets: %d
- Real-time analysis: %s
- Python script path: %s
]], 
        config.num_clusters,
        config.min_packets,
        config.enable_realtime and "Enabled" or "Disabled",
        config.python_script_path ~= "" and config.python_script_path or "Auto-detect"
    )
    print(config_str)
    return config_str
end

function set_kmeans_clusters(num)
    if num and num >= 2 and num <= 20 then
        config.num_clusters = num
        print("K-means Analyzer: Set clusters to " .. num)
        return true
    else
        print("K-means Analyzer: Invalid cluster count. Use 2-20.")
        return false
    end
end

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
            print("K-means Analyzer: Menu items registered")
        end
    end)
end

-- Initialize plugin
local function init_plugin()
    print("K-means Analyzer: Plugin initialization complete")
    print("K-means Analyzer: Version " .. plugin_info.version)
    print("K-means Analyzer: Use console commands:")
    print("  run_kmeans_analysis() - Perform full analysis")
    print("  show_kmeans_stats() - View packet statistics")
    print("  clear_kmeans_data() - Clear collected data")
    print("  show_kmeans_config() - Show configuration")
    print("  set_kmeans_clusters(N) - Set number of clusters (2-20)")
    print("  toggle_kmeans_realtime() - Enable/disable real-time analysis")
    
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
end

-- Initialize when the plugin loads
init_plugin()
