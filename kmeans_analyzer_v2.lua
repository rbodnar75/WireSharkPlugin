-- K-means Anomaly Detection Plugin for Wireshark
-- Simplified version compatible with Wireshark's Lua API

-- Check Wireshark version compatibility
local version_str = get_version()
print("Wireshark version: " .. version_str)

-- Plugin information
local plugin_info = {
    name = "K-means Anomaly Analyzer",
    version = "1.0.0",
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
    min_packets = 100,
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
            -- Try to create a test file to verify write access
            local test_file = dir .. "/wireshark_test_" .. os.time()
            local file = io.open(test_file, "w")
            if file then
                file:close()
                os.remove(test_file)
                return dir
            end
        end
    end
    return "."
end

-- Safe file operations
local function safe_file_exists(path)
    if not path or path == "" then
        return false
    end
    local file = io.open(path, "r")
    if file then
        file:close()
        return true
    end
    return false
end

-- Extract packet features
local function extract_packet_features(pinfo, tvb)
    local features = {}
    
    -- Basic packet information with safe access
    features.timestamp = pinfo.abs_ts or 0
    features.length = pinfo.len or 0
    features.src_ip = tostring(pinfo.src or "")
    features.dst_ip = tostring(pinfo.dst or "")
    features.protocol = tostring(pinfo.match_string or "Unknown")
    features.src_port = pinfo.src_port or 0
    features.dst_port = pinfo.dst_port or 0
    
    -- Protocol type encoding
    local proto_map = {
        ["TCP"] = 1,
        ["UDP"] = 2,
        ["ICMP"] = 3,
        ["HTTP"] = 4,
        ["HTTPS"] = 5,
        ["DNS"] = 6,
        ["TLS"] = 7
    }
    features.proto_num = proto_map[features.protocol] or 0
    
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

-- Convert packet data to CSV format for Python analysis
local function export_to_csv(filename)
    local file = io.open(filename, "w")
    if not file then
        return false, "Could not open file for writing: " .. filename
    end
    
    -- Write CSV header
    file:write("No.,Time,Source,Destination,Protocol,Length,Info\\n")
    
    -- Write packet data
    for i, packet in ipairs(packet_data) do
        local info = (packet.protocol or "Unknown") .. " " .. (packet.src_port or 0) .. " -> " .. (packet.dst_port or 0)
        -- Escape quotes in info field
        info = string.gsub(info, '"', '""')
        file:write(string.format("%d,%.6f,%s,%s,%s,%d,\"%s\"\\n",
            i, packet.timestamp or 0, packet.src_ip or "", packet.dst_ip or "", 
            packet.protocol or "Unknown", packet.length or 0, info))
    end
    
    file:close()
    return true, "CSV exported successfully"
end

-- Run Python analysis
local function run_python_analysis()
    if #packet_data < config.min_packets then
        print("K-means Analyzer: Not enough packets for analysis (minimum: " .. config.min_packets .. ")")
        return false, "Not enough packets for analysis (minimum: " .. config.min_packets .. ")"
    end
    
    -- Export current packet data to CSV
    local temp_dir = get_safe_temp_dir()
    local csv_file = temp_dir .. "/wireshark_kmeans_" .. os.time() .. ".csv"
    local success, msg = export_to_csv(csv_file)
    if not success then
        print("K-means Analyzer: " .. msg)
        return false, msg
    end
    
    -- Determine Python script path
    local script_path = config.python_script_path
    if script_path == "" or not safe_file_exists(script_path) then
        -- Try to find the script in common locations
        local possible_paths = {
            os.getenv("HOME") .. "/.local/lib/wireshark/plugins/wireshark_kmeans_backend.py",
            os.getenv("HOME") .. "/.wireshark/plugins/wireshark_kmeans_backend.py",
            "./wireshark_kmeans_backend.py",
            "/usr/local/bin/wireshark_kmeans_backend"
        }
        
        for _, path in ipairs(possible_paths) do
            if safe_file_exists(path) then
                script_path = path
                break
            end
        end
        
        if not safe_file_exists(script_path) then
            os.remove(csv_file)
            print("K-means Analyzer: Could not find Python backend script")
            return false, "Could not find Python backend script"
        end
    end
    
    -- Check if we have a virtual environment
    local plugin_dir = string.match(script_path, "(.+)/[^/]+$") or ""
    local venv_python = plugin_dir .. "/venv/bin/python"
    local cmd
    
    if safe_file_exists(venv_python) then
        -- Use virtual environment Python
        cmd = string.format('"%s" "%s" "%s" --clusters %d --output "%s/kmeans_result.png" 2>&1',
            venv_python, script_path, csv_file, config.num_clusters, temp_dir)
    else
        -- Fall back to system Python
        cmd = string.format('python3 "%s" "%s" --clusters %d --output "%s/kmeans_result.png" 2>&1',
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
    
    -- Clean up temporary file
    os.remove(csv_file)
    
    if string.find(result_output, "Analysis complete") or string.find(result_output, "Total packets") then
        print("K-means Analyzer: Analysis completed successfully")
        print("K-means Analyzer: " .. result_output)
        return true, "Analysis completed successfully"
    else
        print("K-means Analyzer: Analysis failed - " .. result_output)
        return false, "Python analysis failed: " .. result_output
    end
end

-- Analyze current packet
local function analyze_packet(pinfo, tvb, tree)
    -- Extract features
    local features = extract_packet_features(pinfo, tvb)
    
    -- Store packet data
    table.insert(packet_data, features)
    
    -- Create analysis tree
    local analysis_tree = tree:add(kmeans_proto, tvb(), "K-means Analysis")
    
    -- Add feature information
    local feature_str = string.format("Len:%d Proto:%s SrcLocal:%d DstLocal:%d TimeDelta:%.3f",
        features.length, features.protocol, features.src_local, features.dst_local, features.time_delta)
    analysis_tree:add(f_packet_features, tvb(), feature_str)
    
    -- If we have analysis results, show cluster assignment
    if analysis_results[pinfo.number] then
        local result = analysis_results[pinfo.number]
        analysis_tree:add(f_cluster_id, tvb(), result.cluster_id)
        analysis_tree:add(f_anomaly_score, tvb(), result.anomaly_score)
        analysis_tree:add(f_analysis_result, tvb(), result.description)
    end
    
    -- Real-time analysis trigger
    if config.enable_realtime and #packet_data % 500 == 0 and #packet_data >= config.min_packets then
        local success, msg = run_python_analysis()
        if not success then
            print("K-means Analyzer: Real-time analysis failed - " .. msg)
        end
    end
end

-- Protocol dissector function
function kmeans_proto.dissector(tvb, pinfo, tree)
    -- Only analyze if we're capturing and not in a reload
    if pinfo.visited then
        return
    end
    
    analyze_packet(pinfo, tvb, tree)
end

-- Menu functions
local function run_full_analysis()
    print("K-means Analyzer: Starting full analysis...")
    local success, msg = run_python_analysis()
    if success then
        print("K-means Analyzer: Analysis completed - " .. msg)
        print("K-means Analyzer: Analyzed " .. #packet_data .. " packets with " .. config.num_clusters .. " clusters")
    else
        print("K-means Analyzer: Analysis failed - " .. msg)
    end
end

local function clear_analysis_data()
    packet_data = {}
    analysis_results = {}
    print("K-means Analyzer: Analysis data cleared")
end

local function show_statistics()
    local stats = {
        total_packets = #packet_data,
        protocols = {},
        avg_length = 0,
        time_span = 0
    }
    
    if #packet_data == 0 then
        print("K-means Analyzer: No packets collected yet")
        return
    end
    
    -- Calculate statistics
    local total_length = 0
    local min_time = math.huge
    local max_time = 0
    
    for _, packet in ipairs(packet_data) do
        -- Protocol counts
        local proto = packet.protocol or "Unknown"
        stats.protocols[proto] = (stats.protocols[proto] or 0) + 1
        
        -- Length statistics
        total_length = total_length + (packet.length or 0)
        
        -- Time span
        local timestamp = packet.timestamp or 0
        min_time = math.min(min_time, timestamp)
        max_time = math.max(max_time, timestamp)
    end
    
    stats.avg_length = total_length / #packet_data
    stats.time_span = max_time - min_time
    
    -- Print statistics
    print("K-means Analyzer Statistics:")
    print("  Total packets: " .. stats.total_packets)
    print("  Average packet length: " .. string.format("%.2f", stats.avg_length) .. " bytes")
    print("  Capture time span: " .. string.format("%.2f", stats.time_span) .. " seconds")
    print("  Top protocols:")
    
    -- Show top 5 protocols
    local proto_list = {}
    for proto, count in pairs(stats.protocols) do
        table.insert(proto_list, {proto = proto, count = count})
    end
    table.sort(proto_list, function(a, b) return a.count > b.count end)
    
    for i = 1, math.min(5, #proto_list) do
        local item = proto_list[i]
        local percentage = (item.count / stats.total_packets) * 100
        print(string.format("    %s: %d (%.1f%%)", item.proto, item.count, percentage))
    end
end

local function show_config()
    print("K-means Analyzer Configuration:")
    print("  Number of clusters: " .. config.num_clusters)
    print("  Minimum packets: " .. config.min_packets)
    print("  Real-time analysis: " .. tostring(config.enable_realtime))
    print("  Python script path: " .. (config.python_script_path ~= "" and config.python_script_path or "auto-detect"))
end

-- Register menu items using a simpler approach
local function register_menu_items()
    -- Try to register menu items (may not work in all Wireshark versions)
    if register_menu then
        register_menu("K-means Analyzer/Run Analysis", run_full_analysis, MENU_TOOLS_UNSORTED)
        register_menu("K-means Analyzer/Configuration", show_config, MENU_TOOLS_UNSORTED)
        register_menu("K-means Analyzer/Statistics", show_statistics, MENU_TOOLS_UNSORTED)
        register_menu("K-means Analyzer/Clear Data", clear_analysis_data, MENU_TOOLS_UNSORTED)
        print("K-means Analyzer: Menu items registered")
    else
        print("K-means Analyzer: Menu registration not available in this Wireshark version")
        print("K-means Analyzer: Use console commands instead:")
        print("  - run_kmeans_analysis() for full analysis")
        print("  - show_kmeans_stats() for statistics")
        print("  - clear_kmeans_data() to clear data")
    end
end

-- Register the protocol as a post-dissector
if register_postdissector then
    register_postdissector(kmeans_proto)
    print("K-means Analyzer: Post-dissector registered")
else
    print("K-means Analyzer: Post-dissector registration not available")
end

-- Global functions for console access
function run_kmeans_analysis()
    run_full_analysis()
end

function show_kmeans_stats()
    show_statistics()
end

function clear_kmeans_data()
    clear_analysis_data()
end

function show_kmeans_config()
    show_config()
end

-- Initialize plugin
local function init()
    packet_data = {}
    analysis_results = {}
    print("K-means Anomaly Analyzer plugin loaded successfully!")
    print("Version: " .. plugin_info.version)
    print("Use console commands: run_kmeans_analysis(), show_kmeans_stats(), clear_kmeans_data()")
end

-- Initialize immediately
init()

-- Try to register menu items
register_menu_items()

print("K-means Analyzer: Plugin initialization complete")
