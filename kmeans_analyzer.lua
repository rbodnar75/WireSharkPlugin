-- K-means Anomaly Detection Plugin for Wireshark
-- This plugin adds K-means clustering analysis capabilities to Wireshark
-- for detecting network anomalies and patterns

-- Check Wireshark version compatibility
local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
if not major or tonumber(major) < 3 then
    error("This plugin requires Wireshark 3.0 or later")
end

local kmeans_analyzer = {}

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
            return dir
        end
    end
    return "."
end

-- Safe file operations
local function safe_file_exists(path)
    local file = io.open(path, "r")
    if file then
        file:close()
        return true
    end
    return false
end

-- Configuration dialog (simplified for compatibility)
local function show_config_dialog()
    -- Use a simple input method for configuration
    local new_clusters = get_preference("kmeans.clusters") or config.num_clusters
    local new_min_packets = get_preference("kmeans.min_packets") or config.min_packets
    
    config.num_clusters = tonumber(new_clusters) or 5
    config.min_packets = tonumber(new_min_packets) or 100
    
    print("K-means Analyzer Configuration:")
    print("  Clusters: " .. config.num_clusters)
    print("  Minimum packets: " .. config.min_packets)
    print("  Use 'Edit > Preferences > Protocols > K-means Analyzer' to modify settings")
end

-- Feature extraction functions
local function extract_packet_features(pinfo, tvb)
    local features = {}
    
    -- Basic packet information
    features.timestamp = pinfo.abs_ts
    features.length = pinfo.len
    features.src_ip = tostring(pinfo.src)
    features.dst_ip = tostring(pinfo.dst)
    features.protocol = pinfo.match_string or "Unknown"
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
    
    -- IP address features
    features.src_local = (string.match(features.src_ip, "^192%.168%.") or 
                         string.match(features.src_ip, "^10%.") or 
                         string.match(features.src_ip, "^172%.16%.")) and 1 or 0
    features.dst_local = (string.match(features.dst_ip, "^192%.168%.") or 
                         string.match(features.dst_ip, "^10%.") or 
                         string.match(features.dst_ip, "^172%.16%.")) and 1 or 0
    
    -- Time-based features
    if #packet_data > 0 then
        local prev_time = packet_data[#packet_data].timestamp
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
        return false, "Could not open file for writing"
    end
    
    -- Write CSV header
    file:write("No.,Time,Source,Destination,Protocol,Length,Info\n")
    
    -- Write packet data
    for i, packet in ipairs(packet_data) do
        local info = (packet.protocol or "Unknown") .. " " .. (packet.src_port or 0) .. " -> " .. (packet.dst_port or 0)
        file:write(string.format("%d,%.6f,%s,%s,%s,%d,\"%s\"\n",
            i, packet.timestamp or 0, packet.src_ip or "", packet.dst_ip or "", 
            packet.protocol or "Unknown", packet.length or 0, info))
    end
    
    file:close()
    return true, "CSV exported successfully"
end

-- Run Python analysis
local function run_python_analysis()
    if #packet_data < config.min_packets then
        return false, "Not enough packets for analysis (minimum: " .. config.min_packets .. ")"
    end
    
    -- Export current packet data to CSV
    local temp_dir = get_safe_temp_dir()
    local csv_file = temp_dir .. "/wireshark_kmeans_" .. os.time() .. ".csv"
    local success, msg = export_to_csv(csv_file)
    if not success then
        return false, msg
    end
    
    -- Determine Python script path
    local script_path = config.python_script_path
    if script_path == "" then
        -- Try to find the script in the plugin directory
        local plugin_dir = get_preference("wireshark.plugins.dir") or 
                          os.getenv("HOME") .. "/.local/lib/wireshark/plugins"
        script_path = plugin_dir .. "/wireshark_kmeans_backend.py"
        
        -- Check if we have a virtual environment
        local venv_python = plugin_dir .. "/venv/bin/python"
        
        if safe_file_exists(venv_python) and safe_file_exists(script_path) then
            -- Use virtual environment Python
            cmd = string.format("\"%s\" \"%s\" \"%s\" --clusters %d --output %s/kmeans_result.png",
                venv_python, script_path, csv_file, config.num_clusters, temp_dir)
        else
            -- Fall back to system Python
            cmd = string.format("python3 \"%s\" \"%s\" --clusters %d --output %s/kmeans_result.png",
                script_path, csv_file, config.num_clusters, temp_dir)
        end
    else
        -- Use configured path
        cmd = string.format("python3 \"%s\" \"%s\" --clusters %d --output %s/kmeans_result.png",
            script_path, csv_file, config.num_clusters, temp_dir)
    end
    
    local result = os.execute(cmd)
    
    -- Clean up temporary file
    os.remove(csv_file)
    
    if result and result == 0 then
        return true, "Analysis completed successfully"
    else
        return false, "Python analysis failed"
    end
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
        if success then
            -- Load results (this would need to be implemented based on Python output format)
            load_analysis_results()
        end
    end
end

-- Load analysis results from Python output
local function load_analysis_results()
    -- This function would parse the results from the Python analysis
    -- and populate the analysis_results table
    -- Implementation depends on the output format chosen
end

-- Save configuration
local function save_config()
    local config_file = Dir.personal_config_path() .. "/kmeans_analyzer_config.txt"
    local file = io.open(config_file, "w")
    if file then
        file:write(string.format("num_clusters=%d\n", config.num_clusters))
        file:write(string.format("min_packets=%d\n", config.min_packets))
        file:write(string.format("python_script_path=%s\n", config.python_script_path))
        file:write(string.format("enable_realtime=%s\n", tostring(config.enable_realtime)))
        file:close()
    end
end

-- Load configuration
local function load_config()
    local config_file = Dir.personal_config_path() .. "/kmeans_analyzer_config.txt"
    local file = io.open(config_file, "r")
    if file then
        for line in file:lines() do
            local key, value = line:match("(.+)=(.+)")
            if key and value then
                if key == "num_clusters" then
                    config.num_clusters = tonumber(value) or 5
                elseif key == "min_packets" then
                    config.min_packets = tonumber(value) or 100
                elseif key == "python_script_path" then
                    config.python_script_path = value
                elseif key == "enable_realtime" then
                    config.enable_realtime = (value == "true")
                end
            end
        end
        file:close()
    end
end

-- Protocol dissector function
function kmeans_proto.dissector(tvb, pinfo, tree)
    -- Only analyze if we're capturing
    if pinfo.visited then
        return
    end
    
    analyze_packet(pinfo, tvb, tree)
end

-- Menu functions
local function run_full_analysis()
    local success, msg = run_python_analysis()
    if success then
        -- Show results dialog
        local dialog_items = {
            {type = "label", text = "K-means Analysis Complete"},
            {type = "label", text = string.format("Analyzed %d packets", #packet_data)},
            {type = "label", text = string.format("Used %d clusters", config.num_clusters)},
            {type = "label", text = "Results saved to: /tmp/kmeans_result.png"}
        }
        new_dialog("Analysis Results", function() end, unpack(dialog_items))
    else
        -- Show error dialog
        local dialog_items = {
            {type = "label", text = "Analysis Failed"},
            {type = "label", text = msg}
        }
        new_dialog("Error", function() end, unpack(dialog_items))
    end
end

local function clear_analysis_data()
    packet_data = {}
    analysis_results = {}
end

local function show_statistics()
    local stats = {
        total_packets = #packet_data,
        protocols = {},
        avg_length = 0,
        time_span = 0
    }
    
    -- Calculate statistics
    local total_length = 0
    local min_time = math.huge
    local max_time = 0
    
    for _, packet in ipairs(packet_data) do
        -- Protocol counts
        stats.protocols[packet.protocol] = (stats.protocols[packet.protocol] or 0) + 1
        
        -- Length statistics
        total_length = total_length + packet.length
        
        -- Time span
        min_time = math.min(min_time, packet.timestamp)
        max_time = math.max(max_time, packet.timestamp)
    end
    
    if #packet_data > 0 then
        stats.avg_length = total_length / #packet_data
        stats.time_span = max_time - min_time
    end
    
    -- Create statistics dialog
    local dialog_items = {
        {type = "label", text = "K-means Analyzer Statistics"},
        {type = "label", text = string.format("Total packets: %d", stats.total_packets)},
        {type = "label", text = string.format("Average packet length: %.2f bytes", stats.avg_length)},
        {type = "label", text = string.format("Capture time span: %.2f seconds", stats.time_span)},
        {type = "label", text = "Top protocols:"}
    }
    
    -- Add top 5 protocols
    local proto_list = {}
    for proto, count in pairs(stats.protocols) do
        table.insert(proto_list, {proto = proto, count = count})
    end
    table.sort(proto_list, function(a, b) return a.count > b.count end)
    
    for i = 1, math.min(5, #proto_list) do
        local item = proto_list[i]
        table.insert(dialog_items, {
            type = "label", 
            text = string.format("  %s: %d (%.1f%%)", 
                item.proto, item.count, (item.count / stats.total_packets) * 100)
        })
    end
    
    new_dialog("Statistics", function() end, unpack(dialog_items))
end

-- Register menu items
register_menu("K-means Analyzer/Run Analysis", run_full_analysis, MENU_TOOLS_UNSORTED)
register_menu("K-means Analyzer/Configuration", show_config_dialog, MENU_TOOLS_UNSORTED)
register_menu("K-means Analyzer/Statistics", show_statistics, MENU_TOOLS_UNSORTED)
register_menu("K-means Analyzer/Clear Data", clear_analysis_data, MENU_TOOLS_UNSORTED)

-- Register the protocol
local tcp_table = DissectorTable.get("tcp.port")
local udp_table = DissectorTable.get("udp.port")

-- Post-dissector to analyze all packets
register_postdissector(kmeans_proto)

-- Initialize plugin
local function init()
    load_config()
    packet_data = {}
    analysis_results = {}
    print("K-means Anomaly Analyzer plugin loaded")
end

-- Register init function
register_init_routine(init)

-- Plugin cleanup
local function cleanup()
    save_config()
end

return kmeans_analyzer
