-- Wireshark K-means Anomaly Detection Plugin - Simplified Version
-- Version: 4.0.0 (Direct File Analysis)
-- Description: Real-time network traffic anomaly detection using K-means clustering
-- Author: AI Assistant
-- Date: 2025-01-27

local kmeans_proto = Proto("kmeans_analyzer", "K-means Network Anomaly Analyzer")

-- Plugin info
local plugin_info = {
    version = "4.0.0",
    description = "K-means network anomaly detection with real packet analysis",
    author = "AI Assistant"
}

-- Add to Wireshark's Tools menu
register_menu("K-means Anomaly Analysis/Analyze Current File", function()
    analyze_current_file()
end, MENU_TOOLS_UNSORTED)

register_menu("K-means Anomaly Analysis/About", function()
    show_about_dialog()
end, MENU_TOOLS_UNSORTED)

-- Function to show about dialog
function show_about_dialog()
    local about_text = string.format([[
K-means Network Anomaly Analyzer
Version: %s

This plugin analyzes network traffic using K-means clustering
to identify potential anomalies and unusual patterns.

Features:
• Real packet data analysis
• 15-feature clustering algorithm  
• Automatic anomaly detection
• Works with opened capture files

Author: %s
]], plugin_info.version, plugin_info.author)
    
    local tw_about = TextWindow.new("About K-means Analyzer")
    tw_about:set(about_text)
    tw_about:add_button("OK", function() tw_about:close() end)
end

-- Function to get current capture file path
function get_current_capture_file()
    -- For the simplified plugin, we'll assume a capture file is available
    -- if the user is trying to run analysis from the menu
    -- The external script will handle detection and validation
    return "current_capture"
end

-- Function to check if analysis script exists
function check_analysis_script()
    local script_paths = {
        "/Users/rbodnar/.local/lib/wireshark/plugins/simple_analysis.sh",
        "/Users/rbodnar/Repos/WireSharkPlugin/simple_analysis.sh"
    }
    
    for _, path in ipairs(script_paths) do
        local file = io.open(path, "r")
        if file then
            file:close()
            return path
        end
    end
    
    return nil
end

-- Main analysis function
function analyze_current_file()
    -- Check if analysis script exists
    local script_path = check_analysis_script()
    
    if not script_path then
        -- Use TextWindow instead of new_dialog for better compatibility
        local tw_error = TextWindow.new("K-means Analysis - Script Not Found")
        tw_error:set([[
❌ Analysis Script Not Found

The K-means analysis script is missing. Expected locations:
• /Users/rbodnar/.local/lib/wireshark/plugins/simple_analysis.sh
• /Users/rbodnar/Repos/WireSharkPlugin/simple_analysis.sh

Please ensure the script is installed and executable.

You can also run the analysis manually from Terminal:
./simple_analysis.sh
]])
        tw_error:add_button("OK", function() tw_error:close() end)
        return
    end
    
    -- Always assume we can analyze - the script will handle detection
    local current_file = "menu_triggered"
    
    -- Launch analysis directly with minimal confirmation
    launch_analysis(script_path, current_file)
end

-- Function to launch external analysis
function launch_analysis(script_path, capture_file)
    -- Launch the script without trying to pass specific file path
    -- Let the script handle auto-detection
    local cmd = string.format('osascript -e "tell application \\"Terminal\\" to do script \\"%s\\""', script_path)
    
    -- Execute command
    os.execute(cmd)
    
    -- Show simple completion message
    local tw_complete = TextWindow.new("K-means Analysis - Launched")
    tw_complete:set("Analysis launched in Terminal! Check Terminal window for progress and results.")
    tw_complete:add_button("OK", function() tw_complete:close() end)
end

-- Initialize plugin
local function init_listener()
    print("🔬 K-means Anomaly Analyzer v" .. plugin_info.version .. " loaded")
    print("📊 Use Tools → K-means Anomaly Analysis to start")
end

-- Register post-dissector
kmeans_proto.dissector = function(buffer, pinfo, tree)
    -- This plugin doesn't modify packet dissection
    -- It provides menu-based analysis functionality
end

register_postdissector(kmeans_proto)

-- Initialize
init_listener()
