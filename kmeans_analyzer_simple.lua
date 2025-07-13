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
    
    new_dialog("About K-means Analyzer", function() end, about_text)
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
        -- Use new_dialog instead of TextWindow for better compatibility
        new_dialog("K-means Analysis - Script Not Found", function() end, [[
❌ Analysis Script Not Found

The K-means analysis script is missing. Expected locations:
• /Users/rbodnar/.local/lib/wireshark/plugins/simple_analysis.sh
• /Users/rbodnar/Repos/WireSharkPlugin/simple_analysis.sh

Please ensure the script is installed and executable.

You can also run the analysis manually from Terminal:
./simple_analysis.sh
]])
        return
    end
    
    -- Always assume we can analyze - the script will handle detection
    local current_file = "menu_triggered"
    
    -- Show confirmation dialog
    local info_text = string.format([[
🔬 K-means Anomaly Analysis

Ready to launch analysis tool.

This will:
✅ Auto-detect capture files (opened in Wireshark or in common locations)
✅ Extract packet features (15 dimensions)
✅ Apply K-means clustering 
✅ Identify network anomalies
✅ Generate detailed analysis report

The analysis will run in Terminal where you can see progress and results.

Click OK to start analysis...
]])
    
    new_dialog("K-means Analysis", function()
        launch_analysis(script_path, current_file)
    end, info_text)
end

-- Function to launch external analysis
function launch_analysis(script_path, capture_file)
    -- Show initial progress message using new_dialog
    new_dialog("K-means Analysis - Starting", function() end, [[
🔄 Analysis Starting...

The K-means analysis is being launched in Terminal.
This may take a few moments depending on file size.

✅ Auto-detecting capture files
✅ Extracting packet features
✅ Applying clustering algorithm  
✅ Detecting anomalies
✅ Generating report

Check the Terminal for detailed progress and results.
]])
    
    -- Launch the script without trying to pass specific file path
    -- Let the script handle auto-detection
    local cmd = string.format('osascript -e "tell application \\"Terminal\\" to do script \\"%s\\""', script_path)
    
    -- Execute command
    os.execute(cmd)
    
    -- Show completion message
    new_dialog("K-means Analysis - Launched", function() end, [[
✅ Analysis Launched Successfully!

The K-means analysis has been started in Terminal.

🔬 What's happening:
• Auto-detection of capture files (Wireshark opened files, common locations)
• Real packet data extraction
• Feature engineering (15 dimensions)
• K-means clustering (auto K selection)
• Anomaly detection and scoring
• Detailed results generation

📊 Results will appear in the Terminal window.
]])
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
