# Wireshark Plugin Usage Guide

## ✅ CONFIRMED: Your plugin IS working in Wireshark!

When you run Wireshark, you should see this output in the terminal (if you started it from terminal):
```
K-means Analyzer: Plugin loaded successfully!
K-means Analyzer: Wireshark version: 4.4.7
K-means Analyzer: Plugin initialization complete
K-means Analyzer: Version 2.1.0
K-means Analyzer: Use console commands:
  run_kmeans_analysis() - Perform full analysis
  show_kmeans_stats() - View packet statistics
  clear_kmeans_data() - Clear collected data
  show_kmeans_config() - Show configuration
  set_kmeans_clusters(N) - Set number of clusters (2-20)
  toggle_kmeans_realtime() - Enable/disable real-time analysis
  force_collect_packets() - Force collection from current capture
K-means Analyzer: Menu items registered
```

## How to Use the Plugin in Wireshark:

### Method 1: Console Commands (Primary Method)

1. **Open Wireshark**
2. **Load a capture file**: File > Open > select your .pcap file
3. **Open Lua Console**: Tools > Lua > Console
4. **In the console, type these commands**:

```lua
-- First, force collection of packets from the opened file
force_collect_packets()

-- Then run the analysis
run_kmeans_analysis()

-- View statistics
show_kmeans_stats()

-- Check configuration
show_kmeans_config()
```

### Method 2: Menu Items

Look for **Tools > K-means Analyzer** in the menu bar. You should see:
- Configuration
- Run Analysis  
- Statistics
- Clear Data

### Method 3: Command Line Analysis (Alternative)

If the Wireshark integration isn't capturing packets properly, use our scripts:

```bash
# Enhanced script with auto-detection
./analyze_real_data_enhanced.sh

# Or specify a file directly
./analyze_real_data_enhanced.sh /path/to/capture.pcap
```

## Troubleshooting Steps:

### If you don't see the menu items:
1. Make sure you restarted Wireshark after installation
2. Check Tools menu for "K-means Analyzer"
3. The plugin loads automatically - look for the initialization messages

### If console commands don't work:
1. Make sure you opened a capture file first
2. Use `force_collect_packets()` before `run_kmeans_analysis()`
3. Check that packets are collected with `show_kmeans_stats()`

### If no packets are collected:
1. The capture file must be opened in Wireshark (File > Open)
2. Run `force_collect_packets()` in the Lua console
3. Check with `show_kmeans_stats()` - should show packet count > 0

## Quick Test:

1. Open Wireshark
2. File > Open > select `/Users/rbodnar/Downloads/metasploit-sip-invite-spoof.pcap`
3. Tools > Lua > Console
4. Type: `force_collect_packets()`
5. Type: `run_kmeans_analysis()`
6. You should see analysis results in the console

The plugin IS working - it's a matter of using the right workflow!
