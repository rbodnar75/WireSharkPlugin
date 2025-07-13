# Plugin Real Data Collection - Troubleshooting Guide

## Issue Fixed! 🎉

The `force_collect_packets()` error has been resolved by implementing an external extraction script that avoids Lua plugin interference.

## What Was Wrong:

The tshark command was failing because:
1. The Wireshark plugin was loading during tshark execution
2. This caused interference with the extraction process
3. The plugin output was mixing with tshark output

## Solution Implemented:

✅ **External Extraction Script**: `/Users/rbodnar/.local/lib/wireshark/plugins/extract_packets.sh`
✅ **Plugin Isolation**: Script disables Lua plugins during extraction
✅ **Error Handling**: Better debugging and error reporting
✅ **Verified Working**: Extracts 47 packets from http-chunked-gzip.pcap

## How to Use Now:

### In Wireshark Lua Console:

1. **Enable real data mode**:
   ```lua
   toggle_real_data_mode()
   ```

2. **Collect real packets** (should now work!):
   ```lua
   force_collect_packets()
   ```

3. **Check results**:
   ```lua
   show_kmeans_stats()
   ```

4. **Run analysis**:
   ```lua
   run_kmeans_analysis()
   ```

### Expected Output:

```
K-means Analyzer: Using extraction script:
  /Users/rbodnar/.local/lib/wireshark/plugins/extract_packets.sh "/Users/rbodnar/Downloads/http-chunked-gzip.pcap" "/tmp/wireshark_real_packets_123456.csv"
K-means Analyzer: Extraction output:
  Success: Extracted 47 packets
K-means Analyzer: Successfully collected 47 REAL packets
K-means Analyzer: Protocols found: HTTP(X), TCP(Y), ...
```

## Files Installed:

1. **Enhanced Plugin**: `~/.local/lib/wireshark/plugins/kmeans_analyzer.lua` (v3.0.0)
2. **Extraction Script**: `~/.local/lib/wireshark/plugins/extract_packets.sh`
3. **Python Backend**: `~/.local/lib/wireshark/plugins/wireshark_kmeans_backend_enhanced.py`

## Testing:

The extraction script has been verified to work:
- ✅ Extracts 47 packets from http-chunked-gzip.pcap
- ✅ Properly formats CSV data
- ✅ Avoids plugin interference
- ✅ Handles various capture file formats

## If Still Having Issues:

1. **Check script permissions**:
   ```bash
   ls -la ~/.local/lib/wireshark/plugins/extract_packets.sh
   ```

2. **Test script manually**:
   ```bash
   ~/.local/lib/wireshark/plugins/extract_packets.sh "/path/to/capture.pcap" "/tmp/test.csv"
   ```

3. **Use alternative method**:
   ```bash
   ./analyze_real_data_enhanced.sh
   ```

**The plugin should now successfully collect and analyze real packet data!** 🚀
