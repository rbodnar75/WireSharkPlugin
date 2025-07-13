#!/bin/bash

echo "🧪 Testing Enhanced Plugin Real Data Collection"
echo "=============================================="

# Test the extraction script directly first
echo "1. Testing extraction script:"
./extract_packets.sh "/Users/rbodnar/Downloads/http-chunked-gzip.pcap" "/tmp/plugin_test.csv"

if [ $? -eq 0 ]; then
    echo "✅ Extraction script works!"
    PACKET_COUNT=$(tail -n +2 /tmp/plugin_test.csv | wc -l | tr -d ' ')
    echo "   Extracted: $PACKET_COUNT packets"
    
    echo ""
    echo "Sample data:"
    head -3 /tmp/plugin_test.csv
    
    rm -f /tmp/plugin_test.csv
else
    echo "❌ Extraction script failed"
    exit 1
fi

echo ""
echo "2. Plugin should now work with force_collect_packets():"
echo ""
echo "🎯 Try this in Wireshark Lua Console:"
echo "   toggle_real_data_mode()    # Enable real data"
echo "   force_collect_packets()    # Should now work!"
echo "   show_kmeans_stats()        # Check results"
echo "   run_kmeans_analysis()      # Analyze real data"
echo ""
echo "Expected result:"
echo "   K-means Analyzer: Successfully collected 47 REAL packets"
echo "   K-means Analyzer: Protocols found: HTTP, TCP, etc."
