#!/bin/bash

# Test script for Wireshark K-means plugin integration
echo "=== Wireshark K-means Plugin Test ==="

# Check if plugin files exist
PLUGIN_DIR="/Users/$USER/.local/lib/wireshark/plugins"
LUA_PLUGIN="$PLUGIN_DIR/kmeans_analyzer.lua"
PYTHON_BACKEND="$PLUGIN_DIR/wireshark_kmeans_backend.py"
VENV_PYTHON="$PLUGIN_DIR/venv/bin/python"

echo "Checking plugin installation..."

if [ -f "$LUA_PLUGIN" ]; then
    echo "✓ Lua plugin found: $LUA_PLUGIN"
else
    echo "✗ Lua plugin not found: $LUA_PLUGIN"
    exit 1
fi

if [ -f "$PYTHON_BACKEND" ]; then
    echo "✓ Python backend found: $PYTHON_BACKEND"
else
    echo "✗ Python backend not found: $PYTHON_BACKEND"
    exit 1
fi

if [ -x "$VENV_PYTHON" ]; then
    echo "✓ Virtual environment Python found: $VENV_PYTHON"
else
    echo "✗ Virtual environment Python not found: $VENV_PYTHON"
    exit 1
fi

# Test Python backend
echo ""
echo "Testing Python backend..."
if "$VENV_PYTHON" "$PYTHON_BACKEND" --help > /dev/null 2>&1; then
    echo "✓ Python backend is functional"
else
    echo "✗ Python backend test failed"
    echo "Trying with detailed output:"
    "$VENV_PYTHON" "$PYTHON_BACKEND" --help
    exit 1
fi

# Create a sample CSV for testing
echo ""
echo "Creating sample CSV for testing..."
TEMP_DIR="${TMPDIR:-/tmp}"
TEST_CSV="$TEMP_DIR/test_wireshark_sample.csv"

cat > "$TEST_CSV" << 'EOF'
No.,Time,Source,Destination,Protocol,Length,Info
1,0.000000,192.168.1.100,8.8.8.8,DNS,74,"Standard query A google.com"
2,0.001234,8.8.8.8,192.168.1.100,DNS,90,"Standard query response A google.com"
3,0.002456,192.168.1.100,172.217.14.110,TCP,74,"80 → 45678 [SYN] Seq=0"
4,0.003678,172.217.14.110,192.168.1.100,TCP,74,"45678 → 80 [SYN ACK] Seq=0 Ack=1"
5,0.004890,192.168.1.100,172.217.14.110,TCP,66,"80 → 45678 [ACK] Seq=1 Ack=1"
6,0.006012,192.168.1.100,172.217.14.110,HTTP,512,"GET / HTTP/1.1"
7,0.007234,172.217.14.110,192.168.1.100,HTTP,1434,"HTTP/1.1 200 OK"
8,0.008456,192.168.1.100,172.217.14.110,TCP,66,"80 → 45678 [FIN ACK] Seq=513 Ack=1435"
9,0.009678,172.217.14.110,192.168.1.100,TCP,66,"45678 → 80 [FIN ACK] Seq=1435 Ack=514"
10,0.010890,192.168.1.100,172.217.14.110,TCP,66,"80 → 45678 [ACK] Seq=514 Ack=1436"
11,0.012012,10.0.0.5,239.255.255.250,UDP,125,"SSDP M-SEARCH request"
12,0.013234,192.168.1.100,224.0.0.1,IGMP,46,"Membership Report group 224.0.0.1"
13,0.014456,fe80::1,ff02::1,ICMPv6,86,"Router Advertisement"
14,0.015678,192.168.1.100,192.168.1.1,ARP,42,"Who has 192.168.1.1 Tell 192.168.1.100"
15,0.016890,192.168.1.1,192.168.1.100,ARP,42,"192.168.1.1 is at aa:bb:cc:dd:ee:ff"
16,0.018012,192.168.1.100,8.8.4.4,DNS,74,"Standard query AAAA google.com"
17,0.019234,8.8.4.4,192.168.1.100,DNS,98,"Standard query response AAAA google.com"
18,0.020456,192.168.1.100,17.253.144.10,TCP,74,"443 → 56789 [SYN] Seq=0"
19,0.021678,17.253.144.10,192.168.1.100,TCP,74,"56789 → 443 [SYN ACK] Seq=0 Ack=1"
20,0.022890,192.168.1.100,17.253.144.10,TCP,66,"443 → 56789 [ACK] Seq=1 Ack=1"
21,0.024012,192.168.1.100,17.253.144.10,TLSv1.2,517,"Client Hello"
22,0.025234,17.253.144.10,192.168.1.100,TLSv1.2,1518,"Server Hello Certificate"
23,0.026456,192.168.1.100,17.253.144.10,TLSv1.2,150,"Client Key Exchange"
24,0.027678,17.253.144.10,192.168.1.100,TLSv1.2,97,"Change Cipher Spec"
25,0.028890,192.168.1.100,17.253.144.10,TLSv1.2,123,"Application Data"
26,0.030012,17.253.144.10,192.168.1.100,TLSv1.2,1400,"Application Data"
27,0.031234,192.168.1.100,17.253.144.10,TCP,66,"443 → 56789 [ACK] Seq=574 Ack=2452"
28,0.032456,192.168.1.100,17.253.144.10,TLSv1.2,81,"Encrypted Alert"
29,0.033678,17.253.144.10,192.168.1.100,TCP,66,"56789 → 443 [FIN ACK] Seq=2452 Ack=589"
30,0.034890,192.168.1.100,17.253.144.10,TCP,66,"443 → 56789 [ACK] Seq=589 Ack=2453"
EOF

echo "✓ Created test CSV with 30 sample packets"

# Run analysis on sample data
echo ""
echo "Running K-means analysis on sample data..."
OUTPUT_FILE="$TEMP_DIR/test_analysis_results.json"

if "$VENV_PYTHON" "$PYTHON_BACKEND" "$TEST_CSV" --clusters 5 --output "$OUTPUT_FILE" --format json; then
    echo "✓ Analysis completed successfully"
    
    if [ -f "$OUTPUT_FILE" ]; then
        echo "✓ Results file created: $OUTPUT_FILE"
        echo ""
        echo "=== Analysis Summary ==="
        
        # Extract key information from JSON results
        if command -v jq &> /dev/null; then
            echo "Total packets: $(jq -r '.summary.total_packets' "$OUTPUT_FILE")"
            echo "Number of clusters: $(jq -r '.summary.num_clusters' "$OUTPUT_FILE")"
            echo "High anomaly packets: $(jq -r '.summary.anomaly_statistics.high_anomaly_count' "$OUTPUT_FILE")"
            echo "Cluster sizes: $(jq -r '.summary.cluster_sizes' "$OUTPUT_FILE")"
        else
            echo "Results saved to: $OUTPUT_FILE"
            echo "(Install 'jq' for detailed summary parsing)"
        fi
    else
        echo "✗ Results file not created"
    fi
else
    echo "✗ Analysis failed"
    exit 1
fi

# Clean up
rm -f "$TEST_CSV" "$OUTPUT_FILE"

echo ""
echo "=== Integration Test Results ==="
echo "✓ Plugin installation: OK"
echo "✓ Python backend: OK"  
echo "✓ Virtual environment: OK"
echo "✓ Sample analysis: OK"
echo ""
echo "🎉 Plugin is ready for use!"
echo ""
echo "How to use in Wireshark:"
echo "1. Open Wireshark and load a capture file"
echo "2. Open the Lua console (Tools > Lua > Console)"
echo "3. Run: run_kmeans_analysis()"
echo "4. Check console output for analysis results"
echo ""
echo "Alternative: Use the export helper script"
echo "  ./export_and_analyze.sh"
