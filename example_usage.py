#!/usr/bin/env python3
"""
Example usage of the Wireshark K-means Analyzer

This script demonstrates how to use the analyzer with sample data
or with your own Wireshark CSV exports.
"""

import os
import sys
import tempfile
import pandas as pd
import numpy as np

# Add the current directory to Python path to import our backend
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from wireshark_kmeans_backend import WiresharkKmeansAnalyzer
except ImportError as e:
    print(f"Error importing backend: {e}")
    print("Please ensure all dependencies are installed: pip install -r requirements.txt")
    sys.exit(1)

def create_sample_network_data():
    """Create realistic sample network data for demonstration"""
    np.random.seed(42)
    
    # Simulate different types of network traffic
    data = []
    packet_num = 1
    current_time = 0.0
    
    # 1. Normal web browsing traffic
    for _ in range(100):
        current_time += np.random.exponential(0.1)
        # HTTP requests (small)
        data.append({
            'No.': packet_num,
            'Time': current_time,
            'Source': '192.168.1.10',
            'Destination': '8.8.8.8',
            'Protocol': 'HTTP',
            'Length': np.random.randint(60, 150),
            'Info': 'GET /index.html HTTP/1.1'
        })
        packet_num += 1
        
        current_time += np.random.exponential(0.05)
        # HTTP responses (larger)
        data.append({
            'No.': packet_num,
            'Time': current_time,
            'Source': '8.8.8.8',
            'Destination': '192.168.1.10',
            'Protocol': 'HTTP',
            'Length': np.random.randint(500, 1500),
            'Info': 'HTTP/1.1 200 OK'
        })
        packet_num += 1
    
    # 2. DNS queries
    for _ in range(50):
        current_time += np.random.exponential(1.0)
        data.append({
            'No.': packet_num,
            'Time': current_time,
            'Source': '192.168.1.10',
            'Destination': '8.8.8.8',
            'Protocol': 'DNS',
            'Length': np.random.randint(70, 120),
            'Info': 'Standard query A example.com'
        })
        packet_num += 1
        
        current_time += np.random.exponential(0.02)
        data.append({
            'No.': packet_num,
            'Time': current_time,
            'Source': '8.8.8.8',
            'Destination': '192.168.1.10',
            'Protocol': 'DNS',
            'Length': np.random.randint(90, 200),
            'Info': 'Standard query response A example.com'
        })
        packet_num += 1
    
    # 3. SSH session (encrypted, steady)
    for _ in range(30):
        current_time += np.random.exponential(0.5)
        data.append({
            'No.': packet_num,
            'Time': current_time,
            'Source': '192.168.1.10',
            'Destination': '203.0.113.15',
            'Protocol': 'TCP',
            'Length': np.random.randint(100, 300),
            'Info': 'SSH encrypted data'
        })
        packet_num += 1
    
    # 4. File transfer (large packets)
    for _ in range(25):
        current_time += np.random.exponential(0.1)
        data.append({
            'No.': packet_num,
            'Time': current_time,
            'Source': '192.168.1.20',
            'Destination': '198.51.100.42',
            'Protocol': 'TCP',
            'Length': np.random.randint(1400, 1500),
            'Info': 'FTP data transfer'
        })
        packet_num += 1
    
    # 5. Anomalous traffic (potential security issues)
    for _ in range(5):
        current_time += np.random.exponential(0.1)
        # Port scan
        data.append({
            'No.': packet_num,
            'Time': current_time,
            'Source': '203.0.113.99',
            'Destination': '192.168.1.10',
            'Protocol': 'TCP',
            'Length': 60,
            'Info': '[SYN] Connection attempt'
        })
        packet_num += 1
        
        current_time += 0.001
        # Rejected connection
        data.append({
            'No.': packet_num,
            'Time': current_time,
            'Source': '192.168.1.10',
            'Destination': '203.0.113.99',
            'Protocol': 'TCP',
            'Length': 60,
            'Info': '[RST] Connection reset'
        })
        packet_num += 1
    
    # 6. ICMP ping traffic
    for _ in range(10):
        current_time += np.random.exponential(1.0)
        data.append({
            'No.': packet_num,
            'Time': current_time,
            'Source': '192.168.1.10',
            'Destination': '8.8.8.8',
            'Protocol': 'ICMP',
            'Length': 64,
            'Info': 'Echo (ping) request'
        })
        packet_num += 1
        
        current_time += np.random.exponential(0.02)
        data.append({
            'No.': packet_num,
            'Time': current_time,
            'Source': '8.8.8.8',
            'Destination': '192.168.1.10',
            'Protocol': 'ICMP',
            'Length': 64,
            'Info': 'Echo (ping) reply'
        })
        packet_num += 1
    
    return pd.DataFrame(data)

def run_example_analysis():
    """Run a complete example analysis"""
    print("🔍 Wireshark K-means Analyzer Example")
    print("=" * 50)
    
    # Create sample data
    print("\n1. Creating sample network data...")
    df = create_sample_network_data()
    print(f"   Generated {len(df)} packets representing various network activities:")
    print(f"   - Web browsing (HTTP)")
    print(f"   - DNS queries")
    print(f"   - SSH sessions")
    print(f"   - File transfers")
    print(f"   - Potential security issues")
    print(f"   - ICMP pings")
    
    # Show data preview
    print(f"\n2. Data preview:")
    print(df.head(10).to_string(index=False))
    
    # Initialize analyzer
    print(f"\n3. Initializing K-means analyzer...")
    analyzer = WiresharkKmeansAnalyzer(num_clusters=5)
    
    # Extract features
    print(f"4. Extracting packet features...")
    features_df = analyzer.extract_features(df)
    print(f"   Extracted features: {list(features_df.columns)}")
    
    # Run analysis
    print(f"\n5. Performing K-means clustering analysis...")
    results = analyzer.generate_results(df, features_df)
    
    # Display results
    print(f"\n" + "=" * 50)
    print(f"📊 ANALYSIS RESULTS")
    print(f"=" * 50)
    
    print(f"📈 Overall Statistics:")
    print(f"   Total packets: {results['analysis_info']['total_packets']}")
    print(f"   Clusters found: {results['analysis_info']['num_clusters']}")
    print(f"   Cluster quality (silhouette score): {results['analysis_info']['silhouette_score']:.3f}")
    print(f"   Anomalies detected: {results['analysis_info']['num_anomalies']}")
    
    print(f"\n🎯 Cluster Analysis:")
    for cluster in results['cluster_analysis']['clusters']:
        print(f"\n   Cluster {cluster['id']}:")
        print(f"     Size: {cluster['size']} packets ({cluster['percentage']:.1f}%)")
        print(f"     Avg packet length: {cluster['avg_packet_length']:.1f} bytes")
        print(f"     Avg anomaly score: {cluster['avg_anomaly_score']:.3f}")
        
        # Top protocols
        top_protos = list(cluster['top_protocols'].items())[:3]
        if top_protos:
            print(f"     Top protocols: {', '.join([f'{p}({c})' for p, c in top_protos])}")
        
        # Top sources
        top_sources = list(cluster['top_sources'].items())[:2]
        if top_sources:
            print(f"     Top sources: {', '.join([f'{ip}({c})' for ip, c in top_sources])}")
    
    if results['anomalies']:
        print(f"\n🚨 Anomaly Detection Results:")
        print(f"   Found {len(results['anomalies'])} potentially suspicious packets:")
        
        # Sort by anomaly score
        sorted_anomalies = sorted(results['anomalies'], 
                                key=lambda x: x['anomaly_score'], reverse=True)
        
        for i, anomaly in enumerate(sorted_anomalies[:10]):  # Show top 10
            print(f"\n   {i+1}. Packet #{anomaly['packet_number']} (Score: {anomaly['anomaly_score']:.3f})")
            print(f"      {anomaly['protocol']}: {anomaly['source']} → {anomaly['destination']}")
            print(f"      Length: {anomaly['length']} bytes")
            print(f"      Reason: {anomaly['reason']}")
    else:
        print(f"\n✅ No significant anomalies detected in this sample.")
    
    print(f"\n🔍 Interpretation Guide:")
    print(f"   • Anomaly scores range from 0.0 (normal) to 1.0 (highly unusual)")
    print(f"   • Scores > 0.7 typically indicate potential security issues")
    print(f"   • Small clusters often contain unusual or suspicious traffic")
    print(f"   • Connection resets and port scans are automatically flagged")
    
    # Save results
    output_file = "example_analysis_results.json"
    import json
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n💾 Full results saved to: {output_file}")
    
    print(f"\n✨ Analysis complete! This demonstrates how the plugin works within Wireshark.")

def analyze_user_file(csv_file):
    """Analyze a user-provided CSV file"""
    if not os.path.exists(csv_file):
        print(f"Error: File '{csv_file}' not found.")
        return
    
    print(f"🔍 Analyzing user file: {csv_file}")
    print("=" * 50)
    
    # Initialize analyzer
    analyzer = WiresharkKmeansAnalyzer(num_clusters=5)
    
    # Load data
    print("Loading data...")
    df = analyzer.load_data(csv_file)
    if df is None:
        print("Failed to load data. Please ensure it's a valid Wireshark CSV export.")
        return
    
    # Extract features and analyze
    features_df = analyzer.extract_features(df)
    results = analyzer.generate_results(df, features_df)
    
    # Display summary
    print(f"\nAnalysis Results:")
    print(f"Total packets: {results['analysis_info']['total_packets']}")
    print(f"Clusters: {results['analysis_info']['num_clusters']}")
    print(f"Anomalies: {results['analysis_info']['num_anomalies']}")
    
    # Save results
    output_file = csv_file.replace('.csv', '_analysis.json')
    import json
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # User provided a CSV file
        analyze_user_file(sys.argv[1])
    else:
        # Run example with sample data
        try:
            run_example_analysis()
        except KeyboardInterrupt:
            print("\n\nAnalysis interrupted by user.")
        except Exception as e:
            print(f"\nError during analysis: {e}")
            import traceback
            traceback.print_exc()
