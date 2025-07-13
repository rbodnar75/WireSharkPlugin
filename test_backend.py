#!/usr/bin/env python3
"""
Test script for Wireshark K-means Backend

This script creates sample data and tests the backend functionality
"""

import pandas as pd
import numpy as np
import os
import sys
import tempfile
import json
from wireshark_kmeans_backend import WiresharkKmeansAnalyzer

def create_sample_data():
    """Create sample Wireshark-like data for testing"""
    np.random.seed(42)
    
    # Generate sample packet data
    n_packets = 500
    
    data = {
        'No.': range(1, n_packets + 1),
        'Time': np.cumsum(np.random.exponential(0.1, n_packets)),
        'Source': [],
        'Destination': [],
        'Protocol': [],
        'Length': [],
        'Info': []
    }
    
    # Define some IP ranges and protocols
    local_ips = ['192.168.1.10', '192.168.1.20', '192.168.1.30']
    external_ips = ['8.8.8.8', '1.1.1.1', '74.125.224.72', '151.101.1.140']
    protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP']
    
    for i in range(n_packets):
        # Generate source and destination IPs
        if np.random.random() < 0.7:  # 70% local traffic
            src = np.random.choice(local_ips)
            dst = np.random.choice(external_ips) if np.random.random() < 0.5 else np.random.choice(local_ips)
        else:
            src = np.random.choice(external_ips)
            dst = np.random.choice(local_ips)
        
        data['Source'].append(src)
        data['Destination'].append(dst)
        
        # Generate protocol
        protocol = np.random.choice(protocols, p=[0.4, 0.2, 0.15, 0.1, 0.1, 0.05])
        data['Protocol'].append(protocol)
        
        # Generate packet length based on protocol
        if protocol in ['HTTP', 'HTTPS']:
            length = int(np.random.normal(800, 200))
        elif protocol == 'DNS':
            length = int(np.random.normal(100, 30))
        elif protocol == 'ICMP':
            length = int(np.random.normal(64, 10))
        else:
            length = int(np.random.normal(400, 150))
        
        data['Length'].append(max(64, length))  # Minimum packet size
        
        # Generate info field
        if protocol == 'TCP':
            flags = np.random.choice(['[SYN]', '[ACK]', '[FIN]', '[RST]', ''], p=[0.1, 0.6, 0.1, 0.05, 0.15])
            info = f"TCP {flags}"
        elif protocol == 'DNS':
            info = "Standard query" if np.random.random() < 0.5 else "Standard query response"
        elif protocol == 'ICMP':
            info = "Echo (ping) request" if np.random.random() < 0.5 else "Echo (ping) reply"
        else:
            info = f"{protocol} packet"
        
        # Add occasional errors
        if np.random.random() < 0.02:  # 2% error rate
            info += " [Connection reset]"
        
        data['Info'].append(info)
    
    return pd.DataFrame(data)

def test_analyzer():
    """Test the K-means analyzer with sample data"""
    print("=== Testing Wireshark K-means Backend ===\n")
    
    # Create sample data
    print("1. Creating sample data...")
    df = create_sample_data()
    print(f"   Created {len(df)} sample packets")
    
    # Save to temporary CSV file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        df.to_csv(f, index=False)
        csv_file = f.name
    
    try:
        # Initialize analyzer
        print("\n2. Initializing analyzer...")
        analyzer = WiresharkKmeansAnalyzer(num_clusters=4)
        
        # Load data
        print("3. Loading data...")
        loaded_df = analyzer.load_data(csv_file)
        if loaded_df is None:
            print("   ERROR: Failed to load data")
            return False
        print(f"   Loaded {len(loaded_df)} packets successfully")
        
        # Extract features
        print("4. Extracting features...")
        features_df = analyzer.extract_features(loaded_df)
        print(f"   Extracted {len(features_df.columns)} features: {list(features_df.columns)}")
        
        # Generate results
        print("5. Performing K-means analysis...")
        results = analyzer.generate_results(loaded_df, features_df)
        
        # Display results
        print(f"\n=== Analysis Results ===")
        print(f"Total packets analyzed: {results['analysis_info']['total_packets']}")
        print(f"Number of clusters: {results['analysis_info']['num_clusters']}")
        print(f"Silhouette score: {results['analysis_info']['silhouette_score']:.3f}")
        print(f"Anomalies detected: {results['analysis_info']['num_anomalies']}")
        
        print(f"\nCluster distribution:")
        for cluster in results['cluster_analysis']['clusters']:
            print(f"  Cluster {cluster['id']}: {cluster['size']} packets ({cluster['percentage']:.1f}%)")
            print(f"    Avg length: {cluster['avg_packet_length']:.1f} bytes")
            print(f"    Top protocol: {list(cluster['top_protocols'].keys())[0] if cluster['top_protocols'] else 'N/A'}")
        
        if results['anomalies']:
            print(f"\nTop 5 anomalies:")
            sorted_anomalies = sorted(results['anomalies'], key=lambda x: x['anomaly_score'], reverse=True)
            for i, anomaly in enumerate(sorted_anomalies[:5]):
                print(f"  {i+1}. Packet {anomaly['packet_number']}: {anomaly['protocol']} "
                      f"{anomaly['source']} -> {anomaly['destination']} "
                      f"(score: {anomaly['anomaly_score']:.3f}) - {anomaly['reason']}")
        
        # Test JSON output
        print("\n6. Testing JSON output...")
        output_file = tempfile.mktemp(suffix='.json')
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Verify JSON file
        with open(output_file, 'r') as f:
            loaded_results = json.load(f)
        
        print(f"   JSON output saved and verified: {output_file}")
        
        # Cleanup
        os.unlink(output_file)
        
        print("\n=== Test completed successfully! ===")
        return True
        
    except Exception as e:
        print(f"\nERROR during testing: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Cleanup
        os.unlink(csv_file)

def test_command_line():
    """Test the command line interface"""
    print("\n=== Testing Command Line Interface ===\n")
    
    # Create sample data
    df = create_sample_data()
    
    # Save to temporary CSV file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        df.to_csv(f, index=False)
        csv_file = f.name
    
    try:
        # Test command line execution
        import subprocess
        
        cmd = [
            sys.executable, 
            'wireshark_kmeans_backend.py',
            csv_file,
            '--clusters', '3',
            '--format', 'json'
        ]
        
        print(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("Command line execution successful!")
            print("\nOutput:")
            print(result.stdout)
            return True
        else:
            print(f"Command line execution failed with return code {result.returncode}")
            print(f"Error output: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"Error testing command line: {e}")
        return False
    finally:
        os.unlink(csv_file)

if __name__ == "__main__":
    success = True
    
    # Test analyzer functionality
    if not test_analyzer():
        success = False
    
    # Test command line interface
    if not test_command_line():
        success = False
    
    if success:
        print("\n🎉 All tests passed! The backend is ready for use with Wireshark.")
    else:
        print("\n❌ Some tests failed. Please check the error messages above.")
        sys.exit(1)
