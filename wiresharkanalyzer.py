#!/usr/bin/env python3
"""
Wireshark Packet Capture Analyzer using K-means Clustering

This script analyzes Wireshark packet captures exported as CSV files using machine learning
techniques to identify patterns and potential anomalies in network traffic.
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import argparse
import os
import re
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.decomposition import PCA
from collections import Counter

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Analyze Wireshark CSV exports using K-means clustering')
    
    # Add file as positional argument for easier use and keep -f/--file as an option for backward compatibility
    parser.add_argument('file_path', nargs='?', default=None,
                      help='Path to the Wireshark CSV export file')
    parser.add_argument('--file', '-f', default=None,
                      help='Path to the Wireshark CSV export file (alternative to positional argument)')
    parser.add_argument('--clusters', '-c', type=int, default=5,
                      help='Number of clusters for K-means clustering (default: 5)')
    parser.add_argument('--output', '-o', default='wireshark_clusters.png',
                      help='Output file name for visualization')
    parser.add_argument('--sample', '-s', type=int, default=None,
                      help='Sample size to use (for large captures)')
    parser.add_argument('--verbose', '-v', action='store_true',
                      help='Enable verbose output')
                        
    args = parser.parse_args()
    
    # If both positional and --file are provided, positional takes precedence
    # If neither is provided, show error
    if args.file_path is None and args.file is None:
        parser.error("You must provide a file path either as a positional argument or with --file/-f")
    
    # Use positional argument if provided, otherwise use --file
    if args.file_path is None:
        args.file_path = args.file
        
    return args

def load_wireshark_csv(file_path, sample_size=None):
    """Load and preprocess a Wireshark CSV export file"""
    print(f"Loading Wireshark capture from {file_path}...")
    
    # Check if file exists
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        return None
        
    # Check if file is empty
    if os.path.getsize(file_path) == 0:
        print(f"Error: File '{file_path}' is empty.")
        return None
    
    # Try different encodings
    encodings = ['utf-8', 'latin1', 'iso-8859-1', 'cp1252']
    
    for encoding in encodings:
        try:
            # Read the CSV file with the current encoding
            df = pd.read_csv(file_path, quoting=1, encoding=encoding)  # QUOTE_ALL mode to handle Wireshark's CSV format
            print(f"Successfully loaded using {encoding} encoding")
            
            # Verify that the file appears to be a Wireshark CSV export
            required_columns = ['No.', 'Time', 'Source', 'Destination', 'Protocol']
            missing_columns = [col for col in required_columns if col not in df.columns]
            
            if missing_columns:
                print(f"Warning: File may not be a Wireshark export. Missing columns: {', '.join(missing_columns)}")
                print("Available columns:", ', '.join(df.columns))
                
                # If most of the key columns are missing, abort
                if len(missing_columns) >= 3:
                    print("Too many required columns missing. Is this a Wireshark CSV export?")
                    return None
            
            if sample_size and len(df) > sample_size:
                print(f"Sampling {sample_size} packets from {len(df)} total packets")
                df = df.sample(sample_size, random_state=42)
            
            print(f"Loaded {len(df)} packets")
            return df
        
        except UnicodeDecodeError:
            print(f"Failed with {encoding} encoding, trying another...")
            continue
        except pd.errors.ParserError as e:
            print(f"CSV parsing error: {e}")
            print("The file does not appear to be a valid CSV file.")
            return None
        except Exception as e:
            print(f"Error loading CSV file: {e}")
            return None
    
    print("Failed to load CSV with any of the attempted encodings")
    return None

def extract_ip_features(df):
    """Extract features from IP addresses"""
    features = df.copy()
    
    # Extract source IP features
    features['src_local'] = features['Source'].apply(
        lambda x: 1 if re.match(r'^(10\.|172\.16\.|192\.168\.)', str(x)) else 0
    )
    
    # Extract destination IP features
    features['dst_local'] = features['Destination'].apply(
        lambda x: 1 if re.match(r'^(10\.|172\.16\.|192\.168\.)', str(x)) else 0
    )
    
    return features

def extract_protocol_features(df):
    """Extract features from protocol information"""
    features = df.copy()
    
    # Map common protocols to numeric values for clustering
    protocol_map = {
        'TCP': 1,
        'UDP': 2,
        'ICMP': 3,
        'HTTP': 4,
        'HTTPS': 5,
        'DNS': 6,
        'TLS': 7,
        'TLSv1.2': 7,
        'TLSv1.3': 7
    }
    
    # Extract basic protocol
    features['protocol_num'] = features['Protocol'].apply(
        lambda x: protocol_map.get(x, 0)
    )
    
    return features

def extract_length_time_features(df):
    """Extract features from packet length and timing"""
    features = df.copy()
    
    # Convert packet length to numeric
    features['Length'] = pd.to_numeric(features['Length'], errors='coerce')
    
    # Convert time to numeric
    features['Time'] = pd.to_numeric(features['Time'], errors='coerce')
    
    # Calculate time deltas (time between consecutive packets)
    features['time_delta'] = features['Time'].diff().fillna(0)
    
    return features

def extract_info_features(df):
    """Extract features from the Info field"""
    features = df.copy()
    
    # Check if packet contains error flags
    features['has_error'] = features['Info'].apply(
        lambda x: 1 if re.search(r'error|reset|refused|failed|timeout', str(x).lower()) else 0
    )
    
    # Check if packet is a SYN packet (connection initiation)
    features['is_syn'] = features['Info'].apply(
        lambda x: 1 if re.search(r'\[SYN\]', str(x)) else 0
    )
    
    # Check if packet is a FIN packet (connection termination)
    features['is_fin'] = features['Info'].apply(
        lambda x: 1 if re.search(r'\[FIN', str(x)) else 0
    )
    
    # Check if packet is related to DNS
    features['is_dns'] = features['Info'].apply(
        lambda x: 1 if re.search(r'Standard query|response', str(x)) else 0
    )
    
    return features

def prepare_features(df):
    """Prepare and combine all features for clustering"""
    # Apply all feature extraction functions
    df1 = extract_ip_features(df)
    df2 = extract_protocol_features(df1)
    df3 = extract_length_time_features(df2)
    df4 = extract_info_features(df3)
    
    # Select numerical features for clustering
    numerical_features = ['Length', 'time_delta', 'src_local', 'dst_local', 
                         'protocol_num', 'has_error', 'is_syn', 'is_fin', 'is_dns']
    
    # Filter to only keep valid numerical features
    feature_df = df4[numerical_features].copy()
    
    # Fill any missing values
    feature_df = feature_df.fillna(0)
    
    return feature_df, df4

def perform_clustering(features_df, n_clusters=5):
    """Perform K-means clustering on the features"""
    print(f"Performing K-means clustering with {n_clusters} clusters...")
    
    # Standardize features
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(features_df)
    
    # Apply K-means clustering
    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    cluster_labels = kmeans.fit_predict(scaled_features)
    centroids = kmeans.cluster_centers_
    
    return cluster_labels, centroids, scaled_features

def analyze_clusters(original_df, features_df, labels):
    """Analyze the characteristics of each cluster"""
    # Add cluster labels to the original dataframe
    df_with_clusters = original_df.copy()
    df_with_clusters['cluster'] = labels
    
    n_clusters = len(np.unique(labels))
    print(f"\nAnalysis of {n_clusters} clusters:")
    
    for i in range(n_clusters):
        cluster_data = df_with_clusters[df_with_clusters['cluster'] == i]
        print(f"\nCluster {i} ({len(cluster_data)} packets, {(len(cluster_data)/len(df_with_clusters))*100:.2f}%):")
        
        # Top protocols in this cluster
        top_protocols = cluster_data['Protocol'].value_counts().head(3)
        print("  Top protocols:")
        for protocol, count in top_protocols.items():
            print(f"    {protocol}: {count} packets ({(count/len(cluster_data))*100:.2f}%)")
        
        # Average packet length
        avg_length = cluster_data['Length'].mean()
        print(f"  Average packet length: {avg_length:.2f} bytes")
        
        # Top source IPs
        top_sources = cluster_data['Source'].value_counts().head(3)
        print("  Top source IPs:")
        for ip, count in top_sources.items():
            print(f"    {ip}: {count} packets ({(count/len(cluster_data))*100:.2f}%)")
        
        # Top destination IPs
        top_dests = cluster_data['Destination'].value_counts().head(3)
        print("  Top destination IPs:")
        for ip, count in top_dests.items():
            print(f"    {ip}: {count} packets ({(count/len(cluster_data))*100:.2f}%)")
        
        # Sample packets from this cluster
        print("  Sample packets:")
        sample = cluster_data.head(2)
        for idx, row in sample.iterrows():
            print(f"    {row['Protocol']} {row['Source']} -> {row['Destination']} ({row['Length']} bytes): {row['Info'][:50]}...")

    return df_with_clusters

def visualize_clusters(features, labels, centroids, output_file):
    """Visualize clusters using PCA for dimensionality reduction"""
    # Apply PCA to reduce to 2 dimensions for visualization
    pca = PCA(n_components=2)
    reduced_features = pca.fit_transform(features)
    reduced_centroids = pca.transform(centroids)
    
    # Set up the plot
    plt.figure(figsize=(12, 8))
    
    # Plot data points colored by cluster
    scatter = plt.scatter(reduced_features[:, 0], reduced_features[:, 1], 
                         c=labels, alpha=0.6, s=50, cmap='viridis')
    
    # Plot centroids
    plt.scatter(reduced_centroids[:, 0], reduced_centroids[:, 1], 
               c='red', marker='X', s=200, edgecolors='black', label='Centroids')
    
    # Add labels and title
    plt.title('K-means Clustering of Wireshark Packet Capture', fontsize=16)
    plt.xlabel('Principal Component 1', fontsize=12)
    plt.ylabel('Principal Component 2', fontsize=12)
    
    # Add legend
    legend1 = plt.legend(*scatter.legend_elements(), title="Clusters")
    plt.gca().add_artist(legend1)
    plt.legend()
    
    # Add grid
    plt.grid(True, linestyle='--', alpha=0.7)
    
    # Save and display
    plt.tight_layout()
    plt.savefig(output_file)
    print(f"\nCluster visualization saved to {output_file}")
    plt.show()
    
    # Return the PCA object for further analysis
    return pca

def explain_pca(pca, feature_names):
    """Explain what each PCA component represents"""
    print("\nPCA Component Analysis:")
    
    for i, component in enumerate(pca.components_):
        print(f"\nPrincipal Component {i+1}:")
        
        # Get the feature importance for this component
        feature_importance = list(zip(feature_names, component))
        
        # Sort by absolute importance
        feature_importance.sort(key=lambda x: abs(x[1]), reverse=True)
        
        # Print the top contributing features
        for feature, weight in feature_importance[:5]:
            print(f"  {feature}: {weight:.4f}")

def detect_anomalies(df_with_clusters):
    """Detect potential anomalies based on cluster characteristics"""
    print("\nPotential Anomaly Detection:")
    
    # Get cluster sizes
    cluster_sizes = df_with_clusters['cluster'].value_counts()
    
    # Very small clusters might indicate anomalies
    small_clusters = cluster_sizes[cluster_sizes < len(df_with_clusters) * 0.05].index.tolist()
    
    if small_clusters:
        print(f"\nSmall clusters that might contain anomalies: {small_clusters}")
        
        for cluster in small_clusters:
            cluster_data = df_with_clusters[df_with_clusters['cluster'] == cluster]
            print(f"\nExamining small cluster {cluster} ({len(cluster_data)} packets):")
            
            # Check if this cluster has unusual protocols
            protocols = cluster_data['Protocol'].value_counts()
            print("  Protocol distribution:")
            for protocol, count in protocols.items():
                print(f"    {protocol}: {count} packets")
            
            # Check for unusual packet lengths
            avg_length = cluster_data['Length'].mean()
            max_length = cluster_data['Length'].max()
            print(f"  Average packet length: {avg_length:.2f} bytes")
            print(f"  Maximum packet length: {max_length} bytes")
            
            # Check for error packets
            error_packets = cluster_data[cluster_data['has_error'] == 1]
            if len(error_packets) > 0:
                print(f"  Contains {len(error_packets)} packets with error flags")
            
            # Sample packets from this cluster
            print("  Sample packets:")
            sample = cluster_data.head(3)
            for idx, row in sample.iterrows():
                print(f"    {row['Protocol']} {row['Source']} -> {row['Destination']} ({row['Length']} bytes): {row['Info'][:50]}...")
    
    # Look for specific patterns indicating anomalies
    
    # Unusual packet length
    length_threshold = df_with_clusters['Length'].quantile(0.995)
    unusual_length = df_with_clusters[df_with_clusters['Length'] > length_threshold]
    if len(unusual_length) > 0:
        print(f"\nFound {len(unusual_length)} packets with unusually large size (>{length_threshold:.0f} bytes)")
        for idx, row in unusual_length.head(3).iterrows():
            print(f"  {row['Protocol']} {row['Source']} -> {row['Destination']} ({row['Length']} bytes): {row['Info'][:50]}...")
    
    # Error packets
    error_packets = df_with_clusters[df_with_clusters['has_error'] == 1]
    if len(error_packets) > 0:
        print(f"\nFound {len(error_packets)} packets with error flags")
        for idx, row in error_packets.head(3).iterrows():
            print(f"  {row['Protocol']} {row['Source']} -> {row['Destination']}: {row['Info'][:100]}...")

def generate_traffic_summary(df):
    """Generate a summary of traffic patterns"""
    print("\n=== Traffic Summary ===")
    
    # Count packets by protocol
    protocol_counts = df['Protocol'].value_counts()
    print("\nProtocol Distribution:")
    for protocol, count in protocol_counts.items():
        print(f"  {protocol}: {count} packets ({(count/len(df))*100:.2f}%)")
    
    # Top talkers (source IPs)
    source_counts = df['Source'].value_counts().head(5)
    print("\nTop Talkers (Source IPs):")
    for ip, count in source_counts.items():
        print(f"  {ip}: {count} packets ({(count/len(df))*100:.2f}%)")
    
    # Top destinations
    dest_counts = df['Destination'].value_counts().head(5)
    print("\nTop Destinations:")
    for ip, count in dest_counts.items():
        print(f"  {ip}: {count} packets ({(count/len(df))*100:.2f}%)")
    
    # Packet length statistics
    print("\nPacket Length Statistics:")
    print(f"  Average: {df['Length'].mean():.2f} bytes")
    print(f"  Minimum: {df['Length'].min()} bytes")
    print(f"  Maximum: {df['Length'].max()} bytes")
    
    # Capture duration
    if 'Time' in df.columns:
        duration = df['Time'].max() - df['Time'].min()
        print(f"\nCapture Duration: {duration:.2f} seconds")
        print(f"Average Packet Rate: {len(df)/duration:.2f} packets/second")

def main():
    """Main execution function"""
    # Parse arguments
    args = parse_arguments()
    
    # Load the Wireshark CSV file
    df = load_wireshark_csv(args.file_path, args.sample)
    if df is None:
        return
    
    # Generate a basic traffic summary
    generate_traffic_summary(df)
    
    # Prepare features for clustering
    features_df, enriched_df = prepare_features(df)
    
    if args.verbose:
        print("\nFeatures prepared for clustering:")
        print(features_df.head())
    
    # Perform clustering
    labels, centroids, scaled_features = perform_clustering(features_df, args.clusters)
    
    # Analyze clusters
    df_with_clusters = analyze_clusters(enriched_df, features_df, labels)
    
    # Visualize clusters
    pca = visualize_clusters(scaled_features, labels, centroids, args.output)
    
    # Explain PCA components
    explain_pca(pca, features_df.columns)
    
    # Detect potential anomalies
    detect_anomalies(df_with_clusters)
    
    print("\nAnalysis complete!")

if __name__ == "__main__":
    main()
