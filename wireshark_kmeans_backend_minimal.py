#!/usr/bin/env python3
"""
Matplotlib-free backend for Wireshark K-means analysis
This version removes matplotlib to avoid Lua conflicts in the virtual environment
"""

import pandas as pd
import numpy as np
import json
import argparse
import os
import sys
import re
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score
import warnings
warnings.filterwarnings('ignore')

class WiresharkKmeansAnalyzer:
    def __init__(self, num_clusters=5):
        self.num_clusters = num_clusters
        self.scaler = StandardScaler()
        self.kmeans = None
        self.pca = None
        self.features = None
        self.labels = None
        self.anomaly_scores = None
        
    def load_data(self, csv_file):
        """Load packet data from CSV file"""
        try:
            df = pd.read_csv(csv_file, quoting=1)
            
            # Ensure required columns exist
            required_columns = ['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length']
            missing_columns = [col for col in required_columns if col not in df.columns]
            
            if missing_columns:
                print(f"Error: Missing required columns: {', '.join(missing_columns)}", file=sys.stderr)
                return None
                
            return df
        except Exception as e:
            print(f"Error loading CSV: {e}", file=sys.stderr)
            return None
    
    def extract_features(self, df):
        """Extract features for clustering"""
        features_data = []
        
        for idx, row in df.iterrows():
            features = {}
            
            # Basic packet features
            features['length'] = float(row['Length']) if pd.notna(row['Length']) else 0
            features['time'] = float(row['Time']) if pd.notna(row['Time']) else 0
            
            # Protocol encoding
            protocol_map = {
                'TCP': 1, 'UDP': 2, 'ICMP': 3, 'HTTP': 4, 'HTTPS': 5,
                'DNS': 6, 'TLS': 7, 'TLSv1.2': 7, 'TLSv1.3': 7, 'ARP': 8
            }
            features['protocol_num'] = protocol_map.get(row['Protocol'], 0)
            
            # IP address features
            src_ip = str(row['Source']) if pd.notna(row['Source']) else ""
            dst_ip = str(row['Destination']) if pd.notna(row['Destination']) else ""
            
            features['src_local'] = 1 if re.match(r'^(10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.)', src_ip) else 0
            features['dst_local'] = 1 if re.match(r'^(10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.)', dst_ip) else 0
            
            # Time delta (difference from previous packet)
            if idx > 0:
                prev_time = float(df.iloc[idx-1]['Time']) if pd.notna(df.iloc[idx-1]['Time']) else 0
                features['time_delta'] = features['time'] - prev_time
            else:
                features['time_delta'] = 0
            
            # Info field analysis
            info = str(row.get('Info', '')) if 'Info' in row else ""
            features['has_error'] = 1 if re.search(r'error|reset|refused|failed|timeout', info.lower()) else 0
            features['is_syn'] = 1 if re.search(r'\[SYN\]', info) else 0
            features['is_fin'] = 1 if re.search(r'\[FIN', info) else 0
            features['is_dns'] = 1 if re.search(r'Standard query|response', info) else 0
            
            features_data.append(features)
        
        # Convert to DataFrame
        features_df = pd.DataFrame(features_data)
        
        # Fill any NaN values
        features_df = features_df.fillna(0)
        
        return features_df
    
    def perform_clustering(self, features_df):
        """Perform K-means clustering"""
        # Prepare feature matrix
        feature_matrix = features_df.values
        
        # Scale features
        scaled_features = self.scaler.fit_transform(feature_matrix)
        
        # Perform K-means clustering
        self.kmeans = KMeans(n_clusters=self.num_clusters, random_state=42, n_init=10)
        labels = self.kmeans.fit_predict(scaled_features)
        
        # Calculate silhouette score for cluster quality
        if len(np.unique(labels)) > 1:
            silhouette_avg = silhouette_score(scaled_features, labels)
        else:
            silhouette_avg = 0
        
        # Calculate anomaly scores (distance to nearest centroid)
        distances = self.kmeans.transform(scaled_features)
        anomaly_scores = np.min(distances, axis=1)
        
        # Normalize anomaly scores to 0-1 range
        if len(anomaly_scores) > 1:
            min_score = np.min(anomaly_scores)
            max_score = np.max(anomaly_scores)
            if max_score > min_score:
                anomaly_scores = (anomaly_scores - min_score) / (max_score - min_score)
            else:
                anomaly_scores = np.zeros_like(anomaly_scores)
        
        self.features = scaled_features
        self.labels = labels
        self.anomaly_scores = anomaly_scores
        
        return labels, anomaly_scores, silhouette_avg
    
    def analyze_clusters(self, df, features_df):
        """Analyze cluster characteristics"""
        analysis = {
            'num_clusters': self.num_clusters,
            'total_packets': len(df),
            'clusters': []
        }
        
        df_with_clusters = df.copy()
        df_with_clusters['cluster'] = self.labels
        df_with_clusters['anomaly_score'] = self.anomaly_scores
        
        for cluster_id in range(self.num_clusters):
            cluster_data = df_with_clusters[df_with_clusters['cluster'] == cluster_id]
            
            if len(cluster_data) == 0:
                continue
            
            cluster_info = {
                'id': int(cluster_id),
                'size': len(cluster_data),
                'percentage': (len(cluster_data) / len(df)) * 100,
                'avg_packet_length': float(cluster_data['Length'].mean()),
                'avg_anomaly_score': float(cluster_data['anomaly_score'].mean()),
                'top_protocols': cluster_data['Protocol'].value_counts().head(3).to_dict(),
                'top_sources': cluster_data['Source'].value_counts().head(3).to_dict(),
                'top_destinations': cluster_data['Destination'].value_counts().head(3).to_dict()
            }
            
            analysis['clusters'].append(cluster_info)
        
        return analysis, df_with_clusters
    
    def detect_anomalies(self, df_with_clusters, threshold_percentile=95):
        """Detect anomalies based on cluster analysis"""
        anomalies = []
        
        # High anomaly score threshold
        anomaly_threshold = np.percentile(self.anomaly_scores, threshold_percentile)
        
        # Find packets with high anomaly scores
        high_anomaly_packets = df_with_clusters[df_with_clusters['anomaly_score'] > anomaly_threshold]
        
        for idx, row in high_anomaly_packets.iterrows():
            anomaly = {
                'packet_number': int(row['No.']),
                'anomaly_score': float(row['anomaly_score']),
                'cluster_id': int(row['cluster']),
                'protocol': row['Protocol'],
                'source': row['Source'],
                'destination': row['Destination'],
                'length': int(row['Length']),
                'reason': 'High anomaly score'
            }
            anomalies.append(anomaly)
        
        # Find small clusters (potential anomalies)
        cluster_sizes = df_with_clusters['cluster'].value_counts()
        small_cluster_threshold = len(df_with_clusters) * 0.05  # 5% threshold
        
        for cluster_id, size in cluster_sizes.items():
            if size < small_cluster_threshold:
                cluster_packets = df_with_clusters[df_with_clusters['cluster'] == cluster_id]
                for idx, row in cluster_packets.iterrows():
                    # Avoid duplicates
                    if not any(a['packet_number'] == int(row['No.']) for a in anomalies):
                        anomaly = {
                            'packet_number': int(row['No.']),
                            'anomaly_score': float(row['anomaly_score']),
                            'cluster_id': int(row['cluster']),
                            'protocol': row['Protocol'],
                            'source': row['Source'],
                            'destination': row['Destination'],
                            'length': int(row['Length']),
                            'reason': f'Small cluster (size: {size})'
                        }
                        anomalies.append(anomaly)
        
        return anomalies
    
    def generate_results(self, df, features_df, output_format='json'):
        """Generate analysis results"""
        # Perform clustering
        labels, anomaly_scores, silhouette_score = self.perform_clustering(features_df)
        
        # Analyze clusters
        cluster_analysis, df_with_clusters = self.analyze_clusters(df, features_df)
        
        # Detect anomalies
        anomalies = self.detect_anomalies(df_with_clusters)
        
        # Compile results
        results = {
            'analysis_info': {
                'num_clusters': self.num_clusters,
                'total_packets': len(df),
                'silhouette_score': float(silhouette_score),
                'num_anomalies': len(anomalies)
            },
            'cluster_analysis': cluster_analysis,
            'anomalies': anomalies,
            'packet_results': []
        }
        
        # Add per-packet results
        for idx, row in df_with_clusters.iterrows():
            packet_result = {
                'packet_number': int(row['No.']),
                'cluster_id': int(row['cluster']),
                'anomaly_score': float(row['anomaly_score']),
                'is_anomaly': any(a['packet_number'] == int(row['No.']) for a in anomalies)
            }
            results['packet_results'].append(packet_result)
        
        return results

def main():
    parser = argparse.ArgumentParser(description='Wireshark K-means Backend Analyzer (No matplotlib)')
    parser.add_argument('csv_file', help='Path to Wireshark CSV export')
    parser.add_argument('--clusters', '-c', type=int, default=5, help='Number of clusters')
    parser.add_argument('--output', '-o', default='wireshark_analysis_results.json', help='Output file')
    parser.add_argument('--format', choices=['json', 'csv'], default='json', help='Output format')
    parser.add_argument('--threshold', type=float, default=95.0, help='Anomaly threshold percentile')
    
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = WiresharkKmeansAnalyzer(num_clusters=args.clusters)
    
    # Load data
    df = analyzer.load_data(args.csv_file)
    if df is None:
        sys.exit(1)
    
    print(f"Loaded {len(df)} packets for analysis")
    
    # Extract features
    features_df = analyzer.extract_features(df)
    print(f"Extracted {len(features_df.columns)} features")
    
    # Generate results
    results = analyzer.generate_results(df, features_df)
    
    # Output results
    if args.format == 'json':
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {args.output}")
    
    # Print summary to stdout
    print(f"\\nAnalysis Summary:")
    print(f"- Total packets: {results['analysis_info']['total_packets']}")
    print(f"- Number of clusters: {results['analysis_info']['num_clusters']}")
    print(f"- Silhouette score: {results['analysis_info']['silhouette_score']:.3f}")
    print(f"- Anomalies detected: {results['analysis_info']['num_anomalies']}")
    
    print(f"\\nCluster Distribution:")
    for cluster in results['cluster_analysis']['clusters']:
        print(f"- Cluster {cluster['id']}: {cluster['size']} packets ({cluster['percentage']:.1f}%)")
    
    if results['anomalies']:
        print(f"\\nTop Anomalies:")
        for i, anomaly in enumerate(sorted(results['anomalies'], 
                                         key=lambda x: x['anomaly_score'], reverse=True)[:5]):
            print(f"- Packet {anomaly['packet_number']}: {anomaly['protocol']} "
                  f"{anomaly['source']} -> {anomaly['destination']} "
                  f"(score: {anomaly['anomaly_score']:.3f})")
    
    print("\\nAnalysis complete!")

if __name__ == "__main__":
    main()
