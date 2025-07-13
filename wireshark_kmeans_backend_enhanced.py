#!/usr/bin/env python3
"""
Enhanced Wireshark K-means Backend with improved CSV processing
Designed to work with Wireshark's CSV export format
"""

import pandas as pd
import numpy as np
import argparse
import json
import sys
import os
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Import matplotlib for visualization
try:
    import matplotlib
    # Use Agg backend for non-interactive plotting (works without display)
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import seaborn as sns
    MATPLOTLIB_AVAILABLE = True
    print("📈 Matplotlib available for graph generation (using Agg backend)")
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("⚠️  Matplotlib not available - graphs will be skipped")

class WiresharkKmeansAnalyzer:
    def __init__(self, n_clusters=5):
        self.n_clusters = n_clusters
        self.scaler = StandardScaler()
        self.kmeans = None
        self.features = None
        self.cluster_labels = None
        self.anomaly_scores = None
        
    def process_wireshark_csv(self, csv_file):
        """Process Wireshark CSV export with improved parsing"""
        try:
            # Read CSV with flexible parsing to handle complex Info fields
            df = pd.read_csv(csv_file, low_memory=False, quoting=1, escapechar='\\')
            
            print(f"Loaded CSV with {len(df)} rows and {len(df.columns)} columns")
            print(f"Column names: {list(df.columns)}")
            
            # Handle different CSV export formats from Wireshark
            # Common column names in Wireshark CSV exports
            column_mappings = {
                'No.': 'frame_number',
                'Time': 'timestamp', 
                'Source': 'src_ip',
                'Destination': 'dst_ip',
                'Protocol': 'protocol',
                'Length': 'length',
                'Info': 'info'
            }
            
            # Rename columns if they exist
            for old_name, new_name in column_mappings.items():
                if old_name in df.columns:
                    df = df.rename(columns={old_name: new_name})
            
            # Fill missing values with appropriate defaults
            if 'frame_number' not in df.columns:
                df['frame_number'] = range(1, len(df) + 1)
            if 'timestamp' not in df.columns:
                df['timestamp'] = range(len(df))
            
            df = df.fillna({
                'src_ip': 'unknown',
                'dst_ip': 'unknown', 
                'protocol': 'unknown',
                'length': 0,
                'info': ''
            })
            
            return df
            
        except Exception as e:
            print(f"Error processing CSV with pandas: {e}")
            print("Trying alternative CSV parsing method...")
            
            # Alternative parsing method for problematic CSV files
            try:
                lines = []
                with open(csv_file, 'r') as f:
                    header = f.readline().strip().split(',')
                    for line_num, line in enumerate(f, 2):
                        # Simple parsing that handles quoted fields
                        fields = []
                        current_field = ""
                        in_quotes = False
                        
                        for char in line:
                            if char == '"' and not in_quotes:
                                in_quotes = True
                            elif char == '"' and in_quotes:
                                in_quotes = False
                            elif char == ',' and not in_quotes:
                                fields.append(current_field.strip('"'))
                                current_field = ""
                            else:
                                current_field += char
                        
                        # Add the last field
                        fields.append(current_field.strip().strip('"'))
                        
                        # Pad or truncate to match header length
                        while len(fields) < len(header):
                            fields.append("")
                        fields = fields[:len(header)]
                        
                        lines.append(fields)
                
                # Create DataFrame from parsed data
                df = pd.DataFrame(lines, columns=header)
                
                print(f"Alternative parsing successful: {len(df)} rows")
                
                # Apply column mappings
                column_mappings = {
                    'No.': 'frame_number',
                    'Time': 'timestamp', 
                    'Source': 'src_ip',
                    'Destination': 'dst_ip',
                    'Protocol': 'protocol',
                    'Length': 'length',
                    'Info': 'info'
                }
                
                for old_name, new_name in column_mappings.items():
                    if old_name in df.columns:
                        df = df.rename(columns={old_name: new_name})
                
                # Fill missing values
                if 'frame_number' not in df.columns:
                    df['frame_number'] = range(1, len(df) + 1)
                if 'timestamp' not in df.columns:
                    df['timestamp'] = range(len(df))
                    
                df = df.fillna({
                    'src_ip': 'unknown',
                    'dst_ip': 'unknown', 
                    'protocol': 'unknown',
                    'length': 0,
                    'info': ''
                })
                
                return df
                
            except Exception as e2:
                print(f"Alternative parsing also failed: {e2}")
                return None
    
    def extract_features(self, df):
        """Extract features from processed DataFrame"""
        features = pd.DataFrame()
        
        # Basic packet features
        features['length'] = pd.to_numeric(df['length'], errors='coerce').fillna(0)
        
        # Protocol encoding
        protocol_counts = df['protocol'].value_counts()
        print(f"Top protocols: {protocol_counts.head()}")
        
        protocol_map = {proto: idx for idx, proto in enumerate(protocol_counts.index[:20])}
        features['protocol_encoded'] = df['protocol'].map(protocol_map).fillna(999)
        
        # Time-based features
        if 'timestamp' in df.columns:
            time_vals = pd.to_numeric(df['timestamp'], errors='coerce').fillna(0)
            features['time_normalized'] = (time_vals - time_vals.min()) / max(time_vals.max() - time_vals.min(), 1)
            features['time_delta'] = time_vals.diff().fillna(0)
        else:
            features['time_normalized'] = 0
            features['time_delta'] = 0
        
        # IP address features
        features['src_local'] = df['src_ip'].str.contains(
            r'^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)', 
            na=False, regex=True
        ).astype(int)
        
        features['dst_local'] = df['dst_ip'].str.contains(
            r'^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)', 
            na=False, regex=True
        ).astype(int)
        
        # Port extraction from info field
        features['has_port_info'] = df['info'].str.contains(r'\d+ →', na=False).astype(int)
        
        # Error and flag indicators
        features['has_error'] = df['info'].str.contains(
            r'error|failed|timeout|unreachable', 
            case=False, na=False
        ).astype(int)
        
        # Protocol-specific features
        features['is_tcp'] = (df['protocol'].str.upper() == 'TCP').astype(int)
        features['is_udp'] = (df['protocol'].str.upper() == 'UDP').astype(int)
        features['is_http'] = df['protocol'].str.contains('HTTP', na=False).astype(int)
        features['is_dns'] = (df['protocol'].str.upper() == 'DNS').astype(int)
        
        # Packet size categories
        features['size_small'] = (features['length'] < 100).astype(int)
        features['size_medium'] = ((features['length'] >= 100) & (features['length'] < 1000)).astype(int)
        features['size_large'] = (features['length'] >= 1000).astype(int)
        
        print(f"Extracted {len(features.columns)} features from {len(features)} packets")
        print(f"Feature columns: {list(features.columns)}")
        
        return features
    
    def perform_analysis(self, features):
        """Perform K-means clustering analysis"""
        if len(features) < self.n_clusters:
            raise ValueError(f"Not enough data points ({len(features)}) for {self.n_clusters} clusters")
        
        # Scale features
        features_scaled = self.scaler.fit_transform(features)
        
        # Perform K-means clustering
        self.kmeans = KMeans(n_clusters=self.n_clusters, random_state=42, n_init=10)
        self.cluster_labels = self.kmeans.fit_predict(features_scaled)
        
        # Calculate anomaly scores (distance to nearest cluster center)
        distances = self.kmeans.transform(features_scaled)
        self.anomaly_scores = np.min(distances, axis=1)
        
        # Normalize anomaly scores to 0-1 range
        if len(self.anomaly_scores) > 1:
            score_min, score_max = np.min(self.anomaly_scores), np.max(self.anomaly_scores)
            if score_max > score_min:
                self.anomaly_scores = (self.anomaly_scores - score_min) / (score_max - score_min)
        
        self.features = features
        
        return {
            'cluster_labels': self.cluster_labels,
            'anomaly_scores': self.anomaly_scores,
            'cluster_centers': self.kmeans.cluster_centers_
        }
    
    def get_cluster_summary(self):
        """Generate cluster analysis summary"""
        if self.cluster_labels is None:
            return None
        
        summary = {
            'total_packets': len(self.cluster_labels),
            'num_clusters': self.n_clusters,
            'cluster_sizes': {},
            'anomaly_statistics': {
                'mean_score': float(np.mean(self.anomaly_scores)),
                'std_score': float(np.std(self.anomaly_scores)),
                'high_anomaly_threshold': float(np.percentile(self.anomaly_scores, 90)),
                'high_anomaly_count': int(np.sum(self.anomaly_scores > np.percentile(self.anomaly_scores, 90)))
            }
        }
        
        # Cluster size analysis
        unique_labels, counts = np.unique(self.cluster_labels, return_counts=True)
        for label, count in zip(unique_labels, counts):
            summary['cluster_sizes'][f'cluster_{label}'] = int(count)
        
        # Find small clusters (potential anomalies)
        total_packets = len(self.cluster_labels)
        small_clusters = []
        for label, count in zip(unique_labels, counts):
            if count < total_packets * 0.05:  # Less than 5% of total
                small_clusters.append(f'cluster_{label}')
        
        summary['small_clusters'] = small_clusters
        
        return summary
    
    def generate_visualizations(self, output_dir=".", show_plots=False):
        """Generate K-means analysis visualizations"""
        if not MATPLOTLIB_AVAILABLE:
            print("⚠️  Matplotlib not available - skipping graph generation")
            return []
        
        if self.cluster_labels is None or self.features is None:
            print("❌ No analysis results available for visualization")
            return []
        
        generated_files = []
        
        try:
            # Set up the plotting style
            plt.style.use('default')
            sns.set_palette("husl")
            
            # 1. Cluster Distribution Plot
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
            
            # Cluster size bar chart
            unique_labels, counts = np.unique(self.cluster_labels, return_counts=True)
            colors = plt.cm.Set3(np.linspace(0, 1, len(unique_labels)))
            bars = ax1.bar([f'Cluster {i}' for i in unique_labels], counts, color=colors)
            ax1.set_title('Cluster Size Distribution', fontsize=14, fontweight='bold')
            ax1.set_xlabel('Clusters')
            ax1.set_ylabel('Number of Packets')
            ax1.grid(True, alpha=0.3)
            
            # Add value labels on bars
            for bar, count in zip(bars, counts):
                height = bar.get_height()
                ax1.text(bar.get_x() + bar.get_width()/2., height + 0.5,
                        f'{count}', ha='center', va='bottom', fontweight='bold')
            
            # Anomaly score distribution
            ax2.hist(self.anomaly_scores, bins=30, alpha=0.7, color='skyblue', edgecolor='black')
            ax2.axvline(np.percentile(self.anomaly_scores, 90), color='red', linestyle='--', 
                       label=f'90th Percentile (Anomaly Threshold)')
            ax2.set_title('Anomaly Score Distribution', fontsize=14, fontweight='bold')
            ax2.set_xlabel('Anomaly Score')
            ax2.set_ylabel('Frequency')
            ax2.legend()
            ax2.grid(True, alpha=0.3)
            
            plt.tight_layout()
            cluster_dist_file = os.path.join(output_dir, 'kmeans_cluster_distribution.png')
            plt.savefig(cluster_dist_file, dpi=300, bbox_inches='tight')
            generated_files.append(cluster_dist_file)
            print(f"📊 Generated cluster distribution plot: {cluster_dist_file}")
            
            # Note: show_plots is now False by default for non-interactive backend
            if show_plots:
                print("ℹ️  Interactive plot display disabled in non-interactive mode")
            plt.close()
            
            # 2. PCA Visualization (2D projection of clusters)
            if len(self.features.columns) >= 2:
                # Reduce dimensionality to 2D for visualization
                features_scaled = self.scaler.transform(self.features)
                pca = PCA(n_components=2)
                features_2d = pca.fit_transform(features_scaled)
                
                plt.figure(figsize=(12, 8))
                scatter = plt.scatter(features_2d[:, 0], features_2d[:, 1], 
                                   c=self.cluster_labels, cmap='viridis', 
                                   alpha=0.6, s=50)
                
                # Plot cluster centers
                centers_2d = pca.transform(self.kmeans.cluster_centers_)
                plt.scatter(centers_2d[:, 0], centers_2d[:, 1], 
                           c='red', marker='x', s=200, linewidths=3, label='Centroids')
                
                plt.colorbar(scatter, label='Cluster')
                plt.xlabel(f'First Principal Component ({pca.explained_variance_ratio_[0]:.1%} variance)')
                plt.ylabel(f'Second Principal Component ({pca.explained_variance_ratio_[1]:.1%} variance)')
                plt.title('K-means Clusters (PCA Projection)', fontsize=14, fontweight='bold')
                plt.legend()
                plt.grid(True, alpha=0.3)
                
                pca_file = os.path.join(output_dir, 'kmeans_pca_clusters.png')
                plt.savefig(pca_file, dpi=300, bbox_inches='tight')
                generated_files.append(pca_file)
                print(f"📊 Generated PCA cluster plot: {pca_file}")
                
                plt.close()
            
            # 3. Feature Importance Plot
            feature_names = self.features.columns
            if len(feature_names) > 1:
                # Calculate feature importance based on variance across clusters
                cluster_means = []
                for i in range(self.n_clusters):
                    cluster_mask = self.cluster_labels == i
                    if np.sum(cluster_mask) > 0:
                        cluster_mean = self.features[cluster_mask].mean()
                        cluster_means.append(cluster_mean)
                
                if cluster_means:
                    cluster_means_df = pd.DataFrame(cluster_means)
                    feature_variance = cluster_means_df.var().sort_values(ascending=False)
                    
                    plt.figure(figsize=(12, 8))
                    bars = plt.barh(range(len(feature_variance)), feature_variance.values)
                    plt.yticks(range(len(feature_variance)), feature_variance.index)
                    plt.xlabel('Feature Variance Across Clusters')
                    plt.title('Feature Importance for Clustering', fontsize=14, fontweight='bold')
                    plt.grid(True, alpha=0.3)
                    
                    # Color bars by importance
                    for i, bar in enumerate(bars):
                        bar.set_color(plt.cm.viridis(i / len(bars)))
                    
                    plt.tight_layout()
                    feature_file = os.path.join(output_dir, 'kmeans_feature_importance.png')
                    plt.savefig(feature_file, dpi=300, bbox_inches='tight')
                    generated_files.append(feature_file)
                    print(f"📊 Generated feature importance plot: {feature_file}")
                    
                    plt.close()
            
            # 4. Anomaly Detection Plot
            plt.figure(figsize=(14, 6))
            
            # Plot 1: Anomaly scores over packet sequence
            plt.subplot(1, 2, 1)
            packet_numbers = range(1, len(self.anomaly_scores) + 1)
            plt.plot(packet_numbers, self.anomaly_scores, alpha=0.7, linewidth=1)
            anomaly_threshold = np.percentile(self.anomaly_scores, 90)
            plt.axhline(y=anomaly_threshold, color='red', linestyle='--', 
                       label=f'Anomaly Threshold (90th percentile)')
            
            # Highlight anomalies
            anomaly_mask = self.anomaly_scores > anomaly_threshold
            if np.any(anomaly_mask):
                anomaly_packets = np.array(packet_numbers)[anomaly_mask]
                anomaly_values = self.anomaly_scores[anomaly_mask]
                plt.scatter(anomaly_packets, anomaly_values, color='red', s=50, 
                           label=f'Anomalies ({np.sum(anomaly_mask)})')
            
            plt.xlabel('Packet Number')
            plt.ylabel('Anomaly Score')
            plt.title('Anomaly Scores Over Time', fontweight='bold')
            plt.legend()
            plt.grid(True, alpha=0.3)
            
            # Plot 2: Packet length vs anomaly score
            plt.subplot(1, 2, 2)
            if 'length' in self.features.columns:
                plt.scatter(self.features['length'], self.anomaly_scores, 
                           c=self.cluster_labels, cmap='viridis', alpha=0.6)
                plt.xlabel('Packet Length')
                plt.ylabel('Anomaly Score')
                plt.title('Packet Length vs Anomaly Score', fontweight='bold')
                plt.colorbar(label='Cluster')
                plt.grid(True, alpha=0.3)
            
            plt.tight_layout()
            anomaly_file = os.path.join(output_dir, 'kmeans_anomaly_analysis.png')
            plt.savefig(anomaly_file, dpi=300, bbox_inches='tight')
            generated_files.append(anomaly_file)
            print(f"📊 Generated anomaly analysis plot: {anomaly_file}")
            
            plt.close()
            
            print(f"\n🎨 Graph generation complete! Generated {len(generated_files)} visualization files:")
            for file in generated_files:
                print(f"   📈 {os.path.basename(file)}")
            
            # Automatically open graphs if possible
            if generated_files:
                self.open_generated_graphs(generated_files)
            
            return generated_files
            
        except Exception as e:
            print(f"❌ Error generating visualizations: {e}")
            import traceback
            traceback.print_exc()
            return generated_files
    
    def open_generated_graphs(self, graph_files):
        """Automatically open generated graphs using system default viewer"""
        try:
            import subprocess
            import platform
            
            if not graph_files:
                return
            
            system = platform.system().lower()
            print(f"\n🖼️  Opening {len(graph_files)} graphs in default viewer...")
            
            for graph_file in graph_files:
                try:
                    if system == "darwin":  # macOS
                        subprocess.run(["open", graph_file], check=False)
                    elif system == "linux":
                        subprocess.run(["xdg-open", graph_file], check=False)
                    elif system == "windows":
                        subprocess.run(["start", graph_file], shell=True, check=False)
                    else:
                        print(f"   ⚠️  Unknown system '{system}' - cannot auto-open {os.path.basename(graph_file)}")
                        continue
                    
                    print(f"   🖼️  Opened: {os.path.basename(graph_file)}")
                except Exception as e:
                    print(f"   ❌ Could not open {os.path.basename(graph_file)}: {e}")
            
            print(f"✅ Graph viewing complete!")
            
        except Exception as e:
            print(f"❌ Error opening graphs: {e}")
            print("💡 You can manually open the PNG files in the current directory")
    
    def export_results(self, output_file, format='json'):
        """Export analysis results"""
        if self.cluster_labels is None:
            raise ValueError("No analysis results to export")
        
        summary = self.get_cluster_summary()
        
        # Create detailed results
        results = {
            'analysis_timestamp': datetime.now().isoformat(),
            'summary': summary,
            'packet_results': []
        }
        
        # Add per-packet results
        for i in range(len(self.cluster_labels)):
            packet_result = {
                'packet_number': i + 1,
                'cluster_id': int(self.cluster_labels[i]),
                'anomaly_score': float(self.anomaly_scores[i]),
                'is_anomaly': bool(self.anomaly_scores[i] > np.percentile(self.anomaly_scores, 90))
            }
            results['packet_results'].append(packet_result)
        
        # Export based on format
        if format.lower() == 'json':
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
        elif format.lower() == 'csv':
            # Export packet results as CSV
            packet_df = pd.DataFrame(results['packet_results'])
            packet_df.to_csv(output_file, index=False)
        
        return results

def main():
    parser = argparse.ArgumentParser(description='Enhanced Wireshark K-means Backend Analyzer')
    parser.add_argument('csv_file', help='Path to Wireshark CSV export')
    parser.add_argument('--clusters', '-c', type=int, default=5, help='Number of clusters')
    parser.add_argument('--output', '-o', help='Output file')
    parser.add_argument('--format', choices=['json', 'csv'], default='json', help='Output format')
    parser.add_argument('--threshold', type=float, default=90, help='Anomaly threshold percentile')
    parser.add_argument('--graphs', action='store_true', help='Generate visualization graphs')
    parser.add_argument('--graph-dir', default='.', help='Directory to save graphs (default: current directory)')
    parser.add_argument('--show-plots', action='store_true', help='Display plots in GUI (requires display)')
    parser.add_argument('--auto-open', action='store_true', default=True, help='Automatically open graphs in default viewer')
    parser.add_argument('--no-auto-open', action='store_true', help='Do not automatically open graphs')
    
    args = parser.parse_args()
    
    try:
        # Initialize analyzer
        analyzer = WiresharkKmeansAnalyzer(n_clusters=args.clusters)
        
        # Process CSV file
        print(f"Processing Wireshark CSV: {args.csv_file}")
        df = analyzer.process_wireshark_csv(args.csv_file)
        
        if df is None:
            print("Error: Could not process CSV file")
            return 1
        
        if len(df) == 0:
            print("Error: CSV file is empty")
            return 1
        
        # Extract features
        print("Extracting features...")
        features = analyzer.extract_features(df)
        
        if len(features) < args.clusters:
            print(f"Error: Not enough packets ({len(features)}) for {args.clusters} clusters")
            return 1
        
        # Perform analysis
        print(f"Performing K-means analysis with {args.clusters} clusters...")
        results = analyzer.perform_analysis(features)
        
        # Get summary
        summary = analyzer.get_cluster_summary()
        
        # Print results to console
        print(f"\n=== Analysis Complete ===")
        print(f"Total packets analyzed: {summary['total_packets']}")
        print(f"Number of clusters: {summary['num_clusters']}")
        print(f"Cluster sizes: {summary['cluster_sizes']}")
        print(f"High anomaly packets: {summary['anomaly_statistics']['high_anomaly_count']}")
        print(f"Small clusters (potential anomalies): {summary['small_clusters']}")
        
        # Generate visualizations if requested or by default
        if args.graphs or MATPLOTLIB_AVAILABLE:
            print(f"\n🎨 Generating visualization graphs...")
            
            # Determine auto-open setting
            auto_open = args.auto_open and not args.no_auto_open
            
            # Temporarily modify the analyzer's open behavior
            original_method = analyzer.open_generated_graphs
            if not auto_open:
                analyzer.open_generated_graphs = lambda files: print("📁 Graphs saved (auto-open disabled)")
            
            graph_files = analyzer.generate_visualizations(
                output_dir=args.graph_dir, 
                show_plots=args.show_plots
            )
            
            # Restore original method
            analyzer.open_generated_graphs = original_method
            
            if graph_files:
                print(f"📈 Generated {len(graph_files)} graph files in {args.graph_dir}")
                if not auto_open:
                    print("💡 Use --auto-open to automatically view graphs next time")
        
        # Export results if output file specified
        if args.output:
            print(f"Exporting results to {args.output} ({args.format} format)...")
            analyzer.export_results(args.output, args.format)
            print(f"Results exported successfully")
        
        print("Analysis completed successfully")
        return 0
        
    except Exception as e:
        print(f"Error during analysis: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
