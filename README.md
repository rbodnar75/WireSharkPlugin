# Wireshark K-means Anomaly Detection Plugin

This plugin adds K-means clustering analysis capabilities to Wireshark for detecting network anomalies and patterns in real-time or post-capture analysis.

## Features

- **Real-time Analysis**: Analyze packets as they are captured
- **K-means Clustering**: Group similar packets using machine learning
- **Anomaly Detection**: Identify unusual network behavior
- **🎨 Automatic Graph Generation**: Creates 4 professional visualization graphs
- **🖼️ Auto-View Graphs**: Automatically opens generated graphs in your default image viewer
- **🧹 Lua Conflict-Free**: Enhanced isolation prevents matplotlib/Wireshark Lua conflicts
- **Interactive Configuration**: Adjust clustering parameters through Wireshark's GUI
- **Statistics Dashboard**: View analysis results and network statistics
- **Multi-format Output**: Export results in JSON format for further analysis

## Installation

### Prerequisites

- Wireshark (any recent version)
- Python 3.7 or higher
- pip (Python package manager)

### Quick Install

1. **Clone or download this repository**:
   ```bash
   git clone <repository-url>
   cd WireSharkPlugin
   ```

2. **Run the fixed installation script** (recommended):
   ```bash
   chmod +x install_plugin_fixed.sh
   ./install_plugin_fixed.sh
   ```
   
   This installer fixes common issues including:
   - Externally-managed Python environments (macOS with Homebrew)
   - Matplotlib/Lua conflicts in virtual environments
   - Wireshark API compatibility issues
   - Virtual environment creation and management

3. **Restart Wireshark** to load the plugin

### Alternative Installation Methods

If you encounter issues, try these methods in order:

#### Method 1: Enhanced Installer (for externally-managed environments)
```bash
./install_plugin_enhanced.sh
```

#### Method 2: Virtual Environment (Manual)
```bash
cd WireSharkPlugin
python3 -m venv venv
source venv/bin/activate
pip install -r requirements_minimal.txt  # Note: uses minimal requirements without matplotlib
./install_plugin.sh
```

#### Method 3: User Installation
```bash
pip3 install --user pandas numpy scikit-learn
./install_plugin.sh
```

#### Method 4: Homebrew (macOS)
```bash
brew install python-pandas python-scikit-learn
./install_plugin.sh
```

### Manual Installation

If the automatic installation doesn't work, follow these steps:

1. **Install Python dependencies**:
   ```bash
   pip3 install -r requirements.txt
   ```

2. **Find your Wireshark plugin directory**:
   - macOS: `~/.local/lib/wireshark/plugins` or `~/.wireshark/plugins`
   - Linux: `~/.local/lib/wireshark/plugins` or `~/.wireshark/plugins`
   - Windows: `%APPDATA%\Wireshark\plugins`

3. **Copy plugin files**:
   ```bash
   cp kmeans_analyzer.lua /path/to/wireshark/plugins/
   cp wireshark_kmeans_backend.py /path/to/wireshark/plugins/
   chmod +x /path/to/wireshark/plugins/wireshark_kmeans_backend.py
   ```

## Usage

### How to Use with Current Packet Captures

The improved plugin works seamlessly with Wireshark's opened packet captures. Here are several ways to analyze your data:

#### Method 1: Console Commands (NOW WITH REAL DATA!) ✨

1. **Start Wireshark** and open your packet capture file (File > Open)

2. **Open Lua Console**: Go to `Tools > Lua > Console`

3. **Enable Real Data Mode** (NEW!):
   ```lua
   toggle_real_data_mode()    # Enable real packet analysis
   ```

4. **Run Analysis**: In the console, type:
   ```lua
   force_collect_packets()    # Now collects REAL packets from your file!
   run_kmeans_analysis()      # Analyzes actual network traffic
   ```

5. **View Results**: The console will show analysis progress and results:
   ```
   K-means Analyzer: Successfully collected 17 REAL packets
   K-means Analyzer: Protocols found: SIP(2), ICMP(1), unknown(14)
   === Analysis Complete ===
   Total packets analyzed: 17 (REAL DATA)
   Number of clusters: 5
   High anomaly packets: 2
   ```

**NEW FEATURES** 🎯:
- ✅ **Real packet collection** - Reads actual data from opened capture files
- ✅ **Protocol detection** - Shows real network protocols (SIP, HTTP, TCP, etc.)
- ✅ **Accurate counts** - Matches your actual capture file packet count
- ✅ **Automatic fallback** - Uses sample data only if real collection fails
- ✅ **Enhanced statistics** - Real protocol distribution and analysis

#### Method 2: Export Helper Script

If the Lua integration doesn't capture all packets, use the standalone export script:

1. **Export your capture**: In Wireshark, go to `File > Export Packet Dissections > As CSV...`

2. **Save the CSV file** to your desktop or downloads folder

3. **Run the analyzer**:
   ```bash
   ./export_and_analyze.sh
   ```
   Choose option 2 and enter the path to your CSV file

#### Method 3: Command Line Analysis

For advanced users who prefer command-line analysis:

```bash
# Export current capture to CSV
tshark -r your_capture.pcap -T csv -E header=y > capture.csv

# Run analysis
python3 wireshark_kmeans_backend.py capture.csv --clusters 5 --format json

# Or use the virtual environment
~/.local/lib/wireshark/plugins/venv/bin/python \
  ~/.local/lib/wireshark/plugins/wireshark_kmeans_backend.py \
  capture.csv --clusters 5 --output results.json
```

### Console Commands Available

Once the plugin is loaded, these commands are available in Wireshark's Lua console:

- **`run_kmeans_analysis()`** - Analyze currently collected packet data (REAL or sample)
- **`force_collect_packets()`** - **NOW COLLECTS REAL PACKETS** from opened capture files
- **`toggle_real_data_mode()`** - **NEW!** Switch between real packet data and sample data
- **`show_kmeans_stats()`** - Display packet collection statistics with real protocol info
- **`clear_kmeans_data()`** - Clear collected packet data
- **`show_kmeans_config()`** - Show current configuration
- **`set_kmeans_clusters(N)`** - Set number of clusters (2-20)
- **`toggle_kmeans_realtime()`** - Enable/disable real-time analysis

**✨ NEW: Real Data Features**:
- Real packet collection uses `tshark` to extract actual packet data
- Automatic detection of opened capture files
- Real protocol analysis (shows actual SIP, HTTP, TCP, DNS, etc.)
- Accurate packet counts matching your capture files
- Fallback to sample data only if real collection fails

### Basic Usage

1. **Start Wireshark** and begin capturing packets or open an existing capture file

2. **For Real Packet Analysis with Graphs** (Recommended - Uses Actual Capture Data):
   ```bash
   # Enhanced script with native PCAP/PCAPNG support + AUTOMATIC GRAPHS
   ./analyze_real_data_enhanced.sh
   
   # Or specify a file directly (generates graphs automatically)
   ./analyze_real_data_enhanced.sh /path/to/capture.pcap
   
   # Original script (also generates graphs now)
   ./analyze_real_data.sh
   ```
   
   The enhanced script provides:
   - **Real Packet Data** - Analyzes actual network traffic, not synthetic data
   - **🎨 Automatic Graph Generation** - Creates 4 professional visualizations
   - **Native PCAP/PCAPNG support** - Direct analysis without manual export
   - **Auto-detection** - Finds capture files in Downloads, Desktop, current directory
   - **File validation** - Checks file integrity before analysis
   - **Interactive selection** - Choose from multiple files when found
   - **Real-time feedback** - Shows packet count, file size, protocols detected
   - **Support for multiple formats** - .pcap, .pcapng, .cap files

3. **For Demo/Learning with Sample Data** (Wireshark Console):
   ```lua
   # Open Wireshark > Tools > Lua > Console
   force_collect_packets()    # Generates sample data
   run_kmeans_analysis()      # Analyzes sample patterns
   ```
   ⚠️ **Note**: Console commands use synthetic data for demonstration

4. **View Generated Graphs**: After analysis, check the current directory for:
   - 📊 `kmeans_cluster_distribution.png` - Cluster sizes and anomaly distribution
   - 🗺️ `kmeans_pca_clusters.png` - 2D cluster visualization with centroids  
   - 📈 `kmeans_feature_importance.png` - Feature variance analysis
   - 🚨 `kmeans_anomaly_analysis.png` - Anomaly detection timeline

5. **Access the plugin** through the Tools menu:
   - `Tools > K-means Analyzer > Configuration` - Configure analysis parameters
   - `Tools > K-means Analyzer > Run Analysis` - Perform analysis on sample data
   - `Tools > K-means Analyzer > Statistics` - View current analysis statistics
   - `Tools > K-means Analyzer > Clear Data` - Reset analysis data

6. **View results** in the packet details pane - each packet will show:
   - Cluster assignment
   - Anomaly score
   - Extracted features
   - Analysis results

### Configuration Options

#### Number of Clusters
- **Default**: 5
- **Range**: 2-20
- **Description**: Number of clusters for K-means algorithm. More clusters provide finer granularity but may over-segment the data.

#### Minimum Packets
- **Default**: 100
- **Range**: 50-10000
- **Description**: Minimum number of packets required before analysis can be performed.

#### Real-time Analysis
- **Default**: Disabled
- **Description**: When enabled, analysis runs automatically every 500 packets. May impact performance on high-traffic captures.

#### Python Script Path
- **Default**: Auto-detected
- **Description**: Path to the Python backend script. Usually auto-detected during installation.

### Understanding Results

#### Cluster Analysis
Packets are grouped into clusters based on similarities in:
- Packet length
- Protocol type
- IP address patterns (local vs external)
- Timing patterns
- Error flags and connection states

#### Anomaly Detection
Anomalies are detected using multiple methods:
1. **High Anomaly Score**: Packets far from any cluster center
2. **Small Clusters**: Clusters containing very few packets (< 5% of total)
3. **Unusual Patterns**: Packets with rare protocol combinations or error flags

#### Anomaly Scores
- **Range**: 0.0 to 1.0
- **Low scores (0.0-0.3)**: Normal traffic patterns
- **Medium scores (0.3-0.7)**: Potentially interesting traffic
- **High scores (0.7-1.0)**: Likely anomalies requiring investigation

## Example Workflows

### Real-Time Packet Analysis (Recommended)

1. **Quick Analysis** of any capture file:
   ```bash
   ./analyze_real_data_enhanced.sh
   ```
   The script will automatically find and analyze real packet capture files.

2. **Direct File Analysis**:
   ```bash
   ./analyze_real_data_enhanced.sh /path/to/capture.pcap
   ```
   Analyze a specific PCAP/PCAPNG file directly.

3. **Results Review**: The analysis shows:
   - Real protocol distribution (SIP, HTTP, DNS, etc.)
   - Cluster assignments for packet patterns
   - Anomaly detection results
   - Feature extraction from actual network data

### Network Security Monitoring

1. **Start capture** on your network interface
2. **Enable real-time analysis** in the configuration
3. **Monitor** for high anomaly scores and small clusters
4. **Investigate** flagged packets for potential security issues

### Forensic Analysis

1. **Load** a suspicious packet capture file
2. **Run full analysis** with appropriate cluster count
3. **Examine** anomaly reports and cluster characteristics
4. **Export** results for further analysis or reporting

### Performance Analysis

1. **Capture** traffic during performance issues
2. **Analyze** traffic patterns and cluster distribution
3. **Identify** unusual protocols or connection patterns
4. **Correlate** with performance metrics

## Real Data Analysis (NEW!)

### Enhanced Real Packet Analysis

Your plugin now includes powerful real data analysis capabilities that work directly with PCAP/PCAPNG files:

#### Quick Start with Real Data
```bash
# Auto-detect and analyze capture files (WITH GRAPHS!)
./analyze_real_data_enhanced.sh

# Analyze a specific file (WITH GRAPHS!)
./analyze_real_data_enhanced.sh /path/to/capture.pcap
```

#### 🎨 NEW: Automatic Graph Generation

The K-means analysis now automatically generates **4 professional visualization graphs**:

1. **📊 Cluster Distribution Chart** - Shows the size of each cluster and anomaly score distribution
2. **🗺️ PCA Cluster Plot** - 2D visualization of packet clusters using Principal Component Analysis
3. **📈 Feature Importance Plot** - Shows which packet features are most important for clustering
4. **🚨 Anomaly Analysis Plot** - Timeline of anomaly scores and packet length correlation

**Generated Files:**
- `kmeans_cluster_distribution.png` - Cluster sizes and anomaly distribution
- `kmeans_pca_clusters.png` - 2D cluster visualization with centroids
- `kmeans_feature_importance.png` - Feature variance analysis
- `kmeans_anomaly_analysis.png` - Anomaly detection timeline

**Example Graph Output:**
```
🎨 Generating visualization graphs...
📊 Generated cluster distribution plot: ./kmeans_cluster_distribution.png
📊 Generated PCA cluster plot: ./kmeans_pca_clusters.png
📊 Generated feature importance plot: ./kmeans_feature_importance.png
📊 Generated anomaly analysis plot: ./kmeans_anomaly_analysis.png

🎨 Graph generation complete! Generated 4 visualization files
```

#### What You Get with Real Data Analysis:
- ✅ **Actual Network Protocols**: SIP, HTTP, DNS, ICMP, TCP, UDP, etc.
- ✅ **Real Traffic Patterns**: Genuine packet timing, sizes, and characteristics  
- ✅ **Authentic Anomalies**: True network anomalies, not synthetic patterns
- ✅ **Security Insights**: Real attack patterns, malware communications, etc.
- ✅ **Professional Graphs**: High-resolution PNG visualizations for reports and analysis

#### Supported File Formats:
- `.pcap` - Standard packet capture format
- `.pcapng` - Next generation packet capture format  
- `.cap` - Alternative packet capture format

#### Example Real Analysis Output:
```
📦 Packets: 17
🔬 Protocols detected: SIP (2), ICMP (1), unknown (14)
🧠 Clusters found: 5 
🚨 Anomalies: Small clusters detected (potential security incidents)
```

#### vs Sample Data:
- **Sample Data**: Generic synthetic packets for testing
- **Real Data**: Actual network traffic from your captures
- **Detection**: Script automatically validates you're analyzing real traffic

## Technical Details

### Feature Extraction

The plugin extracts the following features from each packet:
- **Packet length**: Size in bytes
- **Protocol encoding**: Numeric representation of protocol type
- **IP locality**: Whether source/destination IPs are local
- **Timing**: Time delta from previous packet
- **Flags**: Error flags, SYN/FIN flags, DNS queries

### Machine Learning Pipeline

1. **Feature standardization**: Z-score normalization
2. **K-means clustering**: Sklearn implementation with k-means++
3. **Anomaly scoring**: Distance to nearest cluster centroid
4. **PCA visualization**: Dimensionality reduction for visualization

### Performance Considerations

- **Memory usage**: ~100 bytes per packet for feature storage
- **CPU usage**: Analysis runs in separate Python process
- **Real-time limits**: Recommended for captures < 10,000 packets/second
- **Batch processing**: Better for large historical captures

## Troubleshooting

### Lua Errors and Plugin Loading Issues

If you see errors like:
```
Lua: Error during loading:
...matplotlib/mpl-data/kpsewhich.lua:2: attempt to index a nil value (global 'kpse')
Lua: Error during loading:
...kmeans_analyzer.lua:374: attempt to call a nil value (global 'register_init_routine')
Lua: Error during loading:
...kmeans_analyzer.lua:424: bad argument #1 to 'register_postdissector' (userdata expected, got function)
Lua: Error during execution of Menu callback:
...kmeans_analyzer.lua:355: attempt to call a nil value (field 'maxn')
```

**The matplotlib Lua conflict error** has been **completely eliminated** using our enhanced isolation system.

**✅ FIXED SOLUTIONS:**

1. **Automatic Fix Applied**: The matplotlib Lua files have been disabled in your environment
2. **Clean tshark Wrapper**: All analysis now uses `tshark_clean.sh` which completely isolates Lua environments
3. **Enhanced Analysis Script**: `simple_analysis.sh` v4.1.0 includes built-in Lua conflict prevention

**How the fix works:**
- ✅ Matplotlib's problematic `kpsewhich.lua` file renamed to `.disabled`
- ✅ Clean environment wrappers isolate Python from Wireshark Lua
- ✅ All tshark operations use completely clean Lua environment
- ✅ Analysis scripts automatically detect and use conflict-free methods

**Verification:**
```bash
# This should now run without any Lua errors:
./tshark_clean.sh --version

# Analysis also runs clean:
./simple_analysis.sh
```

**If you still see Lua errors:**
```bash
# Run the automatic fixer:
./fix_matplotlib_lua_conflict.sh

# Or use the clean launcher:
./run_wireshark_clean.sh
```

**The enhanced analysis system automatically:**
- ✅ Isolates Python/matplotlib from Wireshark's Lua environment
- ✅ Generates graphs using a non-interactive backend
- ✅ Opens graphs automatically in your default image viewer
- ✅ Works despite the harmless Lua warning

### 🎨 Automatic Graph Generation & Viewing

**NEW FEATURE**: Graphs now open automatically after analysis!

**What happens:**
1. Analysis completes and generates 4 professional graphs
2. **Graphs automatically open** in your default image viewer (Preview on macOS)
3. You can immediately see the visualization results

**Example output:**
```
🖼️  Opening 4 graphs in default viewer...
   🖼️  Opened: kmeans_cluster_distribution.png
   🖼️  Opened: kmeans_pca_clusters.png
   🖼️  Opened: kmeans_feature_importance.png
   🖼️  Opened: kmeans_anomaly_analysis.png
✅ Graph viewing complete!
```

**Control auto-opening:**
```bash
# Disable auto-opening
python3 wireshark_kmeans_backend_enhanced.py capture.csv --no-auto-open

# Force auto-opening (default)
python3 wireshark_kmeans_backend_enhanced.py capture.csv --auto-open
```

This installer:
- Removes matplotlib to avoid Lua conflicts
- Uses Wireshark-compatible Lua API functions
- Removes problematic post-dissector registration
- Fixes table.maxn compatibility for modern Lua versions
- Adds packet collection functionality for existing captures
- Creates a clean virtual environment
- Provides better error handling

### Plugin Now Supports Real Data! (FIXED!) ✅

**Great News**: The Wireshark plugin has been enhanced to work with **REAL packet data** from your capture files!

**What's New in Version 3.0.0**:
- ✅ **Real packet collection** - No more synthetic data limitations
- ✅ **tshark integration** - Extracts actual packet data from opened files
- ✅ **Accurate analysis** - Shows real packet counts and protocols
- ✅ **Smart fallback** - Uses sample data only if real collection fails

**How to Use Real Data in Wireshark**:

1. **Open Wireshark and load your capture file** (File > Open)
2. **Open Lua Console** (Tools > Lua > Console)
3. **Enable real data mode**:
   ```lua
   toggle_real_data_mode()    # Enables real packet analysis
   ```
4. **Collect real packets**:
   ```lua
   force_collect_packets()    # Now reads your actual capture data!
   ```
5. **Run analysis**:
   ```lua
   run_kmeans_analysis()      # Analyzes real network traffic
   ```

**Example Output with Real Data**:
```
K-means Analyzer: Successfully collected 17 REAL packets
K-means Analyzer: Protocols found: SIP(2), ICMP(1), unknown(14)
Total packets analyzed: 17 (matches your capture file!)
```

**Alternative Methods**:
- ✅ **Enhanced Scripts**: `./analyze_real_data_enhanced.sh` (still recommended for batch analysis)
- ✅ **Wireshark Plugin**: Now supports real data with console commands above

### Recommended Workflow:

1. **Use the enhanced script** for real analysis:
   ```bash
   ./analyze_real_data_enhanced.sh
   ```

2. **Use Wireshark plugin** for:
   - Learning how the analysis works
   - Quick demonstration with sample data
   - Understanding cluster analysis concepts

### Plugin Usage After Installation

After successful installation, the plugin provides console commands:
- `run_kmeans_analysis()` - Perform full analysis
- `show_kmeans_stats()` - Display packet statistics
- `clear_kmeans_data()` - Clear collected data
- `show_kmeans_config()` - Show current configuration

### Externally-Managed Environment Error

If you see this error during installation:
```
error: externally-managed-environment
× This environment is externally managed
```

This is common on macOS with Python installed via Homebrew. **Solutions:**

1. **Use the enhanced installer** (recommended):
   ```bash
   ./install_plugin_enhanced.sh
   ```

2. **Create a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Install with user flag**:
   ```bash
   pip3 install --user -r requirements.txt
   ```

4. **Use Homebrew packages**:
   ```bash
   brew install python-pandas python-scikit-learn python-matplotlib
   ```

### Plugin Not Loading

1. **Check Wireshark console** for error messages
2. **Verify plugin directory** is correct for your system
3. **Ensure Lua support** is enabled in Wireshark
4. **Check file permissions** on plugin files

### Python Backend Errors

1. **Verify Python installation**:
   ```bash
   python3 --version
   ```

2. **Check dependencies**:
   ```bash
   python3 -c "import pandas, numpy, sklearn; print('Dependencies OK')"
   ```

3. **Test backend manually**:
   ```bash
   python3 wireshark_kmeans_backend.py --help
   ```

### Analysis Not Running

1. **Check minimum packet threshold** in configuration
2. **Verify CSV export** format is correct
3. **Check available disk space** for temporary files
4. **Review Python script path** in configuration

### Performance Issues

1. **Disable real-time analysis** for large captures
2. **Increase minimum packet threshold**
3. **Use packet sampling** for very large captures
4. **Close other resource-intensive applications**

## Advanced Usage

### Custom Feature Engineering

Modify `wireshark_kmeans_backend.py` to add custom features:

```python
def extract_custom_features(self, df):
    """Add your custom feature extraction logic here"""
    features = self.extract_features(df)
    
    # Add custom features
    features['custom_feature'] = your_calculation
    
    return features
```

### Integration with Other Tools

Export analysis results for use with other security tools:

```bash
# Export to JSON for SIEM integration
python3 wireshark_kmeans_backend.py capture.csv --format json --output results.json

# Process results with jq
jq '.anomalies[] | select(.anomaly_score > 0.8)' results.json
```

### Batch Processing

Process multiple capture files:

```bash
#!/bin/bash
for file in *.pcapng; do
    # Convert to CSV (requires tshark)
    tshark -r "$file" -T csv > "${file%.pcapng}.csv"
    
    # Analyze
    python3 wireshark_kmeans_backend.py "${file%.pcapng}.csv" \
        --output "${file%.pcapng}_analysis.json"
done
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Review Wireshark's plugin documentation
3. Submit an issue with detailed error information

## Changelog

### Version 1.0.0
- Initial release
- K-means clustering analysis
- Real-time and batch processing
- Anomaly detection
- Wireshark GUI integration
