#!/bin/bash

# Cleanup script for WireSharkPlugin repository
# Removes temporary files, backups, and outdated development files

echo "🧹 WireShark Plugin Cleanup Script"
echo "=================================="
echo ""

# Files and directories to clean up
CLEANUP_ITEMS=(
    # Development documentation files (outdated)
    "ENHANCED_PLUGIN_GUIDE.md"
    "ERRORS_FIXED.md" 
    "FIXES_APPLIED.md"
    "INSTALLATION_FIX.md"
    "INTEGRATION_SUCCESS.md"
    "PLUGIN_FIXED_GUIDE.md"
    "PLUGIN_USAGE_GUIDE.md"
    "PROJECT_SUMMARY.md"
    "REAL_DATA_SUCCESS.md"
    "REAL_VS_SAMPLE_DATA.md"
    
    # Backup and old versions
    "wireshark_kmeans_backend.py.backup"
    "simple_analysis_fixed.sh"  # Duplicate of simple_analysis.sh
    
    # Old plugin versions (keeping only the final working version)
    "kmeans_analyzer.lua"           # Original version
    "kmeans_analyzer_v2.lua"        # Version 2
    "kmeans_analyzer_improved.lua"  # Improved version
    "kmeans_analyzer_fixed.lua"     # Fixed version
    "kmeans_analyzer_real_data.lua" # Real data version
    # Keeping: kmeans_analyzer_simple.lua (final working version)
    
    # Old backend versions (keeping only the enhanced version)
    "wireshark_kmeans_backend.py"         # Original
    "wireshark_kmeans_backend_minimal.py" # Minimal version
    # Keeping: wireshark_kmeans_backend_enhanced.py (final version)
    
    # Test and development scripts
    "test_backend.py"
    "test_enhanced_plugin.sh"
    "test_integration.sh"
    "test_plugin_extraction.sh"
    "troubleshoot.sh"
    "verify_real_data.sh"
    "debug_wireshark_detection.sh"
    "extract_packets.sh"
    "wireshark_auto_analysis.sh"
    
    # Old analysis scripts (keeping the working enhanced version)
    "analyze_real_data.sh"  # Basic version
    # Keeping: analyze_real_data_enhanced.sh (enhanced version)
    
    # Development artifacts
    "example_usage.py"
    "example_analysis_results.json"
    "plugin_config.ini"
    "__pycache__/"
    
    # Temporary files patterns
    "*.tmp"
    "*.temp"
    "*.log"
    "/tmp/analysis_*.csv"
)

# Keep these essential files
ESSENTIAL_FILES=(
    "README.md"
    "requirements.txt"
    "requirements_minimal.txt"
    "install_plugin.sh"
    "install_plugin_enhanced.sh"
    "install_plugin_fixed.sh"
    "kmeans_analyzer_simple.lua"
    "wireshark_kmeans_backend_enhanced.py"
    "analyze_real_data_enhanced.sh"
    "simple_analysis.sh"
    "export_and_analyze.sh"
    "tshark_clean.sh"
    "run_wireshark_clean.sh"
    "run_analysis_isolated.sh"
    "fix_matplotlib_lua_conflict.sh"
    "wiresharkanalyzer.py"
)

echo "🔍 Analyzing files to clean up..."
echo ""

# Count files to be removed
removed_count=0
kept_count=0
total_size=0

# Check which files actually exist and can be removed
for item in "${CLEANUP_ITEMS[@]}"; do
    if [ -e "$item" ]; then
        size=$(du -sh "$item" 2>/dev/null | cut -f1)
        echo "  🗑️  Will remove: $item ($size)"
        removed_count=$((removed_count + 1))
    fi
done

echo ""
echo "📊 Summary:"
echo "  Files to remove: $removed_count"

# Ask for confirmation
echo ""
read -p "❓ Proceed with cleanup? (y/N): " confirm

if [[ $confirm =~ ^[Yy]$ ]]; then
    echo ""
    echo "🧹 Starting cleanup..."
    
    # Remove the files
    for item in "${CLEANUP_ITEMS[@]}"; do
        if [ -e "$item" ]; then
            if [ -d "$item" ]; then
                echo "  🗂️  Removing directory: $item"
                rm -rf "$item"
            else
                echo "  📄 Removing file: $item"
                rm -f "$item"
            fi
        fi
    done
    
    # Clean up any temporary files in /tmp
    echo "  🧽 Cleaning temporary analysis files..."
    rm -f /tmp/analysis_*.csv 2>/dev/null
    
    echo ""
    echo "✅ Cleanup complete!"
    echo ""
    echo "📁 Remaining essential files:"
    for file in "${ESSENTIAL_FILES[@]}"; do
        if [ -e "$file" ]; then
            size=$(du -sh "$file" 2>/dev/null | cut -f1)
            echo "  ✅ $file ($size)"
        fi
    done
    
    echo ""
    echo "🎉 Repository cleaned! Only essential files remain."
    echo ""
    echo "💡 Essential files kept:"
    echo "  📝 README.md - Complete documentation"
    echo "  🔧 install_plugin_*.sh - Installation scripts"
    echo "  🧩 kmeans_analyzer_simple.lua - Final working plugin"
    echo "  🐍 wireshark_kmeans_backend_enhanced.py - Enhanced analysis backend"
    echo "  📊 analyze_real_data_enhanced.sh - Main analysis script"
    echo "  🛠️ simple_analysis.sh - Wireshark integration script"
    echo "  🧹 *_clean.sh - Lua conflict prevention tools"
    
else
    echo ""
    echo "❌ Cleanup cancelled. No files were removed."
fi

echo ""
echo "📋 To see current files: ls -la"
echo "💾 Current repository size: $(du -sh . | cut -f1)"
