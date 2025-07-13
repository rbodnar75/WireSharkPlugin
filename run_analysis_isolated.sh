#!/bin/bash

# Create an isolated Python environment wrapper to avoid matplotlib Lua conflicts

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="${SCRIPT_DIR}/venv/bin/python"

# Completely isolate the Python environment from system Lua paths
export LUA_PATH=""
export LUA_CPATH=""
export PYTHONPATH=""

# Clear any matplotlib-related environment variables
unset MPLBACKEND
unset MATPLOTLIBRC

# Run the enhanced backend with isolated environment
exec "$VENV_PYTHON" "$SCRIPT_DIR/wireshark_kmeans_backend_enhanced.py" "$@"
