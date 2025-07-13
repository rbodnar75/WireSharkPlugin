#!/bin/bash

# Wrapper script to run tshark without matplotlib Lua conflicts
# This completely isolates tshark from Python package Lua files

# Save original environment
ORIG_LUA_PATH="$LUA_PATH"
ORIG_LUA_CPATH="$LUA_CPATH"
ORIG_PYTHONPATH="$PYTHONPATH"

# Create a completely clean Lua environment
export LUA_PATH=""
export LUA_CPATH=""
export LUAPATH=""
export LUACPATH=""

# Also clear Python paths that might contain matplotlib
export PYTHONPATH=""

# Clear any matplotlib-specific environment variables
unset MPLBACKEND
unset MATPLOTLIBRC
unset MPLCONFIGDIR

# Disable Wireshark's Lua entirely for tshark operations
export WIRESHARK_LUA_DISABLE=1

# Run tshark with completely isolated environment
exec /Applications/Wireshark.app/Contents/MacOS/tshark "$@"
