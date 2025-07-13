#!/bin/bash

# Run Wireshark with clean Lua environment to avoid matplotlib conflicts
# This prevents the "kpse" error when starting Wireshark

echo "🧹 Starting Wireshark with clean Lua environment..."
echo "   This prevents matplotlib Lua conflicts"

# Clear Lua environment variables that might conflict
export WIRESHARK_LUA_DISABLE=""
export LUA_PATH=""
export LUA_CPATH=""

# Start Wireshark with clean environment
exec /Applications/Wireshark.app/Contents/MacOS/Wireshark "$@"
