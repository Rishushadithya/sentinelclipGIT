# SentinelClip Architecture

See README.md for the architecture diagram and component overview.

## Components

1. **Flask API Hub** (`api/`) — Single source of truth, binds to 127.0.0.1:5000
2. **Clipboard Sentinel Engine** (`clipboard_engine/`) — Polls clipboard, detects/sanitizes
3. **Browser Extension** (`browser_extension/`) — MV3 extension for AI domain file uploads
4. **Native Messaging Host** (`native_host/`) — Bridges extension to Flask API
5. **Detection Engine** (`detection/`) — Shared regex pattern library
6. **Streamlit Dashboard** (`dashboard/`) — Admin monitoring and policy management
