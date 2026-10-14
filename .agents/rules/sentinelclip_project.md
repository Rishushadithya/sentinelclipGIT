# SentinelClip — Workspace Rule & Technical Context

> **Project Name:** SentinelClip (SLIIT Year 3 Semester 2 — Information Security Project)  
> **Core Objective:** Real-time Data Loss Prevention (DLP) engine for monitoring, sanitizing, and auditing sensitive data across Windows desktop clipboard operations and web browser interactions.

---

## 🏗️ Architecture & Component Layout

1. **Flask API Hub (`api/`)**:
   - SQLite backed (`sentinelclip.db`).
   - Central REST API (`/api/v1/policy/all`, `/api/v1/audit/log`, `/api/v1/device/enroll`).
   - Bearer authentication via `config/.device_token` and `config/.device_id`.
   - LAN Fleet Mode (`SENTINELCLIP_HOST="0.0.0.0"`).

2. **Clipboard Sentinel Daemon (`clipboard_engine/`)**:
   - Real-time Windows clipboard monitoring via win32clipboard / polling.
   - Text & image sanitization engine (`detection/`).
   - Dynamic regex detection (SSN, Credit Cards, API Keys, Passwords/Tags, Private/Public IP classification, Company Email alerts).
   - Desktop notifications (Win10Toast / win32gui).

3. **Streamlit Admin Dashboard (`dashboard/`)**:
   - Dark SOC (Security Operations Center) visual theme.
   - Interactive policy management (Add/Edit/Delete DLP rules).
   - Audit event logs with PC Username, IP addresses, match confidence, and clip preview.
   - Live system health metrics.

4. **Browser Extension & Native Host (`browser_extension/`, `native_host/`)**:
   - Manifest V3 Chrome/Edge extension.
   - Content scripts intercepting text inputs, paste events, and AI-readable file uploads (PDF, DOCX, CSV, XLSX, PPTX, TXT, JSON).
   - Native Messaging Host communicating via standard I/O (JSON) with local Python engine.

5. **Application Launcher (`app_launcher.pyw` & `SentinelClip.bat`)**:
   - Native Windows system tray app running `pythonw.exe`.
   - Starts API Hub, Clipboard Engine, and Dashboard concurrently in non-blocking threads/processes.

---

## 🧪 Development Guidelines & Commands

- **Environment Activation**: `.\.venv\Scripts\Activate.ps1`
- **Run Tests**: `.\.venv\Scripts\pytest.exe` (97 unit/integration tests)
- **Run Launcher**: `python app_launcher.pyw`
- **API URL**: `http://127.0.0.1:5000`
- **Dashboard URL**: `http://localhost:8501`
- **Database File**: `sentinelclip.db`
