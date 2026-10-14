# SentinelClip — Desktop & Browser DLP Protection System

> **SLIIT Year 3 Semester 2 — Information Security Project (ISP)**

SentinelClip is a lightweight, real-time Data Loss Prevention (DLP) engine designed to monitor, sanitize, and audit sensitive data across desktop clipboard operations and web browser interactions.

---

## 📄 Submission Documentation

- 📑 **[Software Stack & Progress Submission Report](file:///d:/SLIIT/Y3%20S2/IS%20project%20work/sentinelclipGIT/SOFTWARE_STACK_PROGRESS_SUBMISSION.md)** — Complete software stack breakdown, architectural details, security mechanisms, progress matrix, and test verification metrics.
- 📐 **[Architecture Overview](file:///d:/SLIIT/Y3%20S2/IS%20project%20work/sentinelclipGIT/docs/architecture.md)** — Component details and API specifications.

---

## 🛠️ Quick Start

```powershell
# 1. Activate virtual environment
.\.venv\Scripts\Activate.ps1

# 2. Run automated test suite (97 tests)
.\.venv\Scripts\pytest.exe

# 3. Launch SentinelClip application suite (API + Daemon + Dashboard)
python app_launcher.pyw
```

- **Flask API Hub**: `http://127.0.0.1:5000`
- **Streamlit Admin Dashboard**: `http://localhost:8501`

## LAN Fleet Mode

The central server can expose the API to enrolled agents on the local network:

```powershell
$env:SENTINELCLIP_HOST = "0.0.0.0"
$env:SENTINELCLIP_PORT = "5000"
$env:SENTINELCLIP_API_BASE = "http://192.168.1.10:5000/api/v1"
$env:SENTINELCLIP_DASHBOARD_HOST = "0.0.0.0"
$env:SENTINELCLIP_DASHBOARD_PORT = "8501"
python -m api.app
```

Create an enrollment code from the admin API, then configure a new agent with
`SENTINELCLIP_ENROLLMENT_CODE`. The agent exchanges the one-time code and saves
its credentials in `config/.device_id` and `config/.device_token`.

The API requires device bearer authentication for policy retrieval and audit
logging. Keep the existing admin token separate for dashboard management, and
configure the Windows firewall to allow port 5000 only from the local subnet.
