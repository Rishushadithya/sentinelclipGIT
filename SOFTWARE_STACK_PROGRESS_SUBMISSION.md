# SLIIT Year 3 Semester 2 — Information Security Project (ISP)
## Software Stack & Implementation Progress Submission Report

---

### Project Metadata

| Attribute | Details |
| :--- | :--- |
| **Project Title** | **SentinelClip** — Desktop Clipboard & Browser Data Loss Prevention (DLP) Engine |
| **Course Module** | Information Security Project (ISP) — Y3S2 |
| **Institution** | Sri Lanka Institute of Information Technology (SLIIT) |
| **Target Operating System** | Windows 10 / 11 |
| **Report Type** | Software Stack & Implementation Progress Deliverable |
| **Status** | Implementation Complete / 100% Feature Ready / 97/97 Automated Tests Passing |
| **Repository Path** | `d:\SLIIT\Y3 S2\IS project work\sentinelclipGIT` |

---

## 1. Executive Summary & Project Purpose

**SentinelClip** is a lightweight, high-performance Data Loss Prevention (DLP) system designed to monitor, intercept, sanitize, and audit sensitive data across desktop clipboard operations and web browser interactions in real-time.

### Problem Statement
In modern organizational environments, employees frequently copy and paste text containing confidential assets—such as AWS credentials, API keys, database connection strings, private IP addresses, RSA keys, and Personally Identifiable Information (PII)—into untrusted endpoints, messaging channels, or web-based Generative AI tools (e.g., ChatGPT, Claude, Gemini). Traditional DLP systems are heavy, intrusive, and often fail to protect local clipboard buffers or browser file uploads in real time.

### Solution Overview
SentinelClip provides a **local-first, multi-layered security barrier** consisting of:
1. A **Desktop Clipboard Sentinel Daemon** that monitors and sanitizes the system clipboard buffer in real time.
2. A **Browser Sentinel (Manifest V3) Extension** coupled with a **Native Messaging IPC Host** to inspect web form inputs, paste actions, and file uploads to target AI/external domains.
3. A **Central Flask Security API Hub** acting as the single source of truth for policy distribution and telemetry.
4. A **Tamper-Evident SHA-256 Hash-Chained Audit Ledger** storing security events without recording raw secret payloads.
5. An **Interactive Admin Dashboard** (built with Streamlit) for live threat monitoring, dynamic policy editing, and cryptographic audit log integrity verification.

---

## 2. Comprehensive Software Stack & Technology Matrix

The software architecture of SentinelClip utilizes modular, lightweight, and standards-compliant technologies across desktop, backend, browser, and analytical layers.

```
+-----------------------------------------------------------------------------------+
|                                 SENTINELCLIP STACK                                |
+-----------------------------+-------------------------------+---------------------+
| Layer                       | Technology / Framework        | Purpose             |
+-----------------------------+-------------------------------+---------------------+
| Core Programming Languages  | Python 3.14+                  | Engine, API & UI    |
|                             | JavaScript (ES6+ / Web APIs)  | MV3 Browser Ext.    |
+-----------------------------+-------------------------------+---------------------+
| Backend API & Security Hub  | Flask 3.x                     | RESTful Central Hub |
|                             | Flask-CORS                    | Origin Access Control|
|                             | SQLite3                       | Embedded Storage    |
+-----------------------------+-------------------------------+---------------------+
| Desktop Sentinel Daemon     | Pyperclip                     | System Clipboard API|
|                             | Plyer                         | Windows Desktop Toast|
|                             | Python Threading & Time       | Background Polling  |
+-----------------------------+-------------------------------+---------------------+
| Browser Protection & IPC    | Chrome Extension (Manifest V3)| DOM & Event Watcher |
|                             | Chrome Native Messaging API   | Extension-to-OS IPC |
|                             | Struct Packing (length-prefix)| Binary StdIO Stream |
+-----------------------------+-------------------------------+---------------------+
| Admin & Monitoring Console  | Streamlit                     | Web Management UI   |
|                             | Pandas                        | Log Filtering & Data|
|                             | Plotly                        | Security Metrics Vis|
+-----------------------------+-------------------------------+---------------------+
| Security & Cryptography     | hashlib (SHA-256 / SHA-512)   | Tamper-Proof Audit  |
|                             | Python `re` engine            | Compiled Regex Rules|
+-----------------------------+-------------------------------+---------------------+
| QA & Automated Testing      | Pytest 9.x                    | Unit & Integration  |
|                             | AnyIO                         | Async Testing       |
+-----------------------------+-------------------------------+---------------------+
| OS Automation & Deployment  | Windows Batch (`.bat`)        | Process Launcher    |
|                             | PowerShell (`.ps1`)           | Desktop Shortcut Gen|
|                             | Python `.pyw` (Tray Exec)     | Background Exec     |
+-----------------------------+-------------------------------+---------------------+
```

---

## 3. Detailed Subsystem Architecture

SentinelClip is structured into six modular, decoupled components to maintain high performance, strict separation of concerns, and local loopback security.

```
                                  +-----------------------+
                                  |   Streamlit Admin     |
                                  |      Dashboard        |
                                  | (dashboard/Home.py)   |
                                  +-----------+-----------+
                                              | HTTP REST API
                                              v
+-----------------------+          +-----------------------+          +-----------------------+
|  Clipboard Sentinel   |          |    Flask API Hub      |          | Browser Extension MV3 |
|        Daemon         +--------->|  (api/app.py:5000)    |<---------+ (Content Script / BG) |
| (clipboard_engine/)   | HTTP REST|  Singular DB Interface|  Native  +-----------+-----------+
+-----------+-----------+          +-----------+-----------+   Host               |
            |                                  | IPC                          | Intercepts
            v Intercepts                       v Cryptographic                v Inputs & Uploads
    +---------------+                  +---------------+              +---------------+
    |  System OS    |                  |  SQLite Audit |              | Web Page DOM  |
    | Clipboard Buffer|                | Hash Ledger   |              | / AI Domains  |
    +---------------+                  +---------------+              +---------------+
```

### Component 1: Central Flask Security API Hub (`api/`)
* **Role**: Single source of truth for policy distribution and audit event ingestion.
* **Key Specs**: Binds exclusively to local loopback `127.0.0.1:5000`. Direct database writes are disallowed from other processes.
* **Authentication**: Enforces `X-Admin-Token` verification for administrative routes.
* **Modules**:
  * `api/app.py`: Application factory, Flask-CORS policy, request lifecycle hooks.
  * `api/db.py`: Database connection pool and schema initialization.
  * `api/models.py`: Dataclasses representing `PolicyRuleModel` and `AuditEventModel`.
  * `api/audit.py`: Cryptographic hash chaining recorder and validator.
  * `api/routes/`: Blueprint modular routing (`policy_routes.py`, `log_routes.py`, `event_routes.py`).

### Component 2: Clipboard Sentinel Engine (`clipboard_engine/`)
* **Role**: Lightweight desktop daemon executing active clipboard monitoring and inline sanitization.
* **Key Specs**: Zero-latency polling loop inspecting clipboard state changes.
* **Modules**:
  * `clipboard_engine/main.py`: Main daemon loop coordinating watcher, detector, sanitizer, and notifier.
  * `clipboard_engine/watcher.py`: Safe thread wrapper reading system clipboard via `pyperclip`.
  * `clipboard_engine/detector.py`: Evaluates content against active DLP policy rules.
  * `clipboard_engine/sanitizer.py`: Performs inline string replacement, redaction, obfuscation, or buffer wiping.
  * `clipboard_engine/notifier.py`: Triggers Windows native desktop notifications via `plyer`.
  * `clipboard_engine/reporter.py`: Asynchronously transmits violation metrics to Flask API Hub.

### Component 3: Shared Detection & Pattern Engine (`detection/`)
* **Role**: Centralized rule matching engine housing seed regex patterns and compiled match objects.
* **Pre-configured Patterns**:
  * **AWS Access Keys**: `AKIA[0-9A-Z]{16}` (`BLOCK`)
  * **Generic API Keys**: `(?i)(api[_\-]?key)["\'\s:=]+[A-Za-z0-9_\-]{16,}` (`REDACT`)
  * **Private IP Addresses**: `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x` (`OBFUSCATE` to `[PRIVATE_IP]`)
  * **Public IP Addresses**: IPv4 standard ranges (`WARN`)
  * **Credit Card Numbers**: Luhn-compliant regex rules (`REDACT`)
  * **Social Security Numbers / PII**: Standard SSN formats (`REDACT`)
  * **JWT Auth Tokens**: `eyJ[A-Za-z0-9-_=]+\.eyJ...` (`BLOCK`)
  * **Database URIs**: Connection strings for Postgres, MySQL, MongoDB (`REDACT`)
  * **RSA Private Keys**: `-----BEGIN RSA PRIVATE KEY-----` (`BLOCK`)
  * **Corporate Keyword Lists**: Custom configurable literal terms (`WARN` / `BLOCK`)

### Component 4: Browser Extension MV3 & Native Messaging Host (`browser_extension/` & `native_host/`)
* **Role**: Browser-side protection intercepting paste events, prompt inputs, and file uploads on target domains (ChatGPT, Claude, Gemini, etc.).
* **Key Specs**: Uses Chrome Extension Manifest V3 specs.
* **Modules**:
  * `browser_extension/manifest.json`: Defines permissions (`declarativeNetRequest`, `storage`, `nativeMessaging`, `activeTab`).
  * `browser_extension/content_script.js`: DOM observer attaching listeners to `textarea`, `div[contenteditable]`, `<input type="file">`, and paste events.
  * `browser_extension/background.js`: Service worker managing state and routing native messaging requests.
  * `native_host/native_host.py`: Python host reading/writing length-prefixed JSON frames from standard I/O streams and forwarding to Flask API.

### Component 5: Admin Dashboard (`dashboard/`)
* **Role**: Interactive management console built with Streamlit.
* **Pages**:
  * `Home.py`: System health dashboard, live counter cards, overview telemetry.
  * `pages/1_Violations.py`: Real-time audit log explorer, timeline visualization, severity/action filters.
  * `pages/2_Policy_Editor.py`: Dynamic policy management—create, enable/disable, edit regex rules, adjust severities and actions.
  * `pages/3_Audit_Export.py`: One-click cryptographic chain integrity verification and CSV/JSON export.

---

## 4. Security Engineering & Core Innovations

### 1. Cryptographic Tamper-Evident Audit Ledger (SHA-256 Hash Chaining)
To prevent rogue users or unauthorized administrators from altering security logs in SQLite, SentinelClip implements a blockchain-inspired cryptographic hash chain (`api/audit.py`).

* Each entry calculates its hash as:
  $$\text{Hash}_n = \text{SHA256}(\text{JSON\_Serialize}(\text{Event}_n) + \text{Hash}_{n-1})$$
* Initial entry connects to a fixed `"GENESIS"` hash.
* If any row in the `audit_log` table is tampered with, added, or deleted, the dashboard verification tool (`pages/3_Audit_Export.py`) flags the exact row index where the broken hash link occurs.

### 2. Privacy-Preserving Zero-Payload Logging
SentinelClip follows a strict **Zero-Leak Logging Policy**. Security logs record metadata only (Timestamp, Rule Name, Action Taken, Match Length, Domain/Source, PC Username). Raw confidential strings or secrets are **never stored** in the database or log files.

### 3. Four-Tier Policy Enforcement Spectrum
1. `WARN`: Allows copy/paste or submission while issuing a desktop toast notification.
2. `OBFUSCATE`: Replaces sensitive variables with non-sensitive semantic indicators (e.g., `192.168.1.50` $\rightarrow$ `[PRIVATE_IP]`).
3. `REDACT`: Replaces credentials or secrets with masked string blocks (e.g., `[REDACTED_API_KEY]`).
4. `BLOCK`: Immediately clears system clipboard buffer or cancels browser upload/submit events.

---

## 5. Implementation Progress & Feature Matrix

All planned requirements for the Information Security Project are **100% completed, tested, and integrated**.

| Module / Area | Feature Description | Status | Verification Method |
| :--- | :--- | :---: | :--- |
| **Central API Hub** | REST API Endpoints for policies, logs, health checks | **100% Complete** | `test_api_routes.py` |
| **Database Layer** | SQLite schema initialization & connection lifecycle | **100% Complete** | Automated DB fixture tests |
| **Audit Ledger** | SHA-256 / SHA-512 Hash Chain generation & verification | **100% Complete** | `test_audit_chain.py` |
| **Detection Engine** | Pre-compiled regex pattern library & custom rule matching | **100% Complete** | `test_detector.py` (53 tests) |
| **Clipboard Daemon** | Real-time clipboard polling, inline replacement, & notifications | **100% Complete** | `test_integration.py` |
| **Browser Extension** | MV3 content script for form monitoring & file upload checks | **100% Complete** | Manual Chrome unpack & native test |
| **Native Host IPC** | Binary length-prefixed STDIN/STDOUT communication | **100% Complete** | Host wrapper integration test |
| **Streamlit Dashboard** | Telemetry visuals, rule editor, & cryptographic audit tool | **100% Complete** | End-to-end dashboard execution |
| **Automation** | System tray launcher script & desktop shortcuts | **100% Complete** | Windows `.bat` & `.ps1` execution |

---

## 6. Testing, Quality Assurance & Verification Metrics

SentinelClip features an automated testing suite implemented with **Pytest**.

### Test Suite Execution Summary

* **Total Test Cases**: **97**
* **Passed**: **97 (100% Pass Rate)**
* **Failed**: **0**
* **Execution Time**: **~2.17 seconds**

```
============================= test session starts =============================
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
rootdir: D:\SLIIT\Y3 S2\IS project work\sentinelclipGIT
plugins: anyio-4.14.2
collected 97 items

tests\test_api_routes.py ...................                             [ 19%]
tests\test_audit_chain.py ..............                                 [ 34%]
tests\test_company_email_warning.py ...                                  [ 37%]
tests\test_detector.py ................................................. [ 87%]
....                                                                     [ 91%]
tests\test_integration.py ........                                       [100%]

============================= 97 passed in 2.17s ==============================
```

### Breakdown of Test Modules
1. `test_api_routes.py` (19 tests): Validates API endpoints, error handling, CORS headers, and authentication token enforcement.
2. `test_audit_chain.py` (14 tests): Tests hash computation, ledger creation, and detects simulated log tampering.
3. `test_company_email_warning.py` (3 tests): Tests warning alerts for corporate domain email paste operations.
4. `test_detector.py` (53 tests): Tests every pre-configured regex/keyword pattern against valid secrets and edge cases.
5. `test_integration.py` (8 tests): Validates complete flow from clipboard watcher $\rightarrow$ detection $\rightarrow$ sanitization $\rightarrow$ API audit logging.

---

## 7. Deployment & Execution Instructions

### Prerequisites
* Windows 10 or 11 OS
* Python 3.10+ installed and added to `PATH`
* Google Chrome or Microsoft Edge browser

### Step 1: Virtual Environment & Dependency Setup
```powershell
# Navigate to project directory
cd "d:\SLIIT\Y3 S2\IS project work\sentinelclipGIT"

# Activate existing virtual environment
.\.venv\Scripts\Activate.ps1

# (Optional) Reinstall dependencies if needed
pip install -r requirements.txt
```

### Step 2: Running Automated Tests
```powershell
.\.venv\Scripts\pytest.exe
```

### Step 3: Launching SentinelClip Application Suite
Run the system launcher which boots up the Flask API Hub, Clipboard Sentinel Daemon, and Streamlit Dashboard simultaneously:
```powershell
python app_launcher.pyw
```
Alternatively, double-click `SentinelClip.bat` in the root folder.

### Step 4: Accessing Application Interfaces
* **Flask API Hub**: `http://127.0.0.1:5000`
* **Streamlit Admin Dashboard**: `http://localhost:8501`

### Step 5: Installing Browser Extension
1. Open Google Chrome / Microsoft Edge and navigate to `chrome://extensions`.
2. Enable **Developer mode** toggle (top-right).
3. Click **Load unpacked** and select the directory:
   `d:\SLIIT\Y3 S2\IS project work\sentinelclipGIT\browser_extension`

---

## 8. Summary & Deliverable Approval

The **SentinelClip** software stack and functionality fulfill all technical requirements for the **SLIIT Y3S2 Information Security Project (ISP)**. The project is fully functional, robustly tested, and ready for final submission and demonstration.

---
*Report generated for SLIIT Y3S2 ISP Submission — September 2026.*
