# SentinelClip User Guide

## 1. Install SentinelClip

Use the latest `SentinelClip-Setup-Offline.exe` from the project `dist` folder. The installer bundles Python and the application dependencies, so target PCs do not need Python or internet access.

1. Run the installer and approve the Windows administrator prompt. SentinelClip installs under `C:\Program Files\SentinelClip`.
2. Choose a role:
   - **Server**: this PC hosts the API and dashboard for other PCs.
   - **Agent**: this PC connects to an existing server and protects its clipboard.
   - **Both**: this PC hosts the server and also runs a local agent. Choose this for a one-PC trial.
3. For **Server** or **Both**, leave the private-LAN firewall option enabled if other PCs need to connect. Approve the firewall prompt if Windows asks. Setup shows the server URL and a one-time enrollment code; the code expires in 10 minutes.
4. For **Agent**, enter the server URL and the one-time code from the Server PC.
5. Finish setup. SentinelClip starts in the notification area, creates a desktop shortcut, and is listed in Windows Startup Apps. Its elevated startup task runs at sign-in and restarts the tray app if it exits unexpectedly.

Do not send anyone the admin or device token files. Enrollment codes are one-time and should only be shared with the PC being enrolled.

## 2. Example: One Server and One Agent

Suppose the server PC's LAN address is `192.168.1.25`.

1. Install SentinelClip on the server PC and select **Server**. The setup window displays an address such as `http://192.168.1.25:5000/api/v1` and a temporary enrollment code.
2. On the agent PC, run the same installer and select **Agent**. Enter that server URL and the code while it is still valid.
3. On the agent PC, open `http://192.168.1.25:5000/api/v1/health` in a browser. A healthy server returns JSON containing `"status":"ok"`.
4. On the server PC, open the SentinelClip dashboard from the Start menu or visit `http://localhost:8501`. The Devices page should show the enrolled agent after it connects.

Keep both PCs on the same trusted private LAN. SentinelClip currently uses HTTP; do not expose its API to the public internet.

## 3. Browser Upload Protection

Browser upload scanning needs one manual extension load per browser on unmanaged PCs. SentinelClip cannot silently add an unpacked extension to Chrome or Edge.

1. On the PC running SentinelClip, open `chrome://extensions` or `edge://extensions`.
2. Turn on **Developer mode**, choose **Load unpacked**, and select:
   `C:\Program Files\SentinelClip\browser_extension`
3. Copy the extension ID shown on the extensions page.
4. From the Start menu, open **SentinelClip > Configure Browser Protection**. Paste the ID into the matching Chrome or Edge box and select **Register Native Host**.
5. Restart the browser. Repeat the load-and-register steps for the other browser if needed.

The extension watches file uploads on ChatGPT, Gemini, Claude, and Copilot sites listed in its manifest. The extension must be installed in the same Windows user profile that runs SentinelClip.

## 4. Safe Functional Test

Use this synthetic value only; never test with a real password or company secret.

1. Open Notepad and enter:

   ```text
   password=SentinelTest!234
   ```

2. Save it as `sentinelclip-test.txt`.
3. On a supported AI site, attach the file. SentinelClip should block the upload and show a sensitive-content warning.
4. Open the dashboard's Violations page. Look for a `browser_upload` event with action `BLOCK`, the site domain, detected rule, and PC user name.

The clipboard detector uses the policies assigned to that device. Copy the same synthetic value in Notepad to exercise clipboard scanning; the result depends on the matching policy action (for example, block, warn, redact, or obfuscate).

## 5. Start and Stop

- Start it from the desktop shortcut, Start menu, or `C:\Program Files\SentinelClip\SentinelClip.bat`.
- The tray icon is in the Windows notification area; Windows may place it under **Show hidden icons**.
- SentinelClip starts automatically at sign-in. The Startup Apps entry is named **SentinelClip**.
- The installed tray app has no normal Exit command. Administrator approval is required to uninstall or remove its protected Program Files installation.

## 6. Troubleshooting

- **No server response**: confirm the Server PC is running SentinelClip, check `http://SERVER-IP:5000/api/v1/health`, and allow TCP 5000 on the Private network profile.
- **Agent cannot fetch policies**: check the agent's server URL, confirm its enrollment completed, and enroll it again with a fresh one-time code if its device token is missing or invalid.
- **Upload is not intercepted**: confirm the extension is enabled in that browser, confirm the native host was registered for that exact extension ID, then restart the browser.
- **SentinelClip is absent from Startup Apps**: reinstall/update with the latest installer and approve the administrator prompt. Sign out and back in to refresh Windows' Startup Apps list.
- **Tray app does not start**: run `SentinelClip.bat`. It starts the elevated scheduled task and displays an error if that task is not registered. Run the installer again and approve administrator access if the task is missing.

For build instructions and LAN deployment details, see [windows-installation.md](windows-installation.md).
