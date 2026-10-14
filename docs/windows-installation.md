# Windows Installation and LAN Deployment

## Build the Offline Installer

The build PC needs Windows, the project virtual environment, internet access for
the one-time build downloads, and Inno Setup 6. Target PCs do not need internet
or a separate Python installation.

```powershell
.\.venv\Scripts\Activate.ps1
.\installer\build_offline.ps1
```

The build downloads the CPython embeddable runtime and Windows wheels, installs
the application packages into its isolated runtime, packages the browser
native-messaging host, and creates
`dist\SentinelClip-Setup-Offline.exe`.

## Install Each PC

Run the installer and select a role:

- **Server** starts the LAN API and local dashboard.
- **Agent** enrolls this PC to an existing server and runs clipboard protection.
- **Both** runs the server and enrolls this PC as a local agent.

Agent setup asks for the server API URL and a short-lived enrollment code. On a
Server or Both installation, setup displays the server URL and an initial code.
The tray menu can copy further one-time codes. A Server installation offers to
create a Windows Firewall rule for TCP 5000, restricted to the Private profile
and `LocalSubnet`; Windows may request administrator approval for that rule.

The protected installer prompts for administrator approval and installs under
`Program Files`. It creates an elevated sign-in task for the current account,
restarts the tray app after a crash, and requires administrator approval to
uninstall or delete its protected program files. Do not copy the admin or device
token files between PCs.

## Browser Upload Protection

On an unmanaged PC, the browser requires a one-time manual extension load:

1. Open `chrome://extensions` or `edge://extensions` and enable Developer mode.
2. Select **Load unpacked** and choose the installed `browser_extension` folder.
3. Copy the displayed extension ID.
4. Open **Configure Browser Protection** from the Start menu and register the
   ID for the matching browser.
5. Restart the browser.

Repeat for both browsers if both are used. Managed browser policies can deploy
extensions centrally instead, but require organization-specific policy and
extension distribution configuration.

## LAN Security Boundary

The API currently uses plain HTTP. Keep it on a trusted, isolated private LAN;
do not expose it to the public internet. Event metadata and bearer credentials
are not encrypted in transit. Configure and validate HTTPS before using this
installer for sensitive production traffic.

## Build Limitations

The installer compiler is not bundled. Inno Setup 6 must be installed on the
build PC. The setup `.exe` is generated locally and is not checked into the
repository.
