#define AppName "SentinelClip"
#define AppVersion "1.1.0"
#define AppPublisher "SentinelClip Security"
#define AppId "{{AE5BA123-4B06-4E14-946F-E114B5AC4C3E}"

[Setup]
AppId={#AppId}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppComments=SentinelClip — Local-First Data Loss Prevention Middleware
DefaultDirName={autopf}\SentinelClip
UsePreviousAppDir=no
DefaultGroupName=SentinelClip
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64
OutputDir=..\dist
OutputBaseFilename=SentinelClip-Setup-Offline
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\browser_extension\icons\icon48.png
CloseApplications=force

VersionInfoVersion=1.1.0.0
VersionInfoProductVersion=1.1.0.0
VersionInfoDescription=SentinelClip Offline Setup Installer
VersionInfoCompany=SentinelClip Security
VersionInfoCopyright=Copyright (C) 2026 SentinelClip DLP

[Files]
Source: "..\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: ".git\*,.venv\*,build\*,dist\*,tests\*,__pycache__\*,.pytest_cache\*,installer\.build_venv\*,config\.admin_token,config\.admin_credentials,config\.device_id,config\.device_token,config\deployment.json,installer\payload\*,*.db,*.db-wal,*.db-shm,*.log"
Source: "payload\app\runtime\*"; DestDir: "{app}\runtime"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "payload\native_host\SentinelClipNativeHost.exe"; DestDir: "{app}\native_host"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\SentinelClip\SentinelClip"; Filename: "{sys}\schtasks.exe"; Parameters: "/Run /TN ""\SentinelClip\Tray"""; IconFilename: "{app}\browser_extension\icons\icon48.png"
Name: "{autodesktop}\SentinelClip"; Filename: "{sys}\schtasks.exe"; Parameters: "/Run /TN ""\SentinelClip\Tray"""; IconFilename: "{app}\browser_extension\icons\icon48.png"
Name: "{autoprograms}\SentinelClip\Configure Browser Protection"; Filename: "{sys}\schtasks.exe"; Parameters: "/Run /TN ""\SentinelClip\BrowserSetup"""; IconFilename: "{app}\browser_extension\icons\icon48.png"

[Run]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\installer\setup_wizard.ps1"""; Description: "Configure SentinelClip for this PC"; StatusMsg: "Opening first-run setup..."; Flags: waituntilterminated
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\installer\register_startup_tasks.ps1"""; StatusMsg: "Registering SentinelClip startup protection..."; Flags: runhidden waituntilterminated

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\installer\unregister_startup_tasks.ps1"""; Flags: runhidden waituntilterminated; RunOnceId: RemoveSentinelClipTasks