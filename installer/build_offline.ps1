param()

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$PayloadDir = Join-Path $PSScriptRoot "payload"
$WheelhouseDir = Join-Path $PayloadDir "wheelhouse"
$NativeHostDir = Join-Path $PayloadDir "native_host"
$PythonEmbedZip = Join-Path $PayloadDir "python-3.12.10-embed-amd64.zip"
$RuntimeDir = Join-Path $PayloadDir "app\runtime"
$Python = Join-Path $RepoRoot ".venv\Scripts\python.exe"
$BuildVenv = Join-Path $PSScriptRoot ".build_venv"
$BuildPython = Join-Path $BuildVenv "Scripts\python.exe"

if (-not (Test-Path $Python)) {
    throw "Build Python is missing at $Python. Create the project virtual environment first."
}

$Compiler = (Get-Command ISCC.exe -ErrorAction SilentlyContinue).Source
if (-not $Compiler) {
    $Candidates = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    )
    $Compiler = $Candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $Compiler) {
    throw "Inno Setup 6 is required on the build PC. Install it, then rerun this script."
}

New-Item -ItemType Directory -Force -Path $WheelhouseDir | Out-Null
New-Item -ItemType Directory -Force -Path $NativeHostDir | Out-Null
if (-not (Test-Path $PythonEmbedZip)) {
    Invoke-WebRequest `
        -Uri "https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip" `
        -OutFile $PythonEmbedZip
}

& $Python -m pip download `
    --dest $WheelhouseDir `
    --only-binary=:all: `
    --platform win_amd64 `
    --python-version 3.12 `
    --implementation cp `
    --abi cp312 `
    -r (Join-Path $RepoRoot "requirements.txt") `
    pip
if ($LASTEXITCODE -ne 0) {
    throw "Could not download the complete Windows dependency wheelhouse."
}

if (-not (Test-Path $BuildPython)) {
    & $Python -m venv $BuildVenv
    if ($LASTEXITCODE -ne 0) {
        throw "Could not create the isolated Windows packaging environment."
    }
}
& $BuildPython -m pip install -r (Join-Path $RepoRoot "requirements.txt") pyinstaller
if ($LASTEXITCODE -ne 0) {
    throw "Could not prepare PyInstaller and application dependencies."
}

New-Item -ItemType Directory -Force -Path $RuntimeDir | Out-Null
Expand-Archive -LiteralPath $PythonEmbedZip -DestinationPath $RuntimeDir -Force
$SitePackages = Join-Path $RuntimeDir "Lib\site-packages"
New-Item -ItemType Directory -Force -Path $SitePackages | Out-Null
@("python312.zip", ".", "Lib\site-packages", "..", "import site") |
Set-Content -Path (Join-Path $RuntimeDir "python312._pth") -Encoding ASCII

$PipWheel = Get-ChildItem $WheelhouseDir -Filter "pip-*.whl" | Select-Object -First 1
if (-not $PipWheel) {
    throw "The pip wheel is missing from the offline wheelhouse."
}
$PipZip = Join-Path $env:TEMP ("SentinelClip-pip-" + [guid]::NewGuid().ToString("N") + ".zip")
Copy-Item $PipWheel.FullName $PipZip
Expand-Archive -LiteralPath $PipZip -DestinationPath $SitePackages -Force
Remove-Item $PipZip -Force

$EmbeddedPython = Join-Path $RuntimeDir "python.exe"
& $EmbeddedPython -m pip install `
    --no-index `
    --find-links $WheelhouseDir `
    --target $SitePackages `
    -r (Join-Path $RepoRoot "requirements.txt")
if ($LASTEXITCODE -ne 0) {
    throw "Could not install application dependencies into the embedded runtime."
}
$PrunableDirs = Get-ChildItem $SitePackages -Directory -Recurse -Force |
Where-Object { $_.Name -in @("tests", "test", "__pycache__") } |
Sort-Object { $_.FullName.Length } -Descending
foreach ($Directory in $PrunableDirs) {
    if (Test-Path $Directory.FullName) {
        Remove-Item $Directory.FullName -Recurse -Force
    }
}
$env:SENTINELCLIP_SOURCE_ROOT = $RepoRoot
& $EmbeddedPython -c "import encodings, flask, waitress, streamlit, pystray, os, sys; sys.path.insert(0, os.environ['SENTINELCLIP_SOURCE_ROOT']); import deployment_config"
if ($LASTEXITCODE -ne 0) {
    throw "The embedded runtime failed its import check."
}
Remove-Item Env:\SENTINELCLIP_SOURCE_ROOT

& $BuildPython -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --name SentinelClipNativeHost `
    --distpath $NativeHostDir `
    --workpath (Join-Path $RepoRoot "build\native-host") `
    --specpath (Join-Path $RepoRoot "build\native-host") `
    --hidden-import deployment_config `
(Join-Path $RepoRoot "native_host\native_host.py")
if ($LASTEXITCODE -ne 0) {
    throw "Could not package the native messaging host executable."
}

& $Compiler (Join-Path $PSScriptRoot "SentinelClip.iss")
if ($LASTEXITCODE -ne 0) {
    throw "Inno Setup failed to build the installer."
}

Write-Host "Offline installer created in $RepoRoot\dist\SentinelClip-Setup-Offline.exe" -ForegroundColor Green