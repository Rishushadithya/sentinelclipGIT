$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$AppRoot = Split-Path -Parent $PSScriptRoot
$ConfigDir = Join-Path $AppRoot "config"
$ConfigPath = Join-Path $ConfigDir "deployment.json"
$Python = Join-Path $AppRoot "runtime\python.exe"
$BootstrapScript = Join-Path $PSScriptRoot "bootstrap_server.py"

$LocalAddress = "127.0.0.1"
$Socket = New-Object System.Net.Sockets.UdpClient
try {
    $Socket.Connect("192.0.2.1", 80)
    $LocalAddress = $Socket.Client.LocalEndPoint.Address.IPAddressToString
} catch {
} finally {
    $Socket.Dispose()
}

$Form = New-Object System.Windows.Forms.Form
$Form.Text = "SentinelClip Setup"
$Form.StartPosition = "CenterScreen"
$Form.FormBorderStyle = "FixedDialog"
$Form.MaximizeBox = $false
$Form.MinimizeBox = $false
$Form.ClientSize = New-Object System.Drawing.Size(570, 270)

$Intro = New-Object System.Windows.Forms.Label
$Intro.Text = "Choose how this PC will run SentinelClip."
$Intro.Location = New-Object System.Drawing.Point(18, 16)
$Intro.Size = New-Object System.Drawing.Size(520, 24)
$Form.Controls.Add($Intro)

$RoleLabel = New-Object System.Windows.Forms.Label
$RoleLabel.Text = "PC role"
$RoleLabel.Location = New-Object System.Drawing.Point(18, 56)
$RoleLabel.Size = New-Object System.Drawing.Size(150, 24)
$Form.Controls.Add($RoleLabel)

$Role = New-Object System.Windows.Forms.ComboBox
$Role.DropDownStyle = "DropDownList"
[void]$Role.Items.AddRange(@("Server", "Agent", "Both"))
$Role.SelectedItem = "Server"
$Role.Location = New-Object System.Drawing.Point(190, 52)
$Role.Size = New-Object System.Drawing.Size(350, 28)
$Form.Controls.Add($Role)

$ServerLabel = New-Object System.Windows.Forms.Label
$ServerLabel.Text = "Server API URL"
$ServerLabel.Location = New-Object System.Drawing.Point(18, 100)
$ServerLabel.Size = New-Object System.Drawing.Size(150, 24)
$Form.Controls.Add($ServerLabel)

$ServerUrl = New-Object System.Windows.Forms.TextBox
$ServerUrl.Text = "http://${LocalAddress}:5000/api/v1"
$ServerUrl.Location = New-Object System.Drawing.Point(190, 96)
$ServerUrl.Size = New-Object System.Drawing.Size(350, 24)
$Form.Controls.Add($ServerUrl)

$CodeLabel = New-Object System.Windows.Forms.Label
$CodeLabel.Text = "Enrollment code"
$CodeLabel.Location = New-Object System.Drawing.Point(18, 140)
$CodeLabel.Size = New-Object System.Drawing.Size(150, 24)
$Form.Controls.Add($CodeLabel)

$Code = New-Object System.Windows.Forms.TextBox
$Code.Location = New-Object System.Drawing.Point(190, 136)
$Code.Size = New-Object System.Drawing.Size(350, 24)
$Form.Controls.Add($Code)

$Firewall = New-Object System.Windows.Forms.CheckBox
$Firewall.Text = "Allow TCP 5000 from this private LAN (administrator approval)"
$Firewall.Checked = $true
$Firewall.Location = New-Object System.Drawing.Point(18, 180)
$Firewall.Size = New-Object System.Drawing.Size(520, 24)
$Form.Controls.Add($Firewall)

$Finish = New-Object System.Windows.Forms.Button
$Finish.Text = "Finish Setup"
$Finish.Location = New-Object System.Drawing.Point(420, 220)
$Finish.Size = New-Object System.Drawing.Size(120, 30)
$Form.Controls.Add($Finish)
$Form.AcceptButton = $Finish

$UpdateRoleFields = {
    $IsAgent = $Role.SelectedItem -eq "Agent"
    $IsServer = $Role.SelectedItem -ne "Agent"
    $ServerLabel.Visible = $IsAgent
    $ServerUrl.Visible = $IsAgent
    $CodeLabel.Visible = $IsAgent
    $Code.Visible = $IsAgent
    $Firewall.Visible = $IsServer
}
$Role.add_SelectedIndexChanged($UpdateRoleFields)
& $UpdateRoleFields

$Finish.Add_Click({
    try {
        New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
        $SelectedRole = $Role.SelectedItem.ToString().ToLowerInvariant()
        $EnrollmentCode = ""
        if ($SelectedRole -eq "agent") {
            $ApiBase = $ServerUrl.Text.Trim().TrimEnd("/")
            if (-not $ApiBase.StartsWith("http://") -and -not $ApiBase.StartsWith("https://")) {
                throw "Enter a valid server API URL."
            }
            if ([string]::IsNullOrWhiteSpace($Code.Text)) {
                throw "Enter the one-time enrollment code from the server."
            }
            $Payload = @{
                code = $Code.Text.Trim()
                hostname = $env:COMPUTERNAME
                os_user = [Environment]::UserName
            } | ConvertTo-Json
            $Credentials = Invoke-RestMethod -Method Post -Uri "$ApiBase/devices/enroll" -ContentType "application/json" -Body $Payload -TimeoutSec 15
            Set-Content -Path (Join-Path $ConfigDir ".device_id") -Value $Credentials.device_id -Encoding ASCII
            Set-Content -Path (Join-Path $ConfigDir ".device_token") -Value $Credentials.device_token -Encoding ASCII
        } else {
            $ApiBase = "http://127.0.0.1:5000/api/v1"
            $BootstrapOutput = & $Python $BootstrapScript $SelectedRole
            if ($LASTEXITCODE -ne 0) {
                throw "Server initialization failed: $($BootstrapOutput -join ' ')"
            }
            $BootstrapResult = ($BootstrapOutput -join "`n") | ConvertFrom-Json
            $EnrollmentCode = $BootstrapResult.enrollment_code
        }

        $Settings = @{
            role = $SelectedRole
            api_base = $ApiBase
            api_host = if ($SelectedRole -in @("server", "both")) { "0.0.0.0" } else { "127.0.0.1" }
            api_port = 5000
            dashboard_host = "127.0.0.1"
            dashboard_port = 8501
        } | ConvertTo-Json
        $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($ConfigPath, $Settings + [Environment]::NewLine, $Utf8NoBom)

        if ($SelectedRole -in @("server", "both") -and $Firewall.Checked) {
            if (-not (Get-NetFirewallRule -DisplayName "SentinelClip API (Private LAN)" -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName "SentinelClip API (Private LAN)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5000 -RemoteAddress LocalSubnet -Profile Private | Out-Null
            }
        }

        if ($EnrollmentCode) {
            [Windows.Forms.Clipboard]::SetText($EnrollmentCode)
            $Message = "Server ready at http://${LocalAddress}:5000/api/v1`r`n`r`nOne-time enrollment code (expires in 10 minutes):`r`n$EnrollmentCode`r`n`r`nThe code was copied to the clipboard."
        } else {
            $Message = "Agent enrolled successfully. SentinelClip is configured for this PC."
        }
        [Windows.Forms.MessageBox]::Show($Form, $Message, "SentinelClip is configured", "OK", "Information") | Out-Null
        $Form.Close()
    } catch {
        [Windows.Forms.MessageBox]::Show($Form, $_.Exception.Message, "Setup failed", "OK", "Error") | Out-Null
    }
})

[void]$Form.ShowDialog()