$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$AppRoot = Split-Path -Parent $PSScriptRoot
$ManifestPath = Join-Path $AppRoot "native_host\com.sentinelclip.host.json"
$HostPath = Join-Path $AppRoot "native_host\SentinelClipNativeHost.exe"
$HostName = "com.sentinelclip.host"

$Form = New-Object System.Windows.Forms.Form
$Form.Text = "SentinelClip Browser Setup"
$Form.StartPosition = "CenterScreen"
$Form.FormBorderStyle = "FixedDialog"
$Form.MaximizeBox = $false
$Form.ClientSize = New-Object System.Drawing.Size(590, 250)

$Intro = New-Object System.Windows.Forms.Label
$Intro.Text = "Load the extension in Chrome or Edge, then enter the ID displayed on the extensions page."
$Intro.Location = New-Object System.Drawing.Point(18, 16)
$Intro.Size = New-Object System.Drawing.Size(550, 38)
$Form.Controls.Add($Intro)

$Folder = New-Object System.Windows.Forms.Label
$Folder.Text = "Extension folder: $AppRoot\browser_extension"
$Folder.Location = New-Object System.Drawing.Point(18, 58)
$Folder.Size = New-Object System.Drawing.Size(550, 24)
$Form.Controls.Add($Folder)

$ChromeLabel = New-Object System.Windows.Forms.Label
$ChromeLabel.Text = "Chrome extension ID"
$ChromeLabel.Location = New-Object System.Drawing.Point(18, 98)
$ChromeLabel.Size = New-Object System.Drawing.Size(160, 24)
$Form.Controls.Add($ChromeLabel)

$ChromeId = New-Object System.Windows.Forms.TextBox
$ChromeId.Location = New-Object System.Drawing.Point(190, 94)
$ChromeId.Size = New-Object System.Drawing.Size(378, 24)
$Form.Controls.Add($ChromeId)

$EdgeLabel = New-Object System.Windows.Forms.Label
$EdgeLabel.Text = "Edge extension ID"
$EdgeLabel.Location = New-Object System.Drawing.Point(18, 136)
$EdgeLabel.Size = New-Object System.Drawing.Size(160, 24)
$Form.Controls.Add($EdgeLabel)

$EdgeId = New-Object System.Windows.Forms.TextBox
$EdgeId.Location = New-Object System.Drawing.Point(190, 132)
$EdgeId.Size = New-Object System.Drawing.Size(378, 24)
$Form.Controls.Add($EdgeId)

$OpenChrome = New-Object System.Windows.Forms.Button
$OpenChrome.Text = "Open Chrome Extensions"
$OpenChrome.Location = New-Object System.Drawing.Point(18, 176)
$OpenChrome.Size = New-Object System.Drawing.Size(170, 30)
$OpenChrome.Add_Click({ Start-Process "chrome://extensions" })
$Form.Controls.Add($OpenChrome)

$OpenEdge = New-Object System.Windows.Forms.Button
$OpenEdge.Text = "Open Edge Extensions"
$OpenEdge.Location = New-Object System.Drawing.Point(198, 176)
$OpenEdge.Size = New-Object System.Drawing.Size(160, 30)
$OpenEdge.Add_Click({ Start-Process "edge://extensions" })
$Form.Controls.Add($OpenEdge)

$Register = New-Object System.Windows.Forms.Button
$Register.Text = "Register Native Host"
$Register.Location = New-Object System.Drawing.Point(408, 176)
$Register.Size = New-Object System.Drawing.Size(160, 30)
$Form.Controls.Add($Register)

$Register.Add_Click({
    try {
        $Ids = @{}
        if (-not [string]::IsNullOrWhiteSpace($ChromeId.Text)) { $Ids.Chrome = $ChromeId.Text.Trim() }
        if (-not [string]::IsNullOrWhiteSpace($EdgeId.Text)) { $Ids.Edge = $EdgeId.Text.Trim() }
        if ($Ids.Count -eq 0) { throw "Enter at least one browser extension ID." }
        foreach ($Entry in $Ids.GetEnumerator()) {
            if ($Entry.Value -notmatch '^[a-p]{32}$') {
                throw "The $($Entry.Key) ID must contain 32 letters from a to p."
            }
        }

        $Manifest = @{
            name = $HostName
            description = "SentinelClip native upload scanner"
            path = $HostPath
            type = "stdio"
            allowed_origins = @($Ids.Values | ForEach-Object { "chrome-extension://$_/" })
        } | ConvertTo-Json -Depth 4
        $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($ManifestPath, $Manifest + [Environment]::NewLine, $Utf8NoBom)

        if ($Ids.ContainsKey("Chrome")) {
            $ChromeKey = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName"
            New-Item -Path $ChromeKey -Force | Out-Null
            Set-Item -Path $ChromeKey -Value $ManifestPath
        }
        if ($Ids.ContainsKey("Edge")) {
            $EdgeKey = "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$HostName"
            New-Item -Path $EdgeKey -Force | Out-Null
            Set-Item -Path $EdgeKey -Value $ManifestPath
        }

        [Windows.Forms.MessageBox]::Show($Form, "Native messaging is registered. Restart the browser to apply it.", "Browser setup complete", "OK", "Information") | Out-Null
        $Form.Close()
    } catch {
        [Windows.Forms.MessageBox]::Show($Form, $_.Exception.Message, "Browser setup failed", "OK", "Error") | Out-Null
    }
})

[void]$Form.ShowDialog()