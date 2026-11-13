# Email Analyzer setup
# Graphical per-user installer. No admin rights needed.
# 1. Finds Python 3.11-3.14 with Tk; installs Python for this user if missing (bundled offline copy, or winget / python.org)
# 2. Copies the program to %LOCALAPPDATA%\Programs\Email Analyzer (keeps existing keys and bank list)
# 3. Builds a private Python environment and installs the libraries
# 4. Creates Desktop, Start Menu and Send to shortcuts and an Installed apps entry
# This file is ASCII only on purpose (Windows PowerShell 5.1 misreads UTF-8 without BOM).

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
try {   # hide this console now that the script has loaded; errors before this point stay visible
    Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class ConWin { [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow(); [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n); }'
    [void][ConWin]::ShowWindow([ConWin]::GetConsoleWindow(), 0)
} catch { }
try {   # sharp text on high-DPI laptop screens
    Add-Type -TypeDefinition 'using System.Runtime.InteropServices; public static class DpiFix { [DllImport("user32.dll")] public static extern bool SetProcessDPIAware(); }'
    [void][DpiFix]::SetProcessDPIAware()
} catch { }
[System.Windows.Forms.Application]::EnableVisualStyles()
# Scale every position by the screen's display scaling (125%, 150%...) so the layout stays intact
$gfx = [System.Drawing.Graphics]::FromHwnd([IntPtr]::Zero); $Scale = $gfx.DpiX / 96.0; $gfx.Dispose()
function Sz([double]$v) { [int][Math]::Round($v * $Scale) }

$AppName  = 'Email Analyzer'
$Version  = '2.3'
$Src      = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Dest     = Join-Path $env:LOCALAPPDATA "Programs\$AppName"
# Before v2.1 the tool was called "QR Link Inspector": its settings are carried over and the old copy removed
$OldName  = 'QR Link Inspector'
$OldDest  = Join-Path $env:LOCALAPPDATA "Programs\$OldName"
$PyMin    = 11   # supported Python 3.x minor versions (the pinned libraries exist for these)
$PyMax    = 14
$Offline  = Join-Path $Src 'offline'
$IsOffline = Test-Path (Join-Path $Offline 'wheels\*.whl')
$script:LastLog = ''
$script:Log = New-Object System.Text.StringBuilder

# ------------------------------------------------------------------ colours
$Navy   = [System.Drawing.Color]::FromArgb(0, 70, 128)
$Blue   = [System.Drawing.Color]::FromArgb(0, 138, 216)
$Mid    = [System.Drawing.Color]::FromArgb(0, 105, 177)
$Grey   = [System.Drawing.Color]::FromArgb(136, 139, 141)
$Ink    = [System.Drawing.Color]::FromArgb(24, 36, 52)
$Green  = [System.Drawing.Color]::FromArgb(36, 150, 90)
$Red    = [System.Drawing.Color]::FromArgb(205, 50, 55)
$GLYPH_WAIT = [string][char]0x25CB   # empty circle
$GLYPH_RUN  = [string][char]0x25CF   # filled circle
$GLYPH_OK   = [string][char]0x2714   # check mark
$GLYPH_FAIL = [string][char]0x2716   # cross

function New-Font([single]$size, [System.Drawing.FontStyle]$style = 'Regular', [string]$family = 'Segoe UI') {
    New-Object System.Drawing.Font($family, $size, $style)
}

# ------------------------------------------------------------------- window
$form = New-Object System.Windows.Forms.Form
$form.Text = "$AppName setup"
$form.ClientSize = New-Object System.Drawing.Size((Sz 600), (Sz 480))
$form.FormBorderStyle = 'FixedSingle'
$form.MaximizeBox = $false
$form.StartPosition = 'CenterScreen'
$form.BackColor = [System.Drawing.Color]::White
$form.Font = New-Font 9.5
$form.AutoScaleMode = 'None'
$icoPath = Join-Path $Src 'qr_inspector.ico'
if (Test-Path $icoPath) { $form.Icon = New-Object System.Drawing.Icon($icoPath) }

# header band with the app logo
$header = New-Object System.Windows.Forms.Panel
$header.SetBounds((Sz (0)), (Sz (0)), (Sz (600)), (Sz (96)))
$header.BackColor = $Navy
$form.Controls.Add($header)

$logoPath = Join-Path $Src 'logo.png'
if (Test-Path $logoPath) {
    $logo = New-Object System.Windows.Forms.PictureBox
    $logo.Image = [System.Drawing.Image]::FromFile($logoPath)
    $logo.SizeMode = 'Zoom'
    $logo.BackColor = $Navy
    $logo.SetBounds((Sz (28)), (Sz (26)), (Sz (44)), (Sz (44)))
    $header.Controls.Add($logo)
}
$hdrTitle = New-Object System.Windows.Forms.Label
$hdrTitle.Text = $AppName
$hdrTitle.ForeColor = [System.Drawing.Color]::White
$hdrTitle.BackColor = $Navy
$hdrTitle.Font = New-Font 14 'Bold'
$hdrTitle.TextAlign = 'MiddleRight'
$hdrTitle.SetBounds((Sz (290)), (Sz (24)), (Sz (284)), (Sz (28)))
$header.Controls.Add($hdrTitle)
$hdrSub = New-Object System.Windows.Forms.Label
$hdrSub.Text = "Cybersecurity Tool  |  setup v$Version"
$hdrSub.ForeColor = [System.Drawing.Color]::FromArgb(169, 198, 227)
$hdrSub.BackColor = $Navy
$hdrSub.Font = New-Font 9
$hdrSub.TextAlign = 'MiddleRight'
$hdrSub.SetBounds((Sz (290)), (Sz (52)), (Sz (284)), (Sz (20)))
$header.Controls.Add($hdrSub)
$accent = New-Object System.Windows.Forms.Panel
$accent.SetBounds((Sz (0)), (Sz (96)), (Sz (600)), (Sz (4)))
$accent.BackColor = $Blue
$form.Controls.Add($accent)

$title = New-Object System.Windows.Forms.Label
$title.Text = 'Install Email Analyzer'
$title.Font = New-Font 15 'Bold'
$title.ForeColor = $Ink
$title.SetBounds((Sz (30)), (Sz (120)), (Sz (540)), (Sz (32)))
$form.Controls.Add($title)
$intro = New-Object System.Windows.Forms.Label
$needNet = $(if (Test-Path (Join-Path $Src 'offline\wheels\*.whl')) { 'Works without internet.' } else { 'Needs internet.' })
$intro.Text = "Checks suspicious emails, attachments and links without opening them.`n" +
              "Installs for $env:USERNAME only. No admin rights needed. Takes a few minutes. $needNet"
$intro.ForeColor = $Grey
$intro.SetBounds((Sz (30)), (Sz (154)), (Sz (540)), (Sz (62)))   # 3 lines: long user names wrap (2.3)
$form.Controls.Add($intro)

# step list
$stepNames = @('Check for Python (install it if missing)', 'Copy the program files',
               'Prepare the program and its libraries', 'Create shortcuts', 'Finish')
$stepGlyphs = @(); $stepLabels = @()
for ($i = 0; $i -lt $stepNames.Count; $i++) {
    $y = 220 + $i * 28
    $g = New-Object System.Windows.Forms.Label
    $g.Text = $GLYPH_WAIT; $g.Font = New-Font 11 'Regular' 'Segoe UI Symbol'; $g.ForeColor = $Grey
    $g.SetBounds((Sz (32)), (Sz ($y)), (Sz (24)), (Sz (24))); $form.Controls.Add($g); $stepGlyphs += $g
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $stepNames[$i]; $l.ForeColor = $Ink; $l.Font = New-Font 10
    $l.SetBounds((Sz (60)), (Sz ($y + 1)), (Sz (500)), (Sz (24))); $form.Controls.Add($l); $stepLabels += $l
}

$bar = New-Object System.Windows.Forms.ProgressBar
$bar.SetBounds((Sz (30)), (Sz (366)), (Sz (540)), (Sz (8)))
$bar.Style = 'Continuous'
$bar.Minimum = 0; $bar.Maximum = 100; $bar.Value = 0
$form.Controls.Add($bar)
$status = New-Object System.Windows.Forms.Label
$status.Text = 'Ready to install.'
$status.ForeColor = $Grey
$status.SetBounds((Sz (30)), (Sz (380)), (Sz (540)), (Sz (22)))
$form.Controls.Add($status)

$btnMain = New-Object System.Windows.Forms.Button
$btnMain.Text = 'Install'
$btnMain.SetBounds((Sz (440)), (Sz (418)), (Sz (130)), (Sz (34)))
$btnMain.FlatStyle = 'Flat'
$btnMain.FlatAppearance.BorderSize = 0
$btnMain.BackColor = $Blue
$btnMain.ForeColor = [System.Drawing.Color]::White
$btnMain.Font = New-Font 10 'Bold'
$form.Controls.Add($btnMain)
$btnClose = New-Object System.Windows.Forms.Button
$btnClose.Text = 'Cancel'
$btnClose.SetBounds((Sz (330)), (Sz (418)), (Sz (100)), (Sz (34)))
$btnClose.FlatStyle = 'Flat'
$btnClose.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(200, 208, 218)
$btnClose.ForeColor = $Ink
$form.Controls.Add($btnClose)
$btnLog = New-Object System.Windows.Forms.LinkLabel
$btnLog.Text = 'Show details'
$btnLog.LinkColor = $Mid
$btnLog.SetBounds((Sz (30)), (Sz (426)), (Sz (120)), (Sz (22)))
$btnLog.Visible = $false
$form.Controls.Add($btnLog)

# A button must look switched off while it is (2.3). A flat blue button keeps its blue when disabled,
# so 'Install' looked clickable during the installation itself.
$OffBack = [System.Drawing.Color]::FromArgb(225, 230, 236)
$OffText = [System.Drawing.Color]::FromArgb(150, 158, 168)
function Paint-Buttons {
    if ($btnMain.Enabled) { $btnMain.BackColor = $Blue; $btnMain.ForeColor = [System.Drawing.Color]::White; $btnMain.Cursor = 'Hand' }
    else { $btnMain.BackColor = $OffBack; $btnMain.ForeColor = $OffText; $btnMain.Cursor = 'Default' }
    if ($btnClose.Enabled) { $btnClose.ForeColor = $Ink; $btnClose.Cursor = 'Hand' }
    else { $btnClose.ForeColor = $OffText; $btnClose.Cursor = 'Default' }
}
$btnMain.Add_EnabledChanged({ Paint-Buttons })
$btnClose.Add_EnabledChanged({ Paint-Buttons })
Paint-Buttons

# ------------------------------------------------------------------ helpers
function Pump { [System.Windows.Forms.Application]::DoEvents() }
function Say([string]$text) { $status.Text = $text; [void]$script:Log.AppendLine($text); Pump }
function Set-Step([int]$i, [string]$state) {
    switch ($state) {
        'run'  { $stepGlyphs[$i].Text = $GLYPH_RUN;  $stepGlyphs[$i].ForeColor = $Blue;  $stepLabels[$i].Font = New-Font 10 'Bold' }
        'ok'   { $stepGlyphs[$i].Text = $GLYPH_OK;   $stepGlyphs[$i].ForeColor = $Green; $stepLabels[$i].Font = New-Font 10 }
        'fail' { $stepGlyphs[$i].Text = $GLYPH_FAIL; $stepGlyphs[$i].ForeColor = $Red;   $stepLabels[$i].Font = New-Font 10 'Bold' }
    }
    Pump
}
function Set-Bar([int]$v) { $bar.Value = [Math]::Max(0, [Math]::Min(100, $v)); Pump }

# Cancel during the installation (2.3): setup stops at the next safe point, between steps. Stopping in the
# middle of a step (Python's own installer, pip) could leave a broken Python or library folder behind.
$script:Busy = $false
$script:CancelAsked = $false
function Check-Cancel { Pump; if ($script:CancelAsked) { throw 'setup-cancelled' } }
function Ask-Cancel {
    if ($script:CancelAsked) { return }
    $answer = [System.Windows.Forms.MessageBox]::Show($form,
        "Stop the setup?`n`nSetup stops as soon as the current step is finished. It cannot stop in the middle " +
        "of a step (for example while Python or the libraries are being installed), so this can take a minute.`n`n" +
        "Steps already done are kept. Run setup again any time to finish.",
        "$AppName setup", 'YesNo', 'Question')
    if ($answer -eq 'Yes' -and $script:Busy) {
        $script:CancelAsked = $true
        $btnClose.Text = 'Stopping...'; $btnClose.Enabled = $false
        $status.Text = 'Stopping after the current step...'
    }
}

# Runs a program hidden while keeping the window responsive. Returns the exit code.
function Run-Wait([string]$exe, [string]$argLine) {
    $out = [IO.Path]::GetTempFileName(); $err = [IO.Path]::GetTempFileName()
    try {
        $p = Start-Process -FilePath $exe -ArgumentList $argLine -WindowStyle Hidden -PassThru `
             -RedirectStandardOutput $out -RedirectStandardError $err
        $null = $p.Handle   # makes ExitCode reliable
        while (-not $p.HasExited) { Pump; Start-Sleep -Milliseconds 80 }
        $p.WaitForExit()
        $code = $p.ExitCode
    } catch {
        $script:LastLog = $_.Exception.Message
        [void]$script:Log.AppendLine($script:LastLog)
        return 9999
    }
    $script:LastLog = ((Get-Content $out -Raw -ErrorAction SilentlyContinue) + "`n" +
                       (Get-Content $err -Raw -ErrorAction SilentlyContinue)).Trim()
    [void]$script:Log.AppendLine("> $exe $argLine  (exit $code)")
    if ($script:LastLog) { [void]$script:Log.AppendLine($script:LastLog) }
    Remove-Item $out, $err -ErrorAction SilentlyContinue
    return $code
}

function Test-Python([string]$exe, [string[]]$pre) {
    # returns the interpreter path if it is Python 3.11 to 3.14 with Tk (needed for the window)
    try {
        $out = & $exe @pre -c "import sys, tkinter; print(sys.executable); print(sys.version_info[1] if sys.version_info[0] == 3 else 0)" 2>&1 |
            Where-Object { $_ -is [string] }
        if ($LASTEXITCODE -eq 0 -and $out) {
            $minor = [int]($out | Select-Object -Last 1)
            if ($minor -ge $PyMin -and $minor -le $PyMax) { return ($out | Select-Object -First 1) }
        }
    } catch { }
    return $null
}

function Find-Python {
    $tries = @()
    $versions = $PyMax..$PyMin
    foreach ($launcher in @('py', "$env:LOCALAPPDATA\Programs\Python\Launcher\py.exe", "$env:WINDIR\py.exe")) {
        if (Get-Command $launcher -ErrorAction SilentlyContinue) {
            foreach ($v in $versions) { $tries += ,@($launcher, "-3.$v") }
        }
    }
    foreach ($v in $versions) {
        foreach ($root in @("$env:LOCALAPPDATA\Programs\Python", "$env:ProgramFiles", "${env:ProgramFiles(x86)}")) {
            $p = Join-Path $root "Python3$v\python.exe"
            if (Test-Path $p) { $tries += ,@($p, '') }
        }
    }
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -notlike '*WindowsApps*') { $tries += ,@($cmd.Source, '') }
    foreach ($t in $tries) {
        $pre = @(); if ($t[1]) { $pre = @($t[1]) }
        $found = Test-Python $t[0] $pre
        Pump
        if ($found) { return $found }
    }
    return $null
}

function Get-LatestPythonUrl {
    # newest Python 3.14 Windows installer on python.org (3.13 no longer ships installers)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $base = 'https://www.python.org/ftp/python/'
    $listing = (Invoke-WebRequest -Uri $base -UseBasicParsing).Content
    $patches = [regex]::Matches($listing, '3\.14\.(\d+)/') | ForEach-Object { [int]$_.Groups[1].Value } |
               Sort-Object -Unique -Descending
    foreach ($p in $patches) {
        $url = "${base}3.14.$p/python-3.14.$p-amd64.exe"
        try { if ((Invoke-WebRequest -Uri $url -Method Head -UseBasicParsing).StatusCode -eq 200) { return $url } } catch { }
        Pump
    }
    throw 'No Python 3.14 Windows installer found on python.org.'
}

function Test-PsfSignature([string]$path) {
    $sig = Get-AuthenticodeSignature $path
    return ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -like '*Python Software Foundation*')
}

function Download-File([string]$url, [string]$path) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add('User-Agent', 'EmailAnalyzerSetup')
    try {
        $task = $wc.DownloadFileTaskAsync([Uri]$url, $path)
        while (-not $task.IsCompleted) {
            Pump; Start-Sleep -Milliseconds 120
            if (Test-Path $path) {
                $mb = [Math]::Round((Get-Item $path).Length / 1MB, 1)
                $status.Text = "Downloading Python from python.org... $mb MB"
            }
        }
        if ($task.IsFaulted) { throw $task.Exception.InnerException }
    } finally { $wc.Dispose() }
}

function Fail([int]$step, [string]$text) {
    Set-Step $step 'fail'
    $status.ForeColor = $Red
    $status.Text = 'Setup stopped. See the message for what to do.'
    [void]$script:Log.AppendLine("FAILED: $text")
    $btnLog.Visible = $true
    $btnClose.Text = 'Close'; $btnClose.Enabled = $true
    $btnMain.Text = 'Try again'; $btnMain.Enabled = $true
    [System.Windows.Forms.MessageBox]::Show($form, $text, "$AppName setup", 'OK', 'Error') | Out-Null
    throw 'setup-failed'
}

# --------------------------------------------------------------- the steps
function Do-Install {
    # 1 Python
    Set-Step 0 'run'; Set-Bar 4; Say 'Looking for Python...'
    $py = Find-Python
    $pyArgs = '/quiet InstallAllUsers=0 PrependPath=1 Include_tcltk=1 Include_launcher=1 Include_test=0'
    if (-not $py -and $IsOffline) {
        $bundled = Join-Path $Offline 'python-installer.exe'
        if (-not (Test-Path $bundled)) {
            Fail 0 'This offline installer is missing its bundled Python. Rebuild it with Build-Setup.bat.'
        }
        if (-not (Test-PsfSignature $bundled)) {
            Fail 0 'The bundled Python is not signed by the Python Software Foundation, so it was not run. Rebuild the installer.'
        }
        Say 'Installing the bundled Python for this user (no internet needed), this takes a few minutes...'
        Run-Wait $bundled $pyArgs | Out-Null
        $py = Find-Python
        if (-not $py) { Fail 0 "The bundled Python did not install.`n`n$script:LastLog" }
    }
    if (-not $py) {
        Say 'Python not found. Installing Python 3.14 for this user...'
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Say 'Installing Python with winget, this can take a few minutes...'
            Run-Wait 'winget' 'install --id Python.Python.3.14 -e --scope user --silent --accept-package-agreements --accept-source-agreements --disable-interactivity' | Out-Null
            $py = Find-Python
        }
        if (-not $py) {
            $tmp = Join-Path $env:TEMP 'python-3.14-installer.exe'
            try { Download-File (Get-LatestPythonUrl) $tmp }
            catch { Fail 0 "Could not download Python ($($_.Exception.Message)). Check the internet connection, or use the offline installer (Email-Analyzer-Setup.exe), then run setup again." }
            if (-not (Test-PsfSignature $tmp)) {
                Remove-Item $tmp -Force -ErrorAction SilentlyContinue
                Fail 0 'The Python download did not carry a valid Python Software Foundation signature, so it was not run. Nothing was installed.'
            }
            Say 'Installing Python 3.14, this can take a few minutes...'
            Run-Wait $tmp $pyArgs | Out-Null
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            $py = Find-Python
        }
        if (-not $py) {
            Fail 0 "Python could not be installed automatically (a proxy or company policy may have blocked it). Use the offline installer, or install Python 3.14 from python.org with 'Add python.exe to PATH' ticked, then run setup again."
        }
    }
    Say "Using $py"
    Set-Step 0 'ok'; Set-Bar 20
    Check-Cancel

    # 2 Copy files
    Set-Step 1 'run'; Say "Copying files to $Dest..."
    if (-not (Test-Path (Join-Path $Src 'qr_gui.pyw'))) {
        Fail 1 'The program files were not found next to Install.bat. Extract the whole zip to a folder first, then run Install.bat from that folder.'
    }
    try { New-Item -ItemType Directory -Force -Path (Join-Path $Dest 'setup') -ErrorAction Stop | Out-Null }
    catch { Fail 1 "Could not create $Dest. $($_.Exception.Message)" }
    $files = 'qr_check.py', 'qr_gui.pyw', 'report.py', 'inspectors.py', 'office_check.py', 'web_check.py',
             'email_check.py', 'domain_watch.py', 'appconfig.py', 'i18n.py', 'outlook_grab.py',
             'requirements.txt', 'README.txt', 'README-EL.txt', 'qr_inspector.ico',
             'qr_inspector.png', 'logo.png', 'll_mark.png',
             'Check-Email.bat', 'Check-Email-Offline.bat', 'Uninstall.bat'
    foreach ($f in $files) {
        $from = Join-Path $Src $f
        if (Test-Path $from) {
            try { Copy-Item $from -Destination $Dest -Force -ErrorAction Stop }
            catch { Fail 1 "Could not copy $f. Close Email Analyzer if it is open, then click Try again." }
        }
    }
    Copy-Item (Join-Path $Src 'setup\uninstall.ps1') -Destination (Join-Path $Dest 'setup') -Force
    foreach ($keep in 'banks.txt', 'keys.txt', 'watch_domains.txt', 'config.txt') {
        $target = Join-Path $Dest $keep
        $old = Join-Path $OldDest $keep
        if (-not (Test-Path $target) -and (Test-Path $old)) {
            Copy-Item $old -Destination $Dest -Force -ErrorAction SilentlyContinue
            if (Test-Path $target) { Say "Brought over $keep from $OldName" }
        }
        if (Test-Path $target) { Say "Kept your existing $keep" }
        elseif (Test-Path (Join-Path $Src $keep)) { Copy-Item (Join-Path $Src $keep) -Destination $Dest -Force }
    }
    Get-ChildItem $Dest -Recurse -File | Unblock-File -ErrorAction SilentlyContinue
    Set-Step 1 'ok'; Set-Bar 30
    Check-Cancel

    # 3 Environment and libraries
    Set-Step 2 'run'
    $venvDir = Join-Path $Dest '.venv'
    $venvPy = Join-Path $venvDir 'Scripts\python.exe'
    # an environment left over from an unsupported Python version is rebuilt
    if ((Test-Path $venvPy) -and -not (Test-Python $venvPy @())) {
        Say 'Rebuilding the program environment for the supported Python version...'
        Remove-Item $venvDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (-not (Test-Path $venvPy)) {
        Say 'Creating the program environment...'
        if ((Run-Wait $py "-m venv `"$venvDir`"") -ne 0) { Fail 2 "Could not create the program environment.`n`n$script:LastLog" }
    }
    $req = Join-Path $Dest 'requirements.txt'
    if ($IsOffline) {
        Set-Bar 45; Say 'Installing libraries from the installer (no internet needed)...'
        $wheels = Join-Path $Offline 'wheels'
        $pipArgs = "-m pip install --disable-pip-version-check -q --no-index --find-links `"$wheels`" --upgrade -r `"$req`""
        $failMsg = 'Could not install the bundled libraries. The installer may be damaged: rebuild it or contact ICT.'
    } else {
        Set-Bar 40; Say 'Downloading libraries (about 50 MB), this can take a few minutes...'
        Run-Wait $venvPy '-m pip install --disable-pip-version-check -q --upgrade pip' | Out-Null
        Set-Bar 50
        $pipArgs = "-m pip install --disable-pip-version-check -q --upgrade -r `"$req`""
        $failMsg = "Could not download the program's libraries. Check the internet connection or proxy, or use the offline installer, then click Try again."
    }
    if ((Run-Wait $venvPy $pipArgs) -ne 0) {
        $tail = ($script:LastLog -split "`n" | Select-Object -Last 6) -join "`n"
        Fail 2 "$failMsg`n`n$tail"
    }
    Set-Bar 85; Say 'Checking the libraries...'
    if ((Run-Wait $venvPy '-c "import customtkinter, tkinterdnd2, pymupdf, zxingcpp, tldextract, olefile, pycdlib, dns.resolver"') -ne 0) {
        Fail 2 "The libraries installed but could not be loaded. Contact ICT.`n`n$script:LastLog"
    }
    Set-Step 2 'ok'; Set-Bar 90
    Check-Cancel

    # 4 Shortcuts and Installed apps entry
    Set-Step 3 'run'; Say 'Creating shortcuts...'
    $pythonw = Join-Path $venvDir 'Scripts\pythonw.exe'
    $gui = Join-Path $Dest 'qr_gui.pyw'
    $ws = New-Object -ComObject WScript.Shell
    foreach ($folder in 'Desktop', 'Programs', 'SendTo') {
        $s = $ws.CreateShortcut((Join-Path ([Environment]::GetFolderPath($folder)) "$AppName.lnk"))
        $s.TargetPath = $pythonw
        $s.Arguments = '"' + $gui + '"'
        $s.WorkingDirectory = $Dest
        $s.IconLocation = (Join-Path $Dest 'qr_inspector.ico') + ',0'
        $s.Description = 'Check suspicious emails, attachments and links'
        $s.Save()
    }
    $reg = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\EmailAnalyzer'
    New-Item -Path $reg -Force | Out-Null
    $props = @{
        DisplayName = $AppName; DisplayVersion = $Version; Publisher = 'Email Analyzer Project'
        DisplayIcon = (Join-Path $Dest 'qr_inspector.ico'); InstallLocation = $Dest
        UninstallString = '"' + (Join-Path $Dest 'Uninstall.bat') + '"'
    }
    foreach ($k in $props.Keys) { Set-ItemProperty -Path $reg -Name $k -Value $props[$k] }
    Set-ItemProperty -Path $reg -Name NoModify -Value 1 -Type DWord
    Set-ItemProperty -Path $reg -Name NoRepair -Value 1 -Type DWord
    # remove the copy installed under the old name (settings were carried over above)
    if (Test-Path $OldDest) {
        Say "Removing the old $OldName..."
        Get-Process pythonw -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$OldDest*" } | Stop-Process -Force -ErrorAction SilentlyContinue
        foreach ($folder in 'Desktop', 'Programs', 'SendTo') {
            Remove-Item (Join-Path ([Environment]::GetFolderPath($folder)) "$OldName.lnk") -Force -ErrorAction SilentlyContinue
        }
        Remove-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\QRLinkInspector' -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item $OldDest -Recurse -Force -ErrorAction SilentlyContinue
    }
    Set-Step 3 'ok'; Set-Bar 96

    # 5 Done
    Set-Step 4 'ok'; Set-Bar 100
    $status.ForeColor = $Green
    $status.Text = 'Installed. Find it on the Desktop, in the Start Menu, or right-click a PDF > Send to.'
    $title.Text = 'Email Analyzer is ready'
    $script:Installed = @{ Pythonw = $pythonw; Gui = $gui }
}

# ------------------------------------------------------------------ wiring
$script:Installed = $null
$btnMain.Add_Click({
    if ($script:Busy) { return }        # a second click while working does nothing
    if ($script:Installed) {
        $script:Busy = $true; $btnMain.Enabled = $false     # start the app once, not once per click
        Start-Process -FilePath $script:Installed.Pythonw -ArgumentList ('"' + $script:Installed.Gui + '"') -WorkingDirectory $Dest
        $form.Close(); return
    }
    $script:Busy = $true; $script:CancelAsked = $false
    # while installing only Cancel can be used
    $btnMain.Enabled = $false; $btnLog.Visible = $false
    $btnClose.Text = 'Cancel'; $btnClose.Enabled = $true
    $status.ForeColor = $Grey
    for ($i = 0; $i -lt $stepGlyphs.Count; $i++) {
        $stepGlyphs[$i].Text = $GLYPH_WAIT; $stepGlyphs[$i].ForeColor = $Grey; $stepLabels[$i].Font = New-Font 10
    }
    try {
        Do-Install
        $btnMain.Text = 'Open Email Analyzer'
        $btnMain.SetBounds((Sz (370)), (Sz (418)), (Sz (200)), (Sz (34)))
        $btnMain.Enabled = $true
        $btnClose.Text = 'Close'; $btnClose.SetBounds((Sz (260)), (Sz (418)), (Sz (100)), (Sz (34))); $btnClose.Enabled = $true
    } catch {
        if ("$_" -eq 'setup-cancelled') {
            [void]$script:Log.AppendLine('Cancelled by the user.')
            $status.ForeColor = $Grey
            $status.Text = 'Setup cancelled. Steps already done are kept: run setup again any time to finish.'
            $btnMain.Text = 'Install'; $btnMain.Enabled = $true
            $btnClose.Text = 'Close'; $btnClose.Enabled = $true
        } elseif ("$_" -ne 'setup-failed') {
            $btnClose.Text = 'Close'; $btnClose.Enabled = $true; $btnMain.Enabled = $true; $btnMain.Text = 'Try again'; $btnLog.Visible = $true
            [void]$script:Log.AppendLine("Unexpected error: $_")
            $status.ForeColor = $Red; $status.Text = "Setup stopped: $_"
        }
    } finally {
        $script:Busy = $false
    }
})
$btnClose.Add_Click({ if ($script:Busy) { Ask-Cancel } else { $form.Close() } })
$btnLog.Add_LinkClicked({
    $logFile = Join-Path $env:TEMP 'EmailAnalyzer-setup.log'
    $script:Log.ToString() | Set-Content -Path $logFile -Encoding UTF8
    Start-Process notepad.exe $logFile
})
# the window's X while installing works like Cancel: ask, then stop at the next safe point
$form.Add_FormClosing({ param($s, $e) if ($script:Busy -and -not $script:Installed) { $e.Cancel = $true; Ask-Cancel } })

try {
    [void]$form.ShowDialog()
    # Tidy up when we were started from Email-Analyzer-Setup.exe (unpacked into Temp)
    if ($Src -like '*\Temp\EmailAnalyzerSetup*') {
        # run from TEMP, not from inside the folder: Windows will not remove the folder a process is in (2.3)
        Start-Process cmd.exe -ArgumentList "/c timeout /t 3 /nobreak >nul & rmdir /s /q `"$Src`"" -WindowStyle Hidden -WorkingDirectory $env:TEMP
    }
} catch {
    [void][ConWin]::ShowWindow([ConWin]::GetConsoleWindow(), 5)
    Write-Host "Setup error: $_" -ForegroundColor Red
    exit 1
}
