; Email Analyzer  |  Email Analyzer Project
; Builds Email-Analyzer-Setup-<version>.exe: a single file that unpacks itself and
; starts the branded setup window (setup\install.ps1), which does the real install.
; Build with Build-Setup.bat (needs Inno Setup 6, free from jrsoftware.org).

#define AppName "Email Analyzer"
#define AppVersion "2.3"
#define Publisher "Email Analyzer Project"
#define Unpack "{localappdata}\Temp\EmailAnalyzerSetup"
; Layout: this file and the program (Email-Analyzer\) are in Developer\; the finished
; Email-Analyzer-Setup-<version>.exe is written to ..\Install\, next to README.html
#define App "Email-Analyzer"

[Setup]
AppId={{A36902D3-2CFD-4238-9B6C-048186A889BD}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#Publisher}
AppVerName={#AppName} {#AppVersion}
VersionInfoCompany={#Publisher}
VersionInfoDescription={#AppName} setup
VersionInfoProductName={#AppName}
VersionInfoVersion={#AppVersion}.0.0
OutputDir=..\Install
OutputBaseFilename=Email-Analyzer-Setup-{#AppVersion}
SetupIconFile={#App}\qr_inspector.ico
WizardSmallImageFile=wizard_small_100.bmp,wizard_small_200.bmp
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
; per-user, no admin prompt
PrivilegesRequired=lowest
; only unpacks; the app's own setup window installs and handles uninstall
CreateAppDir=no
Uninstallable=no
DisableWelcomePage=yes
DisableReadyPage=yes
DisableFinishedPage=yes
DisableProgramGroupPage=yes
ShowLanguageDialog=no
SetupLogging=yes

[Messages]
SetupWindowTitle=Email Analyzer  |  {#AppName} setup
WizardInstalling=Unpacking
InstallingLabel=Unpacking {#AppName}. The setup window opens next.

[InstallDelete]
Type: filesandordirs; Name: "{#Unpack}"

[Files]
Source: "{#App}\*"; DestDir: "{#Unpack}"; Excludes: "tests\*,__pycache__\*,.venv\*,*.emailcheck.*"; Flags: recursesubdirs ignoreversion

[Run]
; nowait: this unpacker closes and the branded setup window takes over
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File ""{#Unpack}\setup\install.ps1"""; \
  WorkingDir: "{#Unpack}"; Flags: nowait runhidden
