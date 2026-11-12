# Downloads the libraries listed in requirements.txt into Email-Analyzer\offline\wheels, as Windows files
# for every supported Python (3.11-3.14), so the installer works without internet on any of them.
# Run by Build-Setup.bat when the wheels folder is empty. Needs internet and a Python on THIS PC.
# ASCII only on purpose (Windows PowerShell 5.1).
param([string]$AppDir, [string]$FindLinks = '')   # FindLinks: a local folder of wheels instead of PyPI (for testing)

$ErrorActionPreference = 'Stop'
$req = Join-Path $AppDir 'requirements.txt'
$out = Join-Path $AppDir 'offline\wheels'
New-Item -ItemType Directory -Force -Path $out | Out-Null

$py = $null
foreach ($c in @('py', 'python')) { if (Get-Command $c -ErrorAction SilentlyContinue) { $py = $c; break } }
if (-not $py) { throw 'No Python found on this PC. Install Python 3.11-3.14 from python.org, then run Build-Setup.bat again.' }

$source = @()
if ($FindLinks) { $source = @('--no-index', '--find-links', $FindLinks) }
foreach ($v in '3.11', '3.12', '3.13', '3.14') {
    Write-Host "  Libraries for Python $v..."
    & $py -m pip download --disable-pip-version-check -q -r $req -d $out --only-binary=:all: `
        --platform win_amd64 --python-version $v @source
    if ($LASTEXITCODE -ne 0) { throw "pip could not download the libraries for Python $v." }
}
$n = (Get-ChildItem $out -Filter *.whl).Count
Write-Host "  $n library files ready in $out" -ForegroundColor Green
