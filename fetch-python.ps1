# Downloads the newest Python 3.14 Windows installer from python.org for the OFFLINE setup,
# and checks it is signed by the Python Software Foundation. Run by Build-Setup.bat.
# ASCII only on purpose (Windows PowerShell 5.1).
param([string]$OutDir)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Series = '3.14'
$Base = 'https://www.python.org/ftp/python/'

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$target = Join-Path $OutDir 'python-installer.exe'

Write-Host "  Looking up the newest Python $Series release on python.org..."
$listing = (Invoke-WebRequest -Uri $Base -UseBasicParsing).Content
$patches = [regex]::Matches($listing, [regex]::Escape($Series) + '\.(\d+)/') |
           ForEach-Object { [int]$_.Groups[1].Value } | Sort-Object -Unique -Descending
if (-not $patches) { throw "No Python $Series releases found on python.org." }

$version = $null
foreach ($p in $patches) {
    $v = "$Series.$p"
    $url = "$Base$v/python-$v-amd64.exe"
    try {
        $head = Invoke-WebRequest -Uri $url -Method Head -UseBasicParsing
        if ($head.StatusCode -eq 200) { $version = $v; break }
    } catch { }   # this release has no Windows installer, try the previous one
}
if (-not $version) { throw "No Windows installer found for Python $Series." }

Write-Host "  Downloading Python $version (about 28 MB)..."
# Downloaded under a temporary name and only renamed once the signature is verified, so a failed or
# interrupted check never leaves an unverified python-installer.exe for the next build to use.
$partial = "$target.unverified"
Remove-Item $partial, $target -Force -ErrorAction SilentlyContinue
try {
    Invoke-WebRequest -Uri "$Base$version/python-$version-amd64.exe" -OutFile $partial -UseBasicParsing
    $sig = Get-AuthenticodeSignature $partial
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notlike '*Python Software Foundation*') {
        throw 'The download is not signed by the Python Software Foundation. It was deleted.'
    }
    Move-Item $partial $target
} finally {
    Remove-Item $partial -Force -ErrorAction SilentlyContinue
}
Set-Content -Path (Join-Path $OutDir 'python-version.txt') -Value $version -Encoding ASCII
Write-Host "  Python $version downloaded and signature verified." -ForegroundColor Green
