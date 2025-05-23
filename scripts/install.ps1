Param(
    [string]$Version = "latest"
)

$repo = "khaugen7/eks-security-scanner"
$binary = "eks-scanner"

# Detect architecture
$arch = if ([System.Environment]::Is64BitOperatingSystem) {
    if ([System.Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE") -eq "ARM64") {
        "arm64"
    } else {
        "amd64"
    }
} else {
    Write-Error "Only 64-bit Windows is supported"
    exit 1
}

# Determine version
if ($Version -eq "latest") {
    $latestRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest"
    $Version = $latestRelease.tag_name.TrimStart("v")
}

$filename = "$binary-windows-$arch"
$downloadUrl = "https://github.com/$repo/releases/download/v$Version/$filename"

# Target install directory
$installDir = "$env:USERPROFILE\bin"
$installPath = Join-Path $installDir "$binary.exe"

# Ensure directory exists
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir | Out-Null
}

# Download binary
Write-Host "Downloading $binary version $Version for Windows/$arch..."
Invoke-WebRequest -Uri $downloadUrl -OutFile $installPath

# Add installDir to PATH if not already present
$envPath = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::User)
if ($envPath -notlike "*$installDir*") {
    [System.Environment]::SetEnvironmentVariable("Path", "$envPath;$installDir", [System.EnvironmentVariableTarget]::User)
    Write-Host "`n🔄 Restart your terminal or log out and back in for PATH changes to take effect."
}

Write-Host "`n✅ Installed '$binary' to $installPath"
Write-Host "Run it using: `n  $binary --help"
