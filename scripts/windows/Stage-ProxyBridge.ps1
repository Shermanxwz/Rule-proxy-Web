# Stage a pinned upstream installer without running it or changing the host.
# This is an acceptance candidate, not an installation of a protected backend.
param([string]$Destination = (Join-Path $PSScriptRoot '..\..\bin\windows-candidate'))

$ErrorActionPreference = 'Stop'
$version = '4.1.1'
$name = "ProxyBridge-Setup-$version.exe"
$expected = '754f45fb31f3953b9b81005090f9a479f89827adb628cf2c76bc4139f673a152'
$url = "https://github.com/InterceptSuite/ProxyBridge/releases/download/v$version/$name"
$folder = [System.IO.Path]::GetFullPath($Destination)
New-Item -ItemType Directory -Path $folder -Force | Out-Null
$target = Join-Path $folder $name
$partial = "$target.partial"
try {
    if (-not (Test-Path -LiteralPath $target) -or
        (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) {
        Invoke-WebRequest -Uri $url -OutFile $partial
        $actual = (Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $expected) { throw "ProxyBridge download hash mismatch: $actual" }
        Move-Item -LiteralPath $partial -Destination $target -Force
    }
    Write-Output "Staged $target (SHA256 $expected). No installer or driver was run."
} finally {
    Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
}
