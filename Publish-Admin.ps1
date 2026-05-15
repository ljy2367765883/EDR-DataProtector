param(
    [ValidateSet("Release")]
    [string]$Configuration = "Release",

    [ValidateSet("x64")]
    [string]$Platform = "x64",

    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$msBuild = "D:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe"

if (-not (Test-Path -LiteralPath $msBuild)) {
    throw "VS2019 MSBuild was not found at: $msBuild"
}

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $root "publish\DataProtectorAdmin-$Platform-$Configuration"
}

$staging = Join-Path $root "DataProtectorAdmin\bin\$Platform\$Configuration"
$nativeApi = Join-Path $root "DataProtectorPolicyApi\$Platform\$Configuration\DataProtectorPolicyApi.dll"

Push-Location $root
try {
    & $msBuild ".\DataProtectorPolicyApi\DataProtectorPolicyApi.vcxproj" `
        /p:Configuration=$Configuration `
        /p:Platform=$Platform

    & $msBuild ".\DataProtectorAdmin\DataProtectorAdmin.csproj" `
        /p:Configuration=$Configuration `
        /p:Platform=$Platform

    if (-not (Test-Path -LiteralPath $staging)) {
        throw "Admin build output was not found: $staging"
    }

    if (Test-Path -LiteralPath $OutputDirectory) {
        $resolvedOutput = (Resolve-Path -LiteralPath $OutputDirectory).Path
        $resolvedRoot = (Resolve-Path -LiteralPath $root).Path
        if (-not $resolvedOutput.StartsWith($resolvedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to delete output outside the project root: $resolvedOutput"
        }

        Remove-Item -LiteralPath $OutputDirectory -Recurse -Force
    }

    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

    $adminFiles = @(
        "DataProtectorAdmin.exe",
        "DataProtectorAdmin.exe.config",
        "Wpf.Ui.dll"
    )

    foreach ($file in $adminFiles) {
        $source = Join-Path $staging $file
        if (-not (Test-Path -LiteralPath $source)) {
            throw "Required publish file is missing: $source"
        }

        Copy-Item -LiteralPath $source -Destination $OutputDirectory -Force
    }

    if (-not (Test-Path -LiteralPath $nativeApi)) {
        throw "Required publish file is missing: $nativeApi"
    }

    Copy-Item -LiteralPath $nativeApi -Destination $OutputDirectory -Force

    $notes = @"
DataProtector Admin
===================

Run DataProtectorAdmin.exe after the DataProtector minifilter driver package is installed and running.

Runtime requirements:
- Windows with .NET Framework 4.7.2 or newer installed. Windows 10 1803+ and Windows 11 normally satisfy this.
- x64 process environment.
- DataProtectorPolicyApi.dll must stay beside DataProtectorAdmin.exe.
- The driver communication port \DataProtectorPolicyPort must be available for policy operations.

Build:
- Configuration: $Configuration
- Platform: $Platform
- Published: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
"@

    Set-Content -LiteralPath (Join-Path $OutputDirectory "README.txt") -Value $notes -Encoding UTF8

    Write-Host "Published admin package:"
    Write-Host $OutputDirectory
}
finally {
    Pop-Location
}
