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
    $OutputDirectory = Join-Path $root "publish\DataProtectorWebAdmin-$Platform-$Configuration"
}

$webRoot = Join-Path $root "DataProtectorWebAdmin"
$webDist = Join-Path $webRoot "dist"
$bridgeOutput = Join-Path $root "DataProtectorWebBridge\bin\$Platform\$Configuration"

Push-Location $root
try {
    & $msBuild ".\DataProtectorPolicyApi\DataProtectorPolicyApi.vcxproj" `
        /p:Configuration=$Configuration `
        /p:Platform=$Platform

    & $msBuild ".\DataProtectorWebBridge\DataProtectorWebBridge.csproj" `
        /p:Configuration=$Configuration `
        /p:Platform=$Platform

    Push-Location $webRoot
    try {
        & pnpm install --frozen-lockfile
        & pnpm build
    }
    finally {
        Pop-Location
    }

    if (-not (Test-Path -LiteralPath $webDist)) {
        throw "Web build output was not found: $webDist"
    }

    if (-not (Test-Path -LiteralPath $bridgeOutput)) {
        throw "Bridge build output was not found: $bridgeOutput"
    }

    if (Test-Path -LiteralPath $OutputDirectory) {
        $resolvedOutput = (Resolve-Path -LiteralPath $OutputDirectory).Path
        $resolvedRoot = (Resolve-Path -LiteralPath $root).Path
        if (-not $resolvedOutput.StartsWith($resolvedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to delete output outside the project root: $resolvedOutput"
        }

        Remove-Item -LiteralPath $OutputDirectory -Recurse -Force
    }

    $serverPublish = Join-Path $OutputDirectory "server"
    $agentPublish = Join-Path $OutputDirectory "agent"
    $staticOutput = Join-Path $serverPublish "web"
    New-Item -ItemType Directory -Force -Path $staticOutput, $serverPublish, $agentPublish | Out-Null

    Copy-Item -Path (Join-Path $webDist "*") -Destination $staticOutput -Recurse -Force

    $bridgeFiles = @(
        "DataProtectorWebBridge.exe",
        "DataProtectorWebBridge.exe.config",
        "DataProtectorPolicyApi.dll"
    )

    foreach ($file in $bridgeFiles) {
        $source = Join-Path $bridgeOutput $file
        if (Test-Path -LiteralPath $source) {
            Copy-Item -LiteralPath $source -Destination $serverPublish -Force
            Copy-Item -LiteralPath $source -Destination $agentPublish -Force
        }
    }

    $notes = @"
DataProtector Central Web Admin
===============================

Run the central server on the management machine:
server\DataProtectorWebBridge.exe server

Optional IP intelligence enrichment:
setx DATAPROTECTOR_IPINFO_TOKEN "<ipinfo-token>"

Open the web console:
http://<server-ip>:17643/

Run the endpoint agent on every protected client:
agent\DataProtectorWebBridge.exe agent http://<server-ip>:17643/ 15

Central state:
C:\ProgramData\DataProtector\CentralState.json

The central server listens on all server interfaces by default using the
HTTP.sys wildcard prefix http://+:17643/, which is the Windows equivalent of
binding to 0.0.0.0. It serves the web UI from server\web. Allow inbound TCP
17643 through Windows Firewall on the central server. Clients only need
outbound access to the server.

Legacy single-machine debugging:
server\DataProtectorWebBridge.exe standalone

During development use:
pnpm dev

Build:
- Configuration: $Configuration
- Platform: $Platform
- Published: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
"@

    Set-Content -LiteralPath (Join-Path $OutputDirectory "README.txt") -Value $notes -Encoding UTF8

    Write-Host "Published web admin package:"
    Write-Host $OutputDirectory
}
finally {
    Pop-Location
}
