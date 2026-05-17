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
$driverPackage = Join-Path $root "DataProtector\$Platform\$Configuration\DataProtector"
$driverCertificate = Join-Path $root "DataProtector\$Platform\$Configuration\DataProtector.cer"
$usbCryptDriverPackage = Join-Path $root "DataProtectorUsbCrypt\$Platform\$Configuration\DataProtectorUsbCrypt"
$usbCryptDriverCertificate = Join-Path $root "DataProtectorUsbCrypt\$Platform\$Configuration\DataProtectorUsbCrypt.cer"
$usbToolOutput = Join-Path $root "DataProtectorUsbTool\$Platform\$Configuration\DataProtectorUsbTool.exe"

Push-Location $root
try {
    & $msBuild ".\DataProtector\DataProtector.vcxproj" `
        /p:Configuration=$Configuration `
        /p:Platform=$Platform

    & $msBuild ".\DataProtectorPolicyApi\DataProtectorPolicyApi.vcxproj" `
        /p:Configuration=$Configuration `
        /p:Platform=$Platform

    & $msBuild ".\DataProtectorUsbCrypt\DataProtectorUsbCrypt.vcxproj" `
        /p:Configuration=$Configuration `
        /p:Platform=$Platform

    & $msBuild ".\DataProtectorUsbTool\DataProtectorUsbTool.vcxproj" `
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

    if (-not (Test-Path -LiteralPath $driverPackage)) {
        throw "Driver package output was not found: $driverPackage"
    }

    if (-not (Test-Path -LiteralPath $usbCryptDriverPackage)) {
        throw "USB crypt driver package output was not found: $usbCryptDriverPackage"
    }

    if (-not (Test-Path -LiteralPath $usbToolOutput)) {
        throw "USB crypt tool output was not found: $usbToolOutput"
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
    $agentDriverPublish = Join-Path $agentPublish "driver"
    $agentUsbDriverPublish = Join-Path $agentPublish "usbcrypt-driver"
    $agentUsbToolPublish = Join-Path $agentPublish "usb-tool"
    $staticOutput = Join-Path $serverPublish "web"
    New-Item -ItemType Directory -Force -Path $staticOutput, $serverPublish, $agentPublish, $agentDriverPublish, $agentUsbDriverPublish, $agentUsbToolPublish | Out-Null

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

    Copy-Item -Path (Join-Path $driverPackage "*") -Destination $agentDriverPublish -Recurse -Force
    if (Test-Path -LiteralPath $driverCertificate) {
        Copy-Item -LiteralPath $driverCertificate -Destination $agentDriverPublish -Force
    }

    Copy-Item -Path (Join-Path $usbCryptDriverPackage "*") -Destination $agentUsbDriverPublish -Recurse -Force
    if (Test-Path -LiteralPath $usbCryptDriverCertificate) {
        Copy-Item -LiteralPath $usbCryptDriverCertificate -Destination $agentUsbDriverPublish -Force
    }

    Copy-Item -LiteralPath $usbToolOutput -Destination $agentUsbToolPublish -Force

    $notes = @"
DataProtector Central Web Admin
===============================

Run the central server on the management machine:
server\DataProtectorWebBridge.exe server

Optional IP intelligence enrichment:
setx DATAPROTECTOR_IPINFO_TOKEN "<ipinfo-token>"
or write the token into:
C:\ProgramData\DataProtector\IpInfoToken.txt

Open the web console:
http://<server-ip>:17643/

Run the endpoint agent on every protected client:
agent\DataProtectorWebBridge.exe agent http://<server-ip>:17643/ 15

Endpoint driver package:
agent\driver\DataProtector.inf
agent\driver\DataProtector.sys
agent\driver\dataprotector.cat

USB encryption package:
agent\usbcrypt-driver\DataProtectorUsbCrypt.inf
agent\usbcrypt-driver\DataProtectorUsbCrypt.sys
agent\usbcrypt-driver\dataprotectorusbcrypt.cat
agent\usb-tool\DataProtectorUsbTool.exe

USB encryption workflow:
1. Configure USB encryption policy in the web console.
2. Authorize the removable-device hardware code before unlocking protected media.
3. On a client, use DataProtectorUsbTool.exe install-driver/start-driver.
4. Provisioning is intentionally explicit; the agent never formats removable disks
   from a heartbeat. Use DataProtectorUsbTool.exe init-plan to view the required
   destructive initialization plan before wiring a production provisioning flow.
5. Unlock opens the driver session using the central key reference supplied to the
   operator or provisioning workflow.

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
