param(
    [ValidateSet("Release")]
    [string]$Configuration = "Release",

    [ValidateSet("x64")]
    [string]$Platform = "x64",

    [string]$OutputDirectory = "",

    [switch]$UsbCryptTrace,

    [switch]$AllowInvalidKernelSignature,

    [switch]$AllowInvalidUsbRuntimeKernelSignature
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$msBuild = "D:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe"
$dSignToolRoot = "D:\Program Files (x86)\DSignTool"
$cSignTool = Join-Path $dSignToolRoot "CSignTool.exe"
$dSignRule = "gz"
$usbRuntimeSignerThumbprint = "FF6E2D78C38944B9F3454AA33648BB15186FFC1C"
$usbRuntimeSignerSubject = "Guangzhou Tianmu Yidong Communication Development Co., Ltd"
$signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.18362.0\x64\signtool.exe"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

function Invoke-ReleaseDriverSigning {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    if (-not (Test-Path -LiteralPath $cSignTool)) {
        throw "CSignTool was not found at: $cSignTool"
    }

    if (-not (Test-Path -LiteralPath $FilePath)) {
        throw "USB runtime signing target was not found: $FilePath"
    }

    Push-Location $dSignToolRoot
    try {
        & $cSignTool sign /r $dSignRule /f $FilePath /ac
        if ($LASTEXITCODE -ne 0) {
            throw "Driver release signing failed with exit code $LASTEXITCODE for: $FilePath"
        }
    }
    finally {
        Pop-Location
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $FilePath
    if ($null -eq $signature.SignerCertificate) {
        throw "Driver release signing verification failed; no signer certificate was found for: $FilePath"
    }

    if (-not [string]::Equals($signature.SignerCertificate.Thumbprint, $usbRuntimeSignerThumbprint, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Driver release signing verification failed; unexpected signer thumbprint '$($signature.SignerCertificate.Thumbprint)' for: $FilePath"
    }

    if ($signature.SignerCertificate.Subject -notlike "*$usbRuntimeSignerSubject*") {
        throw "Driver release signing verification failed; unexpected signer subject '$($signature.SignerCertificate.Subject)' for: $FilePath"
    }
}

function Invoke-KernelModeSigningVerification {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    if (-not (Test-Path -LiteralPath $signtool)) {
        throw "signtool was not found at: $signtool"
    }

    & $signtool verify /v /kp $FilePath
    if ($LASTEXITCODE -ne 0) {
        if ($AllowInvalidKernelSignature -or $AllowInvalidUsbRuntimeKernelSignature) {
            Write-Warning "Kernel-mode signature verification failed for: $FilePath. Continuing because an allow-invalid kernel signature switch was specified. This package is not a production driver-signing release and may fail to load with Win32=577 on default Windows systems."
            return
        }

        throw "Kernel-mode signature verification failed for: $FilePath. Windows will reject this driver at load time, usually as Win32=577. Use a currently valid kernel-mode signing certificate or Microsoft attestation/WHQL signing for release builds."
    }
}

function Invoke-ServerDriverArtifactSigning {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerPublish
    )

    $driverArtifacts = Get-ChildItem -LiteralPath $ServerPublish -Recurse -File |
        Where-Object { $_.Extension -in @(".sys", ".cat") } |
        Sort-Object @{ Expression = { if ($_.Extension -ieq ".sys") { 0 } else { 1 } } }, FullName

    foreach ($artifact in $driverArtifacts) {
        Invoke-ReleaseDriverSigning $artifact.FullName
    }

    foreach ($artifact in $driverArtifacts) {
        Invoke-KernelModeSigningVerification $artifact.FullName
    }
}

if (-not (Test-Path -LiteralPath $msBuild)) {
    throw "VS2019 MSBuild was not found at: $msBuild"
}

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $root "publish\DataProtectorWebAdmin-$Platform-$Configuration"
}

$webRoot = Join-Path $root "DataProtectorWebAdmin"
$webDist = Join-Path $webRoot "dist"
$bridgeOutput = Join-Path $root "DataProtectorWebBridge\bin\$Platform\$Configuration"
$agentClientOutput = Join-Path $root "DataProtectorAgentClient\bin\$Platform\$Configuration"
$driverPackage = Join-Path $root "DataProtector\$Platform\$Configuration\DataProtector"
$driverCertificate = Join-Path $root "DataProtector\$Platform\$Configuration\DataProtector.cer"
$policyApiX86Output = Join-Path $root "DataProtectorPolicyApi\Win32\$Configuration\DataProtectorPolicyApi.dll"
$usbCryptDriverPackage = Join-Path $root "DataProtectorUsbCrypt\$Platform\$Configuration\DataProtectorUsbCrypt"
$usbCryptDriverCertificate = Join-Path $root "DataProtectorUsbCrypt\$Platform\$Configuration\DataProtectorUsbCrypt.cer"
$usbToolOutput = Join-Path $root "DataProtectorUsbTool\$Platform\$Configuration\DataProtectorUsbTool.exe"
$userHookRuntimeOutput = Join-Path $root "DataProtectorUserHookRuntime\$Platform\$Configuration\DataProtectorUserHookRuntime.dll"
$userHookRuntimeX86Output = Join-Path $root "DataProtectorUserHookRuntime\Win32\$Configuration\DataProtectorUserHookRuntime.dll"
$sandboxTelemetryOutput = Join-Path $root "DataProtectorSandboxTelemetry\bin\$Platform\$Configuration\DataProtectorSandboxTelemetry.exe"
$sandboxTelemetryX86Output = Join-Path $root "DataProtectorSandboxTelemetry\bin\x86\$Configuration\DataProtectorSandboxTelemetry.exe"

Push-Location $root
try {
    Invoke-Checked $msBuild @(".\DataProtector\DataProtector.vcxproj", "/p:Configuration=$Configuration", "/p:Platform=$Platform") "DataProtector driver build"
    Invoke-Checked $msBuild @(".\DataProtectorPolicyApi\DataProtectorPolicyApi.vcxproj", "/p:Configuration=$Configuration", "/p:Platform=$Platform") "DataProtectorPolicyApi build"
    Invoke-Checked $msBuild @(".\DataProtectorPolicyApi\DataProtectorPolicyApi.vcxproj", "/p:Configuration=$Configuration", "/p:Platform=Win32") "DataProtectorPolicyApi x86 build"
    $usbCryptBuildArguments = @(".\DataProtectorUsbCrypt\DataProtectorUsbCrypt.vcxproj", "/p:Configuration=$Configuration", "/p:Platform=$Platform")
    if ($UsbCryptTrace) {
        $usbCryptBuildArguments += "/t:Rebuild"
        $usbCryptBuildArguments += "/p:DpUsbTrace=true"
    }
    Invoke-Checked $msBuild $usbCryptBuildArguments "DataProtectorUsbCrypt driver build"
    Invoke-Checked $msBuild @(".\DataProtectorUsbTool\DataProtectorUsbTool.vcxproj", "/p:Configuration=$Configuration", "/p:Platform=$Platform") "DataProtectorUsbTool build"
    Invoke-Checked $msBuild @(".\DataProtectorUserHookRuntime\DataProtectorUserHookRuntime.vcxproj", "/p:Configuration=$Configuration", "/p:Platform=$Platform") "DataProtectorUserHookRuntime build"
    Invoke-Checked $msBuild @(".\DataProtectorUserHookRuntime\DataProtectorUserHookRuntime.vcxproj", "/p:Configuration=$Configuration", "/p:Platform=Win32") "DataProtectorUserHookRuntime x86 build"
    Invoke-Checked $msBuild @(".\DataProtectorSandboxTelemetry\DataProtectorSandboxTelemetry.csproj", "/p:Configuration=$Configuration", "/p:Platform=$Platform") "DataProtectorSandboxTelemetry build"
    Invoke-Checked $msBuild @(".\DataProtectorSandboxTelemetry\DataProtectorSandboxTelemetry.csproj", "/p:Configuration=$Configuration", "/p:Platform=x86") "DataProtectorSandboxTelemetry x86 build"
    Invoke-Checked $msBuild @(".\DataProtectorWebBridge\DataProtectorWebBridge.csproj", "/p:Configuration=$Configuration", "/p:Platform=$Platform") "DataProtectorWebBridge build"
    Invoke-Checked $msBuild @(".\DataProtectorAgentClient\DataProtectorAgentClient.csproj", "/p:Configuration=$Configuration", "/p:Platform=$Platform") "DataProtectorAgentClient build"

    Push-Location $webRoot
    try {
        Invoke-Checked "pnpm" @("install", "--frozen-lockfile") "Web dependency restore"
        Invoke-Checked "pnpm" @("build") "Web build"
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

    if (-not (Test-Path -LiteralPath $agentClientOutput)) {
        throw "Agent client build output was not found: $agentClientOutput"
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

    if (-not (Test-Path -LiteralPath $userHookRuntimeOutput)) {
        throw "User hook runtime output was not found: $userHookRuntimeOutput"
    }

    if (-not (Test-Path -LiteralPath $userHookRuntimeX86Output)) {
        throw "User hook runtime x86 output was not found: $userHookRuntimeX86Output"
    }

    if (-not (Test-Path -LiteralPath $sandboxTelemetryOutput)) {
        throw "Sandbox telemetry output was not found: $sandboxTelemetryOutput"
    }

    if (-not (Test-Path -LiteralPath $sandboxTelemetryX86Output)) {
        throw "Sandbox telemetry x86 output was not found: $sandboxTelemetryX86Output"
    }

    if (-not (Test-Path -LiteralPath $policyApiX86Output)) {
        throw "Policy API x86 output was not found: $policyApiX86Output"
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
    $staticOutput = Join-Path $serverPublish "web"
    $serverUsbRuntimePublish = Join-Path $serverPublish "usbcrypt-runtime"
    New-Item -ItemType Directory -Force -Path $staticOutput, $serverPublish, $agentPublish, $agentDriverPublish, $serverUsbRuntimePublish | Out-Null

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

    Copy-Item -LiteralPath $userHookRuntimeOutput -Destination $agentPublish -Force
    Copy-Item -LiteralPath $userHookRuntimeOutput -Destination $serverPublish -Force
    Copy-Item -LiteralPath $sandboxTelemetryOutput -Destination $serverPublish -Force

    $serverSandboxX64Publish = Join-Path $serverPublish "sandbox-telemetry\x64"
    $serverSandboxX86Publish = Join-Path $serverPublish "sandbox-telemetry\x86"
    $serverSandboxKernelPublish = Join-Path $serverPublish "sandbox-telemetry\kernel"
    $serverSandboxKernelX86Publish = Join-Path $serverSandboxKernelPublish "x86"
    New-Item -ItemType Directory -Force -Path $serverSandboxX64Publish, $serverSandboxX86Publish, $serverSandboxKernelPublish, $serverSandboxKernelX86Publish | Out-Null
    Copy-Item -LiteralPath $sandboxTelemetryOutput -Destination (Join-Path $serverPublish "sandbox-telemetry") -Force
    Copy-Item -LiteralPath $sandboxTelemetryOutput -Destination $serverSandboxX64Publish -Force
    Copy-Item -LiteralPath $sandboxTelemetryX86Output -Destination $serverSandboxX86Publish -Force
    Copy-Item -LiteralPath $userHookRuntimeOutput -Destination $serverSandboxX64Publish -Force
    Copy-Item -LiteralPath $userHookRuntimeX86Output -Destination $serverSandboxX86Publish -Force
    Copy-Item -LiteralPath (Join-Path $driverPackage "DataProtector.sys") -Destination $serverSandboxKernelPublish -Force
    Copy-Item -LiteralPath (Join-Path $bridgeOutput "DataProtectorPolicyApi.dll") -Destination $serverSandboxKernelPublish -Force
    Copy-Item -LiteralPath $policyApiX86Output -Destination $serverSandboxKernelX86Publish -Force
    if (Test-Path -LiteralPath (Join-Path $driverPackage "dataprotector.cat")) {
        Copy-Item -LiteralPath (Join-Path $driverPackage "dataprotector.cat") -Destination $serverSandboxKernelPublish -Force
    }
    if (Test-Path -LiteralPath (Join-Path $driverPackage "DataProtector.inf")) {
        Copy-Item -LiteralPath (Join-Path $driverPackage "DataProtector.inf") -Destination $serverSandboxKernelPublish -Force
    }
    Invoke-ServerDriverArtifactSigning $serverPublish

    $agentClientFiles = @(
        "DataProtectorAgentClient.exe",
        "DataProtectorAgentClient.exe.config",
        "Wpf.Ui.dll"
    )

    foreach ($file in $agentClientFiles) {
        $source = Join-Path $agentClientOutput $file
        if (-not (Test-Path -LiteralPath $source)) {
            throw "Required agent client publish file is missing: $source"
        }

        Copy-Item -LiteralPath $source -Destination $agentPublish -Force
    }

    Copy-Item -Path (Join-Path $driverPackage "*") -Destination $agentDriverPublish -Recurse -Force
    if (Test-Path -LiteralPath $driverCertificate) {
        Copy-Item -LiteralPath $driverCertificate -Destination $agentDriverPublish -Force
    }

    $runtimeStaging = Join-Path $env:TEMP ("DataProtectorUsbRuntime-" + [guid]::NewGuid().ToString("N"))
    try {
        $runtimeDriverStaging = Join-Path $runtimeStaging "driver"
        New-Item -ItemType Directory -Force -Path $runtimeDriverStaging | Out-Null
        Copy-Item -LiteralPath $usbToolOutput -Destination $runtimeStaging -Force
        Copy-Item -Path (Join-Path $usbCryptDriverPackage "*") -Destination $runtimeDriverStaging -Recurse -Force
        if (Test-Path -LiteralPath $usbCryptDriverCertificate) {
            Copy-Item -LiteralPath $usbCryptDriverCertificate -Destination $runtimeDriverStaging -Force
        }
        Invoke-ReleaseDriverSigning (Join-Path $runtimeDriverStaging "DataProtectorUsbCrypt.sys")
        Invoke-ReleaseDriverSigning (Join-Path $runtimeDriverStaging "dataprotectorusbcrypt.cat")
        Invoke-KernelModeSigningVerification (Join-Path $runtimeDriverStaging "DataProtectorUsbCrypt.sys")
        Invoke-KernelModeSigningVerification (Join-Path $runtimeDriverStaging "dataprotectorusbcrypt.cat")
        Compress-Archive -Path (Join-Path $runtimeStaging "*") -DestinationPath (Join-Path $serverUsbRuntimePublish "DataProtectorUsbRuntime.zip") -Force
    }
    finally {
        if (Test-Path -LiteralPath $runtimeStaging) {
            Remove-Item -LiteralPath $runtimeStaging -Recurse -Force
        }
    }

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

Open the endpoint WPF-UI client:
agent\DataProtectorAgentClient.exe

Endpoint driver package:
agent\driver\DataProtector.inf
agent\driver\DataProtector.sys
agent\driver\dataprotector.cat

USB encryption runtime package:
server\usbcrypt-runtime\DataProtectorUsbRuntime.zip

USB encryption workflow:
1. The web console discovers removable devices reported by endpoint agents.
2. Upload server\usbcrypt-runtime\DataProtectorUsbRuntime.zip in the web
   console USB encryption package panel. The server stores the package under
   C:\ProgramData\DataProtector\UsbCryptPackages and versions it by metadata.
3. Operators authorize a device and start USB encryption initialization from
   the web console. The initialization password is delivered as a one-shot
   task secret and is not persisted in the central state file.
4. The endpoint agent owns initialization: it validates the hardware id,
   downloads the server-managed runtime package, verifies its SHA256, copies
   DataProtectorUsbTool.exe and driver files to the USB public area, and marks
   driver runtime files as hidden/system.
5. The endpoint agent rebuilds the USB disk layout before initialization:
   the first 2 MB is raw metadata reserve, the next 5 MB is the public NTFS
   tool partition, and the remaining media is the encrypted data region.
6. Unlock key metadata is written by the DataProtector kernel driver to the
   reserved raw-disk metadata area at 1 MB, not to an ADS and not to a public
   DataProtectorUsbUnlock.dat file.
7. DataProtectorUsbTool.exe is only the public-area unlock loader. It validates
   the raw-disk USB metadata with the initialization password before deploying
   or loading the driver. A wrong password never loads the driver.
8. The public tool exposes only metadata-gated unlock operations: UI unlock,
   unlock-password, status, and lock. Direct driver loading is intentionally not
   exposed by the released tool path.

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
