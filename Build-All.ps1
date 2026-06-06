param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",

    [ValidateSet("x64")]
    [string]$Platform = "x64"
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$vs2019MsBuild = "D:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe"

if (-not (Test-Path -LiteralPath $vs2019MsBuild)) {
    throw "VS2019 MSBuild was not found at: $vs2019MsBuild"
}

Push-Location $root
try {
    & $vs2019MsBuild ".\DataProtector.sln" `
        /p:Configuration=$Configuration `
        /p:Platform=$Platform `
        /m
}
finally {
    Pop-Location
}
