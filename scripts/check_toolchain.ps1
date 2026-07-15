[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Resolve-Tool {
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$Candidates
    )

    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }

    foreach ($candidate in $Candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }

    throw "Required tool is missing: $Name"
}

$rustc = Resolve-Tool -Name 'rustc' -Candidates @(
    (Join-Path $HOME '.cargo\bin\rustc.exe')
)
$cargo = Resolve-Tool -Name 'cargo' -Candidates @(
    (Join-Path $HOME '.cargo\bin\cargo.exe')
)
$cmake = Resolve-Tool -Name 'cmake' -Candidates @(
    'C:\Program Files\CMake\bin\cmake.exe'
)
$ninja = Resolve-Tool -Name 'ninja' -Candidates @()
$vswhere = Resolve-Tool -Name 'vswhere' -Candidates @(
    'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
)

$rustVersion = & $rustc '+1.88.0-x86_64-pc-windows-msvc' '--version'
if ($LASTEXITCODE -ne 0 -or $rustVersion -notmatch '^rustc 1\.88\.0 ') {
    throw "Expected rustc 1.88.0, received: $rustVersion"
}

$vsPath = & $vswhere '-latest' '-products' '*' '-requires' 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64' '-property' 'installationPath'
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($vsPath)) {
    throw 'Visual Studio C++ x64 build tools are missing'
}

@(
    $rustVersion
    (& $cargo '+1.88.0-x86_64-pc-windows-msvc' '--version')
    ((& $cmake '--version')[0])
    (& $ninja '--version')
    "msvc=$vsPath"
) | ForEach-Object { Write-Output $_ }
