[CmdletBinding()]
param(
    [string]$Python
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-Checked {
    param(
        [Parameter(Mandatory)]
        [string]$Label,
        [Parameter(Mandatory)]
        [string]$File,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$Arguments
    )

    Write-Output "== $Label =="
    & $File @Arguments
    $exitCode = $LASTEXITCODE
    Write-Output "$Label exit=$exitCode"
    if ($exitCode -ne 0) {
        throw "$Label failed"
    }
}

function Test-TrackedSensitiveMarkers {
    param(
        [Parameter(Mandatory)]
        [string]$Repository
    )

    $privateKeyPattern = 'BEGIN (?:RSA |OPENSSH |EC )?' + 'PRIVATE KEY'
    $keyLogPattern = 'SSL' + 'KEYLOGFILE\s*='
    $credentialPattern = '(?im)^\s*(?:pass' + 'word|passwd|pwd|密码)\s*[:=]\s*\S+'
    $violations = New-Object System.Collections.Generic.List[string]
    $tracked = & git ls-files
    if ($LASTEXITCODE -ne 0) {
        throw 'git ls-files failed'
    }

    foreach ($relative in $tracked) {
        $path = Join-Path $Repository $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            continue
        }
        $bytes = [System.IO.File]::ReadAllBytes($path)
        if ($bytes -contains 0) {
            continue
        }
        $text = [System.Text.Encoding]::UTF8.GetString($bytes)
        if (
            $text -match $privateKeyPattern -or
            $text -match $keyLogPattern -or
            $text -match $credentialPattern
        ) {
            $violations.Add($relative)
        }
    }

    if ($violations.Count -ne 0) {
        $violations | ForEach-Object { Write-Error "sensitive marker: $_" }
        throw 'tracked sensitive-marker scan failed'
    }
    Write-Output 'tracked sensitive-marker scan exit=0'
}

$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if ([string]::IsNullOrWhiteSpace($Python)) {
    $Python = Join-Path $repository '.venv\Scripts\python.exe'
}
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw 'Python interpreter is missing; pass -Python or create .venv'
}

$runtime = $env:FOXREQ_NSS_RUNTIME_DIR
if ([string]::IsNullOrWhiteSpace($runtime) -or -not (Test-Path -LiteralPath $runtime -PathType Container)) {
    throw 'FOXREQ_NSS_RUNTIME_DIR must name the prepared runtime directory'
}

Push-Location $repository
try {
    $version = & $Python -c "import sys; print('.'.join(map(str, sys.version_info[:3]))); raise SystemExit(0 if sys.version_info >= (3, 10) else 2)"
    $versionExit = $LASTEXITCODE
    Write-Output "python=$version"
    Write-Output "python version check exit=$versionExit"
    if ($versionExit -ne 0) {
        throw 'Python 3.10+ is required'
    }

    $availableMemory = & $Python -c "from scripts.capture.capture_foxreq import _available_physical_memory; print(_available_physical_memory() // 1024 // 1024)"
    $memoryExit = $LASTEXITCODE
    if ($memoryExit -ne 0) {
        throw 'available-memory check failed'
    }
    $availableMemoryMiB = [int64]$availableMemory
    Write-Output "available_memory_mib=$availableMemoryMiB"
    if ($availableMemoryMiB -lt 4096) {
        throw 'available physical memory is below the 4096 MiB verification gate'
    }

    $env:CARGO_BUILD_JOBS = '1'
    $env:PYTHONUTF8 = '1'
    $env:PYTHONIOENCODING = 'utf-8'

    Invoke-Checked 'rustc version' 'rustc' @('--version')
    Invoke-Checked 'cargo version' 'cargo' @('--version')
    Invoke-Checked 'cmake version' 'cmake' @('--version')
    Invoke-Checked 'python import' $Python @('-c', "import foxreq; print('foxreq=' + foxreq.__version__)")

    Invoke-Checked 'cargo fmt' 'cargo' @('fmt', '--all', '--', '--check')
    Invoke-Checked 'cargo clippy' 'cargo' @('clippy', '--workspace', '--all-targets', '--', '-D', 'warnings')
    Invoke-Checked 'cargo test core' 'cargo' @('test', '-p', 'foxreq-core', '--no-default-features')
    Invoke-Checked 'cargo test python worker' 'cargo' @('test', '-p', 'foxreq-py', '--lib')

    Invoke-Checked 'cmake configure stub' 'cmake' @(
        '-S', 'native/nss-shim',
        '-B', 'build/nss-shim-fake',
        '-G', 'Ninja',
        '-DFOXREQ_NSS_STUB=ON',
        '-DBUILD_TESTING=ON'
    )
    Invoke-Checked 'cmake build stub' 'cmake' @('--build', 'build/nss-shim-fake', '--parallel', '1')
    Invoke-Checked 'ctest stub' 'ctest' @('--test-dir', 'build/nss-shim-fake', '--output-on-failure')

    Invoke-Checked 'test_real_tls' $Python @(
        '-m', 'scripts.runtime.test_real_tls',
        '--runtime', $runtime,
        '--python-api', $Python
    )

    $fixture = Join-Path $repository 'artifacts\fixtures\certs\orchestrated-valid'
    if (-not (Test-Path -LiteralPath (Join-Path $fixture 'ca.pem') -PathType Leaf)) {
        throw 'real TLS orchestrator did not prepare the Python fixture'
    }
    $env:FOXREQ_PY_TEST_FIXTURE = $fixture
    Invoke-Checked 'python unittest' $Python @(
        '-W', 'error::ResourceWarning',
        '-m', 'unittest',
        'discover', '-s', 'tests/python', '-t', '.', '-v'
    )
    Invoke-Checked 'python pip check' $Python @('-m', 'pip', 'check')
    Invoke-Checked 'git diff --check' 'git' @('diff', '--check')
    Test-TrackedSensitiveMarkers -Repository $repository
} finally {
    Pop-Location
}
