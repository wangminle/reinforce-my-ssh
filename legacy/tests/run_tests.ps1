param(
    [string]$Distribution = 'Debian',
    [switch]$Integration
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$linuxPathResult = & wsl.exe -d $Distribution -- wslpath -a -u $projectRoot.Replace('\', '/')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$linuxRoot = $linuxPathResult.Trim()
$arguments = @('-d', $Distribution)
if ($Integration) { $arguments += @('-u', 'root') }
$arguments += @('--', 'python3', "$linuxRoot/tests/run_tests.py")
if ($Integration) { $arguments += '--integration' }
& wsl.exe @arguments
exit $LASTEXITCODE
