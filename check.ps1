[CmdletBinding()]
param(
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
$appProject = Join-Path $root "src\ProcessArchDemo\ProcessArchDemo.csproj"
$testProject = Join-Path $root "tests\ProcessArchDemo.Tests\ProcessArchDemo.Tests.csproj"
$appDll = Join-Path $root "src\ProcessArchDemo\bin\$Configuration\net11.0-windows\ProcessArchDemo.dll"

$dotnetCommand = Get-Command dotnet -ErrorAction SilentlyContinue
if (-not $dotnetCommand) {
    throw "dotnet SDK was not found on PATH. Install .NET 11 SDK or use a machine with it available."
}
$dotnet = $dotnetCommand.Source

Write-Host "==> Build ($Configuration)"
& $dotnet build $testProject -c $Configuration --nologo
if ($LASTEXITCODE -ne 0) {
    throw "Build failed with exit code $LASTEXITCODE."
}

Write-Host ""
Write-Host "==> Automated checks"
& $dotnet run --project $testProject -c $Configuration --no-build
if ($LASTEXITCODE -ne 0) {
    throw "Automated checks failed with exit code $LASTEXITCODE."
}

Write-Host ""
Write-Host "==> CLI JSON smoke test"
if (-not (Test-Path -LiteralPath $appDll)) {
    throw "Application DLL not found: $appDll"
}

$jsonText = & $dotnet $appDll --json
if ($LASTEXITCODE -ne 0) {
    throw "CLI JSON run failed with exit code $LASTEXITCODE."
}

$report = $jsonText | ConvertFrom-Json -ErrorAction Stop
if ($report.schema_version -ne 1) {
    throw "Unexpected schema_version: $($report.schema_version)"
}
if ([string]::IsNullOrWhiteSpace($report.host.arch)) {
    throw "host.arch is missing from JSON output."
}

$processes = @($report.processes)
if ($processes.Count -ne 1) {
    throw "Expected exactly one process in default JSON output, got $($processes.Count)."
}
if ([string]::IsNullOrWhiteSpace($processes[0].process_arch)) {
    throw "processes[0].process_arch is missing from JSON output."
}
if ([string]::IsNullOrWhiteSpace($processes[0].reason)) {
    throw "processes[0].reason is missing from JSON output."
}

Write-Host "PASS JSON output (host=$($report.host.arch), process=$($processes[0].process_arch), confidence=$($processes[0].confidence))"

Write-Host ""
Write-Host "==> CLI error handling smoke test"
# Use cmd.exe for this negative test: Windows PowerShell wraps native stderr as an
# error record, which would trip $ErrorActionPreference=Stop before we can inspect
# the process exit code.
$negativeCommand = "`"$dotnet`" `"$appDll`" --definitely-invalid-option >nul 2>&1"
& cmd.exe /d /c $negativeCommand
$negativeExitCode = $LASTEXITCODE
if ($negativeExitCode -ne 2) {
    throw "Expected exit code 2 for an unknown option, got $negativeExitCode."
}

Write-Host "PASS unknown option returned exit code 2."
Write-Host ""
Write-Host "All checks passed."
