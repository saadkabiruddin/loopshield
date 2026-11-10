# Run the evaluation with the host controller. No Wokwi or ESP32 required.
# Extra arguments are forwarded to the harness, e.g. matrix --trials 1.
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$children = @()
Push-Location $repo
try {
    & dotnet build
    if ($LASTEXITCODE -ne 0) { throw 'Solution build failed' }
    & dotnet build firmware/test/hostctl
    if ($LASTEXITCODE -ne 0) { throw 'Host controller build failed' }
    New-Item -ItemType Directory -Force firmware/test/build | Out-Null
    & gcc -O2 -Wall -Wextra -Ifirmware/main -shared -static-libgcc firmware/test/hostlib.c firmware/main/sg_proto.c firmware/main/sg_msg.c firmware/main/sg_detect.c -o firmware/test/build/sghost.dll
    if ($LASTEXITCODE -ne 0) { throw 'Native controller build failed (GCC is required)' }
    foreach ($port in 1883, 1884) {
        if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
            throw "Port $port is already in use. Stop the existing LoopShield processes before starting this launcher."
        }
    }
    $logDir = Join-Path $repo ('runs/local-services-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory $logDir | Out-Null
    foreach ($service in @(
        @{ Path = 'broker/bin/Debug/net10.0/LoopShield.Broker.exe'; Name = 'broker' },
        @{ Path = 'firmware/test/hostctl/bin/Debug/net10.0/LoopShield.HostCtl.exe'; Name = 'controller' }
    )) {
        $children += Start-Process -FilePath (Join-Path $repo $service.Path) -WorkingDirectory $repo -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $logDir ($service.Name + '.log')) -RedirectStandardError (Join-Path $logDir ($service.Name + '.err.log'))
    }
    Start-Sleep -Seconds 1
    foreach ($child in $children) {
        if ($child.HasExited) { throw "A local service exited. See $logDir" }
    }
    Write-Host "Local controller active; service logs: $logDir"
    Write-Host 'Timing is from this PC and must not be reported as ESP32 timing.'
    $evalArgs = $args
    if ($evalArgs.Count -eq 0) { $evalArgs = @('single', '--attack', 'bias', '--config', 'both', '--warmup', '3', '--attack-s', '10', '--recover', '3') }
    & ./harness/bin/Debug/net10.0/LoopShield.Eval.exe @evalArgs
    if ($LASTEXITCODE -ne 0) { throw 'Evaluation failed' }
}
finally {
    foreach ($child in $children) {
        if (!$child.HasExited) { Stop-Process -Id $child.Id -ErrorAction SilentlyContinue }
    }
    Pop-Location
}
