# Disposable CI diagnosis: keep only access denials for the synthetic browsers.
param([string]$OutputDirectory = 'loader-results', [string[]]$Cases = @('readonly'))
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Loader diagnosis is restricted to disposable GitHub-hosted Windows runners'
}
$root = Join-Path $env:RUNNER_TEMP 'rp-procmon'
New-Item -ItemType Directory -Force $root | Out-Null
Invoke-WebRequest 'https://download.sysinternals.com/files/ProcessMonitor.zip' -OutFile "$root/procmon.zip"
Expand-Archive "$root/procmon.zip" -DestinationPath $root
$exe = Join-Path $root 'Procmon64a.exe'
if ((Get-AuthenticodeSignature $exe).Status -ne 'Valid') { throw 'Process Monitor signature is invalid' }
Get-FileHash $exe -Algorithm SHA256
$pml = Join-Path $root 'browser.pml'
$csv = Join-Path $root 'browser.csv'
$capture = Start-Process -FilePath $exe -ArgumentList "/AcceptEula /Quiet /Minimized /NoFilter /BackingFile `"$pml`"" -PassThru
try {
    Start-Sleep -Seconds 2
    python -X utf8 -B .github/windows_browser_loader_validation.py --output $OutputDirectory --chrome C:/RuleProxyChrome/chrome-win64/chrome.exe --firefox C:/RuleProxyFirefox/core/firefox.exe --cases @Cases
    if ($LASTEXITCODE -ne 0) { throw 'Loader diagnosis did not complete' }
} finally {
    Start-Process -FilePath $exe -ArgumentList '/AcceptEula /Quiet /Terminate' -Wait
    $capture.WaitForExit(15000) | Out-Null
}
Start-Process -FilePath $exe -ArgumentList "/AcceptEula /Quiet /OpenLog `"$pml`" /SaveAs `"$csv`"" -Wait
if (-not (Test-Path $csv)) { throw 'Process Monitor did not export the captured events' }
$env:RULEPROXY_PROCMON_CSV = $csv
$env:RULEPROXY_PROCMON_OUTPUT = (Join-Path $OutputDirectory 'file-denials.json')
@'
import csv, json, os, pathlib
rows = []
with open(os.environ['RULEPROXY_PROCMON_CSV'], encoding='utf-8-sig', errors='replace', newline='') as source:
    for row in csv.DictReader(source):
        if row.get('Process Name', '').lower() in ('chrome.exe', 'firefox.exe') and row.get('Result') == 'ACCESS DENIED':
            rows.append(row)
pathlib.Path(os.environ['RULEPROXY_PROCMON_OUTPUT']).write_text(json.dumps(rows, indent=2), encoding='utf-8')
print(json.dumps(rows[-80:], ensure_ascii=True, indent=2))
'@ | python -X utf8 -
if ($LASTEXITCODE -ne 0) { throw 'Could not retain filtered file denials' }
