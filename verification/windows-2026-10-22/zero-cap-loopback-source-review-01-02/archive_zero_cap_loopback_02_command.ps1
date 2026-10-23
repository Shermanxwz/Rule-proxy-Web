param([switch]$Archive)
$ErrorActionPreference='Stop'
$SourceCommit='c7145b9d50dc99c14f11764a03ad23f31ce3e638'
$SourceSha256='b726d48d6dddfed2533168ac0921add834488f333931f08b75dc6195cd9fc4ac'
$PublicSha256='457c26fdf13707807a5412ff81951bba7b4112129c472c6f09804c073a6813ed'
$PublicBytes=2731
$ReviewSha256='1f7667177453f7f924891608a57084972d033d5217137580237926ac854b71ea'
$ReviewBytes=40162
$archiveArguments=@('-I','-S','-B',(Join-Path $PSScriptRoot 'archive_zero_cap_loopback_02.py'),
    '--source-commit',$SourceCommit,'--source-sha256',$SourceSha256,
    '--public-sha256',$PublicSha256,'--public-bytes',[string]$PublicBytes,
    '--review-sha256',$ReviewSha256,'--review-bytes',[string]$ReviewBytes)
if($Archive){$archiveArguments+='--archive'}
& python @archiveArguments
if($LASTEXITCODE -ne 0){throw 'File-only archive verification failed'}
