param([switch]$Archive)
$ErrorActionPreference='Stop'
$SourceCommit='07146b7118c345e4a1046fe9066ba2f26b37cf3a'
$SourceSha256='3df55cdbc317522d74a3f6cc8f0f68258aa73da0b1d5cd8ae811aebf7ab9342f'
$PublicSha256='a4502dda11fbc39567e53c909ca2e4d8b9c5b5825e92e056fea46fd8cb396b18'
$PublicBytes=2731
$ReviewSha256='93cebeb25a1fcea5c2766bb02dacaf4ef43f5c46207c134181d048d8d6bf500e'
$ReviewBytes=39309
$archiveArguments=@('-I','-S','-B',(Join-Path $PSScriptRoot 'archive_zero_cap_loopback_01_builder02.py'),
    '--source-commit',$SourceCommit,'--source-sha256',$SourceSha256,
    '--public-sha256',$PublicSha256,'--public-bytes',[string]$PublicBytes,
    '--review-sha256',$ReviewSha256,'--review-bytes',[string]$ReviewBytes)
if($Archive){$archiveArguments+='--archive'}
& python @archiveArguments
if($LASTEXITCODE -ne 0){throw 'File-only archive verification failed'}
