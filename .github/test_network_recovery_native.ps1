param([string]$ScriptPath,[switch]$CompileOnly)
$ErrorActionPreference='Stop'
if(-not $CompileOnly -and $env:GITHUB_ACTIONS -ne 'true'){throw 'Native mutation fixture is restricted to disposable GitHub runners'}
. $ScriptPath -LibraryOnly
if(-not $CompileOnly -and -not (Test-IsAdministrator)){throw 'Native fixture needs runner administrator'}
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RecoveryFixture {
    [StructLayout(LayoutKind.Sequential)]public struct Display{public IntPtr name,description;}
    [StructLayout(LayoutKind.Sequential)]public struct Blob{public uint size;public IntPtr data;}
    [StructLayout(LayoutKind.Sequential)]public struct Provider{public Guid key;public Display display;public uint flags;public Blob data;public IntPtr service;}
    [StructLayout(LayoutKind.Sequential)]public struct Sublayer{public Guid key;public Display display;public ushort flags;public IntPtr provider;public Blob data;public ushort weight;}
    [StructLayout(LayoutKind.Sequential)]public struct FilterHead{public Guid key;public Display display;public uint flags;public IntPtr provider;public Blob data;public Guid layer,sublayer;}
    [StructLayout(LayoutKind.Explicit,Size=8)] public struct Union { [FieldOffset(0)] public ulong integer; [FieldOffset(0)] public IntPtr pointer; }
    [StructLayout(LayoutKind.Sequential)] public struct Value { public uint type;public Union value; }
    [StructLayout(LayoutKind.Sequential)] public struct Action {public uint type;public Guid key;}
    [StructLayout(LayoutKind.Explicit,Size=16)] public struct Context {[FieldOffset(0)]public ulong raw;[FieldOffset(0)]public Guid key;}
    [StructLayout(LayoutKind.Sequential)] public struct Filter {
        public Guid key;public Display display;public uint flags;public IntPtr provider;public Blob data;
        public Guid layer,sublayer;public Value weight;public uint count;public IntPtr conditions;
        public Action action;public Context context;public IntPtr reserved;public ulong id;public Value effective;
    }
    [DllImport("fwpuclnt.dll")]static extern uint FwpmProviderAdd0(IntPtr h,ref Provider p,IntPtr s);
    [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)]static extern uint FwpmEngineOpen0(string s,uint a,IntPtr i,IntPtr session,out IntPtr h);
    [DllImport("fwpuclnt.dll")]static extern uint FwpmEngineClose0(IntPtr h);
    [DllImport("fwpuclnt.dll")]static extern uint FwpmSubLayerAdd0(IntPtr h,ref Sublayer p,IntPtr s);
    [DllImport("fwpuclnt.dll")]static extern uint FwpmFilterAdd0(IntPtr h,ref Filter p,IntPtr s,out ulong id);
    [DllImport("fwpuclnt.dll")]static extern uint FwpmFilterDeleteByKey0(IntPtr h,ref Guid key);
    [DllImport("fwpuclnt.dll")]static extern uint FwpmSubLayerDeleteByKey0(IntPtr h,ref Guid key);
    [DllImport("fwpuclnt.dll")]static extern uint FwpmProviderDeleteByKey0(IntPtr h,ref Guid key);
    [StructLayout(LayoutKind.Sequential)]public struct Http{public uint access;public IntPtr proxy,bypass;}
    [DllImport("winhttp.dll",SetLastError=true)]static extern bool WinHttpSetDefaultProxyConfiguration(ref Http p);
    public static void SetHttp(uint access,string proxy,string bypass){
        Http p=new Http();p.access=access;p.proxy=access==3?Marshal.StringToHGlobalUni(proxy):IntPtr.Zero;p.bypass=access==3?Marshal.StringToHGlobalUni(bypass):IntPtr.Zero;
        try{if(!WinHttpSetDefaultProxyConfiguration(ref p))throw new Exception("Fixture WinHTTP set failed");}finally{if(p.proxy!=IntPtr.Zero)Marshal.FreeHGlobal(p.proxy);if(p.bypass!=IntPtr.Zero)Marshal.FreeHGlobal(p.bypass);}
    }
    static void Check(uint c){if(c!=0)throw new Exception("Fixture WFP 0x"+c.ToString("X8"));}
    public static void Add(string provider,string sublayer,string filter,string marker,bool owned){
        if(Marshal.SizeOf(typeof(Provider))!=64 || Marshal.SizeOf(typeof(Sublayer))!=72 || Marshal.SizeOf(typeof(FilterHead))!=96 || Marshal.SizeOf(typeof(Filter))!=200)throw new Exception("Unexpected WFP ABI");
        IntPtr h;Check(FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out h));
        IntPtr name=Marshal.StringToHGlobalUni("RuleProxy recovery CI fixture"),description=Marshal.StringToHGlobalUni(marker),service=owned?Marshal.StringToHGlobalUni("RuleProxyControl"):IntPtr.Zero;
        IntPtr providerPtr=Marshal.AllocHGlobal(16);
        try{
            Guid pg=new Guid(provider);Marshal.StructureToPtr(pg,providerPtr,false);
            Provider p=new Provider();p.key=pg;p.flags=1;p.display.name=name;p.display.description=description;p.service=service;Check(FwpmProviderAdd0(h,ref p,IntPtr.Zero));
            Sublayer s=new Sublayer();s.key=new Guid(sublayer);s.flags=1;s.display=p.display;s.provider=providerPtr;s.weight=0;Check(FwpmSubLayerAdd0(h,ref s,IntPtr.Zero));
            Filter f=new Filter();f.key=new Guid(filter);f.display=p.display;f.flags=1;f.provider=providerPtr;f.layer=new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");f.sublayer=s.key;
            // Soft permit only: never installs an all-traffic block on the runner.
            f.action.type=0x1002;ulong id;Check(FwpmFilterAdd0(h,ref f,IntPtr.Zero,out id));
        }finally{Marshal.FreeHGlobal(name);Marshal.FreeHGlobal(description);Marshal.FreeHGlobal(service);Marshal.FreeHGlobal(providerPtr);FwpmEngineClose0(h);}
    }
    public static void Cleanup(string provider,string sublayer,string filter){
        IntPtr h;Check(FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out h));
        try{Guid f=new Guid(filter),s=new Guid(sublayer),p=new Guid(provider);FwpmFilterDeleteByKey0(h,ref f);FwpmSubLayerDeleteByKey0(h,ref s);FwpmProviderDeleteByKey0(h,ref p);}finally{FwpmEngineClose0(h);}
    }
}
'@
if($CompileOnly){Write-Host 'PASS: native fixture interop compiles';return}
$id=([guid]::NewGuid().ToString('N')+[guid]::NewGuid().ToString('N'))
$marker='RuleProxyGuard-v1:'+$id
$p=Get-StableGuid $id provider;$s=Get-StableGuid $id sublayer;$f=Get-StableGuid $id '4/block'
$foreign=@([guid]::NewGuid().ToString(),[guid]::NewGuid().ToString(),[guid]::NewGuid().ToString())
$dnsName=$null;$foreignDns=$null
try{
    [RecoveryFixture]::Add($p,$s,$f,$marker,$true)
    [RecoveryFixture]::Add($foreign[0],$foreign[1],$foreign[2],'OtherProduct-CI-Fixture',$false)
    $records=@(Read-WfpRecords);$plan=Get-WfpPlan $records
    if(@($plan.Filters | Where-Object {$_.Key -eq $f}).Count -ne 1){throw 'Native owned filter not recognized'}
    if(@($plan.Filters | Where-Object {$_.Key -eq $foreign[2]}).Count){throw 'Native foreign filter targeted'}
    # Tampering between inventory and apply must fail without deleting the filter.
    $record=@($plan.Filters | Where-Object {$_.Key -eq $f})[0];$original=$record.Description;$record.Description='wrong'
    $rejected=$false;try{Invoke-WfpDeleteTransaction @($record)}catch{$rejected=$true};$record.Description=$original
    if(-not $rejected -or -not @(Read-WfpRecords | Where-Object {$_.Key -eq $f}).Count){throw 'WFP identity revalidation failed'}
    Invoke-WfpRepair $plan
    if(@(Read-WfpRecords | Where-Object {$_.Key -eq $f}).Count){throw 'Owned native filter remains'}
    if(@(Read-WfpRecords | Where-Object {$_.Key -eq $foreign[2]}).Count -ne 1){throw 'Foreign native filter removed'}
    Invoke-WfpRepair (Get-WfpPlan @(Read-WfpRecords)) # repeat is harmless
    $foreignRule=Add-DnsClientNrptRule -Namespace '.ruleproxy-foreign.invalid' -NameServers '127.0.0.254' -Comment 'OtherProduct-CI-Fixture' -PassThru -ErrorAction Stop
    $foreignDns=[string]$foreignRule.Name
    $rule=Add-DnsClientNrptRule -Namespace '.' -NameServers $NrptPeers -DisplayName ('RuleProxy global DNS '+$id.Substring(0,16)) -Comment ('RuleProxyDNS-v1:'+$id) -PassThru -ErrorAction Stop
    $dnsName=[string]$rule.Name
    Invoke-NrptRepair (Get-NrptState)
    if(@(Get-DnsClientNrptRule | Where-Object {$_.Name -eq $dnsName}).Count){throw 'Owned native NRPT remains'}
    if(@(Get-DnsClientNrptRule | Where-Object {$_.Name -eq $foreignDns}).Count -ne 1){throw 'Foreign native NRPT removed'}
    # Exercise the complete default read-only entry point, including JSON / exit code.
    $ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $output=& $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ScriptPath -Json
    $code=$LASTEXITCODE;$report=($output -join "`n") | ConvertFrom-Json
    if($code -notin @(0,1) -or $report.mode -ne 'dry-run' -or @($report.changed).Count){throw ('Native full dry-run failed: '+($output -join "`n"))}
    # Recreate real leftovers and exercise the COMPLETE -Apply entry point, not
    # only its component helpers. The unrelated WFP/NRPT fixtures must survive.
    [RecoveryFixture]::Add($p,$s,$f,$marker,$true)
    $rule=Add-DnsClientNrptRule -Namespace '.' -NameServers $NrptPeers -DisplayName ('RuleProxy global DNS '+$id.Substring(0,16)) -Comment ('RuleProxyDNS-v1:'+$id) -PassThru -ErrorAction Stop
    $dnsName=[string]$rule.Name
    $output=& $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ScriptPath -Apply -Json
    $code=$LASTEXITCODE;$report=($output -join "`n") | ConvertFrom-Json
    if($code -notin @(0,1) -or -not $report.log_directory -or @($report.changed).Count -lt 2){throw ('Native full apply failed: '+($output -join "`n"))}
    if(@(Read-WfpRecords | Where-Object {$_.Key -eq $f}).Count -or @(Get-DnsClientNrptRule | Where-Object {$_.Name -eq $dnsName}).Count){throw 'Full apply left owned blocking objects'}
    if(@(Read-WfpRecords | Where-Object {$_.Key -eq $foreign[2]}).Count -ne 1 -or @(Get-DnsClientNrptRule | Where-Object {$_.Name -eq $foreignDns}).Count -ne 1){throw 'Full apply touched foreign objects'}
    # Exercise actual WinINet flags/registry and WinHTTP, restoring the runner in finally.
    $proxyBefore=Get-ProxyState
    if($null -ne $proxyBefore.Previous){throw 'Unexpected RuleProxy journal on disposable runner'}
    try{
        New-ItemProperty -LiteralPath $proxyBefore.Key -Name ProxyEnable -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -LiteralPath $proxyBefore.Key -Name ProxyServer -Value '127.0.0.1:65531' -PropertyType String -Force | Out-Null
        New-ItemProperty -LiteralPath $proxyBefore.Key -Name AutoConfigURL -Value 'http://127.0.0.1:65530/recovery-fixture.pac' -PropertyType String -Force | Out-Null
        [RuleProxyRecover.Native]::Flags(7)
        [RecoveryFixture]::SetHttp(3,'127.0.0.1:65529','')
        $ResetDeadLoopbackProxy=$true
        Invoke-ProxyRepair (Get-ProxyState)
        $afterProxy=Get-ProxyState
        if($afterProxy.DeadManual -or $afterProxy.DeadPac -or $afterProxy.DeadWinHttp -or ($afterProxy.Flags -band 6)){throw 'Native proxy/PAC restoration failed'}
    }finally{
        foreach($name in $proxyBefore.Current.Keys){$v=$proxyBefore.Current[$name];if($null -eq $v){Remove-ItemProperty -LiteralPath $proxyBefore.Key -Name $name -ErrorAction SilentlyContinue}else{New-ItemProperty -LiteralPath $proxyBefore.Key -Name $name -Value $v[0] -PropertyType ([Microsoft.Win32.RegistryValueKind][int]$v[1]) -Force | Out-Null}}
        [RuleProxyRecover.Native]::Flags($proxyBefore.Flags)
        [RecoveryFixture]::SetHttp([uint32]$proxyBefore.WinHttp[0],$proxyBefore.WinHttp[1],$proxyBefore.WinHttp[2])
    }
    Write-Host 'PASS: native owned/foreign WFP and NRPT recovery'
}finally{
    foreach($r in @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue)){
        if([string]$r.Name -in @($dnsName,$foreignDns)){Remove-DnsClientNrptRule -Name ([string]$r.Name) -Force -ErrorAction Stop}
    }
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    [RecoveryFixture]::Cleanup($p,$s,$f)
    [RecoveryFixture]::Cleanup($foreign[0],$foreign[1],$foreign[2])
}
