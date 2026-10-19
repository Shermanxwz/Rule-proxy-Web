# RuleProxy offline recovery. Windows PowerShell 5.1 / native 64-bit Windows.
# Default: inspect only. -Apply: stop verified RuleProxy runtimes, release owned
# WFP / NRPT / TUN routes, and restore the current user's saved system proxy.
# No downloads, Python, reinstall, blanket firewall reset or physical-NIC reset.
# Exit: 0 no owned blockers found; 1 unresolved; 2 not elevated; 3 error.
# Neither exit 0 nor absence of leftovers proves Internet access. Apply can be partial.
[CmdletBinding()]
param(
    [switch]$Apply,
    # Explicit opt-in: may disable a dead local proxy belonging to OTHER software.
    [switch]$ResetDeadLoopbackProxy,
    [switch]$Json,
    [switch]$CheckInternet,
    [switch]$PauseAtEnd,
    [string]$ExpectedUserSid,
    [Parameter(DontShow=$true)][switch]$LibraryOnly
)
$ErrorActionPreference = 'Stop'
$WfpMarkerPrefix = 'RuleProxyGuard-v1:'
$WfpServiceName = 'RuleProxyControl'
$NrptDisplayPrefix = 'RuleProxy global DNS '
$NrptCommentPrefix = 'RuleProxyDNS-v1:'
$NrptPeers = @('198.18.0.2', 'fdfe:dcba:8879::2')
$TunAdapterName = 'RuleProxyTun'
$script:Changed = New-Object System.Collections.ArrayList
$script:Notes = New-Object System.Collections.ArrayList

if (-not ('RuleProxyRecover.Native' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
namespace RuleProxyRecover {
    [StructLayout(LayoutKind.Sequential)] public struct Display { public IntPtr name, description; }
    [StructLayout(LayoutKind.Sequential)] public struct Blob { public uint size; public IntPtr data; }
    [StructLayout(LayoutKind.Sequential)] public struct Provider {
        public Guid key; public Display display; public uint flags; public Blob data; public IntPtr service;
    }
    [StructLayout(LayoutKind.Sequential)] public struct Sublayer {
        public Guid key; public Display display; public ushort flags; public IntPtr provider; public Blob data; public ushort weight;
    }
    // Only the documented prefix is read; no guessed union sizes / XML layout.
    [StructLayout(LayoutKind.Sequential)] public struct FilterHead {
        public Guid key; public Display display; public uint flags; public IntPtr provider; public Blob data;
        public Guid layer, sublayer;
    }
    public class Record {
        public string Kind, Key, ProviderRef, SubLayerRef, Layer, Name, Description, ServiceName;
        public uint Flags; public bool Marked { get { return (Description ?? "").StartsWith("RuleProxyGuard-v1:", StringComparison.Ordinal); } }
        public bool Persistent { get { return (Flags & 1) != 0; } }
    }
    [StructLayout(LayoutKind.Explicit, Size=8)] public struct OptionValue {
        [FieldOffset(0)] public uint number; [FieldOffset(0)] public IntPtr text;
    }
    [StructLayout(LayoutKind.Sequential)] public struct Option { public uint id; public OptionValue value; }
    [StructLayout(LayoutKind.Sequential)] public struct OptionList {
        public uint size; public IntPtr connection; public uint count, error; public IntPtr options;
    }
    [StructLayout(LayoutKind.Sequential)] public struct HttpProxy { public uint access; public IntPtr proxy, bypass; }
    public static class Native {
        [DllImport("fwpuclnt.dll", CharSet=CharSet.Unicode)] public static extern uint FwpmEngineOpen0(string s,uint a,IntPtr i,IntPtr session,out IntPtr h);
        [DllImport("fwpuclnt.dll")] public static extern uint FwpmEngineClose0(IntPtr h);
        [DllImport("fwpuclnt.dll")] public static extern uint FwpmTransactionBegin0(IntPtr h,uint f);
        [DllImport("fwpuclnt.dll")] public static extern uint FwpmTransactionCommit0(IntPtr h);
        [DllImport("fwpuclnt.dll")] public static extern uint FwpmTransactionAbort0(IntPtr h);
        [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr p);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmProviderCreateEnumHandle0(IntPtr h,IntPtr t,out IntPtr e);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerCreateEnumHandle0(IntPtr h,IntPtr t,out IntPtr e);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterCreateEnumHandle0(IntPtr h,IntPtr t,out IntPtr e);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmProviderEnum0(IntPtr h,IntPtr e,uint n,out IntPtr p,out uint c);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerEnum0(IntPtr h,IntPtr e,uint n,out IntPtr p,out uint c);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterEnum0(IntPtr h,IntPtr e,uint n,out IntPtr p,out uint c);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmProviderDestroyEnumHandle0(IntPtr h,IntPtr e);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerDestroyEnumHandle0(IntPtr h,IntPtr e);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDestroyEnumHandle0(IntPtr h,IntPtr e);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmProviderGetByKey0(IntPtr h,ref Guid k,out IntPtr p);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerGetByKey0(IntPtr h,ref Guid k,out IntPtr p);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterGetByKey0(IntPtr h,ref Guid k,out IntPtr p);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmProviderDeleteByKey0(IntPtr h,ref Guid k);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerDeleteByKey0(IntPtr h,ref Guid k);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteByKey0(IntPtr h,ref Guid k);
        [DllImport("wininet.dll", SetLastError=true)] static extern bool InternetQueryOptionW(IntPtr h,uint o,ref OptionList p,ref uint n);
        [DllImport("wininet.dll", SetLastError=true)] static extern bool InternetSetOptionW(IntPtr h,uint o,IntPtr p,uint n);
        [DllImport("wininet.dll", EntryPoint="InternetSetOptionW", SetLastError=true)] static extern bool SetList(IntPtr h,uint o,ref OptionList p,uint n);
        [DllImport("winhttp.dll", SetLastError=true)] static extern bool WinHttpGetDefaultProxyConfiguration(out HttpProxy p);
        [DllImport("winhttp.dll", SetLastError=true)] static extern bool WinHttpSetDefaultProxyConfiguration(ref HttpProxy p);
        [DllImport("kernel32.dll")] static extern IntPtr GlobalFree(IntPtr p);
        [DllImport("shell32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CommandLineToArgvW(string command,out int count);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
        public static string[] Arguments(string command) {
            int n;IntPtr p=CommandLineToArgvW(command,out n);if(p==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
            try{if(n>256)throw new InvalidOperationException("Command line bound");string[] a=new string[n];for(int i=0;i<n;i++)a[i]=S(Marshal.ReadIntPtr(p,i*IntPtr.Size));return a;}finally{LocalFree(p);}
        }
        static string S(IntPtr p) { return p == IntPtr.Zero ? "" : Marshal.PtrToStringUni(p); }
        static string G(IntPtr p) { return p == IntPtr.Zero ? "" : ((Guid)Marshal.PtrToStructure(p,typeof(Guid))).ToString(); }
        static void Check(uint c) { if(c!=0) throw new InvalidOperationException("WFP 0x"+c.ToString("X8")); }
        // PowerShell coerces $null to an empty string for a string parameter.
        // Keep the local-server NULL inside C#, never call that P/Invoke from PS.
        public static IntPtr OpenEngine() {IntPtr h;Check(FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out h));return h;}
        static Record Read(string kind,IntPtr p) {
            Record r=new Record(); r.Kind=kind; r.ProviderRef=""; r.SubLayerRef=""; r.Layer=""; r.ServiceName="";
            Display d;
            if(kind=="provider") { Provider v=(Provider)Marshal.PtrToStructure(p,typeof(Provider)); r.Key=v.key.ToString();r.Flags=v.flags;d=v.display;r.ServiceName=S(v.service); }
            else if(kind=="sublayer") { Sublayer v=(Sublayer)Marshal.PtrToStructure(p,typeof(Sublayer));r.Key=v.key.ToString();r.Flags=v.flags;d=v.display;r.ProviderRef=G(v.provider); }
            else { FilterHead v=(FilterHead)Marshal.PtrToStructure(p,typeof(FilterHead));r.Key=v.key.ToString();r.Flags=v.flags;d=v.display;r.ProviderRef=G(v.provider);r.SubLayerRef=v.sublayer.ToString();r.Layer=v.layer.ToString(); }
            r.Name=S(d.name);r.Description=S(d.description);return r;
        }
        public static Record[] Snapshot() {
            IntPtr h;Check(FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out h));
            List<Record> records=new List<Record>();
            try { foreach(string kind in new string[]{"provider","sublayer","filter"}) {
                IntPtr e;uint rc=kind=="provider"?FwpmProviderCreateEnumHandle0(h,IntPtr.Zero,out e):kind=="sublayer"?FwpmSubLayerCreateEnumHandle0(h,IntPtr.Zero,out e):FwpmFilterCreateEnumHandle0(h,IntPtr.Zero,out e);Check(rc);
                try { while(true) { IntPtr p=IntPtr.Zero;uint c;
                    rc=kind=="provider"?FwpmProviderEnum0(h,e,256,out p,out c):kind=="sublayer"?FwpmSubLayerEnum0(h,e,256,out p,out c):FwpmFilterEnum0(h,e,256,out p,out c);
                    try { Check(rc); if(c>256 || records.Count+c>200000) throw new InvalidOperationException("WFP enumeration bound");
                        for(int j=0;j<c;j++) records.Add(Read(kind,Marshal.ReadIntPtr(p,j*IntPtr.Size)));
                    } finally { if(p!=IntPtr.Zero) FwpmFreeMemory0(ref p); }
                    if(c<256) break;
                }} finally { if(kind=="provider") FwpmProviderDestroyEnumHandle0(h,e);else if(kind=="sublayer") FwpmSubLayerDestroyEnumHandle0(h,e);else FwpmFilterDestroyEnumHandle0(h,e); }
            }} finally { FwpmEngineClose0(h); } return records.ToArray();
        }
        // Called inside a write transaction. Re-read ownership before each delete.
        public static void DeleteChecked(IntPtr h,Record expected) {
            Guid key=new Guid(expected.Key);IntPtr p=IntPtr.Zero;
            uint rc=expected.Kind=="filter"?FwpmFilterGetByKey0(h,ref key,out p):expected.Kind=="sublayer"?FwpmSubLayerGetByKey0(h,ref key,out p):FwpmProviderGetByKey0(h,ref key,out p);
            uint missing=expected.Kind=="filter"?2150760451U:expected.Kind=="sublayer"?2150760455U:2150760453U;
            if(rc==missing) return;
            try { Check(rc);Record actual=Read(expected.Kind,p);
                if(actual.Description!=expected.Description || actual.ProviderRef!=expected.ProviderRef || actual.SubLayerRef!=expected.SubLayerRef || actual.ServiceName!=expected.ServiceName || actual.Flags!=expected.Flags || actual.Layer!=expected.Layer)
                    throw new InvalidOperationException("WFP identity changed; deletion refused");
            } finally { if(p!=IntPtr.Zero) FwpmFreeMemory0(ref p); }
            rc=expected.Kind=="filter"?FwpmFilterDeleteByKey0(h,ref key):expected.Kind=="sublayer"?FwpmSubLayerDeleteByKey0(h,ref key):FwpmProviderDeleteByKey0(h,ref key);Check(rc);
        }
        public static uint Flags() {
            foreach(uint id in new uint[]{10,1}) { Option v=new Option();v.id=id;IntPtr p=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Option)));
                try { Marshal.StructureToPtr(v,p,false);OptionList l=new OptionList();l.size=(uint)Marshal.SizeOf(typeof(OptionList));l.count=1;l.options=p;uint n=l.size;
                    if(InternetQueryOptionW(IntPtr.Zero,75,ref l,ref n)) return ((Option)Marshal.PtrToStructure(p,typeof(Option))).value.number;
                } finally { Marshal.FreeHGlobal(p); }
            } throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        public static void Flags(uint flags) {
            Option v=new Option();v.id=1;v.value.number=flags;IntPtr p=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Option)));
            try { Marshal.StructureToPtr(v,p,false);OptionList l=new OptionList();l.size=(uint)Marshal.SizeOf(typeof(OptionList));l.count=1;l.options=p;
                if(!SetList(IntPtr.Zero,75,ref l,l.size)) throw new Win32Exception(Marshal.GetLastWin32Error());
            } finally { Marshal.FreeHGlobal(p); } Notify();
        }
        public static void Notify() { foreach(uint o in new uint[]{39,37}) if(!InternetSetOptionW(IntPtr.Zero,o,IntPtr.Zero,0)) throw new Win32Exception(Marshal.GetLastWin32Error()); }
        public static string[] WinHttp() {
            HttpProxy p;if(!WinHttpGetDefaultProxyConfiguration(out p)) throw new Win32Exception(Marshal.GetLastWin32Error());
            try{return new string[]{p.access.ToString(),S(p.proxy),S(p.bypass)};} finally {if(p.proxy!=IntPtr.Zero)GlobalFree(p.proxy);if(p.bypass!=IntPtr.Zero)GlobalFree(p.bypass);}
        }
        public static void ResetWinHttp() { HttpProxy p=new HttpProxy();p.access=1;if(!WinHttpSetDefaultProxyConfiguration(ref p))throw new Win32Exception(Marshal.GetLastWin32Error()); }
        public static void StopVerified(int pid,string executable,long ticks) {
            using(Process p=Process.GetProcessById(pid)) { IntPtr held=p.Handle;
                if(!String.Equals(p.MainModule.FileName,executable,StringComparison.OrdinalIgnoreCase) || p.StartTime.ToUniversalTime().Ticks!=ticks)
                    throw new InvalidOperationException("Process identity changed");
                p.Kill(); if(!p.WaitForExit(15000)) throw new InvalidOperationException("Process did not stop");
            }
        }
    }
}
'@
}

function Say([string]$Text) { if (-not $Json) { Write-Host $Text } }
function Note([string]$Text) { [void]$script:Notes.Add($Text); Say ('NOTE: ' + $Text) }
function Changed([string]$Text) { [void]$script:Changed.Add($Text); Say ('CHANGED: ' + $Text) }
function Test-IsAdministrator {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Get-StableGuid([string]$Identity, [string]$Name) {
    # RFC 4122 v5, same byte order as Python uuid.uuid5(_NAMESPACE, identity+'/'+name).
    $ns = [byte[]]@(0xa7,0xab,0x50,0xd9,0x4a,0xb9,0x4c,0xa7,0xac,0x5a,0x2c,0x6e,0x5e,0xcb,0xb6,0x4c)
    $sha = [Security.Cryptography.SHA1]::Create()
    try { $bytes = $sha.ComputeHash([byte[]]($ns + [Text.Encoding]::UTF8.GetBytes($Identity + '/' + $Name))) } finally { $sha.Dispose() }
    $bytes[6] = ($bytes[6] -band 15) -bor 80; $bytes[8] = ($bytes[8] -band 63) -bor 128
    $hex = ([BitConverter]::ToString($bytes[0..15])).Replace('-','').ToLowerInvariant()
    return $hex.Substring(0,8)+'-'+$hex.Substring(8,4)+'-'+$hex.Substring(12,4)+'-'+$hex.Substring(16,4)+'-'+$hex.Substring(20)
}
function Get-WfpPlan($Records) {
    $providers = @{}; $sublayers = @{}; $filters = @{}; $unresolved = @(); $blocked = @{}
    foreach ($r in $Records) {
        if (-not $r.Marked -or $r.Kind -ne 'provider') { continue }
        $id = $r.Description.Substring($WfpMarkerPrefix.Length)
        if ($id -cmatch '^[0-9a-f]{64}$' -and $r.Persistent -and $r.ServiceName -ceq $WfpServiceName -and $r.Key -eq (Get-StableGuid $id 'provider')) { $providers[$r.Key]=$r }
        else { $unresolved += $r }
    }
    foreach ($r in $Records) {
        if (-not $r.Marked -or $r.Kind -eq 'provider') { continue }
        if (-not $providers.ContainsKey($r.ProviderRef)) { $unresolved += $r; continue }
        $p=$providers[$r.ProviderRef]; $id=$p.Description.Substring($WfpMarkerPrefix.Length)
        $own = $r.Description -ceq $p.Description
        if ($r.Kind -eq 'sublayer') {
            if ($own -and $r.Key -eq (Get-StableGuid $id 'sublayer')) { $sublayers[$r.Key]=$r } else { $unresolved += $r }
        } else {
            $keyMatches=$false
            foreach ($family in @(4,6)) {
                $names=@('loopback','core-system','block','tun-outbound','tun-reauthorize')
                if ($family -eq 4) { $names += 'dhcp4' } else { $names += @('dhcp6-0','dhcp6-1','dhcp6-linklocal'); foreach($n in @(133,135,136)){foreach($s in @('multicast','linklocal')){$names += 'ndp-'+$n+'-'+$s}} }
                $layer=if($family -eq 4){'c38d57d1-05a7-4c33-904f-7fbceee60e82'}else{'4a72393b-319f-44bc-84c3-ba54dcb3b6b4'}
                foreach($name in $names){if($r.Key -eq (Get-StableGuid $id ($family.ToString()+'/'+$name)) -and $r.Layer -eq $layer){$keyMatches=$true}}
            }
            if ($own -and $keyMatches -and $r.SubLayerRef -eq (Get-StableGuid $id 'sublayer')) { $filters[$r.Key]=$r } else { $unresolved += $r }
        }
    }
    foreach($r in $Records){
        if($r.Kind -eq 'provider' -or $filters.ContainsKey($r.Key) -or $sublayers.ContainsKey($r.Key)){continue}
        if($providers.ContainsKey($r.ProviderRef)){$blocked[$r.ProviderRef]=$true}
        if($sublayers.ContainsKey($r.SubLayerRef)){$blocked[$sublayers[$r.SubLayerRef].ProviderRef]=$true}
    }
    return [pscustomobject]@{Filters=@($filters.Values);Sublayers=@($sublayers.Values | Where-Object {-not $blocked.ContainsKey($_.ProviderRef)});Providers=@($providers.Values | Where-Object {-not $blocked.ContainsKey($_.Key)});Unresolved=@($unresolved)}
}
function Read-WfpRecords { return [RuleProxyRecover.Native]::Snapshot() }
function Invoke-WfpDeleteTransaction($Records) {
    if(@($Records).Count -eq 0){return}
    $engine=[RuleProxyRecover.Native]::OpenEngine(); $committed=$false
    try {
        $rc=[RuleProxyRecover.Native]::FwpmTransactionBegin0($engine,0);if($rc){throw ('WFP begin 0x'+$rc.ToString('X8'))}
        try {
            foreach($r in $Records){[RuleProxyRecover.Native]::DeleteChecked($engine,$r)}
            $rc=[RuleProxyRecover.Native]::FwpmTransactionCommit0($engine);if($rc){throw ('WFP commit 0x'+$rc.ToString('X8'))};$committed=$true
        } finally {if(-not $committed){[void][RuleProxyRecover.Native]::FwpmTransactionAbort0($engine)}}
    } finally {[void][RuleProxyRecover.Native]::FwpmEngineClose0($engine)}
}
function Invoke-WfpRepair($Plan) {
    # Network-blocking filters commit independently of cosmetic provider cleanup.
    Invoke-WfpDeleteTransaction $Plan.Filters
    if($Plan.Filters.Count){Changed ('WFP filters: '+$Plan.Filters.Count)}
    foreach($r in @($Plan.Sublayers)+@($Plan.Providers)){
        try{Invoke-WfpDeleteTransaction @($r);Changed ($r.Kind+': '+$r.Key)}catch{Note ('Empty WFP container retained: '+$_.Exception.Message)}
    }
}
function Get-NormalIps($Values) {
    foreach($v in @($Values)){foreach($part in ([string]$v -split '[,;\s]+')){if($part){$ip=$null;if(-not [Net.IPAddress]::TryParse($part,[ref]$ip)){throw 'Invalid DNS address'};$ip.ToString().ToLowerInvariant()}}}
}
function Test-NrptCandidate($Rule) {
    $comment=[string]$Rule.Comment; $display=[string]$Rule.DisplayName
    if($comment -cnotmatch '^RuleProxyDNS-v1:([0-9a-f]{64})$'){return $false}
    $id=$Matches[1]
    foreach($name in @('DirectAccessEnabled','DnsSecEnable','DnsSecValidationRequired','DnsSecIPsecRequired','DnsSecQueryIPsecRequired')){if($Rule.$name -eq $true){return $false}}
    if(@($Rule.DirectAccessDnsServers | Where-Object {[string]$_}).Count -or [string]$Rule.DirectAccessProxyName){return $false}
    if([string]$Rule.DirectAccessProxyType -and [string]$Rule.DirectAccessProxyType -ne 'NoProxy'){return $false}
    $ips=@(Get-NormalIps $Rule.NameServers | Sort-Object -Unique)
    return ($display -ceq ($NrptDisplayPrefix+$id.Substring(0,16)) -and @($Rule.Namespace).Count -eq 1 -and [string]$Rule.Namespace[0] -ceq '.' -and $ips.Count -eq 2 -and $ips -contains $NrptPeers[0] -and $ips -contains $NrptPeers[1])
}
function Get-NrptState {
    # Failure to read effective policy is an ERROR, never an empty/clean result.
    $rules=@(Get-DnsClientNrptRule -ErrorAction Stop);$effective=@(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop)
    $candidates=@();$unresolved=@();$virtual=@()
    foreach($r in $rules){
        if(Test-NrptCandidate $r){$candidates+=$r}
        elseif(([string]$r.Comment).StartsWith($NrptCommentPrefix) -or ([string]$r.DisplayName).StartsWith($NrptDisplayPrefix)){$unresolved+=$r}
    }
    foreach($r in $effective){if(@(Get-NormalIps $r.NameServers | Where-Object {$NrptPeers -contains $_}).Count){$virtual+=$r}}
    return [pscustomobject]@{Candidates=$candidates;Unresolved=$unresolved;Virtual=$virtual}
}
function Invoke-NrptRepair($State) {
    foreach($r in $State.Candidates){
        $now=@(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object {[string]$_.Name -ceq [string]$r.Name})
        if(-not $now.Count){continue} # The stopped control service may have restored it already.
        if($now.Count -ne 1 -or -not (Test-NrptCandidate $now[0]) -or [string]$now[0].Comment -cne [string]$r.Comment){throw 'NRPT identity changed'}
        Remove-DnsClientNrptRule -Name ([string]$r.Name) -Force -ErrorAction Stop
        Changed ('NRPT: '+$r.Name)
    }
    Clear-DnsClientCache -ErrorAction Stop
    for($i=0;$i -lt 5;$i++){$after=Get-NrptState;if(-not $after.Candidates.Count -and -not $after.Virtual.Count){return};if($i -lt 4){Start-Sleep -Seconds 1}}
    throw 'NRPT still effective; changes already made are recorded. Domain policy may require its administrator.'
}
function Assert-NoReparse([string]$Path) {
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    while($item){if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse path refused'};if($item -is [IO.FileInfo]){$item=$item.Directory}else{$item=$item.Parent}}
}
function Assert-ProtectedFile([string]$Path) {
    Assert-NoReparse $Path
    $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
    if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'Installation ownership record is not protected'}
    foreach($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
        if($ace.AccessControlType -eq 'Allow' -and $ace.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -and ([long]$ace.FileSystemRights -band 0x000D0156)){throw 'Installation ownership record is writable by another principal'}
    }
}
function Get-InstallRoots {
    $roots=@();$default=Join-Path $env:ProgramFiles 'RuleProxy-Web'
    if(Test-Path -LiteralPath $default){Assert-NoReparse $default;$roots+=$default}
    $services=@(Get-CimInstance Win32_Service -Filter "Name='RuleProxyControl'" -ErrorAction Stop)
    foreach($s in $services){
        $args=@([RuleProxyRecover.Native]::Arguments([string]$s.PathName))
        if($args.Count -ne 5 -or $args[0] -notmatch '^[A-Za-z]:\\' -or $args[0] -notlike '*\python\python.exe'){throw 'RuleProxyControl identity is not recognized; no changes made'}
        $root=[IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($args[0]))
        if($args[1] -cne '-I' -or $args[2] -cne '-S' -or $args[3] -ine (Join-Path $root 'ruleproxy\windows_proxy_service.py') -or $args[4] -cne '--service' -or $s.StartName -notin @('LocalSystem','NT AUTHORITY\SYSTEM')){throw 'RuleProxyControl command/owner mismatch'}
        if($root -ne $default -and (Test-Path -LiteralPath (Join-Path $root 'deployment.json'))){
            Assert-ProtectedFile (Join-Path $root 'deployment.json');$d=Get-Content -LiteralPath (Join-Path $root 'deployment.json') -Raw | ConvertFrom-Json
            if($d.schema_version -ne 1 -or $d.root -ne $root -or $d.service_name -ne $WfpServiceName){throw 'Custom installation identity invalid'}
        }
        if(Test-Path -LiteralPath $root){Assert-NoReparse $root};$roots+=$root
    }
    return [pscustomobject]@{Roots=@($roots | Select-Object -Unique);Services=$services}
}
function Get-RuntimeState {
    $install=Get-InstallRoots;$processes=@();$unknown=@();$engineServices=@();$autoruns=@()
    foreach($p in @(Get-CimInstance Win32_Process -ErrorAction Stop)){
        $owned=$false
        foreach($root in $install.Roots){
            if($p.ExecutablePath -ieq (Join-Path $root 'bin\windows-amd64\mihomo.exe')){$owned=$true}
            if($p.ExecutablePath -iin @((Join-Path $root 'python\python.exe'),(Join-Path $root 'python\pythonw.exe')) -and $p.CommandLine){$args=@([RuleProxyRecover.Native]::Arguments([string]$p.CommandLine));if($args -icontains (Join-Path $root 'Run-RuleProxy.py')){$owned=$true}}
        }
        if($owned){
            $live=Get-Process -Id $p.ProcessId -ErrorAction Stop
            $processes += [pscustomobject]@{Id=[int]$p.ProcessId;Path=[string]$p.ExecutablePath;Ticks=$live.StartTime.ToUniversalTime().Ticks}
        }elseif($p.Name -ieq 'mihomo.exe'){$unknown+=[int]$p.ProcessId}
    }
    $engine=@(Get-CimInstance Win32_Service -Filter "Name='ProxiFyreService'" -ErrorAction Stop)
    $statePath=Join-Path $env:ProgramData 'RuleProxy-Web\install-state.json'
    if($engine.Count -and (Test-Path -LiteralPath $statePath)){
        Assert-ProtectedFile $statePath;$state=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        if($state.schema_version -eq 1 -and $state.proxifyre_owned -eq $true -and $install.Roots -icontains $state.root){
            foreach($s in $engine){$a=@([RuleProxyRecover.Native]::Arguments([string]$s.PathName));$expected=Join-Path ([string]$state.proxifyre_root) 'ProxiFyre.exe';if($a.Count -in @(1,2) -and $a[0] -ieq $expected -and ($a.Count -eq 1 -or $a[1] -ceq 'run') -and $s.StartName -in @('LocalSystem','NT AUTHORITY\SYSTEM')){$engineServices+=$s}}
        }
    }
    foreach($h in @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Stop)){
        $key='Registry::HKEY_USERS\'+$h.PSChildName+'\Software\Microsoft\Windows\CurrentVersion\Run'
        $e=Get-ItemProperty -LiteralPath $key -Name 'RuleProxy Web' -ErrorAction SilentlyContinue
        if($e){$a=@([RuleProxyRecover.Native]::Arguments([string]$e.'RuleProxy Web'));foreach($root in $install.Roots){if($a.Count -and $a[0] -iin @((Join-Path $root 'python\pythonw.exe'),(Join-Path $root 'python\python.exe')) -and $a -icontains (Join-Path $root 'Run-RuleProxy.py')){$autoruns += [pscustomobject]@{Key=$key;Value=[string]$e.'RuleProxy Web'};break}}}
    }
    return [pscustomobject]@{Roots=$install.Roots;Services=$install.Services;EngineServices=$engineServices;Autoruns=$autoruns;Processes=$processes;ForeignMihomo=$unknown}
}
function Invoke-RuntimeRepair($State) {
    foreach($s in $State.Services){
        $now=Get-CimInstance Win32_Service -Filter "Name='RuleProxyControl'" -ErrorAction Stop
        if($now.PathName -cne $s.PathName){throw 'Service identity changed'}
        Set-Service -Name $WfpServiceName -StartupType Disabled -ErrorAction Stop
        Changed 'RuleProxyControl startup disabled'
        if((Get-Service -Name $WfpServiceName).Status -ne 'Stopped'){Stop-Service -Name $WfpServiceName -ErrorAction Stop;(Get-Service -Name $WfpServiceName).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))}
        Changed 'RuleProxyControl stopped and disabled (reinstall/repair to re-enable)'
    }
    foreach($s in $State.EngineServices){
        $now=Get-CimInstance Win32_Service -Filter "Name='ProxiFyreService'" -ErrorAction Stop
        if($now.PathName -cne $s.PathName){throw 'ProxiFyre service identity changed'}
        Set-Service -Name ProxiFyreService -StartupType Disabled -ErrorAction Stop
        Changed 'Owned ProxiFyre startup disabled'
        if((Get-Service ProxiFyreService).Status -ne 'Stopped'){Stop-Service ProxiFyreService -ErrorAction Stop;(Get-Service ProxiFyreService).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))}
        Changed 'Owned ProxiFyre service stopped and disabled; shared driver retained'
    }
    foreach($p in $State.Processes){
        if(Get-Process -Id $p.Id -ErrorAction SilentlyContinue){[RuleProxyRecover.Native]::StopVerified($p.Id,$p.Path,$p.Ticks);Changed ('RuleProxy process: '+$p.Id)}
    }
    # Only the product's named login entry, with a verified installation path.
    foreach($entry in $State.Autoruns){
        $now=Get-ItemProperty -LiteralPath $entry.Key -Name 'RuleProxy Web' -ErrorAction SilentlyContinue
        if($now -and [string]$now.'RuleProxy Web' -cne $entry.Value){throw 'Login entry changed'}
        if($now){Remove-ItemProperty -LiteralPath $entry.Key -Name 'RuleProxy Web' -ErrorAction Stop;Changed 'Owned RuleProxy login entry removed'}
    }
}
function Get-AdapterState {
    $md5=[Security.Cryptography.MD5]::Create()
    try{$guid=New-Object Guid(,$md5.ComputeHash([Text.Encoding]::UTF8.GetBytes('wintun'+$TunAdapterName)))}finally{$md5.Dispose()}
    $owned=@();$unresolved=@()
    foreach($a in @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {$_.Name -eq $TunAdapterName})){
        if([guid]$a.InterfaceGuid -eq $guid){$owned+=$a}else{$unresolved+=$a}
    }
    return [pscustomobject]@{Owned=$owned;Unresolved=$unresolved}
}
function Invoke-AdapterRepair($State) {
    foreach($a in $State.Owned){
        $now=Get-AdapterState
        if(-not @($now.Owned | Where-Object {$_.InterfaceGuid -eq $a.InterfaceGuid}).Count -and -not $now.Unresolved.Count){continue}
        if(@($now.Owned | Where-Object {$_.InterfaceGuid -eq $a.InterfaceGuid -and $_.ifIndex -eq $a.ifIndex}).Count -ne 1){throw 'TUN interface identity changed'}
        # No physical adapter, global routing table or shared driver is reset.
        foreach($store in @('ActiveStore','PersistentStore')){
            foreach($r in @(Get-NetRoute -PolicyStore $store -ErrorAction Stop | Where-Object {$_.InterfaceIndex -eq $a.ifIndex -and $_.Protocol -eq 'NetMgmt'})){
                $r | Remove-NetRoute -Confirm:$false -ErrorAction Stop
                Changed ('Owned TUN route removed: '+$r.DestinationPrefix+' @ '+$a.ifIndex+' ['+$store+']')
            }
        }
        # Remove the owned dead-end routes even if the driver later refuses disable.
        Disable-NetAdapter -InputObject $a -Confirm:$false -ErrorAction Stop
        Changed ('Owned TUN disabled; owned-interface manual routes removed: '+$a.InterfaceGuid)
    }
}
function Get-LoopbackPorts([string]$Server) {
    $ports=@()
    foreach($p in ($Server -split ';')){
        if(-not $p.Trim()){continue};$part=($p -split '=',2)[-1].Trim()
        if($part -notmatch '^(?:127\.0\.0\.1|localhost|\[::1\]):([0-9]{1,5})$'){return $null}
        $n=[int]$Matches[1];if($n -lt 1 -or $n -gt 65535){return $null};$ports+=$n
    }
    if(-not $ports.Count){return $null};return ,$ports
}
function Test-DeadLocalProxy([string]$Server) {
    $ports=Get-LoopbackPorts $Server;if($null -eq $ports){return $false}
    $listeners=@([Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners())
    foreach($port in $ports){if(@($listeners | Where-Object {$_.Port -eq $port}).Count){return $false}}
    return $true
}
function Read-ProxyValues([string]$Key) {
    $values=[ordered]@{};$registry=Get-Item -LiteralPath $Key -ErrorAction Stop
    foreach($name in @('ProxyEnable','ProxyServer','ProxyOverride','AutoConfigURL','AutoDetect')){
        if($registry.GetValueNames() -contains $name){$values[$name]=@($registry.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames),[int]$registry.GetValueKind($name))}else{$values[$name]=$null}
    };return $values
}
function Test-ValueEqual($A,$B) { return (ConvertTo-Json -InputObject $A -Compress) -ceq (ConvertTo-Json -InputObject $B -Compress) }
function Test-ProxyRestoreEqual($Observed,$Expected,[bool]$FlagsTracked) {
    foreach($name in @('ProxyEnable','ProxyServer','ProxyOverride','AutoConfigURL','AutoDetect')){
        # WinINet can remove the legacy AutoDetect value when setting actual LAN flags.
        if($name -eq 'AutoDetect' -and $FlagsTracked -and $null -eq $Observed[$name]){continue}
        if(-not (Test-ValueEqual $Observed[$name] $Expected[$name])){return $false}
    };return $true
}
function Get-ProxyState {
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $key='Registry::HKEY_USERS\'+$sid+'\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $current=Read-ProxyValues $key;$flags=[RuleProxyRecover.Native]::Flags();$previous=$null;$previousFlags=$null;$journalPath=$null
    $profile=Get-ItemProperty -LiteralPath ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\'+$sid) -ErrorAction SilentlyContinue
    if($profile){$journalPath=Join-Path ([Environment]::ExpandEnvironmentVariables($profile.ProfileImagePath)) 'AppData\Local\RuleProxyWebSafe\system-proxy.json'}
    if($journalPath -and (Test-Path -LiteralPath $journalPath)){
        Assert-NoReparse $journalPath;$file=Get-Item -LiteralPath $journalPath;if($file.Length -gt 65536){throw 'Proxy journal too large'}
        $j=Get-Content -LiteralPath $journalPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $hasSchema=$j.PSObject.Properties.Name -contains 'schema'
        if(($hasSchema -and ($j.schema -ne 1 -or $j.phase -notin @('active','applying'))) -or $j.kind -ne 'wininet' -or $j.port -lt 1025 -or $j.port -gt 65535){throw 'Proxy journal invalid'}
        $expected=[ordered]@{ProxyEnable=@(1,4);ProxyServer=@(('127.0.0.1:'+$j.port),1);ProxyOverride=@('localhost;127.0.0.1;::1;10.*;172.16.*;192.168.*;<local>',1);AutoConfigURL=$null;AutoDetect=@(0,4)}
        foreach($name in $expected.Keys){
            if(-not ($j.previous.PSObject.Properties.Name -contains $name) -or ($hasSchema -and (-not ($j.target.PSObject.Properties.Name -contains $name) -or -not (Test-ValueEqual $j.target.$name $expected[$name])))){throw 'Proxy journal target invalid'}
            $v=$j.previous.$name
            if($null -ne $v){if(@($v).Count -ne 2){throw 'Proxy journal value invalid'};if($name -in @('ProxyEnable','AutoDetect')){if($v[1] -ne 4 -or $v[0] -notin @(0,1)){throw 'Proxy journal DWORD invalid'}}elseif($v[1] -notin @(1,2) -or $v[0] -isnot [string] -or $v[0].Length -gt 16384){throw 'Proxy journal text invalid'}}
            if($name -eq 'AutoDetect' -and $j.connection_flags -and $null -eq $current[$name]){continue}
            if(-not (Test-ValueEqual $current[$name] $v) -and -not (Test-ValueEqual $current[$name] $expected[$name])){throw 'System proxy changed outside RuleProxy; refusing overwrite'}
        }
        $previous=[ordered]@{};foreach($name in $expected.Keys){$previous[$name]=$j.previous.$name}
        if($j.connection_flags){
            if($j.connection_flags.target -ne 3 -or $j.connection_flags.previous -isnot [ValueType] -or $j.connection_flags.previous -lt 0 -or $j.connection_flags.previous -gt [uint32]::MaxValue){throw 'Proxy journal flags invalid'}
            $previousFlags=[uint32]$j.connection_flags.previous
            if($flags -ne 3 -and $flags -ne $previousFlags){throw 'WinINet flags conflict'}
        }
    }
    $manual=(($flags -band 2) -ne 0 -and $current.ProxyServer -and (Test-DeadLocalProxy ([string]$current.ProxyServer[0])))
    $pac=$false
    if(($flags -band 4) -and $current.AutoConfigURL -and $current.AutoConfigURL[0]){
        $uri=$null;if([Uri]::TryCreate([string]$current.AutoConfigURL[0],[UriKind]::Absolute,[ref]$uri) -and $uri.IsLoopback -and $uri.Scheme -in @('http','https')){$server=$uri.Host;if($server.Contains(':')){$server='['+$server.Trim('[',']')+']'};$pac=Test-DeadLocalProxy ($server+':'+$uri.Port)}
    }
    $http=@([RuleProxyRecover.Native]::WinHttp());$httpDead=($http[0] -eq '3' -and (Test-DeadLocalProxy $http[1]))
    $otherOwned=@()
    foreach($h in @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS')){
        if($h.PSChildName -eq $sid -or $h.PSChildName -notmatch '^S-1-5-21-'){continue}
        $p=Get-ItemProperty -LiteralPath ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\'+$h.PSChildName) -ErrorAction SilentlyContinue
        if($p -and (Test-Path -LiteralPath (Join-Path ([Environment]::ExpandEnvironmentVariables($p.ProfileImagePath)) 'AppData\Local\RuleProxyWebSafe\system-proxy.json'))){$otherOwned+=$h.PSChildName}
    }
    return [pscustomobject]@{Key=$key;Current=$current;Flags=$flags;Previous=$previous;PreviousFlags=$previousFlags;DeadManual=[bool]$manual;DeadPac=$pac;WinHttp=$http;DeadWinHttp=[bool]$httpDead;OtherUserJournals=$otherOwned}
}
function Invoke-ProxyRepair($State) {
    $values=Read-ProxyValues $State.Key;$flagsNow=[RuleProxyRecover.Native]::Flags()
    $alreadyRestored=($null -ne $State.Previous -and (Test-ProxyRestoreEqual $values $State.Previous ($null -ne $State.PreviousFlags)) -and ($null -eq $State.PreviousFlags -or $flagsNow -eq $State.PreviousFlags))
    if(-not $alreadyRestored -and (-not (Test-ValueEqual $values $State.Current) -or $flagsNow -ne $State.Flags)){throw 'Proxy settings changed since preflight'}
    if($null -ne $State.Previous -and -not $alreadyRestored){
        foreach($name in $State.Previous.Keys){
            $v=$State.Previous[$name];$current=Read-ProxyValues $State.Key
            if(Test-ValueEqual $current[$name] $v){continue}
            if($null -eq $v){Remove-ItemProperty -LiteralPath $State.Key -Name $name -ErrorAction Stop}else{New-ItemProperty -LiteralPath $State.Key -Name $name -Value $v[0] -PropertyType ([Microsoft.Win32.RegistryValueKind][int]$v[1]) -Force -ErrorAction Stop | Out-Null}
            if(-not (Test-ValueEqual (Read-ProxyValues $State.Key)[$name] $v)){throw ('Proxy field readback failed: '+$name)}
            Changed ('Current-user proxy field restored: '+$name)
        }
        if($null -ne $State.PreviousFlags){[RuleProxyRecover.Native]::Flags($State.PreviousFlags)}else{[RuleProxyRecover.Native]::Notify()}
        if(-not (Test-ProxyRestoreEqual (Read-ProxyValues $State.Key) $State.Previous ($null -ne $State.PreviousFlags))){throw 'Proxy restore readback failed'}
        if($null -ne $State.PreviousFlags -and [RuleProxyRecover.Native]::Flags() -ne $State.PreviousFlags){throw 'Proxy flags restore readback failed'}
        Changed 'Current user system proxy restored from RuleProxy journal (journal retained)'
    }elseif($null -eq $State.Previous -and $ResetDeadLoopbackProxy){
        $flags=[uint32]$State.Flags
        if($State.DeadManual){Set-ItemProperty -LiteralPath $State.Key -Name ProxyEnable -Value 0 -ErrorAction Stop;$flags=($flags -band 13) -bor 1;Changed 'Explicit opt-in: dead current-user manual loopback proxy disabled'}
        if($State.DeadPac){Set-ItemProperty -LiteralPath $State.Key -Name AutoConfigURL -Value '' -ErrorAction Stop;$flags=($flags -band 11) -bor 1;Changed 'Explicit opt-in: dead current-user loopback PAC disabled'}
        if($State.DeadManual -or $State.DeadPac){[RuleProxyRecover.Native]::Flags($flags);if([RuleProxyRecover.Native]::Flags() -ne $flags){throw 'WinINet reset readback failed'}}
    }
    if($ResetDeadLoopbackProxy -and $State.DeadWinHttp){
        if(-not (Test-ValueEqual @([RuleProxyRecover.Native]::WinHttp()) $State.WinHttp)){throw 'WinHTTP settings changed'}
        [RuleProxyRecover.Native]::ResetWinHttp();if(@([RuleProxyRecover.Native]::WinHttp())[0] -ne '1'){throw 'WinHTTP reset readback failed'};Changed 'Explicit opt-in: dead machine WinHTTP loopback proxy reset'
    }
}
function Get-RecoveryState {
    # Complete read-only preflight before ANY networking change.
    return [pscustomobject]@{Runtime=Get-RuntimeState;Wfp=Get-WfpPlan @(Read-WfpRecords);Dns=Get-NrptState;Adapter=Get-AdapterState;Proxy=Get-ProxyState}
}
function New-RecoveryLog($State) {
    $base=Join-Path $env:ProgramData 'RuleProxy-Network-Recovery'
    if(Test-Path -LiteralPath $base){Assert-NoReparse $base}else{New-Item -ItemType Directory -Path $base | Out-Null}
    $acl=New-Object Security.AccessControl.DirectorySecurity;$acl.SetAccessRuleProtection($true,$false)
    foreach($sid in @('S-1-5-32-544','S-1-5-18')){$id=New-Object Security.Principal.SecurityIdentifier($sid);$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))}
    Set-Acl -LiteralPath $base -AclObject $acl
    $dir=Join-Path $base ((Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $dir | Out-Null
    # Diagnostics/settings backup, NOT a promise to recreate WFP filters or undo process termination.
    $State | Export-Clixml -LiteralPath (Join-Path $dir 'before.clixml') -Depth 12 -ErrorAction Stop
    return $dir
}
function Get-Blockers($State) {
    $items=@()
    if($State.Wfp.Filters.Count){$items+='Owned WFP filters: '+$State.Wfp.Filters.Count}
    if($State.Wfp.Unresolved.Count){$items+='Unrecognized marked WFP objects: '+$State.Wfp.Unresolved.Count}
    if($State.Dns.Candidates.Count -or $State.Dns.Virtual.Count -or $State.Dns.Unresolved.Count){$items+='Owned/virtual/unresolved DNS policy remains'}
    if($State.Runtime.Processes.Count -or $State.Runtime.Autoruns.Count -or @(@($State.Runtime.Services)+@($State.Runtime.EngineServices) | Where-Object {$null -ne $_ -and ($_.State -ne 'Stopped' -or $_.StartMode -ne 'Disabled')}).Count){$items+='RuleProxy runtime still enabled/running'}
    if(@($State.Adapter.Owned | Where-Object {$_.Status -ne 'Disabled'}).Count -or $State.Adapter.Unresolved.Count){$items+='Active or unverified RuleProxy TUN adapter remains'}
    if($null -ne $State.Proxy.Previous -and (-not (Test-ProxyRestoreEqual $State.Proxy.Current $State.Proxy.Previous ($null -ne $State.Proxy.PreviousFlags)) -or ($null -ne $State.Proxy.PreviousFlags -and $State.Proxy.Flags -ne $State.Proxy.PreviousFlags))){$items+='Saved RuleProxy user proxy has not been restored'}
    if($State.Proxy.DeadManual -or $State.Proxy.DeadPac -or $State.Proxy.DeadWinHttp){$items+='Dead loopback proxy/PAC remains; ownership unknown, explicit reset required'}
    if($State.Proxy.OtherUserJournals.Count){$items+='Other logged-in user has a RuleProxy recovery journal: run as that user; do not elevate using a different account'}
    return $items
}
function Invoke-InternetCheck {
    # Opt-in external, bounded HTTP probes. Never used as an excuse for broader resets.
    $results=@()
    foreach($url in @('https://www.microsoft.com/','https://www.baidu.com/')){
        try{$r=Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 8 -MaximumRedirection 3 -ErrorAction Stop;$results += [pscustomobject]@{url=$url;ok=($r.StatusCode -ge 200 -and $r.StatusCode -lt 400)}}catch{$results += [pscustomobject]@{url=$url;ok=$false}}
    };return $results
}
function Invoke-Recovery {
    $script:Changed.Clear();$script:Notes.Clear()
    $summary=[ordered]@{schema=2;mode=$(if($Apply){'apply'}else{'dry-run'});exit_code=3;network_verified=$false;changed=@();notes=@();blockers=@();log_directory=$null;error=$null}
    $mutex=$null;$held=$false
    try{
        $mutex=New-Object Threading.Mutex($false,'Global\RuleProxyNetworkRecovery-v2')
        try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException] {$held=$true}
        if(-not $held){throw 'Another recovery is running'}
        $before=Get-RecoveryState;$summary.blockers=@(Get-Blockers $before)
        Say ('Mode: '+$summary.mode);foreach($b in $summary.blockers){Say ('FOUND: '+$b)}
        if($before.Runtime.ForeignMihomo.Count){Note 'Unrelated Mihomo processes retained'}
        if($Apply){
            $summary.log_directory=New-RecoveryLog $before
            # Exceptions stop later phases. Already committed changes are NEVER called rolled back.
            Invoke-RuntimeRepair $before.Runtime
            Invoke-WfpRepair $before.Wfp
            Invoke-NrptRepair $before.Dns
            Invoke-AdapterRepair $before.Adapter
            Invoke-ProxyRepair $before.Proxy
            $after=Get-RecoveryState;$summary.blockers=@(Get-Blockers $after)
        }
        $summary.exit_code=0;if($summary.blockers.Count){$summary.exit_code=1}
        if($CheckInternet){$summary['connectivity']=@(Invoke-InternetCheck);$summary.network_verified=@($summary.connectivity | Where-Object {$_.ok}).Count -gt 0;if(-not $summary.network_verified -and $summary.exit_code -eq 0){$summary.exit_code=1}}
    }catch{$summary.error=$_.Exception.Message;$summary.exit_code=3;Say ('ERROR: '+$summary.error)}
    finally{if($held){$mutex.ReleaseMutex()};if($mutex){$mutex.Dispose()}}
    $summary.changed=@($script:Changed);$summary.notes=@($script:Notes)
    if($summary.log_directory){try{$summary | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $summary.log_directory 'result.json') -Encoding UTF8 -ErrorAction Stop}catch{$summary.exit_code=3;$summary.error='Could not persist final result; see console'}}
    if($Json){[Console]::Out.WriteLine(($summary | ConvertTo-Json -Depth 12))}else{
        Say ('Exit: '+$summary.exit_code+'; changes: '+$summary.changed.Count)
        if($summary.log_directory){Say ('Private diagnostics: '+$summary.log_directory)}
        if(-not $Apply){Say 'Inspection only. To repair: run this same script with -Apply.'}
        Say 'Exit 0 means no detected blockers, NOT proof of Internet. Use -CheckInternet for optional probes.'
        if($summary.exit_code -ne 0){Say 'Keep the report. Do not blanket-reset Windows Firewall, all DNS, routes or shared drivers.'}
    }
    return [int]$summary.exit_code
}
if($LibraryOnly){return}
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or [IntPtr]::Size -ne 8){Write-Error 'Use native 64-bit Windows PowerShell on Windows';exit 3}
$env:PSModulePath=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules'
if(-not (Test-IsAdministrator)){
    if($Json){'{"schema":2,"exit_code":2,"changed":[],"error":"Administrator elevation required"}'}else{Write-Host 'Open PowerShell as administrator using the affected Windows account, then run again. Nothing changed.'};exit 2
}
if($ExpectedUserSid -and [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $ExpectedUserSid){Write-Host 'UAC switched Windows accounts. No changes made. Use the affected account with administrator elevation.';if($PauseAtEnd){$null=Read-Host 'Press Enter to close'};exit 2}
$exitCode=Invoke-Recovery
if($PauseAtEnd -and -not $Json){$null=Read-Host 'Press Enter to close'}
exit $exitCode
