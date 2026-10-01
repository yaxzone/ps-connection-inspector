function Get-ConnectionProcess {
    <#
    .SYNOPSIS
        Shows which processes own this machine's network connections and what they are talking to.

    .DESCRIPTION
        Two modes:

          Live (default)  Established TCP connections right now (Get-NetTCPConnection), joined to
                          process details: arguments, hosted services, owner, parent, signature, hash.
          -History        Every TCP and UDP connection Sysmon recorded in the last -LastMinutes,
                          grouped per process and remote endpoint, including processes that have
                          already exited.

        RemoteHost comes from the best source available. HostSource says which, most to least reliable:

          ProcessDns  This process asked for that name and got that address (Sysmon event 22).
          OtherDns    A different process asked for that name (history mode only).
          DnsCache    The name is in the Windows DNS cache for that address; any process may have asked.
          PTR         Reverse record only. For CDN and cloud addresses this names the provider, not the site.

        Limits worth knowing:

          - Live mode is a point-in-time snapshot and TCP only. Short-lived connections and UDP
            (QUIC/HTTP3, DNS) only show up with -History.
          - The owning process is not always the originator. A browser sends every tab through one
            network process, and one svchost can host several services (see the Services column).
          - Docker Desktop containers run in a Linux VM. Their traffic appears here as
            com.docker.backend.exe, never as the container or the program inside it. To attribute it,
            inspect from inside the container.
          - Names resolved outside the Windows resolver (DNS over HTTPS in a browser, a container's own
            resolver) are not seen, so those rows fall back to DnsCache or PTR.
          - ProcessDns only looks back -LastMinutes. A connection opened before that falls back to
            DnsCache, whose entries vanish when their TTL expires, then to PTR.
          - Arguments and parent PID are self-reported by the process and can be forged. A valid
            signature does not cover DLLs injected later. SHA256 is the dependable identity.
          - There is no history from before Sysmon was installed, or older than the log holds.

        Requirements:

          - PowerShell 7 (uses ForEach-Object -Parallel).
          - An elevated session, for full path/argument/owner details and to read the Sysmon log.
          - Sysmon, for -History and ProcessDns. Without it live mode still works on DnsCache and PTR.

        Live mode takes 5 to 10 seconds; most of that is verifying signatures of large binaries.

    .PARAMETER ProcessId
        Only show connections owned by these process IDs.

    .PARAMETER ExcludeLoopback
        Leave out connections to 127.x.x.x and ::1.

    .PARAMETER SkipDns
        Do not resolve remote addresses to names (drops RemoteHost and HostSource from the table).

    .PARAMETER PassThru
        Return objects instead of a formatted table. Needed for filtering, and for the fields the table
        leaves out (Path, SHA256, Signature, Started, ConnectedAt, FirstSeen, ...).

    .PARAMETER History
        Read Sysmon's record of past connections instead of taking a live snapshot.

    .PARAMETER LastMinutes
        How far back to read Sysmon events: connections for -History, DNS answers for ProcessDns.
        Default 60.

    .EXAMPLE
        Get-ConnectionProcess -ExcludeLoopback

    .EXAMPLE
        Get-ConnectionProcess -ProcessId 16616 -PassThru | Format-List

    .EXAMPLE
        Get-ConnectionProcess -PassThru | Where-Object Signature -ne 'Valid'

    .EXAMPLE
        Get-ConnectionProcess -History -LastMinutes 30 -ExcludeLoopback

    .EXAMPLE
        Get-ConnectionProcess -History -PassThru | Where-Object { -not $_.Running }

        Connections made by processes that have since exited.

    .NOTES
        Sysmon setup, from an elevated session (tested with Sysmon 15.22):

          winget install Microsoft.Sysinternals.Sysmon
          sysmon -accepteula -i sysmon-config.xml
          wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:536870912

        Config:    sysmon-config.xml in this repository. Logs process creation (1), network
                   connections (3) and DNS queries (22); nothing else.
        Log:       Microsoft-Windows-Sysmon/Operational. The wevtutil line raises it from 64 MB to
                   512 MB; oldest events are overwritten when it fills.
        Reconfig:  sysmon -c sysmon-config.xml
        Uninstall: sysmon -u
    #>
    [CmdletBinding()]
    param(
        [int[]]$ProcessId,
        [switch]$ExcludeLoopback,
        [switch]$SkipDns,
        [switch]$PassThru,
        [switch]$History,
        [ValidateRange(1, 525600)]
        [int]$LastMinutes = 60
    )

    $loopback  = '^(127\.|::1$)'
    $sysmonLog = 'Microsoft-Windows-Sysmon/Operational'
    $since     = (Get-Date).AddMinutes(-$LastMinutes)

    # Canonical form so addresses from different sources compare equal
    $normalize = {
        param($address)
        $ip = $null
        if (-not [ipaddress]::TryParse(($address -replace '%\d+$'), [ref]$ip)) { return $address }
        if ($ip.IsIPv4MappedToIPv6) { $ip = $ip.MapToIPv4() }
        $ip.ToString()
    }

    # Path has its own column, so keep only the arguments from a command line
    $getArguments = {
        param($commandLine, $path)
        if (-not $commandLine) { return }
        if ($path -and $commandLine.TrimStart('"').StartsWith($path, [StringComparison]::OrdinalIgnoreCase)) {
            $commandLine.TrimStart('"').Substring($path.Length).TrimStart('"').Trim()
        } else {
            ($commandLine -replace '^\s*("[^"]+"|\S+)\s*', '').Trim()
        }
    }

    # Sysmon events of one type since $since, each as a hashtable of its named fields.
    # Returns nothing when Sysmon is not installed or the session cannot read its log.
    $readSysmon = {
        param([int]$Id)
        Get-WinEvent -FilterHashtable @{ LogName = $sysmonLog; Id = $Id; StartTime = $since } -ErrorAction SilentlyContinue |
            ForEach-Object {
                $fields = @{ Time = $_.TimeCreated }
                foreach ($d in ([xml]$_.ToXml()).Event.EventData.Data) { $fields[$d.Name] = $d.'#text' }
                $fields
            }
    }

    # DNS answers Sysmon recorded: which names resolved to an address, per asking process and machine-wide
    $processDns = @{}
    $machineDns = @{}
    if (-not $SkipDns) {
        foreach ($q in & $readSysmon 22) {
            if ($q.QueryStatus -ne '0' -or $q.QueryName -match '\.arpa\.?$') { continue }
            $name = $q.QueryName.TrimEnd('.')
            foreach ($answer in $q.QueryResults -split ';') {
                # "type: 5 ..." entries are CNAME steps, not addresses
                if (-not $answer.Trim() -or $answer -match '^\s*type:') { continue }
                $ip  = & $normalize $answer.Trim()
                $key = '{0}|{1}|{2}' -f $q.ProcessId, $q.Image, $ip
                if ($name -notin $processDns[$key]) { $processDns[$key] += @($name) }
                if ($name -notin $machineDns[$ip])  { $machineDns[$ip]  += @($name) }
            }
        }
    }

    # An address shared by many sites can have a long list of names; the table shows the first two
    $hostColumn = @{ Name = 'RemoteHost'; Expression = {
        $names = $_.RemoteHost -split ', '
        if ($names.Count -gt 2) { '{0} (+{1})' -f ($names[0..1] -join ', '), ($names.Count - 2) } else { $_.RemoteHost }
    } }

    if ($History) {
        $events = @(& $readSysmon 3)
        if (-not $events) {
            Write-Warning "No Sysmon network events in the last $LastMinutes minutes. -History needs Sysmon and an elevated session; see Get-Help Get-ConnectionProcess -Full."
            return
        }

        $localIps = @{}
        Get-NetIPAddress -ErrorAction SilentlyContinue | ForEach-Object { $localIps[(& $normalize $_.IPAddress)] = $true }

        # Arguments come from the live process when it is still running, else from its Sysmon start event
        $live = @{}
        Get-CimInstance Win32_Process | ForEach-Object { $live[[int]$_.ProcessId] = $_ }
        $started = @{}
        foreach ($e in & $readSysmon 1) { $started[$e.ProcessGuid] = $e }

        $groups = [ordered]@{}
        foreach ($e in $events) {
            if ($ProcessId -and [int]$e.ProcessId -notin $ProcessId) { continue }

            # Sysmon records the direction of travel, so the remote end is whichever side is not this machine
            $sourceIp = & $normalize $e.SourceIp
            if ($localIps.ContainsKey($sourceIp) -or $sourceIp -match $loopback) {
                $direction, $remoteIp, $remotePort, $reverseName = 'out', (& $normalize $e.DestinationIp), $e.DestinationPort, $e.DestinationHostname
            } else {
                $direction, $remoteIp, $remotePort, $reverseName = 'in', $sourceIp, $e.SourcePort, $e.SourceHostname
            }
            if ($ExcludeLoopback -and $remoteIp -match $loopback) { continue }

            $key = '{0}|{1}|{2}|{3}' -f $e.ProcessGuid, $e.Protocol, $remoteIp, $remotePort
            if ($groups.Contains($key)) {
                $g = $groups[$key]
                $g.Count++
                if ($e.Time -lt $g.FirstSeen) { $g.FirstSeen = $e.Time }
                if ($e.Time -gt $g.LastSeen)  { $g.LastSeen  = $e.Time }
                continue
            }

            $names, $source = $null, $null
            if (-not $SkipDns) {
                $names = $processDns[('{0}|{1}|{2}' -f $e.ProcessId, $e.Image, $remoteIp)]
                if ($names) {
                    $source = 'ProcessDns'
                } elseif ($machineDns[$remoteIp]) {
                    $names, $source = $machineDns[$remoteIp], 'OtherDns'
                } elseif ($reverseName -and $reverseName -notin '-', $remoteIp) {
                    $names, $source = @($reverseName.TrimEnd('.')), 'PTR'
                }
            }

            $proc    = $live[[int]$e.ProcessId]
            $running = [bool]($proc -and ($proc.ExecutablePath -eq $e.Image -or $proc.Name -eq $e.Image))
            $start   = $started[$e.ProcessGuid]
            $commandLine = if ($running) { $proc.CommandLine } elseif ($start) { $start.CommandLine }

            $groups[$key] = [pscustomobject]@{
                LastSeen   = $e.Time
                FirstSeen  = $e.Time
                Count      = 1
                PID        = [int]$e.ProcessId
                Name       = ($e.Image -split '\\')[-1]
                Running    = $running
                Protocol   = $e.Protocol
                Direction  = $direction
                Remote     = '{0}:{1}' -f $remoteIp, $remotePort
                RemoteHost = $names -join ', '
                HostSource = $source
                Owner      = $e.User
                Arguments  = & $getArguments $commandLine $e.Image
                Path       = $e.Image
                # Only known for processes Sysmon saw start
                SHA256     = if ($start -and $start.Hashes -match 'SHA256=([0-9A-F]+)') { $Matches[1] }
            }
        }

        $results = @($groups.Values | Sort-Object LastSeen -Descending)
        if (-not $results) {
            Write-Warning "No recorded connections matched in the last $LastMinutes minutes."
            return
        }
        if ($PassThru) { return $results }

        $columns = @(@{ Name = 'LastSeen'; Expression = { $_.LastSeen.ToString('MM-dd HH:mm:ss') } }, 'PID', 'Name', 'Running', 'Protocol', 'Direction', 'Remote')
        if (-not $SkipDns) { $columns += $hostColumn, 'HostSource' }
        $columns += 'Count', 'Owner', 'Arguments'
        return $results | Format-Table $columns -AutoSize
    }

    # Connections are read before processes, so a PID missing from the process list has really exited
    $conns = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)
    if ($ProcessId)       { $conns = @($conns | Where-Object { $_.OwningProcess -in $ProcessId }) }
    if ($ExcludeLoopback) { $conns = @($conns | Where-Object { (& $normalize $_.RemoteAddress) -notmatch $loopback }) }
    if (-not $conns) {
        Write-Warning 'No established TCP connections matched.'
        return
    }

    # One query each instead of one per connection
    $procs = @{}
    Get-CimInstance Win32_Process | ForEach-Object { $procs[[int]$_.ProcessId] = $_ }

    $services = @{}
    Get-CimInstance Win32_Service -Filter "State='Running'" | ForEach-Object {
        $services[[int]$_.ProcessId] += @($_.Name)
    }

    $ownerPids = @($conns.OwningProcess | Sort-Object -Unique)

    # Owners in one call; that needs elevation, so fall back to asking WMI per process
    $owners = @{}
    try {
        Get-Process -Id $ownerPids -IncludeUserName -ErrorAction SilentlyContinue |
            ForEach-Object { $owners[[int]$_.Id] = $_.UserName }
    } catch {
        foreach ($id in $ownerPids) {
            if (-not $procs[[int]$id]) { continue }
            $o = Invoke-CimMethod -InputObject $procs[[int]$id] -MethodName GetOwner -ErrorAction SilentlyContinue
            if ($o -and $o.User) { $owners[[int]$id] = '{0}\{1}' -f $o.Domain, $o.User }
        }
    }

    # Signature and hash once per binary, in parallel: both read the whole file, which is slow for large ones
    $fileCache = @{}
    $ownerPids | ForEach-Object { $procs[[int]$_].ExecutablePath } | Where-Object { $_ } | Sort-Object -Unique |
        ForEach-Object -Parallel {
            $sig = Get-AuthenticodeSignature -LiteralPath $_ -ErrorAction SilentlyContinue
            [pscustomobject]@{
                Path   = $_
                Status = if ($sig) { $sig.Status }
                Signer = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject -replace '^CN="?([^,"]+)"?.*$', '$1' }
                SHA256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            }
        } -ThrottleLimit 8 |
        ForEach-Object { $fileCache[$_.Path] = $_ }

    # Fallback names for addresses Sysmon has no DNS answer for: Windows DNS cache, then PTR
    $hostNames  = @{}
    $hostSource = @{}

    if (-not $SkipDns) {
        $remoteIps = @($conns | ForEach-Object { & $normalize $_.RemoteAddress } | Sort-Object -Unique)

        # Names this machine looked up (A/AAAA answers in the DNS client cache)
        $cached = @{}
        Get-DnsClientCache -ErrorAction SilentlyContinue |
            Where-Object { $_.Type -in 1, 28 -and $_.Status -eq 0 -and $_.Data } |
            ForEach-Object {
                $ip = & $normalize $_.Data
                if ($ip -in $remoteIps -and $_.Entry -notin $cached[$ip]) { $cached[$ip] += @($_.Entry) }
            }

        # PTR in parallel; addresses that don't answer in time stay blank.
        # Resolve-DnsName because it does not add forward records to the cache read above.
        $ptr = @{}
        $remoteIps | Where-Object { $_ -notmatch $loopback } |
            ForEach-Object -Parallel {
                $answer = Resolve-DnsName -Name $_ -Type PTR -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue |
                    Where-Object NameHost | Select-Object -First 1
                if ($answer) { [pscustomobject]@{ Ip = $_; Name = $answer.NameHost } }
            } -ThrottleLimit 32 -TimeoutSeconds 5 |
            ForEach-Object { $ptr[$_.Ip] = $_.Name.TrimEnd('.') }

        # Prefer looked-up names. A cached name identical to the PTR name is usually left behind
        # by an earlier reverse lookup (ping -a, GetHostEntry), so it does not count as one.
        foreach ($ip in $remoteIps) {
            $lookedUp = @($cached[$ip] | Where-Object { $_ -and $_ -ne $ptr[$ip] })
            if ($lookedUp) {
                $hostNames[$ip]  = $lookedUp
                $hostSource[$ip] = 'DnsCache'
            } elseif ($ptr[$ip]) {
                $hostNames[$ip]  = @($ptr[$ip])
                $hostSource[$ip] = 'PTR'
            }
        }
    }

    $results = foreach ($c in $conns | Sort-Object OwningProcess, RemoteAddress, RemotePort) {
        $id = [int]$c.OwningProcess
        $p  = $procs[$id]
        $remoteIp = & $normalize $c.RemoteAddress
        $path = if ($p) { $p.ExecutablePath }

        $names  = $processDns[('{0}|{1}|{2}' -f $id, $path, $remoteIp)]
        $source = if ($names) { 'ProcessDns' } else { $hostSource[$remoteIp] }
        if (-not $names) { $names = $hostNames[$remoteIp] }

        $parent = if ($p) { $procs[[int]$p.ParentProcessId] }
        # PIDs get reused; a "parent" that started after the child is not the real parent
        $parentName = if ($parent -and $parent.CreationDate -le $p.CreationDate) { $parent.Name } else { '<exited>' }

        [pscustomobject]@{
            PID           = $id
            Name          = if ($p) { $p.Name } else { '<exited>' }
            Local         = '{0}:{1}' -f $c.LocalAddress, $c.LocalPort
            Remote        = '{0}:{1}' -f $c.RemoteAddress, $c.RemotePort
            RemoteHost    = $names -join ', '
            HostSource    = $source
            ConnectedAt   = $c.CreationTime
            Arguments     = if ($p) { & $getArguments $p.CommandLine $path }
            Services      = $services[$id] -join ', '
            Owner         = $owners[$id]
            ParentPID     = if ($p) { $p.ParentProcessId }
            ParentName    = if ($p) { $parentName }
            Started       = if ($p) { $p.CreationDate }
            Path          = $path
            Signature     = if ($path) { $fileCache[$path].Status }
            Signer        = if ($path) { $fileCache[$path].Signer }
            SHA256        = if ($path) { $fileCache[$path].SHA256 }
            Threads       = if ($p) { $p.ThreadCount }
            Handles       = if ($p) { $p.HandleCount }
            WorkingSetMB  = if ($p) { [math]::Round($p.WorkingSetSize / 1MB, 1) }
        }
    }

    if ($PassThru) { return $results }

    # Arguments goes last so it is the column that gets truncated
    $columns = @('PID', 'Name', 'Remote')
    if (-not $SkipDns) { $columns += $hostColumn, 'HostSource' }
    $columns += 'Owner', 'ParentName', 'Services', 'Signer', 'Arguments'
    $results | Format-Table $columns -AutoSize
}
