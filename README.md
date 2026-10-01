# ps-connection-inspector

A PowerShell function, `Get-ConnectionProcess`, that shows which processes own a Windows machine's network connections and what they are talking to.

It answers the question `netstat -ano` leaves you with: "PID 16616 has a connection to 104.18.39.21, so what is that process, and what is that address?"

## What it does

**Live mode** (default) lists the established TCP connections right now and joins each one to its process:

- name, arguments (command line without the executable path), and the Windows services hosted in that PID
- owner, parent process, start time
- Authenticode signature status and signer, SHA256 of the binary
- the host name behind the remote address, and how that name was obtained

**History mode** (`-History`) reads what [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) recorded: every TCP and UDP connection in the last N minutes, grouped per process and remote endpoint, including connections from processes that have already exited.

```
  PID Name        Remote             RemoteHost               HostSource Owner               ParentName   Services   Signer            Arguments
  --- ----        ------             ----------               ---------- -----               ----------   --------   ------            ---------
 4924 svchost.exe 146.75.30.172:80   ctldl.windowsupdate.com  ProcessDns NT AUTHORITY\NETWO… services.exe CryptSvc   Microsoft Windows -k NetworkService -p
16616 chrome.exe  142.251.167.83:443 mail.google.com          ProcessDns PC\user             chrome.exe              Google LLC        --type=utility --utility-sub-type=network…
16616 chrome.exe  172.253.115.188:5… bg-in-f188.1e100.net     PTR        PC\user             chrome.exe              Google LLC        --type=utility --utility-sub-type=network…
```

## Requirements

- Windows 10 or 11
- PowerShell 7 (the function uses `ForEach-Object -Parallel`)
- An elevated session, for full path, argument and owner details and to read the Sysmon log
- Sysmon, for `-History` and for the `ProcessDns` name source. Without it, live mode still works using the DNS cache and reverse lookups.

## Install

Dot-source the script, for example from your PowerShell profile (`$PROFILE`):

```powershell
. C:\path\to\ps-connection-inspector\Get-ConnectionProcess.ps1
```

### Sysmon setup (optional, recommended)

From an elevated session in this folder:

```powershell
winget install Microsoft.Sysinternals.Sysmon
sysmon -accepteula -i sysmon-config.xml
wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:536870912
```

- `sysmon-config.xml` logs only process creation (event 1), network connections (event 3) and DNS queries (event 22).
- The `wevtutil` line raises the log from 64 MB to 512 MB. On a busy desktop the default holds only a few hours. Oldest events are overwritten when the log fills.
- Sysmon installs a service (`Sysmon64`) and a kernel driver, and records these events for every process on the machine until you remove it.

To change the config later: `sysmon -c sysmon-config.xml`. To remove Sysmon: `sysmon -u`.

## Usage

```powershell
# Live connections, without loopback noise
Get-ConnectionProcess -ExcludeLoopback

# Everything about one process's connections
Get-ConnectionProcess -ProcessId 16616 -PassThru | Format-List

# Connections owned by binaries without a valid signature
Get-ConnectionProcess -PassThru | Where-Object Signature -ne 'Valid'

# What happened in the last 30 minutes, TCP and UDP
Get-ConnectionProcess -History -LastMinutes 30 -ExcludeLoopback

# Connections made by processes that have since exited
Get-ConnectionProcess -History -PassThru | Where-Object { -not $_.Running }
```

| Parameter | Meaning |
| --- | --- |
| `-ProcessId` | Only show connections owned by these process IDs. |
| `-ExcludeLoopback` | Leave out connections to `127.x.x.x` and `::1`. |
| `-SkipDns` | Do not resolve remote addresses to names. |
| `-PassThru` | Return objects instead of a formatted table. Needed for filtering and for the fields the table leaves out. |
| `-History` | Read Sysmon's record of past connections instead of taking a live snapshot. |
| `-LastMinutes` | How far back to read Sysmon events (default 60). |

Full documentation is in the function's help:

```powershell
Get-Help Get-ConnectionProcess -Full
```

## Where host names come from

`RemoteHost` uses the best source available. `HostSource` says which, most to least reliable:

| HostSource | Meaning |
| --- | --- |
| `ProcessDns` | This process asked for that name and got that address (Sysmon event 22). |
| `OtherDns` | A different process asked for that name (history mode only). |
| `DnsCache` | The name is in the Windows DNS cache for that address; any process may have asked. |
| `PTR` | Reverse record only. For CDN and cloud addresses this names the provider, not the site. |

## Output fields

The table shows a subset. `-PassThru` returns all of them.

**Live mode:** `PID`, `Name`, `Local`, `Remote`, `RemoteHost`, `HostSource`, `ConnectedAt`, `Arguments`, `Services`, `Owner`, `ParentPID`, `ParentName`, `Started`, `Path`, `Signature`, `Signer`, `SHA256`, `Threads`, `Handles`, `WorkingSetMB`

**History mode:** `LastSeen`, `FirstSeen`, `Count`, `PID`, `Name`, `Running`, `Protocol`, `Direction`, `Remote`, `RemoteHost`, `HostSource`, `Owner`, `Arguments`, `Path`, `SHA256`

In history mode, `SHA256` is only filled in for processes Sysmon saw start.

## Limits

- **Live mode is a snapshot, and TCP only.** Short-lived connections and UDP (QUIC/HTTP3, DNS) only show up with `-History`.
- **The owning process is not always the originator.** A browser sends every tab through one network process, and one `svchost` can host several services (see the `Services` column).
- **Docker Desktop containers appear as `com.docker.backend.exe`.** Containers run in a Linux VM, so Windows never sees the container or the program inside it. To attribute that traffic, look from inside the container:

  ```powershell
  docker exec <container> ss -tunp
  # or, if the image has no ss/netstat:
  docker run --rm --net container:<container> --pid container:<container> nicolaka/netshoot ss -tunp
  ```

- **Names resolved outside the Windows resolver are not seen.** DNS over HTTPS in a browser, or a container's own resolver, bypass Sysmon and the DNS cache, so those rows fall back to `DnsCache` or `PTR`.
- **`ProcessDns` only looks back `-LastMinutes`.** A connection opened before that falls back to `DnsCache`, whose entries vanish when their TTL expires, then to `PTR`.
- **Process details can be forged.** Arguments and parent PID are self-reported by the process. A valid signature does not cover DLLs injected later. `SHA256` is the dependable identity.
- **No history from before Sysmon was installed**, or older than its log holds.
- **Live mode takes 5 to 10 seconds.** Most of that is verifying signatures of large binaries.

## Files

| File | Purpose |
| --- | --- |
| `Get-ConnectionProcess.ps1` | The function. |
| `sysmon-config.xml` | Sysmon configuration the history mode relies on. |
