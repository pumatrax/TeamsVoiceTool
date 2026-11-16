<#
.SYNOPSIS
    Traces socket activity for the Microsoft Teams client to compare media paths
    between Calling Plan (PSTN) calls and Teams-to-Teams peer-to-peer calls.

.DESCRIPTION
    Polls TCP connections and UDP endpoints owned by ms-teams.exe and logs
    deltas (new / closed sockets) rather than repeated full dumps. Classifies
    each destination against the published Microsoft 365 Optimize ranges and
    labels well-known Teams media ports.

    Socket polling runs without elevation. UDP endpoints expose only the local
    binding -- Windows does not track a remote peer for connectionless sockets.
    To capture actual UDP destinations, run with -Capture from an elevated
    prompt, which adds a pktmon capture scoped to the Teams media IP ranges.

.PARAMETER IntervalMs
    Polling interval in milliseconds. Default 500.

.PARAMETER DurationSeconds
    How long to trace. Default 180.

.PARAMETER Label
    Free-text tag written into the output filenames and CSV, e.g. "PSTN" or "P2P".

.PARAMETER Capture
    Also run a pktmon packet capture filtered to the Teams Optimize ranges.
    Requires an elevated session.

.EXAMPLE
    .\Trace-TeamsSockets.ps1 -Label P2P -DurationSeconds 120

.EXAMPLE
    .\Trace-TeamsSockets.ps1 -Label PSTN -Capture -DurationSeconds 120
#>

[CmdletBinding()]
param(
    [int]    $IntervalMs      = 500,
    [int]    $DurationSeconds = 180,
    [string] $Label           = 'trace',
    [string] $OutputDir       = "$env:USERPROFILE\TeamsSocketTrace",
    [string[]]$ProcessNames   = @('ms-teams', 'Teams'),
    [switch] $Capture
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

# Microsoft 365 URLs and IP address ranges, ID 11 (Teams media, Optimize).
# Verify against https://aka.ms/o365ip before relying on these long-term.
$OptimizeRanges = @(
    @{ Cidr = '13.107.64.0/18';  Name = 'MS Optimize (13.107.64.0/18)'  }
    @{ Cidr = '52.112.0.0/14';   Name = 'MS Optimize (52.112.0.0/14)'   }
    @{ Cidr = '52.122.0.0/15';   Name = 'MS Optimize (52.122.0.0/15)'   }
)

$PrivateRanges = @(
    @{ Cidr = '10.0.0.0/8';      Name = 'Private / internal' }
    @{ Cidr = '172.16.0.0/12';   Name = 'Private / internal' }
    @{ Cidr = '192.168.0.0/16';  Name = 'Private / internal' }
    @{ Cidr = '127.0.0.0/8';     Name = 'Loopback'           }
    @{ Cidr = '169.254.0.0/16';  Name = 'Link-local'         }
)

function Get-PortRole {
    param([int]$Port, [string]$Protocol)

    if ($Protocol -eq 'UDP') {
        switch ($Port) {
            3478 { return 'STUN / TURN allocation' }
            3479 { return 'Audio (documented)'     }
            3480 { return 'Video (documented)'     }
            3481 { return 'Sharing / VBSS'         }
        }
        if ($Port -ge 49152 -and $Port -le 53247) { return 'Media Processor range (49152-53247)' }
        if ($Port -ge 50000 -and $Port -le 59999) { return 'Relay / MP high port (50000-59999)'  }
    }
    else {
        switch ($Port) {
            443  { return 'HTTPS / TURN over TCP' }
            80   { return 'HTTP'                  }
            8080 { return 'Proxy listener'        }
        }
    }
    return ''
}

function Get-SourceRole {
    param([int]$Port)
    if ($Port -ge 50000 -and $Port -le 50019) { return 'QoS audio'   }
    if ($Port -ge 50020 -and $Port -le 50039) { return 'QoS video'   }
    if ($Port -ge 50040 -and $Port -le 50059) { return 'QoS sharing' }
    return ''
}

# ---------------------------------------------------------------------------
# Subnet helpers
# ---------------------------------------------------------------------------

function ConvertTo-UInt32Address {
    param([string]$Address)
    try {
        $ip = [System.Net.IPAddress]::Parse($Address)
        if ($ip.AddressFamily -ne 'InterNetwork') { return $null }
        $bytes = $ip.GetAddressBytes()
        [Array]::Reverse($bytes)
        return [System.BitConverter]::ToUInt32($bytes, 0)
    }
    catch { return $null }
}

function Test-InCidr {
    param([string]$Address, [string]$Cidr)

    $parts  = $Cidr.Split('/')
    $base   = ConvertTo-UInt32Address $parts[0]
    $target = ConvertTo-UInt32Address $Address
    if ($null -eq $base -or $null -eq $target) { return $false }

    $prefix = [int]$parts[1]
    if ($prefix -le 0)  { return $true }
    if ($prefix -ge 32) { return ($base -eq $target) }

    # Compare the top $prefix bits by discarding the host bits.
    # Division avoids PowerShell 5.1 parsing 0xFFFFFFFF as [int] -1,
    # which breaks any [uint64] cast in shift-based mask arithmetic.
    $divisor = [double][math]::Pow(2, 32 - $prefix)

    return ([math]::Floor([double]$base / $divisor) -eq
            [math]::Floor([double]$target / $divisor))
}

function Get-DestinationClass {
    param([string]$Address)

    if ([string]::IsNullOrWhiteSpace($Address)) { return '' }
    if ($Address -eq '0.0.0.0' -or $Address -eq '::') { return 'Unbound' }
    if ($Address -like '*:*') { return 'IPv6' }

    foreach ($r in $OptimizeRanges) {
        if (Test-InCidr -Address $Address -Cidr $r.Cidr) { return $r.Name }
    }
    foreach ($r in $PrivateRanges) {
        if (Test-InCidr -Address $Address -Cidr $r.Cidr) { return $r.Name }
    }
    return 'External'
}

# ---------------------------------------------------------------------------
# Process discovery
# ---------------------------------------------------------------------------

function Get-TeamsProcesses {
    $procs = @()
    foreach ($name in $ProcessNames) {
        $found = Get-Process -Name $name -ErrorAction SilentlyContinue
        if ($found) { $procs += $found }
    }
    return $procs
}

# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

function Get-SocketSnapshot {
    param([int[]]$Pids)

    $snapshot = @{}
    if (-not $Pids -or $Pids.Count -eq 0) { return $snapshot }

    $tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue |
           Where-Object { $Pids -contains $_.OwningProcess }

    foreach ($c in $tcp) {
        # Listening sockets have no peer -- they add noise without information.
        if ($c.RemoteAddress -in @('0.0.0.0', '::') -or $c.RemotePort -eq 0) { continue }
        if ($c.State -eq 'Listen') { continue }

        $key = "TCP|$($c.LocalAddress):$($c.LocalPort)|$($c.RemoteAddress):$($c.RemotePort)"
        $snapshot[$key] = [PSCustomObject]@{
            Protocol      = 'TCP'
            ProcessId     = $c.OwningProcess
            LocalAddress  = $c.LocalAddress
            LocalPort     = $c.LocalPort
            RemoteAddress = $c.RemoteAddress
            RemotePort    = $c.RemotePort
            State         = $c.State
        }
    }

    $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
           Where-Object { $Pids -contains $_.OwningProcess }

    foreach ($u in $udp) {
        $key = "UDP|$($u.LocalAddress):$($u.LocalPort)"
        $snapshot[$key] = [PSCustomObject]@{
            Protocol      = 'UDP'
            ProcessId     = $u.OwningProcess
            LocalAddress  = $u.LocalAddress
            LocalPort     = $u.LocalPort
            RemoteAddress = ''
            RemotePort    = 0
            State         = 'Bound'
        }
    }

    return $snapshot
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$stamp    = Get-Date -Format 'yyyyMMdd-HHmmss'
$safeTag  = ($Label -replace '[^\w\-]', '_')
$csvPath  = Join-Path $OutputDir "teams-sockets-$safeTag-$stamp.csv"
$etlPath  = Join-Path $OutputDir "teams-packets-$safeTag-$stamp.etl"
$txtPath  = Join-Path $OutputDir "teams-packets-$safeTag-$stamp.txt"

$isAdmin = ([Security.Principal.WindowsPrincipal] `
            [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host ''
Write-Host '=== Teams socket trace ===' -ForegroundColor Cyan
Write-Host "Label       : $Label"
Write-Host "Duration    : $DurationSeconds s   Interval: $IntervalMs ms"
Write-Host "CSV output  : $csvPath"
Write-Host "Elevated    : $isAdmin"

$procs = Get-TeamsProcesses
if (-not $procs) {
    Write-Host ''
    Write-Warning "No Teams process found (looked for: $($ProcessNames -join ', '))."
    Write-Warning 'Start Teams, then re-run. Continuing -- new PIDs are picked up automatically.'
}
else {
    Write-Host ''
    Write-Host 'Teams processes:' -ForegroundColor Cyan
    $procs | ForEach-Object {
        Write-Host ("  PID {0,-8} {1}" -f $_.Id, $_.ProcessName)
    }
}

# ---------------------------------------------------------------------------
# Optional packet capture
# ---------------------------------------------------------------------------

$captureRunning = $false
if ($Capture) {
    if (-not $isAdmin) {
        Write-Warning 'Packet capture needs an elevated session. Continuing with socket polling only.'
    }
    else {
        try {
            & pktmon filter remove | Out-Null
            $i = 1
            foreach ($r in $OptimizeRanges) {
                & pktmon filter add "TeamsMedia$i" -i $r.Cidr | Out-Null
                $i++
            }
            & pktmon start --capture --pkt-size 160 -f $etlPath | Out-Null
            $captureRunning = $true
            Write-Host ''
            Write-Host "Packet capture started -> $etlPath" -ForegroundColor Green
        }
        catch {
            Write-Warning "pktmon failed to start: $_"
        }
    }
}

# ---------------------------------------------------------------------------
# Trace loop
# ---------------------------------------------------------------------------

$events    = New-Object System.Collections.Generic.List[object]
$firstSeen = @{}
$previous  = @{}
$deadline  = (Get-Date).AddSeconds($DurationSeconds)

Write-Host ''
Write-Host 'Tracing. Place your test call now. Ctrl+C to stop early.' -ForegroundColor Yellow
Write-Host ''

try {
    while ((Get-Date) -lt $deadline) {

        $pids = @(Get-TeamsProcesses | Select-Object -ExpandProperty Id)
        $now  = Get-Date
        $snap = Get-SocketSnapshot -Pids $pids

        foreach ($key in $snap.Keys) {
            if (-not $previous.ContainsKey($key)) {
                $s = $snap[$key]
                $firstSeen[$key] = $now

                $row = [PSCustomObject]@{
                    Timestamp     = $now.ToString('yyyy-MM-dd HH:mm:ss.fff')
                    Label         = $Label
                    Event         = 'OPEN'
                    Protocol      = $s.Protocol
                    ProcessId     = $s.ProcessId
                    LocalAddress  = $s.LocalAddress
                    LocalPort     = $s.LocalPort
                    SourceRole    = (Get-SourceRole -Port $s.LocalPort)
                    RemoteAddress = $s.RemoteAddress
                    RemotePort    = $s.RemotePort
                    DestClass     = (Get-DestinationClass -Address $s.RemoteAddress)
                    PortRole      = (Get-PortRole -Port $s.RemotePort -Protocol $s.Protocol)
                    State         = $s.State
                    LifetimeMs    = ''
                }
                $events.Add($row)

                $color = 'Gray'
                if ($row.DestClass -like 'MS Optimize*') { $color = 'Green'  }
                if ($row.Protocol  -eq 'UDP')            { $color = 'Cyan'   }
                if ($row.PortRole  -ne '')               { $color = 'Yellow' }

                $line = '{0}  OPEN  {1,-4} {2}:{3}' -f `
                        $now.ToString('HH:mm:ss.fff'), $s.Protocol,
                        $s.LocalAddress, $s.LocalPort
                if ($s.RemoteAddress) {
                    $line += ' -> {0}:{1}' -f $s.RemoteAddress, $s.RemotePort
                }
                if ($row.PortRole)   { $line += "  [$($row.PortRole)]"   }
                if ($row.SourceRole) { $line += "  [$($row.SourceRole)]" }
                Write-Host $line -ForegroundColor $color
            }
        }

        foreach ($key in $previous.Keys) {
            if (-not $snap.ContainsKey($key)) {
                $s = $previous[$key]
                $life = ''
                if ($firstSeen.ContainsKey($key)) {
                    $life = [int]($now - $firstSeen[$key]).TotalMilliseconds
                }

                $events.Add([PSCustomObject]@{
                    Timestamp     = $now.ToString('yyyy-MM-dd HH:mm:ss.fff')
                    Label         = $Label
                    Event         = 'CLOSE'
                    Protocol      = $s.Protocol
                    ProcessId     = $s.ProcessId
                    LocalAddress  = $s.LocalAddress
                    LocalPort     = $s.LocalPort
                    SourceRole    = (Get-SourceRole -Port $s.LocalPort)
                    RemoteAddress = $s.RemoteAddress
                    RemotePort    = $s.RemotePort
                    DestClass     = (Get-DestinationClass -Address $s.RemoteAddress)
                    PortRole      = (Get-PortRole -Port $s.RemotePort -Protocol $s.Protocol)
                    State         = $s.State
                    LifetimeMs    = $life
                })

                $line = '{0}  CLOSE {1,-4} {2}:{3}' -f `
                        $now.ToString('HH:mm:ss.fff'), $s.Protocol,
                        $s.LocalAddress, $s.LocalPort
                if ($s.RemoteAddress) {
                    $line += ' -> {0}:{1}' -f $s.RemoteAddress, $s.RemotePort
                }
                if ($life -ne '') { $line += "  ({0} ms)" -f $life }
                Write-Host $line -ForegroundColor DarkGray
            }
        }

        $previous = $snap
        Start-Sleep -Milliseconds $IntervalMs
    }
}
finally {

    if ($captureRunning) {
        Write-Host ''
        Write-Host 'Stopping packet capture...' -ForegroundColor Cyan
        try {
            & pktmon stop | Out-Null
            & pktmon etl2txt $etlPath -o $txtPath | Out-Null
            & pktmon filter remove | Out-Null
            Write-Host "Packet text output -> $txtPath" -ForegroundColor Green
        }
        catch {
            Write-Warning "pktmon stop/convert failed: $_"
        }
    }

    if ($events.Count -gt 0) {
        $events | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    }

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------

    Write-Host ''
    Write-Host '=== Summary ===' -ForegroundColor Cyan
    Write-Host "Events captured: $($events.Count)"

    $remote = $events | Where-Object {
        $_.Event -eq 'OPEN' -and $_.RemoteAddress -and $_.RemoteAddress -ne '0.0.0.0'
    }

    if ($remote) {
        Write-Host ''
        Write-Host 'Distinct remote endpoints:' -ForegroundColor Cyan
        $remote |
            Group-Object Protocol, RemoteAddress, RemotePort |
            Sort-Object Count -Descending |
            ForEach-Object {
                $s = $_.Group[0]
                $tag = @($s.DestClass, $s.PortRole) | Where-Object { $_ } 
                Write-Host ("  {0,-4} {1}:{2,-6}  x{3,-4} {4}" -f `
                    $s.Protocol, $s.RemoteAddress, $s.RemotePort,
                    $_.Count, ($tag -join ' | '))
            }
    }

    $mediaPorts = $events | Where-Object {
        $_.Event -eq 'OPEN' -and $_.Protocol -eq 'UDP' -and (Get-SourceRole -Port $_.LocalPort)
    }
    if ($mediaPorts) {
        Write-Host ''
        Write-Host 'UDP sockets bound in the QoS media range:' -ForegroundColor Cyan
        $mediaPorts |
            Sort-Object LocalPort -Unique |
            ForEach-Object {
                Write-Host ("  {0}:{1}  [{2}]" -f $_.LocalAddress, $_.LocalPort, $_.SourceRole)
            }
    }

    Write-Host ''
    Write-Host "CSV: $csvPath" -ForegroundColor Green
    if ($captureRunning) {
        Write-Host ''
        Write-Host 'To find actual UDP destinations in the packet text file:' -ForegroundColor Yellow
        Write-Host "  Select-String -Path '$txtPath' -Pattern 'UDP' | Select-Object -First 50"
    }
    else {
        Write-Host ''
        Write-Host 'Note: UDP remote peers are not shown by Windows socket tables.' -ForegroundColor Yellow
        Write-Host 'Re-run elevated with -Capture to record actual UDP destinations.' -ForegroundColor Yellow
    }
    Write-Host ''
}
