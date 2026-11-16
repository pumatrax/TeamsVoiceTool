param([string]$SampleFolder)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$source = Join-Path (Split-Path $PSScriptRoot -Parent) 'TeamsVoiceProvisioning.ps1'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw "Script has parse errors: $($errors -join '; ')" }
$functions = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
foreach ($function in $functions) {
    Set-Item -Path ("Function:\script:" + $function.Name) -Value $function.Body.GetScriptBlock()
}

$script:QualityThresholds = @{
    AvgJitterMs=30; MaxJitterMs=30; AvgPacketLossRate=0.10; MaxPacketLossRate=0.10
    AvgRoundTripTimeMs=500; MaxRoundTripTimeMs=500; AvgAudioDegradation=1.0; AvgRatioConcealedSamples=0.07
}
$script:UnsetSentinels = @(4294967295, 0xFFFFFFFF, -1)

function Assert-True($Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Get-MatchNodes($Node) {
    return @($Node.Nodes | Where-Object { $_.Text -like 'Possible match:*' })
}
function Get-ChildNode($Node, [string]$Prefix) {
    $Node.Expand()
    $child = @($Node.Nodes | Where-Object { $_.Text.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase) }) | Select-Object -First 1
    if (-not $child) { throw "Missing tree node: $Prefix" }
    return $child
}

$usage = '{"id":"usage-1","callId":"call-1","callType":"user_out","callerNumber":"+10000000001","calleeNumber":"+10000000002","userDisplayName":"Test User","userPrincipalName":"test@example.invalid","duration":0,"charge":0,"currency":"USD","conferenceId":null,"startDateTime":"2026-01-01T00:00:00Z","endDateTime":"2026-01-01T00:00:08Z"}' | ConvertFrom-Json
$call = Expand-CallRecord $usage
Assert-True ($call.IsUsageRecord -and $call.Type -eq 'user_out') 'Usage type was not recognized.'
Assert-True ($call.DurationSeconds -eq 0 -and $call.Verdict -eq 'Unknown' -and $call.QualityVerdict -eq 'Unrated') 'Usage duration or verdict is incorrect.'
Assert-True ($call.SessionCount -eq 0) 'Usage records must not invent sessions.'

$page = New-DiagnosticsTabPage
$form = New-Object System.Windows.Forms.Form
$form.ClientSize = New-Object System.Drawing.Size(1200, 700)
$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = 'Fill'
$tabs.TabPages.Add($page)
$form.Controls.Add($tabs)
$form.Show()
$c = $script:JA.Ctl
Assert-True $c.LayoutInitialized 'Analyzer pane sizes were not initialized.'
Assert-True ([math]::Abs($c.Split.SplitterDistance / $c.Split.Width - 0.46) -lt 0.02) 'Tree width does not match the default layout.'
Assert-True (-not $c.Split.IsSplitterFixed) 'Tree divider must be adjustable.'
$c.Split.SplitterDistance = 400
Initialize-JALayout
Assert-True ($c.Split.SplitterDistance -eq 400) 'User-adjusted tree width was reset.'
$form.ClientSize = New-Object System.Drawing.Size(1100, 650)
Assert-True ([math]::Abs($c.Split.SplitterDistance / $c.Split.Width - 0.46) -gt 0.02) 'Resizing the window reset the user-adjusted tree width.'
Invoke-JARender -Records @($usage) -Label 'first'
Assert-True ($script:JA.Ctl.Tree.Nodes.Count -eq 1) 'Usage record tree is missing.'
Assert-True ($script:JA.Ctl.Flow.Text.Contains('+10000000001') -and $script:JA.Ctl.Flow.Text.Contains('+10000000002')) 'Caller or callee is missing from flow.'
Assert-True ($script:JA.Ctl.Verdict.Text.Contains('Test User') -and $script:JA.Ctl.Verdict.Text.Contains('PSTN CALL STATISTICS')) 'Usage summary is incorrect.'
Assert-True (-not $script:JA.Ctl.Verdict.Text.Contains('Worst media') -and $script:JA.Ctl.Flow.Text.Contains('duration')) 'Usage records must show statistics, not quality.'
$usageFields = Get-ChildNode $script:JA.Ctl.Tree.Nodes[0] 'JSON fields'
$charge = Get-ChildNode $usageFields 'charge:'
$script:JA.Ctl.Tree.SelectedNode = $charge
Assert-True ($script:JA.Ctl.Raw.Text.Trim() -eq '0') 'Zero-valued usage field is missing.'
$nullField = Get-ChildNode $usageFields 'conferenceId:'
$script:JA.Ctl.Tree.SelectedNode = $nullField
Assert-True ($script:JA.Ctl.Raw.Text.Trim() -eq 'null') 'Null JSON field is missing.'

$direct = '{"id":"dr-1","correlationId":"corr-1","callType":"dr_in","callerNumber":"+10000000001","successfulCall":false,"finalSipCode":0,"finalSipCodePhrase":"test","mediaBypassEnabled":false,"failureDateTime":"2026-01-01T00:00:00Z"}' | ConvertFrom-Json
Invoke-JARender -Records @($direct) -Label 'direct routing'
Assert-True ($script:JA.Expanded[0].Verdict -eq 'NotEstablished') 'Direct Routing attempt outcome was not recognized.'
Assert-True ($script:JA.Ctl.Verdict.Text.Contains('not established') -and $script:JA.Ctl.Verdict.Text.Contains('corr-1')) 'Direct Routing outcome or correlation ID is missing.'
Assert-True ($script:JA.Ctl.Verdict.Text.Contains('DIRECT ROUTING CALL STATISTICS') -and $script:JA.Ctl.Flow.Text.Contains('False')) 'Direct Routing statistics are missing.'
Assert-True ($script:JA.Ctl.Flow.Text.Contains('finalSipCode') -and $script:JA.Ctl.Flow.Text.Contains('failureDateTime') -and -not $script:JA.Ctl.Verdict.Text.Contains('Worst media')) 'Direct Routing call statistics are incomplete.'
$directFields = Get-ChildNode $script:JA.Ctl.Tree.Nodes[0] 'JSON fields'
$bypass = Get-ChildNode $directFields 'mediaBypassEnabled:'
$script:JA.Ctl.Tree.SelectedNode = $bypass
Assert-True ($script:JA.Ctl.Raw.Text.Trim() -eq 'false') 'Boolean JSON field is incorrect.'
Assert-True ($script:JA.Ctl.Flow.Text.Contains('(not reported)')) 'Missing callee was not identified.'
$direct.successfulCall = $true
Assert-True ((Expand-CallRecord $direct).Verdict -eq 'Success') 'Direct Routing success was not recognized.'

$usage.calleeNumber = '+10000000003'
Invoke-JARender -Records @($usage) -Label 'reloaded'
Assert-True ($script:JA.Ctl.Flow.Text.Contains('+10000000003')) 'Reloading the same ID left stale flow.'
$second = $usage | ConvertTo-Json | ConvertFrom-Json
$second.calleeNumber = '+10000000004'
Invoke-JARender -Records @($usage, $second) -Label 'duplicates'
$script:JA.Ctl.Tree.SelectedNode = $script:JA.Ctl.Tree.Nodes[1]
Assert-True ($script:JA.Ctl.Flow.Text.Contains('+10000000004')) 'Selecting a duplicate ID left stale flow.'

$detail = '{"id":"detail-1","type":"peerToPeer","sessions":[{"id":"s1","caller":{"identity":{"user":{"displayName":"Alice"}}},"callee":{"identity":{"phone":{"id":"+10000000002"}}},"segments":[]}]}' | ConvertFrom-Json
$legacy = '{"id":"legacy","organizer":{"user":{"displayName":"Alice"}},"participants":[{"user":{"displayName":"Alice"}},{"phone":{"id":"+10000000002"}}]}' | ConvertFrom-Json
$legacyCall = Expand-CallRecord $legacy
Assert-True ($legacyCall.Organizer -eq 'Alice' -and $legacyCall.Participants[1] -eq '+10000000002') 'Legacy organizer or participants are incorrect.'
Invoke-JARender -Records @($detail) -Label 'detail'
Assert-True ($script:JA.Expanded[0].Verdict -eq 'Success' -and -not $script:JA.Expanded[0].IsUsageRecord) 'Detailed call behavior changed.'
Assert-True ($script:JA.Ctl.Flow.Text.Contains('Alice') -and $script:JA.Ctl.Flow.Text.Contains('+10000000002')) 'Detailed session flow is missing.'
$fields = Get-ChildNode $script:JA.Ctl.Tree.Nodes[0] 'JSON fields'
$sessions = Get-ChildNode $fields 'sessions ['
$script:JA.Ctl.Tree.SelectedNode = $sessions
Assert-True ($script:JA.Ctl.Raw.Text.TrimStart().StartsWith('[')) 'Single-element arrays must remain arrays in the raw pane.'
$session = Get-ChildNode $sessions '[0]'
$caller = Get-ChildNode $session 'caller'
$identity = Get-ChildNode $caller 'identity'
$user = Get-ChildNode $identity 'user'
$name = Get-ChildNode $user 'displayName'
$script:JA.Ctl.Tree.SelectedNode = $name
Assert-True ($script:JA.Ctl.Raw.Text.Trim() -eq '"Alice"') 'Nested field JSON is incorrect.'
$empty = Get-ChildNode $session 'segments ['
$script:JA.Ctl.Tree.SelectedNode = $empty
Assert-True ($script:JA.Ctl.Raw.Text -match '^\s*\[\s*\]\s*$') 'Empty arrays must remain visible as JSON.'
Assert-True ((Get-JARawJsonDirectory) -eq (Join-Path (Join-Path (Get-OutputRoot) 'CDR') 'RawJSON')) 'Unexpected JSON picker folder.'
$unexpanded = '{"id":"unexpanded","type":"peerToPeer"}' | ConvertFrom-Json
Invoke-JARender -Records @($unexpanded) -Label 'unexpanded'
Assert-True ($script:JA.Expanded[0].Verdict -eq 'Unknown') 'Missing sessions must not be reported as a successful call.'
Assert-True (-not $script:JA.Ctl.Verdict.Text.Contains('no warnings above threshold')) 'Missing quality data must not be reported as clean.'

$usageMatch = '{"id":"usage-match","callType":"user_out","callerNumber":"+10000000001","calleeNumber":"+10000000002","userId":"user-1","startDateTime":"2026-01-01T00:00:00.900Z","endDateTime":"2026-01-01T00:00:08.900Z"}' | ConvertFrom-Json
$detailMatch = '{"id":"detail-match","type":"peerToPeer","startDateTime":"2026-01-01T00:00:01.100Z","endDateTime":"2026-01-01T00:00:09.100Z","participants_v2":[{"identity":{"user":{"id":"user-1"}}},{"identity":{"phone":{"id":"+10000000002"}}}],"sessions":[]}' | ConvertFrom-Json
$wrongEnd = $detailMatch | ConvertTo-Json -Depth 10 | ConvertFrom-Json
$wrongEnd.id = 'wrong-end'
$wrongEnd.endDateTime = '2026-01-01T00:00:11Z'
Invoke-JARender -Records @($usageMatch, $detailMatch, $wrongEnd) -Label 'matching'
$node = $script:JA.Ctl.Tree.Nodes[0]
$matches = @(Get-MatchNodes $node)
Assert-True ($matches.Count -eq 1 -and $matches[0].Text.Contains('detail-match')) 'Expected exactly one time-based match.'
Assert-True ($matches[0].Text.Contains('user ID matches') -and $matches[0].Text.Contains('number matches')) 'Matching evidence is missing.'
$script:JA.Ctl.Tree.SelectedNode = $matches[0]
Assert-True ($script:JA.Ctl.Raw.Text.Contains('detail-match') -and $script:JA.Ctl.Verdict.Text.Contains('peerToPeer')) 'Selecting a match did not show the related record.'
$matchFields = Get-ChildNode $matches[0] 'JSON fields'
$matchType = Get-ChildNode $matchFields 'type:'
$script:JA.Ctl.Tree.SelectedNode = $matchType
Assert-True ($script:JA.Ctl.Raw.Text.Trim() -eq '"peerToPeer"') 'Matched call record fields must be navigable.'
Assert-True (@(Get-MatchNodes $script:JA.Ctl.Tree.Nodes[1])[0].Text.Contains('usage-match')) 'Reverse match is missing.'
$detailMatch.participants_v2[0].identity.user.id = 'other-user'
$detailMatch.participants_v2[1].identity.phone.id = '+10000000009'
Invoke-JARender -Records @($usageMatch, $detailMatch) -Label 'different identities'
Assert-True (@(Get-MatchNodes $script:JA.Ctl.Tree.Nodes[0])[0].Text.Contains('user ID differs') -and @(Get-MatchNodes $script:JA.Ctl.Tree.Nodes[0])[0].Text.Contains('number differs')) 'Conflicting match evidence must be shown.'
$usageMatch | Add-Member -NotePropertyName _SourceFile -NotePropertyValue 'C:\export-one\Pstn-1.json'
$detailMatch | Add-Member -NotePropertyName _SourceFile -NotePropertyValue 'C:\export-two\callRecord-1.json'
Invoke-JARender -Records @($usageMatch, $detailMatch) -Label 'different folders'
Assert-True (@(Get-MatchNodes $script:JA.Ctl.Tree.Nodes[0]).Count -eq 0) 'Records from different export folders must not be matched.'
$usageMatch.PSObject.Properties.Remove('_SourceFile')
$detailMatch.PSObject.Properties.Remove('_SourceFile')
$usageMatch.endDateTime = $null
Invoke-JARender -Records @($usageMatch, $detailMatch) -Label 'missing end'
Assert-True (@(Get-MatchNodes $script:JA.Ctl.Tree.Nodes[0]).Count -eq 0) 'Missing end time must not produce a match.'
$usageMatch.endDateTime = '2026-01-01T00:00:08.900Z'
$detailMatch.startDateTime = '2026-01-01T00:00:02.000Z'
Invoke-JARender -Records @($usageMatch, $detailMatch) -Label 'outside tolerance'
Assert-True (@(Get-MatchNodes $script:JA.Ctl.Tree.Nodes[0]).Count -eq 0) 'Start times more than one second apart must not match.'

if ($SampleFolder) {
    Invoke-JALoad -Path $SampleFolder
    Assert-True (@($script:JA.Expanded | Where-Object IsUsageRecord).Count -gt 0) 'Sample folder has no usage records.'
    Assert-True (@($script:JA.Expanded | Where-Object { -not $_.IsUsageRecord }).Count -gt 0) 'Sample folder has no detailed records.'
    for ($i = 0; $i -lt $script:JA.Expanded.Count; $i++) {
        $item = $script:JA.Expanded[$i]
        $script:JA.Ctl.Tree.SelectedNode = $script:JA.Ctl.Tree.Nodes[$i]
        if ($item.IsUsageRecord) {
            $matches = @(Get-MatchNodes $script:JA.Ctl.Tree.Nodes[$i])
            Assert-True ($matches.Count -eq 1) 'Expected one possible match for each sample PSTN record.'
            Assert-True ($matches[0].Text.Contains('user ID matches') -and $matches[0].Text.Contains('number matches')) 'Sample match evidence is missing.'
            if ($item.CallerNumber) { Assert-True ($script:JA.Ctl.Flow.Text.Contains($item.CallerNumber)) 'Sample caller missing from flow.' }
            if ($item.CalleeNumber) { Assert-True ($script:JA.Ctl.Flow.Text.Contains($item.CalleeNumber)) 'Sample callee missing from flow.' }
        }
        elseif ($item.HasExpandedData) {
            Assert-True ($script:JA.Ctl.Flow.Text.Contains('SESSION 1')) 'Sample detailed session missing from flow.'
            Assert-True (-not $script:JA.Ctl.Raw.Text.Contains('_SourceFile')) 'Internal source path must not appear in raw JSON.'
            $fields = Get-ChildNode $script:JA.Ctl.Tree.Nodes[$i] 'JSON fields'
            $sessionArray = Get-ChildNode $fields 'sessions ['
            $sessionNode = Get-ChildNode $sessionArray '[0]'
            $segments = Get-ChildNode $sessionNode 'segments ['
            $segment = Get-ChildNode $segments '[0]'
            $media = Get-ChildNode $segment 'media ['
            $mediaItem = Get-ChildNode $media '[0]'
            $network = Get-ChildNode $mediaItem 'callerNetwork'
            $script:JA.Ctl.Tree.SelectedNode = $network
            Assert-True ($script:JA.Ctl.Raw.Text -match 'ipAddress') 'Sample caller network JSON is missing.'
            $streams = Get-ChildNode $mediaItem 'streams ['
            $stream = Get-ChildNode $streams '[0]'
            $script:JA.Ctl.Tree.SelectedNode = $stream
            Assert-True ($script:JA.Ctl.Raw.Text -match 'streamDirection') 'Sample media stream JSON is missing.'
        }
    }
    $pstnFile = Get-ChildItem -LiteralPath $SampleFolder -Filter 'Pstn-*.json' -File | Select-Object -First 1
    Invoke-JALoad -Path $pstnFile.FullName
    Assert-True ($script:JA.Ctl.Tree.Nodes.Count -eq 1 -and @(Get-MatchNodes $script:JA.Ctl.Tree.Nodes[0]).Count -eq 1) 'Loading one file did not find its sibling match.'
}
$page.Dispose()
$form.Dispose()

$form = New-Object System.Windows.Forms.Form
$form.ClientSize = New-Object System.Drawing.Size(1200, 700)
$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = 'Fill'
$tabs.TabPages.Add((New-Object System.Windows.Forms.TabPage('Other')))
$page = New-DiagnosticsTabPage
$tabs.TabPages.Add($page)
$form.Controls.Add($tabs)
$form.Show()
$tabs.SelectedTab = $page
Assert-True $script:JA.Ctl.LayoutInitialized 'Analyzer layout was not initialized when its tab became visible.'
Assert-True ([math]::Abs($script:JA.Ctl.Split.SplitterDistance / $script:JA.Ctl.Split.Width - 0.46) -lt 0.02) 'Analyzer tree width is incorrect after tab activation.'
$form.Dispose()
Write-Host 'JSON analyzer tests passed.'
