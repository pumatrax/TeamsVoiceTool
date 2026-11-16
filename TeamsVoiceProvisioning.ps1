#Requires -Version 5.1
# WinForms/GDI+ are Windows-only - there is no cross-platform build from
# Microsoft, on any PowerShell version. This script will not run under
# PowerShell 7 (pwsh) on macOS or Linux; run it under Windows PowerShell 5.1
# (or Windows PowerShell/pwsh on Windows itself) instead.

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic
[System.Windows.Forms.Application]::EnableVisualStyles()

# Semantic version. Bump MAJOR for breaking changes to saved files or workflow,
# MINOR for new features, PATCH for fixes. Keep in step with git tags (vX.Y.Z).
$script:AppVersion = '1.0.0'

# Proxy, set once, process-wide, before anything else runs. Every Invoke-RestMethod
# and Invoke-WebRequest below inherits it, which is why no -Proxy switch appears
# anywhere in this file. Silent by design: on a network with no proxy this throws
# and the default (direct) is already correct.
#
# The same block is repeated inside the CDR runspace worker - a new runspace does
# not inherit this.
try {
    $dp = [System.Net.WebRequest]::GetSystemWebProxy()
    $dp.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    [System.Net.WebRequest]::DefaultWebProxy = $dp
    [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
} catch { }

################################################################################
#
#  TOOLKIT LIBRARY - policy migration, call analysis, diagnostics
#
#  Appended to the provisioning app rather than dot-sourced: a separate file that
#  must travel alongside is a deployment failure waiting to happen, and a missing
#  one fails at click time rather than load time.
#
#  Defined here BEFORE the UI is constructed, because the tab builders below are
#  called during form construction, not at click time.
#
#  NOTE ON STRICTMODE: the toolkit was written under Set-StrictMode -Version 2.
#  The host app does not set it, which is the laxer of the two, so the toolkit's
#  property guards remain correct. Do not add StrictMode to the app without
#  retesting the app's own handlers.
#
################################################################################





################################################################################
#
#  PART 1-2  AUTH, SESSION LIFECYCLE AND POLICY ESTATE
#
################################################################################

# ==============================================================================
# REGION 1 - GRAPH TOKEN LIFECYCLE
# ==============================================================================

# Synchronized so the CDR runspace and the UI thread can share one cache.
# $script: scope does NOT cross a runspace boundary - you must hand this object
# to the runspace explicitly (see New-TokenAwareRunspace below).
$script:TokenCache = [hashtable]::Synchronized(@{
    AccessToken = $null
    ExpiresOn   = [datetime]::MinValue   # never do arithmetic ON this - see the
                                         # comparison in Get-GraphAccessToken
    ClientId    = $null
    TenantId    = $null
    Scope       = $null
})

# Credentials for the currently selected environment (dev / UAT).
# Set-ToolkitAuthContext populates this when the env dropdown changes.
#
# TeamsAuthMode is deliberately independent of the Graph credential.
#
# App-only auth on the MicrosoftTeams module covers essentially every Cs cmdlet
# from 4.7.1+ (commercial/GCC) and 5.0.1+ (GCC High/DoD). It is NOT a capability
# gap - it is an RBAC requirement. The service principal needs an Entra DIRECTORY
# ROLE, not just Graph API permissions: assign Teams Administrator to the SPN.
# Skype for Business Administrator is reported not to work.
#
# Symptom of a missing role: cmdlets connect fine and return EMPTY rather than
# throwing. An empty civic address export is a role problem, not an auth problem.
#
# The genuine exclusions under app auth, per Microsoft's documented list:
#   Set-CsOnlineApplicationInstance                 (everywhere)
#   [Get|New|Sync]-CsOnlineApplicationInstance      (GCC High / DoD only)
#   New-Team, *PolicyPackage*, *-CsTeamsShiftsConnection*, *-CsBatchTeamsDeployment*
#   [Get|Set]-CsTeamsSettingsCustomApp, Get-MultiGeoRegion, and the
#   M365Unified* / M365TeamsApp family
#
# The application-instance entries matter here: those are resource accounts. If
# the provisioning tool needs to Set one, that path requires a delegated session
# regardless of how well the SPN is roled. None of the 15 policy types in the
# manifest below are excluded.
#
# So Interactive/DeviceCode exists for resource-account writes, GCC High
# environments, break-glass when the SPN's role assignment is in question, and
# operators who must act under their own identity for audit. Not because the
# policy cmdlets need it.
$script:AuthContext = @{
    TenantId              = $null
    ClientId              = $null
    ClientSecret          = $null
    CertificateThumbprint = $null
    GraphBase             = 'https://graph.microsoft.com/v1.0'
    Scope                 = 'https://graph.microsoft.com/.default'
    TeamsAuthMode         = 'Application'   # Application | Interactive | DeviceCode
    TeamsAccountId        = $null           # optional UPN hint for interactive sign-in
    UseAccountIdHint      = $false          # OFF by default - see Confirm-TeamsConnection
    AccessTokens          = $null           # @($graphToken, $teamsToken) for AccessToken mode
}

function Set-ToolkitAuthContext {
<#
.SYNOPSIS
    Point the toolkit at a tenant. Call this on environment switch.
.DESCRIPTION
    Changing tenant or client wipes the cached token so the next Graph call
    re-authenticates against the new environment rather than reusing dev's token
    against UAT.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$CertificateThumbprint,
        [ValidateSet('Application','Interactive','DeviceCode','AccessToken')][string]$TeamsAuthMode = 'Application',
        [string]$TeamsAccountId,
        [switch]$UseAccountIdHint,
        [string]$GraphBase = 'https://graph.microsoft.com/v1.0',
        [string]$Scope     = 'https://graph.microsoft.com/.default'
    )

    $hasAppCred = $ClientSecret -or $CertificateThumbprint

    if ($TeamsAuthMode -eq 'Application') {
        if (-not $ClientId)   { throw 'Set-ToolkitAuthContext: -ClientId is required for Application auth.' }
        if (-not $hasAppCred) { throw 'Set-ToolkitAuthContext: supply either -ClientSecret or -CertificateThumbprint for Application auth.' }
    }
    elseif (-not $hasAppCred) {
        # Delegated Teams auth with no SPN is legitimate, but Graph calls will
        # have nothing to authenticate with. Say so now rather than at first use.
        Write-ToolkitLog "TeamsAuthMode is $TeamsAuthMode with no app credential - Graph calls (numbers, CDR) will be unavailable in this environment." 'WARN'
    }

    $changed = ($script:AuthContext.TenantId      -ne $TenantId) -or
               ($script:AuthContext.ClientId      -ne $ClientId) -or
               ($script:AuthContext.TeamsAuthMode -ne $TeamsAuthMode)

    $script:AuthContext.TenantId              = $TenantId
    $script:AuthContext.ClientId              = $ClientId
    $script:AuthContext.ClientSecret          = $ClientSecret
    $script:AuthContext.CertificateThumbprint = $CertificateThumbprint
    $script:AuthContext.TeamsAuthMode         = $TeamsAuthMode
    $script:AuthContext.TeamsAccountId        = $TeamsAccountId
    $script:AuthContext.UseAccountIdHint      = [bool]$UseAccountIdHint
    $script:AuthContext.GraphBase             = $GraphBase.TrimEnd('/')
    $script:AuthContext.Scope                 = $Scope

    if ($changed) {
        Clear-GraphTokenCache
        $script:TeamsConnectedAt = $null
        Write-Verbose "Auth context switched to tenant $TenantId - token and Teams session invalidated."
    }
}

function Clear-GraphTokenCache {
    [CmdletBinding()]
    param()
    [System.Threading.Monitor]::Enter($script:TokenCache.SyncRoot)
    try {
        $script:TokenCache.AccessToken = $null
        $script:TokenCache.ExpiresOn   = [datetime]::MinValue
    }
    finally { [System.Threading.Monitor]::Exit($script:TokenCache.SyncRoot) }
}

function Get-GraphAccessToken {
<#
.SYNOPSIS
    Return a valid Graph access token, minting a new one only when needed.
.DESCRIPTION
    Client-credentials grant issues no refresh token and needs none - we hold the
    secret/cert, so "refresh" is simply re-requesting. Lazy-on-demand rather than
    a timer: the app may idle for hours between provisioning runs, and a timer
    would both waste token requests and block the WinForms UI thread on the wire.

    Thread-safe: the CDR runspace and the UI thread may both call this.
.PARAMETER SkewSeconds
    Renew this many seconds before actual expiry. 300 covers clock drift and a
    slow call that starts valid and lands expired.
#>
    [CmdletBinding()]
    param(
        [int]$SkewSeconds = 300,
        [switch]$Force,
        [hashtable]$Cache = $script:TokenCache,
        [hashtable]$Context = $script:AuthContext
    )

    [System.Threading.Monitor]::Enter($Cache.SyncRoot)
    try {
        $valid = $Cache.AccessToken -and
                 $Cache.ClientId -eq $Context.ClientId -and
                 $Cache.TenantId -eq $Context.TenantId -and
                 (Get-Date).AddSeconds($SkewSeconds) -lt $Cache.ExpiresOn

        if ($valid -and -not $Force) { return $Cache.AccessToken }

        $body = @{
            client_id  = $Context.ClientId
            scope      = $Context.Scope
            grant_type = 'client_credentials'
        }

        if ($Context.ClientSecret) {
            $body['client_secret'] = $Context.ClientSecret
        }
        else {
            $body['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            $body['client_assertion']      = New-ClientAssertion `
                                                -TenantId $Context.TenantId `
                                                -ClientId $Context.ClientId `
                                                -Thumbprint $Context.CertificateThumbprint
        }

        $uri = "https://login.microsoftonline.com/$($Context.TenantId)/oauth2/v2.0/token"

        try {
            $resp = Invoke-RestMethod -Method Post -Uri $uri -Body $body `
                        -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
        }
        catch {
            $detail = $_.ErrorDetails.Message
            if (-not $detail) { $detail = $_.Exception.Message }
            throw "Token request failed for tenant $($Context.TenantId): $detail"
        }

        $Cache.AccessToken = $resp.access_token
        $Cache.ExpiresOn   = (Get-Date).AddSeconds([int]$resp.expires_in)
        $Cache.ClientId    = $Context.ClientId
        $Cache.TenantId    = $Context.TenantId
        $Cache.Scope       = $Context.Scope

        Write-Verbose "New Graph token acquired; expires $($Cache.ExpiresOn.ToString('u'))."
        return $Cache.AccessToken
    }
    finally { [System.Threading.Monitor]::Exit($Cache.SyncRoot) }
}

function New-ClientAssertion {
<#
.SYNOPSIS
    Build a signed JWT client assertion from a cert in the local store.
.DESCRIPTION
    Only needed when authenticating with -CertificateThumbprint instead of a
    secret. Certificate auth is worth preferring here: it lets the tool reconnect
    unattended without the secret-rotation churn, and unlike interactive auth it
    will not prompt an operator mid-rollback.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$Thumbprint
    )

    $cert = Get-ChildItem -Path "Cert:\CurrentUser\My\$Thumbprint" -ErrorAction SilentlyContinue
    if (-not $cert) {
        $cert = Get-ChildItem -Path "Cert:\LocalMachine\My\$Thumbprint" -ErrorAction SilentlyContinue
    }
    if (-not $cert)          { throw "Certificate $Thumbprint not found in CurrentUser\My or LocalMachine\My." }
    if (-not $cert.HasPrivateKey) { throw "Certificate $Thumbprint has no private key available to this account." }

    $enc = [System.Text.Encoding]::UTF8
    function ConvertTo-Base64Url([byte[]]$Bytes) {
        [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
    }

    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

    $header = @{
        alg = 'RS256'
        typ = 'JWT'
        x5t = ConvertTo-Base64Url $cert.GetCertHash()
    } | ConvertTo-Json -Compress

    $payload = @{
        aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        iss = $ClientId
        sub = $ClientId
        jti = [guid]::NewGuid().ToString()
        nbf = $now
        exp = $now + 600
    } | ConvertTo-Json -Compress

    $unsigned = (ConvertTo-Base64Url $enc.GetBytes($header)) + '.' +
                (ConvertTo-Base64Url $enc.GetBytes($payload))

    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if (-not $rsa) { throw "Could not obtain an RSA private key from certificate $Thumbprint." }

    $sig = $rsa.SignData(
        $enc.GetBytes($unsigned),
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

    "$unsigned." + (ConvertTo-Base64Url $sig)
}

function Invoke-GraphRequest {
<#
.SYNOPSIS
    Graph call with automatic token refresh, 401 retry, throttling backoff and paging.
.DESCRIPTION
    Route every Graph call through this so the expiry check happens once, in one
    place. The 401 retry is the backstop for the case the skew window cannot
    cover: AAD revoking a token early after a credential change, CA policy update
    or key rollover.
.PARAMETER All
    Follow @odata.nextLink and return the concatenated .value collections.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [ValidateSet('GET','POST','PATCH','PUT','DELETE')][string]$Method = 'GET',
        $Body,
        [hashtable]$ExtraHeaders,
        [switch]$All,
        [int]$MaxRetries = 3
    )

    if ($Uri -notmatch '^https?://') {
        $Uri = "$($script:AuthContext.GraphBase)/$($Uri.TrimStart('/'))"
    }

    $results = New-Object System.Collections.ArrayList
    $next    = $Uri

    while ($next) {
        $attempt  = 0
        $response = $null

        while ($true) {
            $token = Get-GraphAccessToken -Force:($attempt -gt 0 -and $script:LastGraphStatus -eq 401)

            $headers = @{ Authorization = "Bearer $token" }
            if ($ExtraHeaders) { foreach ($k in $ExtraHeaders.Keys) { $headers[$k] = $ExtraHeaders[$k] } }

            $params = @{
                Uri = $next; Method = $Method; Headers = $headers; ErrorAction = 'Stop'
            }
            if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
                $params['Body'] = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 12 }
                $params['ContentType'] = 'application/json'
            }

            try {
                $response = Invoke-RestMethod @params
                $script:LastGraphStatus = 200
                break
            }
            catch {
                $status = 0
                if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) {
                    $status = [int]$_.Exception.Response.StatusCode
                }
                $script:LastGraphStatus = $status
                $attempt++

                if ($attempt -gt $MaxRetries) { throw }

                if ($status -eq 401) {
                    Write-Verbose 'Graph returned 401 - forcing token refresh and retrying.'
                    continue
                }
                if ($status -eq 429 -or $status -ge 500) {
                    $wait = [Math]::Pow(2, $attempt)
                    try {
                        $ra = $_.Exception.Response.Headers['Retry-After']
                        if ($ra) { $wait = [int]$ra }
                    } catch { }
                    Write-Verbose "Graph returned $status - backing off $wait s."
                    Start-Sleep -Seconds $wait
                    continue
                }
                throw
            }
        }

        if (-not $All) { return $response }

        if ($response.PSObject.Properties['value']) { [void]$results.AddRange(@($response.value)) }
        else { [void]$results.Add($response) }

        $next = if ($response.PSObject.Properties['@odata.nextLink']) { $response.'@odata.nextLink' } else { $null }
    }

    ,$results.ToArray()
}

function Add-TokenCacheToRunspace {
<#
.SYNOPSIS
    Hand the shared token cache and auth context to a background runspace.
.DESCRIPTION
    Call this on the CDR runspace before Open()/BeginInvoke(). Without it the
    runspace gets its own null copy of $script:TokenCache and will silently fail
    or re-authenticate on every single call.

    The runspace must also import the token functions - pass their definitions in
    via the same session state, or dot-source this file inside the worker.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Management.Automation.Runspaces.Runspace]$Runspace
    )
    $Runspace.SessionStateProxy.SetVariable('TokenCache',  $script:TokenCache)
    $Runspace.SessionStateProxy.SetVariable('AuthContext', $script:AuthContext)
}

# ==============================================================================
# REGION 2 - MICROSOFTTEAMS SESSION LIFECYCLE
#
# Design assumption: on a locked-down network, ANY given auth path may be barred
# by policy rather than broken. Application auth needs an app registration and a
# directory role the org may not grant. DeviceCode is commonly disabled outright
# by a Conditional Access authentication-flows policy. Interactive depends on the
# default browser, which may be SSO-pinned to the wrong identity.
#
# So: never assume a mode works, never retry a mode that policy has refused, and
# always tell the operator WHICH wall was hit. An opaque MSAL dump sends people
# down the wrong path for an afternoon.
# ==============================================================================

# AADSTS codes worth translating. The message text moves around between library
# versions; the numeric code does not.
$script:AadErrorMap = [ordered]@{
    'AADSTS50076'   = 'MFA required for this account. App-only auth avoids it; otherwise complete the MFA prompt.'
    'AADSTS50079'   = 'The account must enrol in MFA before it can sign in here.'
    'AADSTS53003'   = 'Blocked by Conditional Access policy. This is deliberate org config - a different auth mode, or a CA exclusion, is needed. Retrying will not help.'
    'AADSTS50005'   = 'Device-based Conditional Access blocked this. The machine is not compliant/joined as the policy requires.'
    'AADSTS700016'  = 'Application not found in this tenant. A service principal is tenant-local - the app must be registered and consented in EACH tenant.'
    'AADSTS7000215' = 'Invalid client secret. Check the value, and whether it has expired.'
    'AADSTS7000222' = 'The client secret has expired. Rotate it in the app registration.'
    'AADSTS7000218' = 'No client credential was sent. The secret or certificate assertion did not reach the token endpoint.'
    'AADSTS700027'  = 'Certificate assertion rejected. The public key is probably not uploaded to the app registration in THIS tenant.'
    'AADSTS65001'   = 'Admin consent has not been granted for the requested permissions in this tenant.'
    'AADSTS50105'   = 'The signed-in identity is not assigned a role for this application.'
    'AADSTS90002'   = 'Tenant not found. Check the tenant ID or domain.'
    'AADSTS50020'   = 'The account does not exist in this tenant. Cross-tenant sign-in needs guest access.'
    'AADSTS70016'   = 'Device code flow pending or expired - the code was not entered in time.'
    'AADSTS50059'   = 'No tenant-identifying information found. Pass -TenantId explicitly.'
}

# Not an AADSTS code - this is a Teams-module-side 401/403/40301 surfaced after
# a token was issued successfully. Named separately because the AadErrorMap
# above only covers failures at the token endpoint itself.
$script:TeamsRoleErrorMap = [ordered]@{
    '40301' = 'Authenticated, but the backend refused the action (40301). If this app registration uses an Administrative Unit-scoped Teams Administrator role, Microsoft requires RoleManagement.Read.Directory (all AU-scoped apps) and, for group-related cmdlets, GroupMember.Read.All as of September 15, 2025 - add the missing permission and re-consent, then reconnect.'
}

function Resolve-TeamsAuthError {
<#
.SYNOPSIS
    Turn an auth exception into a plain statement of what to do next.
.DESCRIPTION
    Returns a Retryable flag alongside the guidance. Retryable is false for
    anything that is org policy rather than a transient fault - there is no point
    falling through to another attempt of the same mode when Conditional Access
    has refused it.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$ErrorRecord,
        [string]$Mode = 'Application'
    )

    $msg = ''
    try { $msg = $ErrorRecord.Exception.Message } catch { }
    if (-not $msg) { $msg = [string]$ErrorRecord }

    $code = $null; $guidance = $null
    foreach ($k in $script:AadErrorMap.Keys) {
        if ($msg -match [regex]::Escape($k)) { $code = $k; $guidance = $script:AadErrorMap[$k]; break }
    }
    if (-not $guidance) {
        foreach ($k in $script:TeamsRoleErrorMap.Keys) {
            if ($msg -match [regex]::Escape($k)) { $code = $k; $guidance = $script:TeamsRoleErrorMap[$k]; break }
        }
    }

    if (-not $guidance) {
        $guidance = switch -Regex ($msg) {
            'interaction_required|user_interaction'  { 'Silent auth was refused and interaction is required. Do not pass -AccountId; let the browser prompt open.' ; break }
            'authorization_pending|slow_down'        { 'Device code not yet entered.' ; break }
            'AADSTS'                                 { 'Entra rejected the sign-in. The AADSTS code in the message is the thing to search for.' ; break }
            'Forbidden|Authoriz|denied|privileg'     { 'Authenticated, but not authorized. Assign the Teams Administrator directory role to this identity.' ; break }
            'could not be resolved|No such host|timed out|proxy' { 'Network or proxy problem reaching the identity endpoint, not an auth failure.' ; break }
            default                                  { 'Unrecognised failure - see the raw message below.' }
        }
    }

    # Policy refusals and bad credentials are not worth retrying.
    $terminal = $code -in @('AADSTS53003','AADSTS50005','AADSTS700016','AADSTS7000215',
                            'AADSTS7000222','AADSTS700027','AADSTS65001','AADSTS90002','AADSTS50020')

    [pscustomobject]@{
        Mode      = $Mode
        Code      = $code
        Guidance  = $guidance
        Retryable = -not $terminal
        Raw       = $msg
    }
}

$script:TeamsConnectedAt = $null
$script:TeamsTenantId    = $null   # tenant the LIVE session is actually bound to
$script:TeamsAccount     = $null   # UPN or app: identifier the session signed in as

function Confirm-TeamsConnection {
<#
.SYNOPSIS
    Ensure a usable MicrosoftTeams session bound to the intended tenant.
.DESCRIPTION
    Connect-MicrosoftTeams manages its own token internally and will NOT pick up
    anything Get-GraphAccessToken refreshes. It renews silently for a while, then
    the session goes stale and cmdlets that worked ten minutes ago start failing.
    There is no refresh API - the fix is to reconnect. Do it proactively before a
    long operation rather than discovering it halfway through a rollback.

    A tenant mismatch counts as stale. The module holds ONE session, so switching
    environments must tear the old one down first: reconnecting on top of a live
    session can leave the previous tenant's context in place, and a policy import
    would then write into the tenant you thought you had left.
#>
    [CmdletBinding()]
    param(
        [int]$MaxAgeMinutes = 45,
        [switch]$Force
    )

    $ctx = $script:AuthContext
    if (-not $ctx.TenantId) { throw 'Confirm-TeamsConnection: no auth context. Call Switch-ToolkitEnvironment first.' }

    $wrongTenant = $script:TeamsTenantId -and ($script:TeamsTenantId -ne $ctx.TenantId)

    $stale = $Force -or $wrongTenant -or
             (-not $script:TeamsConnectedAt) -or
             (((Get-Date) - $script:TeamsConnectedAt).TotalMinutes -gt $MaxAgeMinutes)

    if (-not $stale) { return }

    if ($wrongTenant) {
        Write-ToolkitLog "Teams session is bound to $($script:TeamsTenantId) but $($ctx.TenantId) is selected - tearing down." 'WARN'
    }

    # Always disconnect before reconnecting. Cheap, and it removes the ambiguity.
    Disconnect-ToolkitTeamsSession

    $p = @{ TenantId = $ctx.TenantId; ErrorAction = 'Stop' }

    switch ($ctx.TeamsAuthMode) {

        'Interactive' {
            # DO NOT pass -AccountId by default.
            #
            # Supplying it makes MSAL attempt a silent / integrated-Windows flow
            # first. Networks that block that path fail here rather than falling
            # back, and the failure does not name the cause. Omitting it forces
            # the interactive browser handoff, which is what actually works.
            #
            # The UPN is therefore a HINT only, used when -UseAccountIdHint is
            # set on the environment row. Default is off.
            if ($ctx.TeamsAccountId -and $ctx.UseAccountIdHint) {
                $p['AccountId'] = $ctx.TeamsAccountId
                Write-ToolkitLog "Passing AccountId hint $($ctx.TeamsAccountId) - if sign-in hangs or fails silently, clear UseAccountIdHint for this environment." 'WARN'
            }

            # Connect-MicrosoftTeams hands the auth URL to the DEFAULT browser.
            # Where the default browser is SSO-pinned to a work identity, the tab
            # lands in the wrong session. Opening a guest/incognito window first
            # gives the new tab somewhere neutral to land.
            Write-ToolkitLog 'Interactive sign-in: a browser tab will open. If your default browser is SSO-pinned, open a guest window BEFORE clicking through.' 'INFO'
        }

        'DeviceCode' {
            $p['UseDeviceAuthentication'] = $true
            Write-ToolkitLog 'Device code sign-in: a code will be written to the console for you to enter at microsoft.com/devicelogin.' 'INFO'
        }

        'AccessToken' {
            # The escape hatch when every interactive path is barred by policy.
            #
            # Connect-MicrosoftTeams accepts -AccessTokens @($graphToken, $teamsToken).
            # It decouples token ACQUISITION from the module entirely: obtain the
            # two tokens by whatever means the org permits - an approved internal
            # broker, an existing MSAL session, a pipeline secret - and hand them
            # in. Nothing here launches a browser or contacts a device endpoint.
            #
            # Two tokens are needed because the module spans the Graph-era cmdlets
            # and the older Skype-derived Cs* estate, which are separate resources.
            #
            # VERIFY the Teams resource audience against your own tenant before
            # relying on this. The value in Set-ToolkitAccessToken's help is the
            # commonly cited one, but it is thinly documented and differs in
            # sovereign clouds - which is why it is a parameter, not a constant.
            if (-not $ctx.AccessTokens -or @($ctx.AccessTokens).Count -lt 2) {
                throw 'AccessToken mode needs two tokens: @($graphToken, $teamsToken). Supply them with Set-ToolkitAccessToken.'
            }
            $p['AccessTokens'] = @($ctx.AccessTokens)
            Write-ToolkitLog 'Connecting with supplied access tokens - no browser, no device prompt.' 'INFO'
        }

        default {
            $p['ApplicationId'] = $ctx.ClientId
            if ($ctx.CertificateThumbprint) {
                $p['CertificateThumbprint'] = $ctx.CertificateThumbprint
            }
            else {
                $sec = ConvertTo-SecureString $ctx.ClientSecret -AsPlainText -Force
                $p['Credential'] = New-Object System.Management.Automation.PSCredential($ctx.ClientId, $sec)
            }
        }
    }

    Write-Verbose "Establishing MicrosoftTeams session against $($ctx.TenantId) ($($ctx.TeamsAuthMode))."

    try {
        $session = Connect-MicrosoftTeams @p
    }
    catch {
        $diag = Resolve-TeamsAuthError -ErrorRecord $_ -Mode $ctx.TeamsAuthMode
        Write-ToolkitLog "Teams sign-in failed in $($ctx.TeamsAuthMode) mode$(if ($diag.Code) { " [$($diag.Code)]" })." 'ERROR'
        Write-ToolkitLog "  -> $($diag.Guidance)" 'ERROR'

        # Offer the modes not yet tried, but never suggest re-running one that
        # policy has definitively refused.
        $alternatives = @('Application','Interactive','DeviceCode','AccessToken') |
                            Where-Object { $_ -ne $ctx.TeamsAuthMode }
        if ($diag.Retryable) {
            Write-ToolkitLog "  Other modes available for this environment: $($alternatives -join ', '). If all are blocked by policy, use AccessToken mode with tokens obtained however your org permits." 'INFO'
        }

        throw ("Teams sign-in failed ({0} mode){1}.`n{2}`n`nRaw: {3}" -f
               $ctx.TeamsAuthMode,
               $(if ($diag.Code) { " [$($diag.Code)]" } else { '' }),
               $diag.Guidance, $diag.Raw)
    }

    $script:TeamsConnectedAt = Get-Date
    $script:TeamsTenantId    = $ctx.TenantId

    # Record who actually signed in - useful in the log when a cmdlet later fails
    # on permissions rather than on auth.
    $who = $null
    try { $who = $session.Account.Id } catch { }
    if (-not $who -and $ctx.TeamsAuthMode -eq 'Application') { $who = "app:$($ctx.ClientId)" }
    $script:TeamsAccount = $who
    if ($who) { Write-ToolkitLog "Teams session established as $who." 'OK' }
}

function Get-TeamsSessionInfo {
<#
.SYNOPSIS
    Report what the current Teams session is, and how it was established.
#>
    [CmdletBinding()]
    param()
    [pscustomobject]@{
        TenantId    = $script:TeamsTenantId
        Account     = $script:TeamsAccount
        AuthMode    = $script:AuthContext.TeamsAuthMode
        ConnectedAt = $script:TeamsConnectedAt
        AgeMinutes  = if ($script:TeamsConnectedAt) { [math]::Round(((Get-Date) - $script:TeamsConnectedAt).TotalMinutes, 1) } else { $null }
    }
}

function Disconnect-ToolkitTeamsSession {
<#
.SYNOPSIS
    Drop the MicrosoftTeams session and forget which tenant it was bound to.
#>
    [CmdletBinding()]
    param()
    try {
        if (Get-Command Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue) {
            Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue | Out-Null
        }
    }
    catch { }
    $script:TeamsConnectedAt = $null
    $script:TeamsTenantId    = $null
}

function Set-ToolkitAccessToken {
<#
.SYNOPSIS
    Supply externally acquired tokens for AccessToken auth mode.
.DESCRIPTION
    For environments where app registration, interactive browser sign-in and
    device code are all barred. You obtain the tokens by whatever route your org
    sanctions; this just hands them to the module.

    Two resources are required:
      [0] Microsoft Graph          - https://graph.microsoft.com
      [1] Skype and Teams Tenant Admin API

    The second audience is the fiddly one. 48ac35b8-9aa8-4d74-927d-1f4a14a0b239
    is the value commonly used in commercial cloud, but it is thinly documented
    and differs in sovereign clouds - confirm it against your tenant rather than
    trusting this note. Decode what you get with jwt.ms and check the 'aud'
    claim before assuming a failure is a permissions problem.

    Tokens are short-lived. When they expire the session dies and there is no
    refresh path here - re-acquire and call this again.
.EXAMPLE
    Set-ToolkitAccessToken -GraphToken $g -TeamsToken $t
    Confirm-TeamsConnection -Force
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$GraphToken,
        [Parameter(Mandatory)][string]$TeamsToken
    )

    foreach ($pair in @(@{N='Graph';V=$GraphToken}, @{N='Teams';V=$TeamsToken})) {
        if ($pair.V -notmatch '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.') {
            Write-ToolkitLog "$($pair.N) token does not look like a JWT - check you passed the token and not the whole response object." 'WARN'
        }
    }

    $script:AuthContext.AccessTokens  = @($GraphToken, $TeamsToken)
    $script:AuthContext.TeamsAuthMode = 'AccessToken'
    Disconnect-ToolkitTeamsSession

    Write-ToolkitLog 'Access tokens stored; auth mode set to AccessToken. Call Confirm-TeamsConnection to use them.' 'OK'
}

function Get-ConnectedTenantId {
<#
.SYNOPSIS
    Ask the SERVICE which tenant this session is on - not what the app believes.
.DESCRIPTION
    $script:TeamsTenantId records our intent. This goes to the wire and reports
    reality. The two disagreeing is precisely the condition worth catching before
    a write.
#>
    [CmdletBinding()]
    param()
    try   { return [string](Get-CsTenant -ErrorAction Stop).TenantId }
    catch { return $null }
}

function Assert-ConnectedTenant {
<#
.SYNOPSIS
    Hard guard: throw unless the live session is on the expected tenant.
.DESCRIPTION
    Call before any write against a tenant that is not the one you started in.
    Costs one round trip; prevents restoring a bundle into the wrong estate.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ExpectedTenantId,
        [string]$Because = 'operation'
    )

    $actual = Get-ConnectedTenantId
    if (-not $actual) {
        throw "Cannot confirm the connected tenant (Get-CsTenant failed). Refusing to proceed with $Because."
    }
    if ($actual -ne $ExpectedTenantId) {
        throw ("Tenant mismatch - refusing to proceed with {0}.`n" -f $Because) +
              ("  Expected : {0}`n" -f $ExpectedTenantId) +
              ("  Connected: {0}`n" -f $actual) +
              '  Run Switch-ToolkitEnvironment against the intended environment first.'
    }
    Write-ToolkitLog "Tenant confirmed: $actual" 'OK'
    $actual
}

function Test-TeamsCmdletAvailable {
    param([Parameter(Mandatory)][string]$Name)
    [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

# ==============================================================================
# REGION 2b - ENVIRONMENT SWITCHING
#
# Backed by TeamsVoice_Environments.csv - the same file the Manage Environments
# dialog edits. Adding the migration target is a matter of adding a row, but that
# row needs its OWN app registration: an SPN is a tenant-local object, so the
# client ID from tenant A does not exist in tenant B. The target tenant needs the
# app consented with Teams administrator rights, and if you are using certificate
# auth, the public key uploaded there too.
# ==============================================================================

# Column-name tolerance: the CSV predates this module, so accept the obvious
# variants rather than forcing a schema change on an in-use file.
$script:EnvColumnAliases = @{
    Name           = @('Name','Environment','Env','Label','DisplayName')
    TenantId       = @('TenantId','Tenant','TenantGuid','TenantID','Directory')
    ClientId       = @('ClientId','AppId','ApplicationId','ClientID','SpnId')
    Thumbprint     = @('CertificateThumbprint','Thumbprint','CertThumbprint','Cert')
    ClientSecret   = @('ClientSecret','Secret','AppSecret')
    GraphBase      = @('GraphBase','GraphEndpoint','Graph')
    TeamsAuthMode  = @('TeamsAuthMode','TeamsAuth','AuthMode','SignInMode')
    TeamsAccountId = @('TeamsAccountId','TeamsAccount','AdminUpn','SignInAs','Upn')
    UseAccountIdHint = @('UseAccountIdHint','AccountIdHint','PassAccountId')
}

function Get-EnvColumnValue {
    param($Row, [Parameter(Mandatory)][string]$Field)

    foreach ($alias in $script:EnvColumnAliases[$Field]) {
        if ($Row.PSObject.Properties[$alias]) {
            $v = $Row.$alias
            if (-not [string]::IsNullOrWhiteSpace($v)) { return [string]$v }
        }
    }
    $null
}

function Get-ToolkitEnvironment {
<#
.SYNOPSIS
    Read the environment definitions from TeamsVoice_Environments.csv.
.PARAMETER Path
    Defaults to the CSV alongside the script.
.EXAMPLE
    Get-ToolkitEnvironment | Format-Table Name, TenantId, TeamsAuthMode, GraphAuthMode
#>
    [CmdletBinding()]
    param([string]$Path)

    if (-not $Path) {
        $Path = if ($script:EnvCsvPath) { $script:EnvCsvPath } else { Join-Path (Get-ToolkitRoot) 'TeamsVoice_Environments.csv' }
    }
    if (-not (Test-Path $Path)) { throw "Environment file not found: $Path" }

    foreach ($row in @(Import-Csv -Path $Path)) {
        $name = Get-EnvColumnValue -Row $row -Field Name
        $tid  = Get-EnvColumnValue -Row $row -Field TenantId
        if (-not $name -or -not $tid) { continue }

        $thumb  = Get-EnvColumnValue -Row $row -Field Thumbprint
        $secret = Get-EnvColumnValue -Row $row -Field ClientSecret

        $teamsMode = Get-EnvColumnValue -Row $row -Field TeamsAuthMode
        if (-not $teamsMode) { $teamsMode = 'Application' }
        if ($teamsMode -notin 'Application','Interactive','DeviceCode','AccessToken') {
            Write-ToolkitLog "Environment '$name': unrecognised auth mode '$teamsMode' - treating as Application." 'WARN'
            $teamsMode = 'Application'
        }

        [pscustomobject]@{
            Name                  = $name
            TenantId              = $tid
            ClientId              = Get-EnvColumnValue -Row $row -Field ClientId
            CertificateThumbprint = $thumb
            ClientSecret          = $secret
            GraphBase             = (Get-EnvColumnValue -Row $row -Field GraphBase)
            TeamsAuthMode         = $teamsMode
            TeamsAccountId        = (Get-EnvColumnValue -Row $row -Field TeamsAccountId)
            UseAccountIdHint      = ((Get-EnvColumnValue -Row $row -Field UseAccountIdHint) -in 'True','true','1','Yes','yes')
            GraphAuthMode         = if ($thumb) { 'Certificate' } elseif ($secret) { 'Secret' } else { 'None' }
            SourcePath            = $Path
        }
    }
}

function Switch-ToolkitEnvironment {
<#
.SYNOPSIS
    Point the toolkit at a named environment and drop every session bound to the old one.
.DESCRIPTION
    The single entry point for changing tenant. Wire the Manage Environments
    dropdown's SelectedIndexChanged handler to this and nothing else - going
    around it is how a session ends up disagreeing with the UI.

    Tears down in this order: Teams session, Graph token cache, then auth context.
    Nothing is reconnected here; the next Confirm-TeamsConnection or Graph call
    establishes a fresh session lazily against the new tenant.
.PARAMETER Verify
    Immediately connect and confirm the service agrees on the tenant. Slower, but
    the right default before a migration write.
.EXAMPLE
    Switch-ToolkitEnvironment -Name 'UAT' -Verify
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Path,
        [switch]$Verify
    )

    $envs = @(Get-ToolkitEnvironment -Path $Path)
    $env  = $envs | Where-Object { $_.Name -eq $Name } | Select-Object -First 1

    if (-not $env) {
        throw "Environment '$Name' not found. Available: $(($envs.Name) -join ', ')"
    }
    if ($env.TeamsAuthMode -eq 'Application') {
        if ($env.GraphAuthMode -eq 'None') {
            throw "Environment '$Name' uses Application auth but has neither a certificate thumbprint nor a client secret."
        }
        if (-not $env.ClientId) {
            throw "Environment '$Name' has no client ID. Remember the target tenant needs its own app registration - the source tenant's SPN does not exist there."
        }
    }

    Write-ToolkitLog "Switching to environment '$Name' (tenant $($env.TenantId), Teams=$($env.TeamsAuthMode), Graph=$($env.GraphAuthMode))."

    Disconnect-ToolkitTeamsSession
    Clear-GraphTokenCache

    $p = @{
        TenantId      = $env.TenantId
        TeamsAuthMode = $env.TeamsAuthMode
    }
    if ($env.ClientId)              { $p['ClientId']              = $env.ClientId }
    if ($env.CertificateThumbprint) { $p['CertificateThumbprint'] = $env.CertificateThumbprint }
    elseif ($env.ClientSecret)      { $p['ClientSecret']          = $env.ClientSecret }
    if ($env.GraphBase)             { $p['GraphBase']             = $env.GraphBase }
    if ($env.TeamsAccountId)        { $p['TeamsAccountId']        = $env.TeamsAccountId }
    if ($env.UseAccountIdHint)      { $p['UseAccountIdHint']      = $true }

    Set-ToolkitAuthContext @p

    if ($Verify) {
        Confirm-TeamsConnection -Force
        $actual = Get-ConnectedTenantId
        if ($actual -ne $env.TenantId) {
            Disconnect-ToolkitTeamsSession
            throw "Connected to $actual but expected $($env.TenantId) for '$Name'. Session dropped."
        }
        Write-ToolkitLog "Environment '$Name' verified against the service." 'OK'
    }

    [pscustomobject]@{
        Name          = $env.Name
        TenantId      = $env.TenantId
        ClientId      = $env.ClientId
        TeamsAuthMode = $env.TeamsAuthMode
        GraphAuthMode = $env.GraphAuthMode
        Account       = $script:TeamsAccount
        Verified      = [bool]$Verify
    }
}

function Invoke-CrossTenantPolicyMigration {
<#
.SYNOPSIS
    End-to-end: export from the source environment, switch, replay into the target.
.DESCRIPTION
    Encodes the serialization the MicrosoftTeams module forces on us - one session
    at a time, disk as the handoff. Defaults to a dry run on the write half.
.EXAMPLE
    Invoke-CrossTenantPolicyMigration -SourceEnvironment DEV -TargetEnvironment UAT `
        -Path 'C:\TeamsVoice\Backups'
    # inspect the plan, then re-run with -Apply
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourceEnvironment,
        [Parameter(Mandatory)][string]$TargetEnvironment,
        [Parameter(Mandatory)][string]$Path,
        [string]$EnvironmentCsv,
        [string[]]$Include,
        [hashtable]$NameMap = @{},
        [switch]$Apply,
        [switch]$ContinueOnError
    )

    if ($SourceEnvironment -eq $TargetEnvironment) {
        throw 'Source and target environments are the same.'
    }

    # --- Phase 1: export from source -----------------------------------------
    $src = Switch-ToolkitEnvironment -Name $SourceEnvironment -Path $EnvironmentCsv -Verify
    Write-ToolkitLog "Phase 1: exporting from '$SourceEnvironment'."
    $export = Export-TeamsVoiceConfiguration -Path $Path -Label $SourceEnvironment -Include $Include

    # --- Phase 2: switch ------------------------------------------------------
    Write-ToolkitLog "Phase 2: switching to '$TargetEnvironment'."
    $tgt = Switch-ToolkitEnvironment -Name $TargetEnvironment -Path $EnvironmentCsv -Verify

    if ($tgt.TenantId -eq $src.TenantId) {
        throw "'$SourceEnvironment' and '$TargetEnvironment' resolve to the same tenant ($($src.TenantId)). Check the CSV."
    }

    # --- Phase 3: replay into target -----------------------------------------
    Assert-ConnectedTenant -ExpectedTenantId $tgt.TenantId -Because "import into '$TargetEnvironment'" | Out-Null

    Write-ToolkitLog "Phase 3: $(if ($Apply) { 'applying' } else { 'planning (dry run)' }) against '$TargetEnvironment'."

    $importArgs = @{
        BundlePath      = $export.BundlePath
        NameMap         = $NameMap
        ExpectedTenantId = $tgt.TenantId
        ContinueOnError = $ContinueOnError
    }
    if ($Include) { $importArgs['Include'] = $Include }
    if (-not $Apply) { $importArgs['WhatIf'] = $true }

    $result = Import-TeamsVoiceConfiguration @importArgs

    [pscustomobject]@{
        SourceEnvironment = $SourceEnvironment
        SourceTenantId    = $src.TenantId
        TargetEnvironment = $TargetEnvironment
        TargetTenantId    = $tgt.TenantId
        BundlePath        = $export.BundlePath
        Applied           = [bool]$Apply
        Results           = $result
    }
}

# ==============================================================================
# REGION 3 - POLICY MANIFEST
#
# Tier drives ordering on import. Dependencies must exist before the things that
# reference them, or the New-Cs* call fails with an unhelpful error:
#
#   civic addresses -> LIS locations
#   gateways -> PSTN usages -> voice routes -> voice routing policies
#   PSTN usages -> emergency call routing policies
#   emergency call routing policies -> shared calling routing policies
#
# NameParameter is the parameter New-Cs* uses to name the object. Most take
# -Identity; PSTN gateways take -Fqdn; civic addresses have no name parameter at
# all and are matched on Description.
# ==============================================================================

$script:PolicyManifest = @(
    [pscustomobject]@{
        Key='CivicAddress'; Tier=10; DisplayName='Emergency civic addresses'
        Get='Get-CsOnlineLisCivicAddress'; New='New-CsOnlineLisCivicAddress'; Set='Set-CsOnlineLisCivicAddress'
        NameParameter='Description'; IdProperty='CivicAddressId'; SupportsGlobal=$false; Special='CivicAddress'
    }
    [pscustomobject]@{
        Key='LisLocation'; Tier=11; DisplayName='Emergency locations'
        Get='Get-CsOnlineLisLocation'; New='New-CsOnlineLisLocation'; Set='Set-CsOnlineLisLocation'
        NameParameter='Location'; IdProperty='LocationId'; SupportsGlobal=$false; Special='LisLocation'
    }
    [pscustomobject]@{
        Key='PstnGateway'; Tier=20; DisplayName='Direct Routing SBCs'
        Get='Get-CsOnlinePSTNGateway'; New='New-CsOnlinePSTNGateway'; Set='Set-CsOnlinePSTNGateway'
        NameParameter='Fqdn'; IdProperty='Identity'; SupportsGlobal=$false; Special=$null
    }
    [pscustomobject]@{
        Key='PstnUsage'; Tier=30; DisplayName='PSTN usages'
        Get='Get-CsOnlinePstnUsage'; New=$null; Set='Set-CsOnlinePstnUsage'
        NameParameter='Identity'; IdProperty='Identity'; SupportsGlobal=$true; Special='PstnUsage'
    }
    [pscustomobject]@{
        Key='VoiceRoute'; Tier=40; DisplayName='Voice routes'
        Get='Get-CsOnlineVoiceRoute'; New='New-CsOnlineVoiceRoute'; Set='Set-CsOnlineVoiceRoute'
        NameParameter='Identity'; IdProperty='Identity'; SupportsGlobal=$false; Special=$null
    }
    [pscustomobject]@{
        Key='VoiceRoutingPolicy'; Tier=50; DisplayName='Voice routing policies'
        Get='Get-CsOnlineVoiceRoutingPolicy'; New='New-CsOnlineVoiceRoutingPolicy'; Set='Set-CsOnlineVoiceRoutingPolicy'
        NameParameter='Identity'; IdProperty='Identity'; SupportsGlobal=$true; Special=$null
    }
    [pscustomobject]@{
        Key='TenantDialPlan'; Tier=60; DisplayName='Tenant dial plans'
        Get='Get-CsTenantDialPlan'; New='New-CsTenantDialPlan'; Set='Set-CsTenantDialPlan'
        NameParameter='Identity'; IdProperty='Identity'; SupportsGlobal=$true; Special='DialPlan'
    }
    [pscustomobject]@{
        Key='EmergencyCallRoutingPolicy'; Tier=70; DisplayName='Emergency call routing policies'
        Get='Get-CsTeamsEmergencyCallRoutingPolicy'; New='New-CsTeamsEmergencyCallRoutingPolicy'; Set='Set-CsTeamsEmergencyCallRoutingPolicy'
        NameParameter='Identity'; IdProperty='Identity'; SupportsGlobal=$true; Special='EmergencyNumbers'
    }
    [pscustomobject]@{
        Key='EmergencyCallingPolicy'; Tier=71; DisplayName='Emergency calling policies'
        Get='Get-CsTeamsEmergencyCallingPolicy'; New='New-CsTeamsEmergencyCallingPolicy'; Set='Set-CsTeamsEmergencyCallingPolicy'
        NameParameter='Identity'; IdProperty='Identity'; SupportsGlobal=$true; Special=$null
    }
    [pscustomobject]@{
        Key='CallingPolicy'; Tier=80; DisplayName='Calling policies'
        Get='Get-CsTeamsCallingPolicy'; New='New-CsTeamsCallingPolicy'; Set='Set-CsTeamsCallingPolicy'
        NameParameter='Identity'; IdProperty='Identity'; SupportsGlobal=$true; Special=$null
    }
    [pscustomobject]@{
        Key='CallParkPolicy'; Tier=80; DisplayName='Call park policies'
        Get='Get-CsTeamsCallParkPolicy'; New='New-CsTeamsCallParkPolicy'; Set='Set-CsTeamsCallParkPolicy'
        NameParameter='Identity'; IdProperty='Identity'; SupportsGlobal=$true; Special=$null
    }
    [pscustomobject]@{
        Key='CallHoldPolicy'; Tier=80; DisplayName='Call hold policies'
        Get='Get-CsTeamsCallHoldPolicy'; New='New-CsTeamsCallHoldPolicy'; Set='Set-CsTeamsCallHoldPolicy'
        NameParameter='Identity'; IdProperty='Identity'; SupportsGlobal=$true; Special=$null
    }
    [pscustomobject]@{
        Key='VoicemailPolicy'; Tier=80; DisplayName='Voicemail policies'
        Get='Get-CsOnlineVoicemailPolicy'; New='New-CsOnlineVoicemailPolicy'; Set='Set-CsOnlineVoicemailPolicy'
        NameParameter='Identity'; IdProperty='Identity'; SupportsGlobal=$true; Special=$null
    }
    [pscustomobject]@{
        Key='IPPhonePolicy'; Tier=80; DisplayName='IP phone policies'
        Get='Get-CsTeamsIPPhonePolicy'; New='New-CsTeamsIPPhonePolicy'; Set='Set-CsTeamsIPPhonePolicy'
        NameParameter='Identity'; IdProperty='Identity'; SupportsGlobal=$true; Special=$null
    }
    [pscustomobject]@{
        Key='SharedCallingRoutingPolicy'; Tier=85; DisplayName='Shared calling routing policies'
        Get='Get-CsTeamsSharedCallingRoutingPolicy'; New='New-CsTeamsSharedCallingRoutingPolicy'; Set='Set-CsTeamsSharedCallingRoutingPolicy'
        NameParameter='Identity'; IdProperty='Identity'; SupportsGlobal=$false; Special=$null
    }
)

# Properties every Cs* object carries that are computed, structural, or read-only.
# The writable-parameter intersection below catches most of these anyway; this
# list is belt-and-braces for parameters that exist on Set-* but must not travel.
$script:NeverExport = @(
    'Identity','Element','Anchor','ScopeClass','TypedIdentity','XsAnyElements',
    'XsAnyAttributes','Key','KeyValue','ObjectId','PSComputerName','RunspaceId',
    'PSShowComputerName','InMemory','SerializedContainer','DistinguishedName',
    'TenantId','WhenCreated','WhenChanged','_Identity','ProvisionedPlanType'
)

$script:CommonParameters = @(
    'Verbose','Debug','ErrorAction','WarningAction','InformationAction','ProgressAction',
    'ErrorVariable','WarningVariable','InformationVariable','OutVariable','OutBuffer',
    'PipelineVariable','WhatIf','Confirm','Force','InMemory','AsJob','Tenant','Instance',
    'BypassDualWrite','MsftInternalProcessingMode'
)

# ==============================================================================
# REGION 4 - HELPERS
# ==============================================================================

function ConvertTo-PlainObject {
<#
.SYNOPSIS
    Recursively flatten a Cs* policy object into primitives, arrays and hashtables.
.DESCRIPTION
    Policy objects contain typed sub-objects (normalization rules, emergency
    numbers) that do not survive a JSON round-trip as themselves. Reducing to
    plain data makes the bundle stable, diffable in source control, and readable
    a year from now when the module version has moved on.
#>
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)]$InputObject, [int]$Depth = 0)

    process {
        if ($null -eq $InputObject)                  { return $null }
        if ($Depth -gt 12)                           { return [string]$InputObject }

        $t = $InputObject.GetType()
        if ($t.IsPrimitive -or $InputObject -is [string] -or $InputObject -is [datetime] -or
            $InputObject -is [decimal] -or $InputObject -is [guid] -or $t.IsEnum) {
            if ($t.IsEnum) { return [string]$InputObject }
            return $InputObject
        }

        if ($InputObject -is [System.Collections.IDictionary]) {
            $h = [ordered]@{}
            foreach ($k in $InputObject.Keys) {
                $h[[string]$k] = ConvertTo-PlainObject -InputObject $InputObject[$k] -Depth ($Depth + 1)
            }
            return $h
        }

        if ($InputObject -is [System.Collections.IEnumerable]) {
            $out = @()
            foreach ($item in $InputObject) {
                $out += ,(ConvertTo-PlainObject -InputObject $item -Depth ($Depth + 1))
            }
            return ,$out
        }

        $h = [ordered]@{}
        foreach ($p in $InputObject.PSObject.Properties) {
            if ($p.MemberType -notin 'Property','NoteProperty','AliasProperty') { continue }
            try { $v = $p.Value } catch { continue }
            $h[$p.Name] = ConvertTo-PlainObject -InputObject $v -Depth ($Depth + 1)
        }
        if ($h.Count -eq 0) { return [string]$InputObject }
        return $h
    }
}

function Get-PolicyDisplayName {
<#
.SYNOPSIS
    Strip the Tag: prefix off a policy Identity to get its usable name.
#>
    param($Policy, [string]$IdProperty = 'Identity')

    if (-not $Policy.PSObject.Properties[$IdProperty]) { return $null }
    $id = [string]$Policy.$IdProperty
    if ([string]::IsNullOrWhiteSpace($id)) { return $null }
    if ($id -eq 'Global') { return 'Global' }
    $id -replace '^Tag:', ''
}

function Get-WritableParameterName {
<#
.SYNOPSIS
    The set of parameters a cmdlet actually accepts, minus plumbing.
.DESCRIPTION
    Intersecting exported properties against this is what makes the engine
    version-tolerant: if the source tenant's module exposed a property that the
    target's New-Cs* does not accept yet, it is dropped with a warning instead of
    blowing up the whole restore.
#>
    param([Parameter(Mandatory)][string]$CommandName)

    $cmd = Get-Command -Name $CommandName -ErrorAction SilentlyContinue
    if (-not $cmd) { return @() }
    @($cmd.Parameters.Keys | Where-Object { $_ -notin $script:CommonParameters })
}

function Write-ToolkitLog {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR','OK')][string]$Level = 'INFO')

    $line = "[{0}] [{1,-5}] {2}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message

    # If the host GUI exposes a log sink, use it; otherwise fall back to console.
    if (Get-Command -Name 'Add-Log' -ErrorAction SilentlyContinue) { Add-Log $line; return }

    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'OK'    { Write-Host $line -ForegroundColor Green }
        default { Write-Host $line }
    }
}

# ==============================================================================
# REGION 5 - EXPORT
# ==============================================================================

function Export-TeamsVoiceConfiguration {
<#
.SYNOPSIS
    Capture every voice policy definition in the tenant to a JSON bundle (+ CSVs).
.DESCRIPTION
    This is the backup / migration / drift-baseline artifact. One JSON file holds
    the whole estate with tenant and timestamp metadata; the per-type CSVs are the
    convenient surface for bulk edit-and-reapply.
.PARAMETER Path
    Output directory. A timestamped subfolder is created inside it.
.PARAMETER Include
    Restrict to specific manifest keys, e.g. 'VoiceRoutingPolicy','VoiceRoute'.
.PARAMETER SkipCsv
    JSON only.
.EXAMPLE
    Export-TeamsVoiceConfiguration -Path 'C:\TeamsVoice\Backups' -Label 'PROD-preflight'
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$Include,
        [string]$Label = 'export',
        [switch]$SkipCsv,
        [switch]$NoConnect
    )

    if (-not $NoConnect) { Confirm-TeamsConnection }

    $stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
    $outDir  = Join-Path $Path "$Label-$stamp"
    $csvDir  = Join-Path $outDir 'csv'
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    if (-not $SkipCsv) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

    $bundle = [ordered]@{
        SchemaVersion = '1.0'
        ExportedUtc   = (Get-Date).ToUniversalTime().ToString('o')
        TenantId      = $script:AuthContext.TenantId
        Label         = $Label
        ModuleVersion = (Get-Module MicrosoftTeams | Select-Object -First 1 -ExpandProperty Version) -as [string]
        ExportedBy    = "$env:USERDOMAIN\$env:USERNAME"
        Policies      = [ordered]@{}
    }

    $manifest = $script:PolicyManifest | Sort-Object Tier
    if ($Include) { $manifest = $manifest | Where-Object { $_.Key -in $Include } }

    foreach ($m in $manifest) {

        if (-not (Test-TeamsCmdletAvailable -Name $m.Get)) {
            Write-ToolkitLog "$($m.DisplayName): $($m.Get) not available in this module version - skipped." 'WARN'
            continue
        }

        try {
            $items = @(& $m.Get -ErrorAction Stop)
        }
        catch {
            Write-ToolkitLog "$($m.DisplayName): read failed - $($_.Exception.Message)" 'ERROR'
            continue
        }

        $records = @()
        foreach ($item in $items) {
            $plain = ConvertTo-PlainObject -InputObject $item
            $name  = Get-PolicyDisplayName -Policy $item -IdProperty $m.IdProperty

            $rec = [ordered]@{
                Name       = $name
                SourceId   = if ($item.PSObject.Properties[$m.IdProperty]) { [string]$item.$($m.IdProperty) } else { $null }
                IsGlobal   = ($name -eq 'Global')
                Settings   = [ordered]@{}
            }

            foreach ($k in $plain.Keys) {
                if ($k -in $script:NeverExport) { continue }
                $rec.Settings[$k] = $plain[$k]
            }

            $records += $rec
        }

        $bundle.Policies[$m.Key] = [ordered]@{
            DisplayName = $m.DisplayName
            Tier        = $m.Tier
            Count       = $records.Count
            Items       = $records
        }

        Write-ToolkitLog "$($m.DisplayName): $($records.Count) exported." 'OK'

        if (-not $SkipCsv -and $records.Count) {
            $flat = foreach ($r in $records) {
                $row = [ordered]@{ Name = $r.Name }
                foreach ($k in $r.Settings.Keys) {
                    $v = $r.Settings[$k]
                    $row[$k] = Get-ComparableValue $v
                }
                [pscustomobject]$row
            }
            $flat | Export-Csv -Path (Join-Path $csvDir "$($m.Key).csv") -NoTypeInformation -Encoding UTF8
        }
    }

    $jsonPath = Join-Path $outDir 'VoiceConfiguration.json'
    $bundle | ConvertTo-Json -Depth 20 | Set-Content -Path $jsonPath -Encoding UTF8

    Write-ToolkitLog "Bundle written to $jsonPath" 'OK'
    [pscustomobject]@{ BundlePath = $jsonPath; Directory = $outDir; CsvDirectory = $csvDir; Bundle = $bundle }
}

# ==============================================================================
# REGION 6 - IMPORT / REPLAY
# ==============================================================================

function Import-TeamsVoiceConfiguration {
<#
.SYNOPSIS
    Replay an exported bundle into the currently connected tenant.
.DESCRIPTION
    Processes in dependency-tier order. Existing objects are updated with Set-Cs*,
    missing ones created with New-Cs*. Global policies are always Set, never New.

    ALWAYS run with -WhatIf first. Two categories of setting do not travel
    cleanly between tenants and are reported rather than silently mangled:

      * SBC FQDNs must belong to a domain verified in the TARGET tenant.
      * Resource account / user object IDs embedded in policies are tenant-local.

    Use -NameMap to rename objects on the way in (dev -> UAT naming conventions).
.PARAMETER BundlePath
    Path to VoiceConfiguration.json produced by Export-TeamsVoiceConfiguration.
.PARAMETER NameMap
    Hashtable of source name -> target name, e.g. @{ 'DEV-UK-Routing' = 'UAT-UK-Routing' }
.EXAMPLE
    Import-TeamsVoiceConfiguration -BundlePath .\VoiceConfiguration.json -WhatIf
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$BundlePath,
        [string]$ExpectedTenantId,
        [string[]]$Include,
        [string[]]$Exclude,
        [hashtable]$NameMap = @{},
        [switch]$SkipGlobal,
        [switch]$ContinueOnError,
        [switch]$SkipTenantCheck,
        [switch]$NoConnect
    )

    if (-not (Test-Path $BundlePath)) { throw "Bundle not found: $BundlePath" }
    if (-not $NoConnect) { Confirm-TeamsConnection }

    $bundle = Get-Content -Path $BundlePath -Raw -Encoding UTF8 | ConvertFrom-Json

    # Verify against the SERVICE, not against what the app believes. These
    # disagreeing is exactly the case that writes a bundle into the wrong estate.
    if (-not $SkipTenantCheck) {
        $expected = if ($ExpectedTenantId) { $ExpectedTenantId } else { $script:AuthContext.TenantId }
        if (-not $expected) { throw 'No tenant to verify against. Pass -ExpectedTenantId or switch environment first.' }
        Assert-ConnectedTenant -ExpectedTenantId $expected -Because "import of $(Split-Path $BundlePath -Leaf)" | Out-Null

        if ($bundle.TenantId -eq $expected) {
            Write-ToolkitLog 'Bundle was exported from the tenant you are connected to. This is a restore-in-place, not a migration.' 'WARN'
        }
        else {
            Write-ToolkitLog "Migrating $($bundle.TenantId) -> $expected (bundle labelled '$($bundle.Label)', exported $($bundle.ExportedUtc))." 'INFO'
        }
    }

    $results  = New-Object System.Collections.ArrayList
    $manifest = $script:PolicyManifest | Sort-Object Tier

    if ($Include) { $manifest = $manifest | Where-Object { $_.Key -in $Include } }
    if ($Exclude) { $manifest = $manifest | Where-Object { $_.Key -notin $Exclude } }

    foreach ($m in $manifest) {

        if (-not $bundle.Policies.PSObject.Properties[$m.Key]) { continue }
        $section = $bundle.Policies.$($m.Key)
        if (-not $section.Items) { continue }

        if (-not (Test-TeamsCmdletAvailable -Name $m.Set)) {
            Write-ToolkitLog "$($m.DisplayName): $($m.Set) unavailable - section skipped." 'WARN'
            continue
        }

        Write-ToolkitLog "--- $($m.DisplayName) (tier $($m.Tier)) ---"

        $newParams = Get-WritableParameterName -CommandName $m.New
        $setParams = Get-WritableParameterName -CommandName $m.Set

        try   { $existing = @(& $m.Get -ErrorAction Stop) }
        catch { $existing = @() }

        $existingNames = @($existing | ForEach-Object { Get-PolicyDisplayName -Policy $_ -IdProperty $m.IdProperty })

        foreach ($item in $section.Items) {

            $sourceName = $item.Name
            $targetName = if ($NameMap.ContainsKey($sourceName)) { $NameMap[$sourceName] } else { $sourceName }

            if ($item.IsGlobal -and $SkipGlobal) {
                Write-ToolkitLog "Global $($m.Key) skipped by request." 'INFO'
                continue
            }
            if ([string]::IsNullOrWhiteSpace($targetName)) { continue }

            $exists = $targetName -in $existingNames
            $isNew  = (-not $exists) -and (-not $item.IsGlobal) -and $m.New

            $cmdName    = if ($isNew) { $m.New } else { $m.Set }
            $allowed    = if ($isNew) { $newParams } else { $setParams }
            $action     = if ($isNew) { 'Create' } else { 'Update' }

            # Build the parameter splat from exported settings, keeping only what
            # the target cmdlet accepts.
            $splat   = @{}
            $dropped = @()

            foreach ($prop in $item.Settings.PSObject.Properties) {
                $k = $prop.Name
                $v = $prop.Value
                if ($null -eq $v) { continue }
                if ($k -eq $m.NameParameter) { continue }
                if ($k -notin $allowed) { $dropped += $k; continue }
                $splat[$k] = $v
            }

            # Per-type rehydration of complex sub-objects.
            $skipItem = $false
            switch ($m.Special) {
                'DialPlan' {
                    if ($item.Settings.PSObject.Properties['NormalizationRules']) {
                        $splat['NormalizationRules'] = ConvertTo-NormalizationRule -Rules $item.Settings.NormalizationRules
                    }
                }
                'EmergencyNumbers' {
                    if ($item.Settings.PSObject.Properties['EmergencyNumbers']) {
                        $splat['EmergencyNumbers'] = ConvertTo-EmergencyNumber -Numbers $item.Settings.EmergencyNumbers
                    }
                }
                'PstnUsage' {
                    Import-PstnUsageSet -Item $item -WhatIf:$WhatIfPreference
                    $skipItem = $true
                }
                'CivicAddress' {
                    if ($exists) { $skipItem = $true }   # matched on Description; updating in place is a separate concern
                }
                'LisLocation' {
                    $mapped = Resolve-CivicAddressId -Item $item
                    if (-not $mapped) {
                        Write-ToolkitLog "Location '$targetName': no matching civic address in target tenant - skipped." 'WARN'
                        $skipItem = $true
                    }
                    else { $splat['CivicAddressId'] = $mapped }
                }
            }
            if ($skipItem) { continue }

            if ($m.NameParameter -in $allowed) { $splat[$m.NameParameter] = $targetName }

            if ($dropped.Count) {
                Write-ToolkitLog "$targetName - $($dropped.Count) setting(s) not accepted by $cmdName and dropped: $($dropped -join ', ')" 'WARN'
            }

            $target = "$($m.DisplayName) '$targetName'"
            if (-not $PSCmdlet.ShouldProcess($target, $action)) {
                [void]$results.Add([pscustomobject]@{
                    Type = $m.Key; Name = $targetName; Action = "$action (WhatIf)"; Status = 'Planned'
                    Command = $cmdName; Dropped = ($dropped -join ',')
                })
                continue
            }

            try {
                & $cmdName @splat -ErrorAction Stop | Out-Null
                Write-ToolkitLog "$action $target" 'OK'
                [void]$results.Add([pscustomobject]@{
                    Type = $m.Key; Name = $targetName; Action = $action; Status = 'Success'
                    Command = $cmdName; Dropped = ($dropped -join ',')
                })
            }
            catch {
                $msg = $_.Exception.Message
                Write-ToolkitLog "$action $target FAILED - $msg" 'ERROR'
                [void]$results.Add([pscustomobject]@{
                    Type = $m.Key; Name = $targetName; Action = $action; Status = "Failed: $msg"
                    Command = $cmdName; Dropped = ($dropped -join ',')
                })
                if (-not $ContinueOnError) { throw }
            }
        }
    }

    $results.ToArray()
}

function ConvertTo-NormalizationRule {
<#
.SYNOPSIS
    Rebuild in-memory normalization rule objects for a tenant dial plan.
.DESCRIPTION
    Dial plan rules cannot be passed as plain hashtables - Set-CsTenantDialPlan
    requires real rule objects built with -InMemory and -Parent Global.
#>
    param($Rules)

    $out = @()
    foreach ($r in @($Rules)) {
        if (-not $r) { continue }
        $p = @{
            Parent      = 'Global'
            Name        = $r.Name
            Pattern     = $r.Pattern
            Translation = $r.Translation
            InMemory    = $true
        }
        if ($r.PSObject.Properties['Description'] -and $r.Description) { $p['Description'] = $r.Description }
        if ($r.PSObject.Properties['IsInternalExtension'])             { $p['IsInternalExtension'] = [bool]$r.IsInternalExtension }
        $out += (New-CsVoiceNormalizationRule @p)
    }
    ,$out
}

function ConvertTo-EmergencyNumber {
<#
.SYNOPSIS
    Rebuild emergency number objects for an emergency call routing policy.
#>
    param($Numbers)

    $out = @()
    foreach ($n in @($Numbers)) {
        if (-not $n) { continue }
        $p = @{ EmergencyDialString = $n.EmergencyDialString }
        if ($n.PSObject.Properties['EmergencyDialMask'] -and $n.EmergencyDialMask) { $p['EmergencyDialMask'] = $n.EmergencyDialMask }
        if ($n.PSObject.Properties['OnlinePSTNUsage']   -and $n.OnlinePSTNUsage)   { $p['OnlinePSTNUsage']   = $n.OnlinePSTNUsage }
        $out += (New-CsTeamsEmergencyNumber @p)
    }
    ,$out
}

function Import-PstnUsageSet {
<#
.SYNOPSIS
    Merge exported PSTN usages into the target tenant's single Global usage set.
.DESCRIPTION
    PSTN usages are not individual objects - they are one string array on a single
    Global record, mutated with @{Add=...}. Additive only: this never removes a
    usage the target already has, because voice routes there may depend on it.
#>
    [CmdletBinding(SupportsShouldProcess)]
    param($Item)

    $wanted = @()
    if ($Item.Settings.PSObject.Properties['Usage']) { $wanted = @($Item.Settings.Usage) }
    if (-not $wanted.Count) { return }

    $current = @()
    try { $current = @((Get-CsOnlinePstnUsage -Identity Global -ErrorAction Stop).Usage) } catch { }

    $missing = @($wanted | Where-Object { $_ -and $_ -notin $current })
    if (-not $missing.Count) {
        Write-ToolkitLog "PSTN usages: all $($wanted.Count) already present." 'INFO'
        return
    }

    foreach ($u in $missing) {
        if ($PSCmdlet.ShouldProcess("PSTN usage '$u'", 'Add')) {
            try {
                Set-CsOnlinePstnUsage -Identity Global -Usage @{Add = $u} -ErrorAction Stop
                Write-ToolkitLog "PSTN usage '$u' added." 'OK'
            }
            catch { Write-ToolkitLog "PSTN usage '$u' failed - $($_.Exception.Message)" 'ERROR' }
        }
        else { Write-ToolkitLog "PSTN usage '$u' would be added." 'INFO' }
    }
}

function Resolve-CivicAddressId {
<#
.SYNOPSIS
    Map a source-tenant civic address to the equivalent in the target tenant.
.DESCRIPTION
    CivicAddressId GUIDs are tenant-local, so a LIS location cannot carry its
    parent ID across. Match on Description first, then on the street address.
#>
    param($Item)

    $desc = $null
    if ($Item.Settings.PSObject.Properties['CivicAddressDescription']) { $desc = $Item.Settings.CivicAddressDescription }
    elseif ($Item.Settings.PSObject.Properties['Description'])         { $desc = $Item.Settings.Description }

    if (-not $desc) { return $null }

    try {
        $match = @(Get-CsOnlineLisCivicAddress -ErrorAction Stop |
                   Where-Object { $_.Description -eq $desc }) | Select-Object -First 1
        if ($match) { return $match.CivicAddressId }
    }
    catch { }
    $null
}

# ==============================================================================
# REGION 7 - COMPARE / DRIFT
# ==============================================================================

function Compare-TeamsVoiceConfiguration {
<#
.SYNOPSIS
    Diff two exported bundles - dev vs UAT, or last week vs today.
.DESCRIPTION
    This is the payoff for keeping regular exports. Answers "what actually changed
    between environments" without clicking through two admin centres.
.EXAMPLE
    Compare-TeamsVoiceConfiguration -ReferenceBundle .\dev.json -DifferenceBundle .\uat.json |
        Where-Object Status -ne 'Match' | Format-Table -AutoSize
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ReferenceBundle,
        [Parameter(Mandatory)][string]$DifferenceBundle,
        [string[]]$Include,
        [string[]]$IgnoreProperty = @('Description')
    )

    $ref = Get-Content $ReferenceBundle  -Raw -Encoding UTF8 | ConvertFrom-Json
    $dif = Get-Content $DifferenceBundle -Raw -Encoding UTF8 | ConvertFrom-Json

    $out  = New-Object System.Collections.ArrayList
    $keys = @($script:PolicyManifest | Sort-Object Tier | Select-Object -ExpandProperty Key)
    if ($Include) { $keys = $keys | Where-Object { $_ -in $Include } }

    foreach ($key in $keys) {

        $rItems = if ($ref.Policies.PSObject.Properties[$key]) { @($ref.Policies.$key.Items) } else { @() }
        $dItems = if ($dif.Policies.PSObject.Properties[$key]) { @($dif.Policies.$key.Items) } else { @() }

        $rMap = @{}; foreach ($i in $rItems) { if ($i.Name) { $rMap[$i.Name] = $i } }
        $dMap = @{}; foreach ($i in $dItems) { if ($i.Name) { $dMap[$i.Name] = $i } }

        foreach ($name in @($rMap.Keys + $dMap.Keys | Select-Object -Unique | Sort-Object)) {

            if (-not $dMap.ContainsKey($name)) {
                [void]$out.Add([pscustomobject]@{
                    Type=$key; Name=$name; Property=''; Status='MissingInDifference'
                    Reference='(present)'; Difference='(absent)' })
                continue
            }
            if (-not $rMap.ContainsKey($name)) {
                [void]$out.Add([pscustomobject]@{
                    Type=$key; Name=$name; Property=''; Status='MissingInReference'
                    Reference='(absent)'; Difference='(present)' })
                continue
            }

            $rs = $rMap[$name].Settings
            $ds = $dMap[$name].Settings
            $props = @($rs.PSObject.Properties.Name + $ds.PSObject.Properties.Name) |
                        Select-Object -Unique | Sort-Object

            $anyDiff = $false
            foreach ($p in $props) {
                if ($p -in $IgnoreProperty) { continue }

                $rv = if ($rs.PSObject.Properties[$p]) { $rs.$p } else { $null }
                $dv = if ($ds.PSObject.Properties[$p]) { $ds.$p } else { $null }

                $rj = Get-ComparableValue $rv
                $dj = Get-ComparableValue $dv

                if ($rj -ne $dj) {
                    $anyDiff = $true
                    [void]$out.Add([pscustomobject]@{
                        Type=$key; Name=$name; Property=$p; Status='Different'
                        Reference=$rj; Difference=$dj })
                }
            }

            if (-not $anyDiff) {
                [void]$out.Add([pscustomobject]@{
                    Type=$key; Name=$name; Property=''; Status='Match'; Reference=''; Difference='' })
            }
        }
    }

    $out.ToArray()
}

# ==============================================================================
# REGION 8 - BULK UPDATE FROM CSV
# ==============================================================================

function Update-TeamsVoicePolicyFromCsv {
<#
.SYNOPSIS
    Apply edits made to an exported CSV back to the tenant.
.DESCRIPTION
    The intended loop is: export -> open the CSV in Excel -> change the cells you
    care about -> replay. Only the columns you name in -Property are written, so
    an untouched export replayed with a single -Property is a safe no-op for every
    other setting.

    Values that were serialized as JSON on export (arrays, nested objects) are
    parsed back automatically.
.EXAMPLE
    Update-TeamsVoicePolicyFromCsv -CsvPath .\csv\CallingPolicy.csv `
        -PolicyKey CallingPolicy -Property AllowPrivateCalling,AllowVoicemail -WhatIf
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$CsvPath,
        [Parameter(Mandatory)][string]$PolicyKey,
        [Parameter(Mandatory)][string[]]$Property,
        [switch]$NoConnect
    )

    $m = $script:PolicyManifest | Where-Object Key -eq $PolicyKey | Select-Object -First 1
    if (-not $m) { throw "Unknown policy key '$PolicyKey'. Valid: $(($script:PolicyManifest.Key) -join ', ')" }
    if (-not $m.Set) { throw "'$PolicyKey' has no Set cmdlet - not bulk-updatable." }

    if (-not $NoConnect) { Confirm-TeamsConnection }

    $rows    = @(Import-Csv -Path $CsvPath)
    $allowed = Get-WritableParameterName -CommandName $m.Set
    $results = New-Object System.Collections.ArrayList

    $bad = @($Property | Where-Object { $_ -notin $allowed })
    if ($bad.Count) { throw "$($m.Set) does not accept: $($bad -join ', ')" }

    foreach ($row in $rows) {

        if (-not $row.Name) { continue }

        $splat = @{ $m.NameParameter = $row.Name }
        foreach ($p in $Property) {
            if (-not $row.PSObject.Properties[$p]) { continue }
            $raw = $row.$p
            if ([string]::IsNullOrWhiteSpace($raw)) { continue }

            $val = $raw
            if ($raw -match '^\s*[\[{]') {
                try { $val = $raw | ConvertFrom-Json } catch { $val = $raw }
            }
            elseif ($raw -in 'True','False') { $val = [bool]::Parse($raw) }

            $splat[$p] = $val
        }

        if ($splat.Count -le 1) { continue }

        if ($PSCmdlet.ShouldProcess("$($m.DisplayName) '$($row.Name)'", "Set $($Property -join ',')")) {
            try {
                & $m.Set @splat -ErrorAction Stop | Out-Null
                Write-ToolkitLog "Updated $($row.Name)" 'OK'
                [void]$results.Add([pscustomobject]@{ Name=$row.Name; Status='Success' })
            }
            catch {
                Write-ToolkitLog "Update $($row.Name) FAILED - $($_.Exception.Message)" 'ERROR'
                [void]$results.Add([pscustomobject]@{ Name=$row.Name; Status="Failed: $($_.Exception.Message)" })
            }
        }
        else {
            [void]$results.Add([pscustomobject]@{ Name=$row.Name; Status='Planned' })
        }
    }

    $results.ToArray()
}

function Test-ToolkitPermission {
<#
.SYNOPSIS
    Probe every policy type against the live session and classify the result.
.DESCRIPTION
    Answers the question app-only auth actually raises: is this thing empty
    because the tenant has none, or because the service principal has no role?

    The three outcomes mean different things:

      Ok        - returned objects. Nothing to do.
      Empty     - connected, returned nothing. Either genuinely none configured,
                  or the SPN lacks the Teams Administrator directory role. Check
                  the same cmdlet in the admin centre before believing 'none'.
      Denied    - threw an authorization error. Definitively a role problem.
      Failed    - threw something else. Read the message.
      Missing   - cmdlet not in this module version.

    Under Application auth, a wall of Empty across every type is the classic
    signature of a service principal that was granted Graph API permissions but
    never assigned a directory role.
.EXAMPLE
    Test-ToolkitPermission | Format-Table -AutoSize
.EXAMPLE
    Test-ToolkitPermission | Where-Object Outcome -in 'Empty','Denied'
#>
    [CmdletBinding()]
    param([switch]$NoConnect)

    if (-not $NoConnect) { Confirm-TeamsConnection }

    $session = Get-TeamsSessionInfo
    Write-ToolkitLog "Probing as $($session.Account) ($($session.AuthMode)) against $($session.TenantId)."

    foreach ($m in ($script:PolicyManifest | Sort-Object Tier)) {

        if (-not (Test-TeamsCmdletAvailable -Name $m.Get)) {
            [pscustomobject]@{
                Key = $m.Key; Cmdlet = $m.Get; Outcome = 'Missing'; Count = $null
                Detail = 'Not present in this module version.'
            }
            continue
        }

        $outcome = 'Ok'; $count = 0; $detail = ''

        try {
            $r = @(& $m.Get -ErrorAction Stop)
            $count = $r.Count
            if ($count -eq 0) {
                $outcome = 'Empty'
                $detail  = 'None returned - confirm against the admin centre before assuming none exist.'
            }
        }
        catch {
            $msg = $_.Exception.Message
            $detail = $msg
            $outcome = if ($msg -match 'Authoriz|Access.*denied|Forbidden|privileg|not have permission|401|403') {
                'Denied'
            } else { 'Failed' }
        }

        [pscustomobject]@{
            Key = $m.Key; Cmdlet = $m.Get; Outcome = $outcome; Count = $count; Detail = $detail
        }
    }
}

function Get-TeamsVoicePolicyKey {
<#
.SYNOPSIS
    List the policy types this toolkit understands, and whether they are usable
    against the currently loaded MicrosoftTeams module.
#>
    [CmdletBinding()]
    param()
    foreach ($m in ($script:PolicyManifest | Sort-Object Tier)) {
        [pscustomobject]@{
            Key         = $m.Key
            Tier        = $m.Tier
            DisplayName = $m.DisplayName
            CanExport   = Test-TeamsCmdletAvailable -Name $m.Get
            CanCreate   = [bool]($m.New) -and (Test-TeamsCmdletAvailable -Name $m.New)
            CanUpdate   = [bool]($m.Set) -and (Test-TeamsCmdletAvailable -Name $m.Set)
        }
    }
}

<#
================================================================================
 USAGE
--------------------------------------------------------------------------------
 # 1. Switch environment - the ONLY supported way to change tenant. Wire the
 #    Manage Environments dropdown to this and nothing else.
 Get-ToolkitEnvironment | Format-Table Name, TenantId, TeamsAuthMode, GraphAuthMode
 Switch-ToolkitEnvironment -Name 'UAT' -Verify

 # 2. Graph calls now refresh themselves
 $users = Invoke-GraphRequest -Uri 'users?$select=id,userPrincipalName' -All

 # 3. In the CDR runspace setup, before Open():
 Add-TokenCacheToRunspace -Runspace $rs

 # 4. Back up the whole voice estate
 $exp = Export-TeamsVoiceConfiguration -Path 'C:\TeamsVoice\Backups' -Label 'DEV'

 # 5. Diff two environments
 Compare-TeamsVoiceConfiguration -ReferenceBundle $dev -DifferenceBundle $uat |
     Where-Object Status -ne 'Match' | Format-Table -AutoSize

 # 6. Cross-tenant migration. Export, switch, replay - dry run by default.
 #    The target tenant must already be a row in TeamsVoice_Environments.csv,
 #    with its OWN app registration consented there.
 Invoke-CrossTenantPolicyMigration -SourceEnvironment DEV -TargetEnvironment UAT `
     -Path 'C:\TeamsVoice\Backups' -NameMap @{ 'DEV-UK-Routing' = 'UAT-UK-Routing' }
 # review the plan, then:
 Invoke-CrossTenantPolicyMigration -SourceEnvironment DEV -TargetEnvironment UAT `
     -Path 'C:\TeamsVoice\Backups' -NameMap @{ 'DEV-UK-Routing' = 'UAT-UK-Routing' } `
     -Apply -ContinueOnError

 # Or drive it by hand, with the guard still enforced:
 Switch-ToolkitEnvironment -Name 'UAT' -Verify
 Import-TeamsVoiceConfiguration -BundlePath $exp.BundlePath -WhatIf

 # 7. Bulk edit loop
 Update-TeamsVoicePolicyFromCsv -CsvPath "$($exp.CsvDirectory)\CallingPolicy.csv" `
     -PolicyKey CallingPolicy -Property AllowPrivateCalling -WhatIf
================================================================================
#>

################################################################################
#
#  PART 3  CALL RECORD ANALYZER
#
################################################################################

# ==============================================================================
# REGION 1 - QUALITY THRESHOLDS
#
# Aligned to the stream classifiers Microsoft uses in Call Quality Dashboard. A
# stream is Poor if ANY single condition trips - that is CQD's rule, not an
# average of averages, and it is why a call with good mean figures can still be
# correctly flagged.
# ==============================================================================

$script:QualityThresholds = @{
    AvgJitterMs               = 30      # ms
    MaxJitterMs               = 30
    AvgPacketLossRate         = 0.10    # 10%
    MaxPacketLossRate         = 0.10
    AvgRoundTripTimeMs        = 500     # ms
    MaxRoundTripTimeMs        = 500
    AvgAudioDegradation       = 1.0     # NMOS degradation
    AvgRatioConcealedSamples  = 0.07    # 7%
}

function Set-CallQualityThreshold {
<#
.SYNOPSIS
    Adjust a quality threshold for this session.
.EXAMPLE
    Set-CallQualityThreshold -Name AvgJitterMs -Value 40
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateScript({ $script:QualityThresholds.ContainsKey($_) })][string]$Name,
        [Parameter(Mandatory)][double]$Value
    )
    $script:QualityThresholds[$Name] = $Value
    [pscustomobject]$script:QualityThresholds
}

# ==============================================================================
# REGION 2 - PARSING HELPERS
# ==============================================================================

function ConvertFrom-CallRecordDuration {
<#
.SYNOPSIS
    ISO 8601 duration string -> milliseconds.
.DESCRIPTION
    Call records express every timing metric as xs:duration ("PT0.0353S" = 35.3ms).
    XmlConvert handles the full grammar including minutes and hours, which a naive
    regex on the seconds field does not.
#>
    [CmdletBinding()]
    param($Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [double] -or $Value -is [int] -or $Value -is [decimal]) { return [double]$Value }

    $s = [string]$Value
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }

    try   { return [System.Xml.XmlConvert]::ToTimeSpan($s).TotalMilliseconds }
    catch { }

    # Fall back for the plain-number case some exports produce.
    $d = 0.0
    if ([double]::TryParse($s, [ref]$d)) { return $d }
    $null
}

function Get-JsonProperty {
<#
.SYNOPSIS
    Safe nested property read against a ConvertFrom-Json object.
.DESCRIPTION
    Under StrictMode, touching an absent property throws. Call records are
    sparse by nature - a PSTN endpoint has no user identity, a failed session has
    no media - so every read goes through here.
#>
    param($Object, [Parameter(Mandatory)][string]$Path, $Default = $null)

    $cur = $Object
    foreach ($part in $Path.Split('.')) {
        if ($null -eq $cur) { return $Default }
        if (-not $cur.PSObject.Properties[$part]) { return $Default }
        $cur = $cur.$part
    }
    if ($null -eq $cur) { return $Default }
    $cur
}

function Get-EndpointLabel {
<#
.SYNOPSIS
    Human-readable name for a call endpoint.
.DESCRIPTION
    Endpoints identify themselves differently depending on what they are: a Teams
    user has identity.user, a PSTN leg has identity.phone, a resource account has
    an applicationInstance. Falls back through them in that order so a Direct
    Routing call reads as a number rather than as blank.
#>
    param($Endpoint)

    if (-not $Endpoint) { return '(unknown)' }

    # associatedIdentity is the richest field on a participantEndpoint and the
    # one most often populated - it carries userPrincipalName where identity.user
    # does not. Check it FIRST.
    $ai = Get-JsonProperty $Endpoint 'associatedIdentity.displayName'
    if ($ai) { return $ai }

    $aiPhone = Get-JsonProperty $Endpoint 'associatedIdentity.id'

    $name = Get-JsonProperty $Endpoint 'identity.user.displayName'
    if ($name) { return $name }

    $upn = Get-JsonProperty $Endpoint 'identity.user.userPrincipalName'
    if ($upn) { return $upn }

    $upn2 = Get-JsonProperty $Endpoint 'userPrincipalName'
    if ($upn2) { return $upn2 }

    $phone = Get-JsonProperty $Endpoint 'identity.phone.id'
    if ($phone) { return $phone }

    if ($aiPhone) { return $aiPhone }

    $acs = Get-JsonProperty $Endpoint 'identity.acsApplicationInstance.displayName'
    if ($acs) { return $acs }

    $ai = Get-JsonProperty $Endpoint 'identity.applicationInstance.displayName'
    if ($ai) { return $ai }

    $app = Get-JsonProperty $Endpoint 'identity.application.displayName'
    if ($app) { return $app }

    # 'name' is the device/host name - 'Joe's MacBook Pro', or an SBC-side tag
    # like 'MP000021'. Far better than '(unknown)'.
    $devName = Get-JsonProperty $Endpoint 'name'
    if ($devName) { return $devName }

    # Media-processing and conferencing legs identify only by user agent.
    $ua = Get-JsonProperty $Endpoint 'userAgent.headerValue'
    if ($ua) {
        if ($ua -match '^ic3-media')  { return 'Teams media service' }
        if ($ua -match '^pstn')       { return 'PSTN gateway' }
        if ($ua -match '^conf|MCU')   { return 'Conferencing service' }
        return ($ua -split '[ (/]')[0]
    }

    '(unidentified endpoint)'
}

function Get-EndpointDetail {
    param($Endpoint)

    [pscustomobject]@{
        Label          = Get-EndpointLabel $Endpoint
        UserId         = Get-JsonProperty $Endpoint 'identity.user.id'
        PhoneId        = Get-JsonProperty $Endpoint 'identity.phone.id'
        UserAgent      = Get-JsonProperty $Endpoint 'userAgent.headerValue'
        Platform       = Get-JsonProperty $Endpoint 'userAgent.platform'
        ProductFamily  = Get-JsonProperty $Endpoint 'userAgent.productFamily'
        CpuName        = Get-JsonProperty $Endpoint 'cpuName'
        CpuCores       = Get-JsonProperty $Endpoint 'cpuCoresCount'
        FeedbackRating = Get-JsonProperty $Endpoint 'feedback.rating'
        FeedbackText   = Get-JsonProperty $Endpoint 'feedback.text'
    }
}

# ==============================================================================
# REGION 3 - LOADING
# ==============================================================================

function Import-CallRecord {
<#
.SYNOPSIS
    Load call records from a JSON file, a folder of them, or a raw string.
.DESCRIPTION
    Tolerates the three shapes that turn up in practice: a bare callRecord, an
    array of them, and a full Graph response with a .value collection.
.EXAMPLE
    $records = Import-CallRecord -Path 'C:\TeamsVoice\CDR\raw'
#>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path', Position = 0)][string]$Path,
        [Parameter(Mandatory, ParameterSetName = 'Json')][string]$Json,
        [switch]$Recurse
    )

    $blobs = @()

    if ($PSCmdlet.ParameterSetName -eq 'Json') {
        $blobs += [pscustomobject]@{ Source = '(inline)'; Text = $Json }
    }
    else {
        if (-not (Test-Path $Path)) { throw "Path not found: $Path" }

        $files = if ((Get-Item $Path).PSIsContainer) {
            Get-ChildItem -Path $Path -Filter '*.json' -File -Recurse:$Recurse
        } else {
            Get-Item -Path $Path
        }

        foreach ($f in $files) {
            $text = Get-Content -Path $f.FullName -Raw -Encoding UTF8

            # PowerShell 5.1's -Encoding UTF8 writes a BOM. ConvertFrom-Json
            # tolerates it; strict parsers elsewhere in the pipeline do not, and
            # a leading U+FEFF also breaks naive string comparisons. Strip it.
            if ($text -and [int][char]$text[0] -eq 0xFEFF) { $text = $text.Substring(1) }

            $blobs += [pscustomobject]@{ Source = $f.FullName; Text = $text }
        }
    }

    foreach ($b in $blobs) {
        if ([string]::IsNullOrWhiteSpace($b.Text)) { continue }

        try   { $parsed = $b.Text | ConvertFrom-Json }
        catch { Write-Warning "Not valid JSON, skipped: $($b.Source)"; continue }

        $items = if ($parsed -is [array]) { $parsed }
                 elseif ($parsed.PSObject.Properties['value']) { @($parsed.value) }
                 else { @($parsed) }

        foreach ($item in $items) {
            if (-not $item) { continue }
            if (-not $item.PSObject.Properties['id']) { continue }
            $item | Add-Member -NotePropertyName '_SourceFile' -NotePropertyValue $b.Source -Force
            $item
        }
    }
}

# ==============================================================================
# REGION 4 - STREAM QUALITY
# ==============================================================================

function Get-StreamQuality {
<#
.SYNOPSIS
    Normalise one media stream and classify it Good / Poor / Unrated.
.DESCRIPTION
    Unrated is a real and important third state: a stream with no metrics at all
    is not a good stream, and averaging it in as one is how a quality report ends
    up quietly optimistic.
#>
    [CmdletBinding()]
    param($Stream, [string]$MediaLabel = 'audio')

    $avgJitter = ConvertFrom-CallRecordDuration (Get-JsonProperty $Stream 'averageJitter')
    $maxJitter = ConvertFrom-CallRecordDuration (Get-JsonProperty $Stream 'maxJitter')
    $avgRtt    = ConvertFrom-CallRecordDuration (Get-JsonProperty $Stream 'averageRoundTripTime')
    $maxRtt    = ConvertFrom-CallRecordDuration (Get-JsonProperty $Stream 'maxRoundTripTime')

    # averageJitter is end-to-end; averageAudioNetworkJitter isolates the network
    # contribution and is the more diagnostic of the two when chasing a transport
    # problem. Capture both rather than choosing.
    $netJitter = ConvertFrom-CallRecordDuration (Get-JsonProperty $Stream 'averageAudioNetworkJitter')
    $maxNetJit = ConvertFrom-CallRecordDuration (Get-JsonProperty $Stream 'maxAudioNetworkJitter')

    $avgLoss   = Get-JsonProperty $Stream 'averagePacketLossRate'
    $maxLoss   = Get-JsonProperty $Stream 'maxPacketLossRate'
    $avgDeg    = Get-JsonProperty $Stream 'averageAudioDegradation'
    $concealed = Get-JsonProperty $Stream 'averageRatioOfConcealedSamples'

    $t       = $script:QualityThresholds
    $reasons = New-Object System.Collections.ArrayList
    $rated   = $false

    function Test-Metric($Value, $Limit, $Label, $Format) {
        if ($null -eq $Value) { return $false }
        $script:__rated = $true
        if ($Value -gt $Limit) {
            [void]$reasons.Add(("{0} {1} > {2}" -f $Label, ($Format -f $Value), ($Format -f $Limit)))
            return $true
        }
        $false
    }

    $script:__rated = $false
    $poor = $false
    $poor = (Test-Metric $avgJitter $t.AvgJitterMs              'avg jitter'      '{0:N1}ms') -or $poor
    $poor = (Test-Metric $maxJitter $t.MaxJitterMs              'max jitter'      '{0:N1}ms') -or $poor
    $poor = (Test-Metric $avgRtt    $t.AvgRoundTripTimeMs       'avg RTT'         '{0:N0}ms') -or $poor
    $poor = (Test-Metric $maxRtt    $t.MaxRoundTripTimeMs       'max RTT'         '{0:N0}ms') -or $poor
    $poor = (Test-Metric $avgLoss   $t.AvgPacketLossRate        'avg loss'        '{0:P1}')   -or $poor
    $poor = (Test-Metric $maxLoss   $t.MaxPacketLossRate        'max loss'        '{0:P1}')   -or $poor
    $poor = (Test-Metric $avgDeg    $t.AvgAudioDegradation      'audio degrade'   '{0:N2}')   -or $poor
    $poor = (Test-Metric $concealed $t.AvgRatioConcealedSamples 'concealed samp'  '{0:P1}')   -or $poor
    $rated = $script:__rated

    $verdict = if (-not $rated) { 'Unrated' } elseif ($poor) { 'Poor' } else { 'Good' }

    [pscustomobject]@{
        StreamId            = Get-JsonProperty $Stream 'streamId'
        MediaLabel          = $MediaLabel
        Direction           = Get-JsonProperty $Stream 'streamDirection'
        StartDateTime       = Get-JsonProperty $Stream 'startDateTime'
        EndDateTime         = Get-JsonProperty $Stream 'endDateTime'
        AvgJitterMs         = $avgJitter
        MaxJitterMs         = $maxJitter
        AvgRoundTripMs      = $avgRtt
        MaxRoundTripMs      = $maxRtt
        AvgPacketLossRate   = $avgLoss
        MaxPacketLossRate   = $maxLoss
        AvgAudioDegradation = $avgDeg
        ConcealedSampleRate = $concealed
        AvgNetworkJitterMs  = $netJitter
        MaxNetworkJitterMs  = $maxNetJit
        AudioCodec          = Get-JsonProperty $Stream 'audioCodec'
        VideoCodec          = Get-JsonProperty $Stream 'videoCodec'
        AudioFecUsed        = Get-JsonProperty $Stream 'isAudioForwardErrorCorrectionUsed'
        PacketUtilization   = Get-JsonProperty $Stream 'packetUtilization'
        AvgBandwidthEst     = Get-JsonProperty $Stream 'averageBandwidthEstimate'
        WasMediaBypassed    = Get-JsonProperty $Stream 'wasMediaBypassed'
        AvgVideoFrameRate   = Get-JsonProperty $Stream 'averageVideoFrameRate'
        Verdict             = $verdict
        Reasons             = ($reasons -join '; ')
    }
}

function Get-NetworkDetail {
    param($Network)

    if (-not $Network) { return $null }

    $linkSpeed = Get-JsonProperty $Network 'linkSpeed'
    $linkMbps  = if ($linkSpeed) { [math]::Round([double]$linkSpeed / 1MB, 1) } else { $null }

    [pscustomobject]@{
        ConnectionType      = Get-JsonProperty $Network 'connectionType'
        IPAddress           = Get-JsonProperty $Network 'ipAddress'
        Subnet              = Get-JsonProperty $Network 'subnet'
        ReflexiveIP         = Get-JsonProperty $Network 'reflexiveIPAddress'
        RelayIP             = Get-JsonProperty $Network 'relayIPAddress'
        LinkSpeedMbps       = $linkMbps
        DnsSuffix           = Get-JsonProperty $Network 'dnsSuffix'
        WifiBand            = Get-JsonProperty $Network 'wifiBand'
        WifiSignalStrength  = Get-JsonProperty $Network 'wifiSignalStrength'
        WifiVendorDriver    = Get-JsonProperty $Network 'wifiVendorDriver'
        DelayEventRatio     = Get-JsonProperty $Network 'delayEventRatio'
        BandwidthLowRatio   = Get-JsonProperty $Network 'bandwidthLowEventRatio'
        SentQualityRatio    = Get-JsonProperty $Network 'sentQualityEventRatio'
        ReceivedQualityRatio= Get-JsonProperty $Network 'receivedQualityEventRatio'
    }
}

function Get-DeviceDetail {
    param($Device)

    if (-not $Device) { return $null }

    [pscustomobject]@{
        CaptureDevice        = Get-JsonProperty $Device 'captureDeviceName'
        CaptureDriver        = Get-JsonProperty $Device 'captureDeviceDriver'
        RenderDevice         = Get-JsonProperty $Device 'renderDeviceName'
        RenderDriver         = Get-JsonProperty $Device 'renderDeviceDriver'
        MicGlitchRate        = Get-JsonProperty $Device 'micGlitchRate'
        SpeakerGlitchRate    = Get-JsonProperty $Device 'speakerGlitchRate'
        CpuInsufficientRatio = Get-JsonProperty $Device 'cpuInsufficentEventRatio'
        DeviceGlitchRatio    = Get-JsonProperty $Device 'deviceGlitchEventRatio'
        HowlingEventCount    = Get-JsonProperty $Device 'howlingEventCount'
        ReceivedSignalLevel  = Get-JsonProperty $Device 'receivedSignalLevel'
        SentSignalLevel      = Get-JsonProperty $Device 'sentSignalLevel'
        InitialSignalLevel   = Get-JsonProperty $Device 'initialSignalLevelRootMeanSquare'
    }
}

# ==============================================================================
# REGION 5 - TREE CONSTRUCTION
# ==============================================================================

function Expand-CallRecord {
<#
.SYNOPSIS
    Turn one raw callRecord into a navigable call / session / segment / media / stream tree.
.DESCRIPTION
    Failure attribution follows the same rule the Teams admin centre uses: a
    failureInfo on a session or segment marks that leg failed, and its 'stage'
    separates a call that never connected (callSetup) from one that dropped
    (midcall). Those are different problems and should never be lumped together
    in a success rate.
.EXAMPLE
    Import-CallRecord -Path .\raw | Expand-CallRecord
#>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)]$CallRecord)

    process {
        $sessions   = @(Get-JsonProperty $CallRecord 'sessions' @())
        $allStreams = New-Object System.Collections.ArrayList
        $failures   = New-Object System.Collections.ArrayList

        $sessionNodes = foreach ($s in $sessions) {

            $sFail = Get-JsonProperty $s 'failureInfo'
            if ($sFail) {
                [void]$failures.Add([pscustomobject]@{
                    Level  = 'Session'
                    Stage  = Get-JsonProperty $sFail 'stage'
                    Reason = Get-JsonProperty $sFail 'reason'
                })
            }

            $segments = @(Get-JsonProperty $s 'segments' @())

            $segmentNodes = foreach ($seg in $segments) {

                $gFail = Get-JsonProperty $seg 'failureInfo'
                if ($gFail) {
                    [void]$failures.Add([pscustomobject]@{
                        Level  = 'Segment'
                        Stage  = Get-JsonProperty $gFail 'stage'
                        Reason = Get-JsonProperty $gFail 'reason'
                    })
                }

                $mediaNodes = foreach ($m in @(Get-JsonProperty $seg 'media' @())) {

                    $label = Get-JsonProperty $m 'label' 'audio'

                    $streamNodes = foreach ($st in @(Get-JsonProperty $m 'streams' @())) {
                        $q = Get-StreamQuality -Stream $st -MediaLabel $label
                        [void]$allStreams.Add($q)
                        $q
                    }

                    [pscustomobject]@{
                        NodeType      = 'Media'
                        Label         = $label
                        CallerNetwork = Get-NetworkDetail (Get-JsonProperty $m 'callerNetwork')
                        CalleeNetwork = Get-NetworkDetail (Get-JsonProperty $m 'calleeNetwork')
                        CallerDevice  = Get-DeviceDetail  (Get-JsonProperty $m 'callerDevice')
                        CalleeDevice  = Get-DeviceDetail  (Get-JsonProperty $m 'calleeDevice')
                        Streams       = @($streamNodes)
                        PoorStreams   = @($streamNodes | Where-Object Verdict -eq 'Poor').Count
                    }
                }

                [pscustomobject]@{
                    NodeType      = 'Segment'
                    Id            = Get-JsonProperty $seg 'id'
                    Caller        = Get-EndpointDetail (Get-JsonProperty $seg 'caller')
                    Callee        = Get-EndpointDetail (Get-JsonProperty $seg 'callee')
                    StartDateTime = Get-JsonProperty $seg 'startDateTime'
                    EndDateTime   = Get-JsonProperty $seg 'endDateTime'
                    FailureStage  = Get-JsonProperty $gFail 'stage'
                    FailureReason = Get-JsonProperty $gFail 'reason'
                    Succeeded     = (-not $gFail)
                    Media         = @($mediaNodes)
                }
            }

            [pscustomobject]@{
                NodeType      = 'Session'
                Id            = Get-JsonProperty $s 'id'
                Caller        = Get-EndpointDetail (Get-JsonProperty $s 'caller')
                Callee        = Get-EndpointDetail (Get-JsonProperty $s 'callee')
                StartDateTime = Get-JsonProperty $s 'startDateTime'
                EndDateTime   = Get-JsonProperty $s 'endDateTime'
                Modalities    = @(Get-JsonProperty $s 'modalities' @())
                IsTest        = Get-JsonProperty $s 'isTest'
                FailureStage  = Get-JsonProperty $sFail 'stage'
                FailureReason = Get-JsonProperty $sFail 'reason'
                Succeeded     = (-not $sFail)
                Segments      = @($segmentNodes)
            }
        }

        $sessionNodes = @($sessionNodes)
        $poor  = @($allStreams | Where-Object Verdict -eq 'Poor')
        $rated = @($allStreams | Where-Object Verdict -ne 'Unrated')

        $start = Get-JsonProperty $CallRecord 'startDateTime'
        $end   = Get-JsonProperty $CallRecord 'endDateTime'
        $dur   = $null
        if ($start -and $end) {
            try { $dur = [math]::Round(([datetime]$end - [datetime]$start).TotalSeconds, 1) } catch { }
        }

        # Participant shape changed between API revisions; accept either.
        $participants = @(Get-JsonProperty $CallRecord 'participants_v2' @())
        if (-not $participants.Count) { $participants = @(Get-JsonProperty $CallRecord 'participants' @()) }

        # A participant's .id is a phone number for PSTN legs and a raw GUID for
        # Teams users. Resolve through identity first so the list reads as names
        # and numbers rather than a column of GUIDs.
        $participantLabels = foreach ($pt in $participants) {
            $lbl = Get-JsonProperty $pt 'identity.user.displayName'
            if (-not $lbl) { $lbl = Get-JsonProperty $pt 'identity.phone.id' }
            if (-not $lbl) { $lbl = Get-JsonProperty $pt 'identity.user.userPrincipalName' }
            if (-not $lbl) { $lbl = Get-JsonProperty $pt 'id' }
            if ($lbl) { $lbl }
        }

        $verdict = if ($failures.Count -eq 0) { 'Success' }
                   elseif (@($sessionNodes | Where-Object Succeeded).Count -gt 0) { 'Partial' }
                   else { 'Failed' }

        [pscustomobject]@{
            NodeType        = 'Call'
            Id              = Get-JsonProperty $CallRecord 'id'
            Type            = Get-JsonProperty $CallRecord 'type'
            StartDateTime   = $start
            EndDateTime     = $end
            DurationSeconds = $dur
            Organizer       = Get-EndpointLabel (Get-JsonProperty $CallRecord 'organizer_v2')
            Modalities      = @(Get-JsonProperty $CallRecord 'modalities' @())
            ParticipantCount= $participants.Count
            Participants    = @($participantLabels)
            JoinWebUrl      = Get-JsonProperty $CallRecord 'joinWebUrl'
            SourceFile      = Get-JsonProperty $CallRecord '_SourceFile'
            Verdict         = $verdict
            Failures        = @($failures)
            SessionCount    = $sessionNodes.Count
            StreamCount     = $allStreams.Count
            RatedStreams    = $rated.Count
            PoorStreams     = $poor.Count
            QualityVerdict  = if (-not $rated.Count) { 'Unrated' } elseif ($poor.Count) { 'Poor' } else { 'Good' }
            HasExpandedData = [bool]$sessionNodes.Count
            Sessions        = $sessionNodes
            AllStreams      = @($allStreams)
        }
    }
}

function Get-CallRecordSummary {
<#
.SYNOPSIS
    Flatten expanded calls into one row each - the shape for CSV or a grid.
.EXAMPLE
    Import-CallRecord -Path .\raw | Expand-CallRecord | Get-CallRecordSummary |
        Export-Csv .\calls.csv -NoTypeInformation
#>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)]$Call)

    process {
        [pscustomobject]@{
            CallId          = $Call.Id
            Type            = $Call.Type
            Start           = $Call.StartDateTime
            DurationSeconds = $Call.DurationSeconds
            Organizer       = $Call.Organizer
            Participants    = $Call.ParticipantCount
            Verdict         = $Call.Verdict
            FailureStage    = ($Call.Failures | Select-Object -First 1 -ExpandProperty Stage  -ErrorAction SilentlyContinue)
            FailureReason   = ($Call.Failures | Select-Object -First 1 -ExpandProperty Reason -ErrorAction SilentlyContinue)
            Sessions        = $Call.SessionCount
            Streams         = $Call.StreamCount
            PoorStreams     = $Call.PoorStreams
            QualityVerdict  = $Call.QualityVerdict
            SourceFile      = $Call.SourceFile
        }
    }
}

function Export-CallQualityReport {
<#
.SYNOPSIS
    Write per-call and per-stream CSVs from a folder of raw call records.
.EXAMPLE
    Export-CallQualityReport -Path .\cdr\raw -OutputDirectory .\reports
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$OutputDirectory,
        [switch]$Recurse
    )

    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

    $calls = @(Import-CallRecord -Path $Path -Recurse:$Recurse | Expand-CallRecord)
    if (-not $calls.Count) { throw "No call records found under $Path" }

    $callCsv = Join-Path $OutputDirectory "calls-$stamp.csv"
    $calls | Get-CallRecordSummary | Export-Csv -Path $callCsv -NoTypeInformation -Encoding UTF8

    $streamRows = foreach ($c in $calls) {
        foreach ($s in $c.AllStreams) {
            $row = [ordered]@{ CallId = $c.Id; CallStart = $c.StartDateTime }
            foreach ($p in $s.PSObject.Properties) { $row[$p.Name] = $p.Value }
            [pscustomobject]$row
        }
    }

    $streamCsv = Join-Path $OutputDirectory "streams-$stamp.csv"
    if ($streamRows) { $streamRows | Export-Csv -Path $streamCsv -NoTypeInformation -Encoding UTF8 }

    $unexpanded = @($calls | Where-Object { -not $_.HasExpandedData }).Count
    if ($unexpanded) {
        Write-Warning "$unexpanded of $($calls.Count) records had no sessions - the CDR pull did not expand them, so no quality data exists for those."
    }

    [pscustomobject]@{
        Calls          = $calls.Count
        Failed         = @($calls | Where-Object Verdict -eq 'Failed').Count
        Partial        = @($calls | Where-Object Verdict -eq 'Partial').Count
        PoorQuality    = @($calls | Where-Object QualityVerdict -eq 'Poor').Count
        Unexpanded     = $unexpanded
        CallReport     = $callCsv
        StreamReport   = if ($streamRows) { $streamCsv } else { $null }
    }
}

# ==============================================================================
# REGION 6 - WINFORMS VIEWER
# ==============================================================================

function Show-CallRecordAnalyzer {
<#
.SYNOPSIS
    Interactive tree viewer for call records.
.DESCRIPTION
    Left pane is the call tree; select any node to see its full detail on the
    right. Nodes are coloured by outcome - red for a failure, amber for poor
    media, grey for unrated - so a bad call is visible without expanding it.
.PARAMETER Path
    File or folder of raw callRecord JSON. Defaults to whatever the CDR tab used.
.EXAMPLE
    Show-CallRecordAnalyzer -Path $script:cdrRawRoot
#>
    [CmdletBinding()]
    param(
        [string]$Path,
        [switch]$Recurse
    )

    $ColFail    = [System.Drawing.Color]::FromArgb(192,  32,  32)
    $ColPoor    = [System.Drawing.Color]::FromArgb(200, 120,   0)
    $ColGood    = [System.Drawing.Color]::FromArgb( 24, 110,  40)
    $ColUnrated = [System.Drawing.Color]::FromArgb(110, 110, 110)

    $form = New-Object System.Windows.Forms.Form
    $form.Text          = 'Call Record Analyzer'
    $form.Size          = New-Object System.Drawing.Size(1180, 760)
    $form.StartPosition = 'CenterScreen'

    $toolbar = New-Object System.Windows.Forms.Panel
    $toolbar.Dock   = 'Top'
    $toolbar.Height = 40

    $btnLoad = New-Object System.Windows.Forms.Button
    $btnLoad.Text = 'Load folder...'; $btnLoad.Location = New-Object System.Drawing.Point(8, 8); $btnLoad.Width = 110

    $btnExpand = New-Object System.Windows.Forms.Button
    $btnExpand.Text = 'Expand all'; $btnExpand.Location = New-Object System.Drawing.Point(126, 8); $btnExpand.Width = 90

    $btnCollapse = New-Object System.Windows.Forms.Button
    $btnCollapse.Text = 'Collapse'; $btnCollapse.Location = New-Object System.Drawing.Point(222, 8); $btnCollapse.Width = 80

    $chkFailOnly = New-Object System.Windows.Forms.CheckBox
    $chkFailOnly.Text = 'Problems only'; $chkFailOnly.Location = New-Object System.Drawing.Point(314, 11); $chkFailOnly.Width = 110

    $btnExport = New-Object System.Windows.Forms.Button
    $btnExport.Text = 'Export CSV'; $btnExport.Location = New-Object System.Drawing.Point(432, 8); $btnExport.Width = 90

    $lblSummary = New-Object System.Windows.Forms.Label
    $lblSummary.Location = New-Object System.Drawing.Point(534, 12)
    $lblSummary.Width = 600; $lblSummary.Text = 'No records loaded.'

    $toolbar.Controls.AddRange(@($btnLoad, $btnExpand, $btnCollapse, $chkFailOnly, $btnExport, $lblSummary))

    $split = New-Object System.Windows.Forms.SplitContainer
    $split.Dock = 'Fill'; $split.SplitterDistance = 470

    $tree = New-Object System.Windows.Forms.TreeView
    $script:CraTree = $tree
    $script:CraTree.Dock = 'Fill'; $script:CraTree.HideSelection = $false
    $script:CraTree.Font = New-Object System.Drawing.Font('Segoe UI', 9)

    $detail = New-Object System.Windows.Forms.TextBox
    $script:CraDetail = $detail
    $script:CraDetail.Dock = 'Fill'; $script:CraDetail.Multiline = $true; $script:CraDetail.ReadOnly = $true
    $script:CraDetail.ScrollBars = 'Both'; $script:CraDetail.WordWrap = $false
    $script:CraDetail.Font = New-Object System.Drawing.Font('Consolas', 9)

    $split.Panel1.Controls.Add($script:CraTree)
    $split.Panel2.Controls.Add($script:CraDetail)
    $form.Controls.AddRange(@($split, $toolbar))

    # State shared with the handlers.
    $state = @{ Calls = @() }

    $addNode = {
        param($ParentNodes, $Text, $Colour, $Tag)
        $n = New-Object System.Windows.Forms.TreeNode($Text)
        $n.ForeColor = $Colour
        $n.Tag = $Tag
        [void]$ParentNodes.Add($n)
        $n
    }

    $render = {
        $script:CraTree.BeginUpdate()
        $script:CraTree.Nodes.Clear()

        $calls = $state.Calls
        if ($chkFailOnly.Checked) {
            $calls = @($calls | Where-Object { $_.Verdict -ne 'Success' -or $_.QualityVerdict -eq 'Poor' })
        }

        foreach ($c in $calls) {

            $colour = if ($c.Verdict -ne 'Success') { $ColFail }
                      elseif ($c.QualityVerdict -eq 'Poor') { $ColPoor }
                      elseif ($c.QualityVerdict -eq 'Unrated') { $ColUnrated }
                      else { $ColGood }

            $dur = if ($null -ne $c.DurationSeconds) { "$($c.DurationSeconds)s" } else { '?' }
            $txt = "{0}  |  {1}  |  {2}  |  {3}" -f $c.StartDateTime, $c.Type, $dur, $c.Verdict
            if ($c.PoorStreams) { $txt += "  |  $($c.PoorStreams) poor stream(s)" }

            $cn = & $addNode $script:CraTree.Nodes $txt $colour $c

            if (-not $c.HasExpandedData) {
                [void](& $addNode $cn.Nodes '(no sessions - CDR pull did not expand this record)' $ColUnrated $null)
                continue
            }

            foreach ($s in $c.Sessions) {

                $sCol = if (-not $s.Succeeded) { $ColFail } else { $ColGood }
                $sTxt = "Session: {0} -> {1}" -f $s.Caller.Label, $s.Callee.Label
                if (-not $s.Succeeded) { $sTxt += "  [{0}: {1}]" -f $s.FailureStage, $s.FailureReason }
                $sn = & $addNode $cn.Nodes $sTxt $sCol $s

                foreach ($seg in $s.Segments) {

                    $gCol = if (-not $seg.Succeeded) { $ColFail } else { $ColGood }
                    $gTxt = "Segment: {0} -> {1}" -f $seg.Caller.Label, $seg.Callee.Label
                    if (-not $seg.Succeeded) { $gTxt += "  [{0}: {1}]" -f $seg.FailureStage, $seg.FailureReason }
                    $gn = & $addNode $sn.Nodes $gTxt $gCol $seg

                    foreach ($m in $seg.Media) {

                        $mCol = if ($m.PoorStreams) { $ColPoor } else { $ColGood }
                        $mTxt = "Media: {0}  ({1} stream(s))" -f $m.Label, @($m.Streams).Count
                        $mn = & $addNode $gn.Nodes $mTxt $mCol $m

                        foreach ($st in $m.Streams) {
                            $stCol = switch ($st.Verdict) {
                                'Poor'    { $ColPoor }
                                'Unrated' { $ColUnrated }
                                default   { $ColGood }
                            }
                            $j = if ($null -ne $st.AvgJitterMs)       { '{0:N1}ms' -f $st.AvgJitterMs }    else { '-' }
                            $l = if ($null -ne $st.AvgPacketLossRate) { '{0:P1}'   -f $st.AvgPacketLossRate } else { '-' }
                            $r = if ($null -ne $st.AvgRoundTripMs)    { '{0:N0}ms' -f $st.AvgRoundTripMs } else { '-' }

                            # Codecs are TWO fields. Concatenating them yields the
                            # infamous 'satinunknown'. Show the codec relevant to
                            # this media label and drop 'unknown' rather than
                            # printing it.
                            $codec = if ($m.Label -match 'video|screen') { $st.VideoCodec } else { $st.AudioCodec }
                            $cTxt  = if ($codec -and $codec -ne 'unknown') { "  $codec" } else { '' }

                            $stTxt = "{0}{1}  jitter {2}  loss {3}  rtt {4}  [{5}]" -f $st.Direction, $cTxt, $j, $l, $r, $st.Verdict
                            [void](& $addNode $mn.Nodes $stTxt $stCol $st)
                        }
                    }
                }
            }
        }

        $script:CraTree.EndUpdate()

        $all     = $state.Calls
        $failed  = @($all | Where-Object Verdict -eq 'Failed').Count
        $partial = @($all | Where-Object Verdict -eq 'Partial').Count
        $poor    = @($all | Where-Object QualityVerdict -eq 'Poor').Count
        $lblSummary.Text = "{0} call(s)   |   {1} failed, {2} partial   |   {3} with poor media   |   showing {4}" -f
                            $all.Count, $failed, $partial, $poor, @($calls).Count
    }

    $load = {
        param($SelectedPath)
        try {
            $form.Cursor = 'WaitCursor'
            $state.Calls = @(Import-CallRecord -Path $SelectedPath -Recurse:$Recurse | Expand-CallRecord |
                             Sort-Object StartDateTime -Descending)
            & $render
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Load failed:`n`n$($_.Exception.Message)", 'Call Record Analyzer',
                'OK', 'Error') | Out-Null
        }
        finally { $form.Cursor = 'Default' }
    }

    $btnLoad.Add_Click({
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.Description = 'Select the folder containing raw call record JSON'
        if ($dlg.ShowDialog() -eq 'OK') { & $load $dlg.SelectedPath }
    })

    $btnExpand.Add_Click({   $script:CraTree.ExpandAll() })
    $btnCollapse.Add_Click({ $script:CraTree.CollapseAll() })
    $chkFailOnly.Add_CheckedChanged({ & $render })

    $btnExport.Add_Click({
        if (-not $state.Calls.Count) { return }
        $dlg = New-Object System.Windows.Forms.SaveFileDialog
        $dlg.Filter = 'CSV files (*.csv)|*.csv'
        $dlg.FileName = "call-analysis-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
        if ($dlg.ShowDialog() -eq 'OK') {
            $state.Calls | Get-CallRecordSummary | Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8
            [System.Windows.Forms.MessageBox]::Show("Written to $($dlg.FileName)", 'Export', 'OK', 'Information') | Out-Null
        }
    })

    $script:CraTree.Add_AfterSelect({
        param($sender, $e)
        $tag = $e.Node.Tag
        if (-not $tag) { $script:CraDetail.Text = ''; return }

        $sb = New-Object System.Text.StringBuilder

        function Add-Section($Title, $Object) {
            if (-not $Object) { return }
            [void]$sb.AppendLine("--- $Title ---")
            foreach ($p in $Object.PSObject.Properties) {
                if ($p.Value -is [System.Collections.IEnumerable] -and $p.Value -isnot [string]) { continue }
                if ($null -eq $p.Value -or $p.Value -eq '') { continue }
                [void]$sb.AppendLine(("  {0,-24} {1}" -f $p.Name, $p.Value))
            }
            [void]$sb.AppendLine()
        }

        switch ($tag.NodeType) {
            'Call' {
                Add-Section 'Call' $tag
                foreach ($f in $tag.Failures) { Add-Section "Failure ($($f.Level))" $f }
            }
            'Session' {
                Add-Section 'Session' $tag
                Add-Section 'Caller'  $tag.Caller
                Add-Section 'Callee'  $tag.Callee
            }
            'Segment' {
                Add-Section 'Segment' $tag
                Add-Section 'Caller'  $tag.Caller
                Add-Section 'Callee'  $tag.Callee
            }
            'Media' {
                Add-Section 'Media'          $tag
                Add-Section 'Caller network' $tag.CallerNetwork
                Add-Section 'Callee network' $tag.CalleeNetwork
                Add-Section 'Caller device'  $tag.CallerDevice
                Add-Section 'Callee device'  $tag.CalleeDevice
            }
            default { Add-Section 'Stream' $tag }
        }

        $script:CraDetail.Text = $sb.ToString()
    })

    if ($Path) { & $load $Path }

    [void]$form.ShowDialog()
    $form.Dispose()
}

<#
================================================================================
 USAGE
--------------------------------------------------------------------------------
 # Interactive
 Show-CallRecordAnalyzer -Path $script:cdrRawRoot

 # Headless
 Export-CallQualityReport -Path .\cdr\raw -OutputDirectory .\reports -Recurse

 # Pipeline
 Import-CallRecord -Path .\cdr\raw |
     Expand-CallRecord |
     Where-Object { $_.Verdict -ne 'Success' } |
     Get-CallRecordSummary | Format-Table -AutoSize

 # Loosen a threshold for a noisy site
 Set-CallQualityThreshold -Name AvgJitterMs -Value 40
================================================================================
#>

################################################################################
#
#  PART 4  DIAGNOSTIC RULES ENGINE AND FLEET CORRELATION
#
################################################################################

# Sentinel values that mean "not reported", not a real reading.
$script:UnsetSentinels = @(4294967295, 0xFFFFFFFF, -1)

# ==============================================================================
# REGION 1 - PRIMITIVES
# ==============================================================================

function Get-DiagProperty {
    param($Object, [Parameter(Mandatory)][string]$Path, $Default = $null)
    $cur = $Object
    foreach ($part in $Path.Split('.')) {
        if ($null -eq $cur) { return $Default }
        if ($cur -isnot [psobject] -and $cur -isnot [hashtable]) { return $Default }
        if (-not $cur.PSObject.Properties[$part]) { return $Default }
        $cur = $cur.$part
    }
    if ($null -eq $cur) { return $Default }
    $cur
}

function ConvertTo-Ms {
<#
.SYNOPSIS
    ISO 8601 duration -> milliseconds, preserving a legitimate zero.
.DESCRIPTION
    'PT0S' must return 0, not $null. Treating zero jitter as missing data is the
    single most common defect in call-record tooling - it reports the healthiest
    possible reading as an absence.
#>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [double] -or $Value -is [int]) { return [double]$Value }
    $s = [string]$Value
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    try { return [System.Xml.XmlConvert]::ToTimeSpan($s).TotalMilliseconds } catch { }
    $d = 0.0
    if ([double]::TryParse($s, [ref]$d)) { return $d }
    $null
}

function Test-RealValue {
<#
.SYNOPSIS
    True when a metric is genuinely reported - zero counts, sentinels do not.
#>
    param($Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value)) { return $false }
    if (($Value -is [double] -or $Value -is [int] -or $Value -is [long]) -and
        ([double]$Value -in $script:UnsetSentinels)) { return $false }
    if ($Value -is [string] -and $Value -eq 'unknown') { return $false }
    $true
}

function New-DiagFinding {
    param(
        [Parameter(Mandatory)][string]$Title,
        [ValidateSet('Critical','Warning','Info')][string]$Severity = 'Warning',
        [ValidateSet('High','Medium','Low')][string]$Confidence = 'Medium',
        [ValidateSet('Failure','Transport','Network','Endpoint','Device','Codec','Service','Config')][string]$Area = 'Network',
        [ValidateSet('Caller','Callee','Both','Service','Unknown')][string]$Blame = 'Unknown',
        [string]$Evidence = '',
        [string]$Recommendation = '',
        [string]$Scope = ''
    )
    [pscustomobject]@{
        Title = $Title; Severity = $Severity; Confidence = $Confidence
        Area = $Area; Blame = $Blame; Evidence = $Evidence
        Recommendation = $Recommendation; Scope = $Scope
    }
}

# ==============================================================================
# REGION 2 - RULES
# ==============================================================================

function Get-FailureFinding {
<#
.SYNOPSIS
    Interpret failureInfo. Setup failures and mid-call drops are different faults.
#>
    param($FailureInfo, [string]$Scope)

    if (-not $FailureInfo) { return }

    $stage  = Get-DiagProperty $FailureInfo 'stage'
    $reason = Get-DiagProperty $FailureInfo 'reason'

    if ($stage -eq 'callSetup') {
        New-DiagFinding -Title 'Call failed during setup - never connected' `
            -Severity Critical -Confidence High -Area Failure -Blame Service -Scope $Scope `
            -Evidence "stage=callSetup; reason=$reason" `
            -Recommendation 'Signalling/routing fault. Check voice routing policy, PSTN usage and SBC trunk state. Media metrics below (if any) are not meaningful for a call that never connected.'
    }
    elseif ($stage -eq 'midcall') {
        New-DiagFinding -Title 'Call dropped mid-conversation' `
            -Severity Critical -Confidence High -Area Failure -Blame Unknown -Scope $Scope `
            -Evidence "stage=midcall; reason=$reason" `
            -Recommendation 'Connected then failed - look at transport and network findings below, which are relevant here in a way they are not for a setup failure.'
    }
    else {
        New-DiagFinding -Title "Call failed ($stage)" `
            -Severity Critical -Confidence High -Area Failure -Blame Unknown -Scope $Scope `
            -Evidence "stage=$stage; reason=$reason"
    }
}

function Get-NetworkFinding {
<#
.SYNOPSIS
    Rules over one side's network block.
#>
    param($Network, [string]$Side, [string]$Scope)

    if (-not $Network) { return }

    $conn      = Get-DiagProperty $Network 'connectionType'
    $relay     = Get-DiagProperty $Network 'relayIPAddress'
    $transport = Get-DiagProperty $Network 'networkTransportProtocol'
    $subnet    = Get-DiagProperty $Network 'subnet'
    $wifiSig   = Get-DiagProperty $Network 'wifiSignalStrength'
    $wifiBand  = Get-DiagProperty $Network 'wifiBand'
    $delayRat  = Get-DiagProperty $Network 'delayEventRatio'
    $bwRat     = Get-DiagProperty $Network 'bandwidthLowEventRatio'

    # TCP means UDP was blocked. Always worse for real-time media.
    if ($transport -eq 'tcp') {
        New-DiagFinding -Title "$Side media fell back to TCP" `
            -Severity Warning -Confidence High -Area Transport -Blame $Side -Scope $Scope `
            -Evidence "networkTransportProtocol=tcp; subnet=$subnet" `
            -Recommendation 'UDP 3478-3481 was unavailable, so media used TCP. TCP retransmission is actively harmful to real-time audio. Open UDP to the Teams media ranges on this path.'
    }

    # A relay address means media is going via Microsoft TURN, not peer-to-peer.
    if (Test-RealValue $relay) {
        New-DiagFinding -Title "$Side media relayed rather than direct" `
            -Severity Info -Confidence High -Area Transport -Blame $Side -Scope $Scope `
            -Evidence "relayIPAddress=$relay" `
            -Recommendation 'Media traversed a TURN relay, adding a hop and some latency. Normal across NAT/firewall boundaries and not a fault by itself - but if RTT is also high, this is a likely contributor.'
    }

    if ($conn -eq 'wifi') {
        # wifiSignalStrength is a percentage. 0 with a wifi connection type is
        # usually "not reported" rather than a genuinely dead link.
        if ((Test-RealValue $wifiSig) -and $wifiSig -gt 0 -and $wifiSig -lt 40) {
            New-DiagFinding -Title "$Side on weak Wi-Fi" `
                -Severity Warning -Confidence Medium -Area Network -Blame $Side -Scope $Scope `
                -Evidence "connectionType=wifi; signalStrength=$wifiSig%; band=$wifiBand" `
                -Recommendation 'Weak signal drives jitter and loss. Move closer to the AP, or use wired/5GHz.'
        }
        elseif ($wifiBand -eq '2.4GHz') {
            New-DiagFinding -Title "$Side on 2.4GHz Wi-Fi" `
                -Severity Info -Confidence Low -Area Network -Blame $Side -Scope $Scope `
                -Evidence "connectionType=wifi; band=2.4GHz" `
                -Recommendation '2.4GHz is congestion-prone. Worth checking if quality findings cluster on this band across many calls.'
        }
    }

    if ((Test-RealValue $bwRat) -and $bwRat -gt 0.1) {
        New-DiagFinding -Title "$Side hit low-bandwidth conditions" `
            -Severity Warning -Confidence High -Area Network -Blame $Side -Scope $Scope `
            -Evidence ("bandwidthLowEventRatio={0:P0}" -f $bwRat) `
            -Recommendation 'The client detected insufficient bandwidth during the call. Contention on the local link or upstream shaping.'
    }

    if ((Test-RealValue $delayRat) -and $delayRat -gt 0.1) {
        New-DiagFinding -Title "$Side saw sustained delay events" `
            -Severity Warning -Confidence High -Area Network -Blame $Side -Scope $Scope `
            -Evidence ("delayEventRatio={0:P0}" -f $delayRat) `
            -Recommendation 'Queuing or congestion on the path. Correlate with subnet across other calls.'
    }
}

function Get-DeviceFinding {
<#
.SYNOPSIS
    Rules over one side's device block. Endpoint faults masquerade as network
    faults constantly - a glitching capture device produces audio complaints
    while every network metric stays clean.
#>
    param($Device, [string]$Side, [string]$Scope)

    if (-not $Device) { return }

    $cpu     = Get-DiagProperty $Device 'cpuInsufficentEventRatio'
    $glitch  = Get-DiagProperty $Device 'deviceGlitchEventRatio'
    $capFail = Get-DiagProperty $Device 'captureNotFunctioningEventRatio'
    $renFail = Get-DiagProperty $Device 'renderNotFunctioningEventRatio'
    $howl    = Get-DiagProperty $Device 'howlingEventCount'
    $clip    = Get-DiagProperty $Device 'deviceClippingEventRatio'
    $lowSnr  = Get-DiagProperty $Device 'lowSpeechToNoiseEventRatio'
    $lowLvl  = Get-DiagProperty $Device 'lowSpeechLevelEventRatio'
    $sentLvl = Get-DiagProperty $Device 'sentSignalLevel'
    $mute    = Get-DiagProperty $Device 'renderMuteEventRatio'
    $capName = Get-DiagProperty $Device 'captureDeviceName'
    $renName = Get-DiagProperty $Device 'renderDeviceName'

    if ((Test-RealValue $cpu) -and $cpu -gt 0.05) {
        New-DiagFinding -Title "$Side machine short of CPU during the call" `
            -Severity Warning -Confidence High -Area Endpoint -Blame $Side -Scope $Scope `
            -Evidence ("cpuInsufficentEventRatio={0:P0}" -f $cpu) `
            -Recommendation 'Audio processing was starved. This produces choppy audio that no network change will fix. Look at what else was running.'
    }

    if ((Test-RealValue $glitch) -and $glitch -gt 0.05) {
        New-DiagFinding -Title "$Side audio device glitching" `
            -Severity Warning -Confidence High -Area Device -Blame $Side -Scope $Scope `
            -Evidence ("deviceGlitchEventRatio={0:P0}; capture='$capName'; render='$renName'" -f $glitch) `
            -Recommendation 'Driver or USB-level interruption. Check the driver version and, if USB, the hub/port. Frequently reported by users as "the network is bad".'
    }

    foreach ($pair in @(@{V=$capFail; N='capture'}, @{V=$renFail; N='render'})) {
        if ((Test-RealValue $pair.V) -and $pair.V -gt 0.05) {
            New-DiagFinding -Title "$Side $($pair.N) device stopped functioning during the call" `
                -Severity Critical -Confidence High -Area Device -Blame $Side -Scope $Scope `
                -Evidence ("$($pair.N)NotFunctioningEventRatio={0:P0}" -f $pair.V) `
                -Recommendation 'The device dropped out mid-call. Almost always a driver or hardware fault, not the network.'
        }
    }

    if ((Test-RealValue $howl) -and $howl -gt 0) {
        New-DiagFinding -Title "$Side acoustic feedback (howling) detected" `
            -Severity Warning -Confidence High -Area Device -Blame $Side -Scope $Scope `
            -Evidence "howlingEventCount=$howl" `
            -Recommendation 'Speaker output looping into the mic - two devices in one room, or speakerphone with gain too high. A headset resolves it.'
    }

    if ((Test-RealValue $clip) -and $clip -gt 0.1) {
        New-DiagFinding -Title "$Side microphone clipping" `
            -Severity Warning -Confidence High -Area Device -Blame $Side -Scope $Scope `
            -Evidence ("deviceClippingEventRatio={0:P0}" -f $clip) `
            -Recommendation 'Input gain too high - distorted audio at the far end. Reduce mic level.'
    }

    if ((Test-RealValue $lowSnr) -and $lowSnr -gt 0.2) {
        New-DiagFinding -Title "$Side in a noisy environment" `
            -Severity Info -Confidence Medium -Area Device -Blame $Side -Scope $Scope `
            -Evidence ("lowSpeechToNoiseEventRatio={0:P0}" -f $lowSnr) `
            -Recommendation 'Background noise close to speech level. Environmental, not a fault.'
    }

    if ((Test-RealValue $lowLvl) -and $lowLvl -gt 0.2) {
        New-DiagFinding -Title "$Side speaking too quietly for the mic" `
            -Severity Info -Confidence Medium -Area Device -Blame $Side -Scope $Scope `
            -Evidence ("lowSpeechLevelEventRatio={0:P0}; sentSignalLevel=$sentLvl dBFS" -f $lowLvl) `
            -Recommendation 'Raise input gain or move the mic closer.'
    }

    if ((Test-RealValue $mute) -and $mute -gt 0.5) {
        New-DiagFinding -Title "$Side output muted for most of the call" `
            -Severity Info -Confidence Medium -Area Device -Blame $Side -Scope $Scope `
            -Evidence ("renderMuteEventRatio={0:P0}" -f $mute) `
            -Recommendation 'Likely deliberate, but worth noting if the user reported hearing nothing.'
    }
}

function Get-StreamFinding {
<#
.SYNOPSIS
    Rules over one media stream, including the comparisons that separate a
    transport problem from an endpoint problem.
#>
    param($Stream, [string]$MediaLabel, [string]$Scope)

    $dir       = Get-DiagProperty $Stream 'streamDirection'
    $jitter    = ConvertTo-Ms (Get-DiagProperty $Stream 'averageJitter')
    $netJitter = ConvertTo-Ms (Get-DiagProperty $Stream 'averageAudioNetworkJitter')
    $maxJitter = ConvertTo-Ms (Get-DiagProperty $Stream 'maxJitter')
    $rtt       = ConvertTo-Ms (Get-DiagProperty $Stream 'averageRoundTripTime')
    $loss      = Get-DiagProperty $Stream 'averagePacketLossRate'
    $maxLoss   = Get-DiagProperty $Stream 'maxPacketLossRate'
    $conceal   = Get-DiagProperty $Stream 'averageRatioOfConcealedSamples'
    $degrade   = Get-DiagProperty $Stream 'averageAudioDegradation'
    $fec       = Get-DiagProperty $Stream 'isAudioForwardErrorCorrectionUsed'
    $codec     = Get-DiagProperty $Stream 'audioCodec'
    $bwEst     = Get-DiagProperty $Stream 'averageBandwidthEstimate'

    $where = "$Scope $dir"

    # --- absence, stated rather than assumed --------------------------------
    $anyMetric = @($jitter, $rtt, $loss, $conceal, $degrade) | Where-Object { $null -ne $_ }
    if (-not $anyMetric.Count) {
        New-DiagFinding -Title 'No quality metrics on this stream' `
            -Severity Info -Confidence High -Area Service -Blame Unknown -Scope $where `
            -Evidence 'All quality fields null.' `
            -Recommendation 'Cannot be assessed - not the same as good. Common on very short calls and on service-side legs.'
        return
    }

    if ((Test-RealValue $rtt) -and $rtt -gt 500) {
        New-DiagFinding -Title 'Round-trip time above the poor-call threshold' `
            -Severity Critical -Confidence High -Area Network -Blame Unknown -Scope $where `
            -Evidence ("averageRoundTripTime={0:N0}ms (threshold 500ms)" -f $rtt) `
            -Recommendation 'Above ~500ms conversation becomes hard to hold - people talk over each other. Check for a relayed path, geographically distant media, or an overloaded SBC.'
    }
    elseif ((Test-RealValue $rtt) -and $rtt -gt 300) {
        New-DiagFinding -Title 'Round-trip time elevated' `
            -Severity Warning -Confidence Medium -Area Network -Blame Unknown -Scope $where `
            -Evidence ("averageRoundTripTime={0:N0}ms" -f $rtt) `
            -Recommendation 'Under the 500ms poor threshold but high enough to be noticed as sluggishness.'
    }

    if ((Test-RealValue $loss) -and $loss -gt 0.10) {
        New-DiagFinding -Title 'Packet loss above the poor-call threshold' `
            -Severity Critical -Confidence High -Area Network -Blame Unknown -Scope $where `
            -Evidence ("averagePacketLossRate={0:P1}; max={1:P1}" -f $loss, $(if ($null -ne $maxLoss) { $maxLoss } else { 0 })) `
            -Recommendation 'Audible dropouts. Correlate with subnet and connection type across other calls before treating it as a one-off.'
    }
    elseif ((Test-RealValue $loss) -and $loss -gt 0.02) {
        New-DiagFinding -Title 'Moderate packet loss' `
            -Severity Warning -Confidence Medium -Area Network -Blame Unknown -Scope $where `
            -Evidence ("averagePacketLossRate={0:P1}" -f $loss)
    }

    # --- the discriminating comparison --------------------------------------
    # Total jitter high while NETWORK jitter is low means the delay was
    # introduced after the packets arrived - jitter buffer, decoder, or a
    # starved CPU. Chasing the network here wastes days.
    if ((Test-RealValue $jitter) -and (Test-RealValue $netJitter) -and
        $jitter -gt 30 -and $netJitter -lt ($jitter / 2)) {
        New-DiagFinding -Title 'Jitter is endpoint-side, not network-side' `
            -Severity Warning -Confidence Medium -Area Endpoint -Blame Unknown -Scope $where `
            -Evidence ("averageJitter={0:N1}ms but averageAudioNetworkJitter={1:N1}ms" -f $jitter, $netJitter) `
            -Recommendation 'The network delivered packets steadily; the delay appeared afterwards. Look at CPU and device findings rather than the transport path.'
    }
    elseif ((Test-RealValue $netJitter) -and $netJitter -gt 30) {
        New-DiagFinding -Title 'Network jitter above threshold' `
            -Severity Critical -Confidence High -Area Network -Blame Unknown -Scope $where `
            -Evidence ("averageAudioNetworkJitter={0:N1}ms (threshold 30ms); max={1:N1}ms" -f $netJitter, $(if ($null -ne $maxJitter) { $maxJitter } else { 0 })) `
            -Recommendation 'Uneven packet arrival on the transport path - queuing, congestion, or a variable-latency link.'
    }
    elseif ((Test-RealValue $jitter) -and $jitter -gt 30) {
        New-DiagFinding -Title 'Jitter above threshold' `
            -Severity Critical -Confidence High -Area Network -Blame Unknown -Scope $where `
            -Evidence ("averageJitter={0:N1}ms (threshold 30ms)" -f $jitter)
    }

    # Concealment high while loss is low - the decoder is papering over
    # something the loss counter did not see.
    if ((Test-RealValue $conceal) -and $conceal -gt 0.07) {
        $lossTxt = if (Test-RealValue $loss) { '{0:P1}' -f $loss } else { 'not reported' }
        $sev  = if ((Test-RealValue $loss) -and $loss -lt 0.02) { 'Warning' } else { 'Info' }
        $conf = if ((Test-RealValue $loss) -and $loss -lt 0.02) { 'Medium' } else { 'Low' }
        New-DiagFinding -Title 'High concealed-sample ratio' `
            -Severity $sev -Confidence $conf -Area Codec -Blame Unknown -Scope $where `
            -Evidence ("averageRatioOfConcealedSamples={0:P1} while packet loss={1}" -f $conceal, $lossTxt) `
            -Recommendation 'The decoder synthesised audio to cover gaps - this is what users actually hear as robotic or warbly. When loss is low, suspect late packets rather than lost ones.'
    }

    if ((Test-RealValue $degrade) -and $degrade -gt 1.0) {
        New-DiagFinding -Title 'Measured audio degradation above threshold' `
            -Severity Critical -Confidence High -Area Codec -Blame Unknown -Scope $where `
            -Evidence ("averageAudioDegradation={0:N2} (threshold 1.0)" -f $degrade) `
            -Recommendation "Microsoft's own composite quality measure says this call sounded bad. Treat as authoritative over individual metrics."
    }

    if ($fec -eq $true) {
        New-DiagFinding -Title 'Forward error correction was active' `
            -Severity Info -Confidence High -Area Codec -Blame Unknown -Scope $where `
            -Evidence 'isAudioForwardErrorCorrectionUsed=true' `
            -Recommendation 'FEC engages in response to loss. The reported loss rate is what survived correction - the raw path was worse than it appears.'
    }

    if ($codec -eq 'pcmu' -or $codec -eq 'pcma') {
        New-DiagFinding -Title "G.711 ($codec) on this leg - no adaptivity" `
            -Severity Info -Confidence High -Area Codec -Blame Unknown -Scope $where `
            -Evidence ("audioCodec=$codec; bandwidthEstimate={0}" -f $(if (Test-RealValue $bwEst) { "$bwEst bps" } else { 'not reported' })) `
            -Recommendation 'Normal on a Direct Routing leg to an SBC. G.711 is fixed-rate and cannot adapt to congestion the way Satin does, so this leg is inherently less resilient to loss.'
    }
}

# ==============================================================================
# REGION 3 - PER-CALL DIAGNOSIS
# ==============================================================================

function Get-CallDiagnosis {
<#
.SYNOPSIS
    Produce ranked findings for one raw callRecord.
.EXAMPLE
    $rec  = Get-Content $path -Raw | ConvertFrom-Json
    Get-CallDiagnosis -CallRecord $rec | Format-Table Severity, Area, Title -AutoSize
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$CallRecord,
        [ValidateSet('High','Medium','Low')][string]$MinimumConfidence = 'Low'
    )

    process {
        $findings = New-Object System.Collections.ArrayList
        $add = { param($f) foreach ($x in @($f)) { if ($x) { [void]$findings.Add($x) } } }

        $sessions = @(Get-DiagProperty $CallRecord 'sessions' @())

        if (-not $sessions.Count) {
            & $add (New-DiagFinding -Title 'Record has no session detail' `
                -Severity Info -Confidence High -Area Service -Scope 'call' `
                -Evidence 'sessions absent or empty' `
                -Recommendation 'The CDR pull did not expand sessions. Re-fetch with $expand=sessions($expand=segments) - no quality assessment is possible without it.')
        }

        $si = 0
        foreach ($s in $sessions) {
            $si++
            $scope = "session $si"
            & $add (Get-FailureFinding -FailureInfo (Get-DiagProperty $s 'failureInfo') -Scope $scope)

            $gi = 0
            foreach ($seg in @(Get-DiagProperty $s 'segments' @())) {
                $gi++
                $segScope = "$scope/segment $gi"
                & $add (Get-FailureFinding -FailureInfo (Get-DiagProperty $seg 'failureInfo') -Scope $segScope)

                foreach ($m in @(Get-DiagProperty $seg 'media' @())) {
                    $label = Get-DiagProperty $m 'label' 'audio'
                    $mScope = "$segScope/$label"

                    & $add (Get-NetworkFinding -Network (Get-DiagProperty $m 'callerNetwork') -Side 'Caller' -Scope $mScope)
                    & $add (Get-NetworkFinding -Network (Get-DiagProperty $m 'calleeNetwork') -Side 'Callee' -Scope $mScope)
                    & $add (Get-DeviceFinding  -Device  (Get-DiagProperty $m 'callerDevice')  -Side 'Caller' -Scope $mScope)
                    & $add (Get-DeviceFinding  -Device  (Get-DiagProperty $m 'calleeDevice')  -Side 'Callee' -Scope $mScope)

                    foreach ($st in @(Get-DiagProperty $m 'streams' @())) {
                        & $add (Get-StreamFinding -Stream $st -MediaLabel $label -Scope $mScope)
                    }
                }
            }
        }

        $sevRank  = @{ Critical = 0; Warning = 1; Info = 2 }
        $confRank = @{ High = 0; Medium = 1; Low = 2 }
        $minConf  = $confRank[$MinimumConfidence]

        @($findings) |
            Where-Object { $confRank[$_.Confidence] -le $minConf } |
            Sort-Object @{E={$sevRank[$_.Severity]}}, @{E={$confRank[$_.Confidence]}}, Area
    }
}

function Format-CallDiagnosisText {
<#
.SYNOPSIS
    Render findings for a detail pane.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Diagnosis,
        [switch]$IncludeRecommendations
    )

    $f = @($Diagnosis)
    if (-not $f.Count) { return 'No findings. Nothing in this record indicates a problem.' }

    $sb = New-Object System.Text.StringBuilder
    $crit = @($f | Where-Object Severity -eq 'Critical').Count
    $warn = @($f | Where-Object Severity -eq 'Warning').Count

    [void]$sb.AppendLine(("{0} finding(s): {1} critical, {2} warning" -f $f.Count, $crit, $warn))
    [void]$sb.AppendLine(('-' * 72))

    foreach ($x in $f) {
        [void]$sb.AppendLine(("[{0}] {1}" -f $x.Severity.ToUpper(), $x.Title))
        [void]$sb.AppendLine(("    where : {0}" -f $x.Scope))
        [void]$sb.AppendLine(("    signal: {0}  (confidence: {1}, area: {2})" -f $x.Evidence, $x.Confidence, $x.Area))
        if ($IncludeRecommendations -and $x.Recommendation) {
            [void]$sb.AppendLine(("    action: {0}" -f $x.Recommendation))
        }
        [void]$sb.AppendLine()
    }

    $sb.ToString()
}

# ==============================================================================
# REGION 4 - FLEET CORRELATION
#
# One bad call is an anecdote. The value of a folder of records is finding what
# the bad ones have in common - and that requires resisting the urge to report
# "100% of calls on subnet X were poor" when X appeared twice.
# ==============================================================================

function Get-CallFleetAnalysis {
<#
.SYNOPSIS
    Find what poor calls have in common across many records.
.DESCRIPTION
    For each dimension (subnet, connection type, codec, far-end endpoint, capture
    device, platform, transport) compare that group's poor rate against the
    overall baseline and report the lift.

    Groups below -MinimumSample are reported as InsufficientData rather than
    given a rate. A 100% failure rate over two calls is noise, and presenting it
    as a finding sends someone to re-cable a subnet that was never the problem.
.EXAMPLE
    Get-CallFleetAnalysis -Path .\cdr\raw -Recurse |
        Where-Object Verdict -eq 'Elevated' | Format-Table -AutoSize
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Recurse,
        [int]$MinimumSample = 5,
        [double]$LiftThreshold = 1.5
    )

    $files = if ((Get-Item $Path).PSIsContainer) {
        Get-ChildItem -Path $Path -Filter '*.json' -File -Recurse:$Recurse
    } else { @(Get-Item $Path) }

    $observations = New-Object System.Collections.ArrayList

    foreach ($file in $files) {
        $text = Get-Content -Path $file.FullName -Raw -Encoding UTF8
        if ($text -and [int][char]$text[0] -eq 0xFEFF) { $text = $text.Substring(1) }
        try { $rec = $text | ConvertFrom-Json } catch { continue }

        foreach ($s in @(Get-DiagProperty $rec 'sessions' @())) {
            $failed = [bool](Get-DiagProperty $s 'failureInfo')

            foreach ($seg in @(Get-DiagProperty $s 'segments' @())) {
                foreach ($m in @(Get-DiagProperty $seg 'media' @())) {

                    $cNet = Get-DiagProperty $m 'callerNetwork'
                    $eNet = Get-DiagProperty $m 'calleeNetwork'
                    $cDev = Get-DiagProperty $m 'callerDevice'

                    foreach ($st in @(Get-DiagProperty $m 'streams' @())) {

                        $jit  = ConvertTo-Ms (Get-DiagProperty $st 'averageAudioNetworkJitter')
                        if ($null -eq $jit) { $jit = ConvertTo-Ms (Get-DiagProperty $st 'averageJitter') }
                        $rtt  = ConvertTo-Ms (Get-DiagProperty $st 'averageRoundTripTime')
                        $loss = Get-DiagProperty $st 'averagePacketLossRate'
                        $deg  = Get-DiagProperty $st 'averageAudioDegradation'

                        $rated = @($jit, $rtt, $loss, $deg) | Where-Object { $null -ne $_ }
                        if (-not $rated.Count) { continue }

                        $poor = (($null -ne $jit)  -and $jit  -gt 30)   -or
                                (($null -ne $rtt)  -and $rtt  -gt 500)  -or
                                (($null -ne $loss) -and $loss -gt 0.10) -or
                                (($null -ne $deg)  -and $deg  -gt 1.0)

                        [void]$observations.Add([pscustomobject]@{
                            CallId        = Get-DiagProperty $rec 'id'
                            Poor          = [bool]$poor
                            Failed        = $failed
                            CallerSubnet  = Get-DiagProperty $cNet 'subnet'
                            CalleeSubnet  = Get-DiagProperty $eNet 'subnet'
                            ConnectionType= Get-DiagProperty $cNet 'connectionType'
                            Transport     = Get-DiagProperty $cNet 'networkTransportProtocol'
                            Relayed       = [bool](Test-RealValue (Get-DiagProperty $cNet 'relayIPAddress'))
                            Codec         = Get-DiagProperty $st 'audioCodec'
                            Direction     = Get-DiagProperty $st 'streamDirection'
                            FarEnd        = Get-DiagProperty $seg 'callee.name'
                            Platform      = Get-DiagProperty $seg 'caller.userAgent.platform'
                            CaptureDevice = Get-DiagProperty $cDev 'captureDeviceName'
                            MediaLabel    = Get-DiagProperty $m 'label'
                        })
                    }
                }
            }
        }
    }

    $obs = @($observations)
    if (-not $obs.Count) { Write-Warning "No rated streams found under $Path"; return }

    $baseline = @($obs | Where-Object Poor).Count / $obs.Count
    Write-Verbose ("Baseline poor rate: {0:P1} over {1} streams" -f $baseline, $obs.Count)

    $dimensions = 'CallerSubnet','CalleeSubnet','ConnectionType','Transport','Relayed',
                  'Codec','Direction','FarEnd','Platform','CaptureDevice'

    foreach ($dim in $dimensions) {
        $groups = $obs | Where-Object { $null -ne $_.$dim -and '' -ne [string]$_.$dim } |
                         Group-Object -Property $dim

        foreach ($g in $groups) {
            $n    = $g.Count
            $bad  = @($g.Group | Where-Object Poor).Count
            $rate = $bad / $n
            $lift = if ($baseline -gt 0) { $rate / $baseline } else { 0 }

            $verdict = if ($n -lt $MinimumSample) { 'InsufficientData' }
                       elseif ($rate -eq 0)       { 'Clean' }
                       elseif ($lift -ge $LiftThreshold) { 'Elevated' }
                       else { 'Typical' }

            [pscustomobject]@{
                Dimension    = $dim
                Value        = $g.Name
                Streams      = $n
                PoorStreams  = $bad
                PoorRate     = if ($n -ge $MinimumSample) { '{0:P1}' -f $rate } else { 'n/a' }
                BaselineRate = '{0:P1}' -f $baseline
                Lift         = if ($n -ge $MinimumSample) { '{0:N2}x' -f $lift } else { 'n/a' }
                Verdict      = $verdict
            }
        }
    }
}

<#
================================================================================
 USAGE
--------------------------------------------------------------------------------
 # Per-call, for the detail pane
 $rec  = Get-Content $path -Raw | ConvertFrom-Json
 $diag = Get-CallDiagnosis -CallRecord $rec
 Format-CallDiagnosisText -Diagnosis $diag -IncludeRecommendations

 # Only what you'd act on
 Get-CallDiagnosis -CallRecord $rec -MinimumConfidence Medium |
     Where-Object Severity -ne 'Info'

 # Across the estate - what do the bad calls share?
 Get-CallFleetAnalysis -Path .\cdr\raw -Recurse |
     Where-Object Verdict -eq 'Elevated' | Format-Table -AutoSize
================================================================================
#>

################################################################################
#
#  PART 5  DIAGNOSTICS TAB
#
################################################################################


# ==============================================================================
# REGION 2 - SHARED SUBJECT
#
# Lets the existing JSON Analyzer tab hand its loaded record to this tab without
# either knowing about the other's controls.
# ==============================================================================

$script:DiagSubject = @{ Record = $null; Label = $null; FolderPath = $null }

function Set-DiagnosticsSubject {
<#
.SYNOPSIS
    Hand a raw callRecord to the Diagnostics tab from elsewhere in the app.
.EXAMPLE
    Set-DiagnosticsSubject -CallRecord $rec -Label 'from analyzer tree'
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$CallRecord,
        [string]$Label = 'shared from analyzer'
    )
    $script:DiagSubject.Record = $CallRecord
    $script:DiagSubject.Label  = $Label
    if ($script:DiagOnSubjectChanged) { & $script:DiagOnSubjectChanged }
}

$script:DiagOnSubjectChanged = $null

# ==============================================================================
# REGION 3 - THE TAB
# ==============================================================================

function New-DiagnosticsTabPage {
<#
.SYNOPSIS
    JSON Analyzer tab - call tree, verdict, call flow, raw node JSON.
.DESCRIPTION
    SCOPE NOTE, and the reason the previous build silently did nothing:

    This function RETURNS a TabPage and then exits. Any variable declared local
    to it is gone by the time a click handler runs, so handlers that closed over
    function-local state invoked a null and WinForms swallowed the error - no
    message, no action. Everything the handlers touch therefore lives in
    $script:JA. Show-CallRecordAnalyzer does not have this problem only because
    its function stays on the stack inside ShowDialog.
#>
    [CmdletBinding()]
    param([string]$Text = '  JSON Analyzer  ')

    $script:JA = @{
        Records = @(); Expanded = @(); Current = $null; CurrentRaw = $null
        Path = $null; Ctl = @{}
    }

    $ColCrit = [System.Drawing.Color]::FromArgb(192, 32, 32)
    $ColWarn = [System.Drawing.Color]::FromArgb(200,120,  0)
    $ColOk   = [System.Drawing.Color]::FromArgb( 24,110, 40)
    $ColInfo = [System.Drawing.Color]::FromArgb(100,100,100)
    $ColKey  = [System.Drawing.Color]::FromArgb( 40, 90,190)
    $Mono    = New-Object System.Drawing.Font('Consolas', 9)

    $page = New-Object System.Windows.Forms.TabPage
    $page.Text = $Text

    # ---------- toolbar ------------------------------------------------------
    $bar = New-Object System.Windows.Forms.Panel
    $bar.Dock = 'Top'; $bar.Height = 40

    $btnFile = New-Object System.Windows.Forms.Button
    $btnFile.Text = 'Load callRecord JSON...'
    $btnFile.Location = New-Object System.Drawing.Point(6,6); $btnFile.Size = New-Object System.Drawing.Size(170,26)

    $btnFolder = New-Object System.Windows.Forms.Button
    $btnFolder.Text = 'Load from RawJSON folder...'
    $btnFolder.Location = New-Object System.Drawing.Point(182,6); $btnFolder.Size = New-Object System.Drawing.Size(190,26)

    $btnRe = New-Object System.Windows.Forms.Button
    $btnRe.Text = 'Re-Analyze'
    $btnRe.Location = New-Object System.Drawing.Point(378,6); $btnRe.Size = New-Object System.Drawing.Size(100,26)

    $btnFleet = New-Object System.Windows.Forms.Button
    $btnFleet.Text = 'Fleet...'
    $btnFleet.Location = New-Object System.Drawing.Point(484,6); $btnFleet.Size = New-Object System.Drawing.Size(80,26)

    if (Get-Command Style-Button -ErrorAction SilentlyContinue) {
        Style-Button $btnFile   ([System.Drawing.Color]::FromArgb(0,120,215))
        Style-Button $btnFolder ([System.Drawing.Color]::FromArgb(92,60,140))
        Style-Button $btnRe     ([System.Drawing.Color]::FromArgb(96,96,96))
        Style-Button $btnFleet  ([System.Drawing.Color]::FromArgb(16,124,16))
    }

    $lblPath = New-Object System.Windows.Forms.Label
    $lblPath.Location = New-Object System.Drawing.Point(572,11); $lblPath.Size = New-Object System.Drawing.Size(720,20)
    $lblPath.AutoEllipsis = $true; $lblPath.ForeColor = $ColInfo
    $lblPath.Text = 'No file loaded.'

    $bar.Controls.AddRange(@($btnFile,$btnFolder,$btnRe,$btnFleet,$lblPath))

    # ---------- split: tree | (verdict / flow / raw) -------------------------
    $split = New-Object System.Windows.Forms.SplitContainer
    $split.Dock = 'Fill'; $split.Orientation = 'Vertical'; $split.SplitterDistance = 520

    $tree = New-Object System.Windows.Forms.TreeView
    $tree.Dock = 'Fill'; $tree.Font = $Mono; $tree.HideSelection = $false
    $split.Panel1.Controls.Add($tree)

    $right = New-Object System.Windows.Forms.TableLayoutPanel
    $right.Dock = 'Fill'; $right.ColumnCount = 1; $right.RowCount = 3
    [void]$right.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 30)))
    [void]$right.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 40)))
    [void]$right.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 30)))

    $grpVerdict = New-Object System.Windows.Forms.GroupBox
    $grpVerdict.Text = 'Verdict / Summary'; $grpVerdict.Dock = 'Fill'
    $rtbVerdict = New-Object System.Windows.Forms.RichTextBox
    $rtbVerdict.Dock = 'Fill'; $rtbVerdict.ReadOnly = $true; $rtbVerdict.Font = $Mono
    $rtbVerdict.BorderStyle = 'None'; $rtbVerdict.BackColor = [System.Drawing.Color]::White
    $grpVerdict.Controls.Add($rtbVerdict)

    $grpFlow = New-Object System.Windows.Forms.GroupBox
    $grpFlow.Text = 'Call Flow'; $grpFlow.Dock = 'Fill'
    $rtbFlow = New-Object System.Windows.Forms.RichTextBox
    $rtbFlow.Dock = 'Fill'; $rtbFlow.ReadOnly = $true; $rtbFlow.Font = $Mono
    $rtbFlow.BorderStyle = 'None'; $rtbFlow.WordWrap = $false
    $rtbFlow.BackColor = [System.Drawing.Color]::White
    $grpFlow.Controls.Add($rtbFlow)

    $grpRaw = New-Object System.Windows.Forms.GroupBox
    $grpRaw.Text = 'Selected Node (raw JSON)'; $grpRaw.Dock = 'Fill'
    $txtRaw = New-Object System.Windows.Forms.TextBox
    $txtRaw.Dock = 'Fill'; $txtRaw.ReadOnly = $true; $txtRaw.Multiline = $true
    $txtRaw.ScrollBars = 'Both'; $txtRaw.WordWrap = $false; $txtRaw.Font = $Mono
    # A WinForms TextBox caps at 32767 characters by default and truncates
    # silently. A 10-session group call serializes well past that, so the pane
    # would show a JSON fragment that simply stops. 0 removes the cap.
    $txtRaw.MaxLength = 0
    $grpRaw.Controls.Add($txtRaw)

    $right.Controls.Add($grpVerdict,0,0)
    $right.Controls.Add($grpFlow,   0,1)
    $right.Controls.Add($grpRaw,    0,2)
    $split.Panel2.Controls.Add($right)

    $page.Controls.Add($split)
    $page.Controls.Add($bar)

    # Everything a handler needs, reachable after this function returns.
    $script:JA.Ctl = @{
        Tree=$tree; Verdict=$rtbVerdict; Flow=$rtbFlow; Raw=$txtRaw; Path=$lblPath; Page=$page
        ColCrit=$ColCrit; ColWarn=$ColWarn; ColOk=$ColOk; ColInfo=$ColInfo; ColKey=$ColKey
    }

    # ---------- handlers -----------------------------------------------------
    $btnFile.Add_Click({
        $dlg = New-Object System.Windows.Forms.OpenFileDialog
        $dlg.Filter = 'callRecord JSON (*.json)|*.json|All files (*.*)|*.*'
        if ($dlg.ShowDialog() -ne 'OK') { return }
        Invoke-JALoad -Path $dlg.FileName
    })

    $btnFolder.Add_Click({
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.Description = 'Select a RawJSON folder'
        if ($dlg.ShowDialog() -ne 'OK') { return }
        Invoke-JALoad -Path $dlg.SelectedPath -Recurse
    })

    $btnRe.Add_Click({
        if ($script:JA.Path) { Invoke-JALoad -Path $script:JA.Path -Recurse }
        elseif ($script:DiagSubject.Record) { Invoke-JARender -Records @($script:DiagSubject.Record) -Label 'shared from app' }
    })

    $btnFleet.Add_Click({
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.Description = 'Correlate poor streams across a folder of call records'
        if ($dlg.ShowDialog() -ne 'OK') { return }
        Show-JAFleet -Path $dlg.SelectedPath
    })

    $tree.Add_AfterSelect({ param($s,$e) Update-JASelection -Node $e.Node })

    $page
}

function Invoke-JALoad {
<#
.SYNOPSIS
    Load one file or a folder of callRecord JSON and render.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [switch]$Recurse)

    $c = $script:JA.Ctl
    try {
        $c.Page.Cursor = 'WaitCursor'

        $files = if ((Get-Item $Path).PSIsContainer) {
            @(Get-ChildItem -Path $Path -Filter '*.json' -File -Recurse:$Recurse)
        } else { @(Get-Item $Path) }

        $recs = New-Object System.Collections.ArrayList
        foreach ($f in $files) {
            $t = Get-Content -Path $f.FullName -Raw -Encoding UTF8
            # PS 5.1 writes a BOM; ConvertFrom-Json tolerates it but a leading
            # U+FEFF breaks strict parsers and naive comparisons downstream.
            if ($t -and [int][char]$t[0] -eq 0xFEFF) { $t = $t.Substring(1) }
            try { $o = $t | ConvertFrom-Json } catch { continue }
            $items = if ($o -is [array]) { $o } elseif ($o.PSObject.Properties['value']) { @($o.value) } else { @($o) }
            foreach ($i in $items) {
                if ($i -and $i.PSObject.Properties['id']) {
                    $i | Add-Member -NotePropertyName '_SourceFile' -NotePropertyValue $f.FullName -Force
                    [void]$recs.Add($i)
                }
            }
        }

        if (-not $recs.Count) {
            [System.Windows.Forms.MessageBox]::Show(
                "No call records found in:`n$Path`n`nA callRecord needs an 'id' property. If this is a CDR summary CSV or a report, it will not parse here.",
                'JSON Analyzer','OK','Warning') | Out-Null
            return
        }

        $script:JA.Path = $Path
        Invoke-JARender -Records @($recs) -Label $Path
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Load failed:`n`n$($_.Exception.Message)",'JSON Analyzer','OK','Error') | Out-Null
    }
    finally { $c.Page.Cursor = 'Default' }
}

function Invoke-JARender {
<#
.SYNOPSIS
    Build the tree from loaded records and show the first one's summary.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Records, [string]$Label)

    $c = $script:JA.Ctl
    $script:JA.Records  = @($Records)
    $script:JA.Expanded = @($Records | Expand-CallRecord)

    $c.Tree.BeginUpdate()
    $c.Tree.Nodes.Clear()

    for ($i = 0; $i -lt $script:JA.Expanded.Count; $i++) {
        $x   = $script:JA.Expanded[$i]
        $raw = $script:JA.Records[$i]

        $head = "callRecord  id=$($x.Id)  type=$($x.Type)"
        $n = New-Object System.Windows.Forms.TreeNode($head)
        $n.Tag = [pscustomobject]@{ Kind='Call'; Exp=$x; Raw=$raw }
        $n.ForeColor = if ($x.Verdict -ne 'Success') { $c.ColCrit }
                       elseif ($x.QualityVerdict -eq 'Poor') { $c.ColWarn } else { $c.ColOk }

        $o = New-Object System.Windows.Forms.TreeNode("organizer: $($x.Organizer)")
        $o.Tag = [pscustomobject]@{ Kind='Raw'; Raw=(Get-JsonProperty $raw 'organizer_v2') }
        [void]$n.Nodes.Add($o)

        $pn = New-Object System.Windows.Forms.TreeNode("participants ($($x.ParticipantCount))")
        $rawParts = @(Get-JsonProperty $raw 'participants_v2' @())
        if (-not $rawParts.Count) { $rawParts = @(Get-JsonProperty $raw 'participants' @()) }
        # Grouping nodes get the underlying array as their payload rather than
        # nothing - clicking one and getting a blank pane reads as a failure.
        $pn.Tag = [pscustomobject]@{ Kind='Raw'; Raw=$rawParts }
        for ($p = 0; $p -lt @($x.Participants).Count; $p++) {
            $pl = New-Object System.Windows.Forms.TreeNode("participant: $(@($x.Participants)[$p])")
            if ($p -lt $rawParts.Count) { $pl.Tag = [pscustomobject]@{ Kind='Raw'; Raw=$rawParts[$p] } }
            [void]$pn.Nodes.Add($pl)
        }
        [void]$n.Nodes.Add($pn)

        $rawSessions = @(Get-JsonProperty $raw 'sessions' @())
        $sn = New-Object System.Windows.Forms.TreeNode("sessions ($($x.SessionCount))")
        $sn.Tag = [pscustomobject]@{ Kind='Raw'; Raw=$rawSessions }

        for ($si = 0; $si -lt @($x.Sessions).Count; $si++) {
            $s    = @($x.Sessions)[$si]
            $sRaw = if ($si -lt $rawSessions.Count) { $rawSessions[$si] } else { $null }

            $sTxt = "session $($si+1) : $($s.Caller.Label) -> $($s.Callee.Label)"
            if (-not $s.Succeeded) { $sTxt += "   FAILED [$($s.FailureStage): $($s.FailureReason)]" }
            $snode = New-Object System.Windows.Forms.TreeNode($sTxt)
            $snode.Tag = [pscustomobject]@{ Kind='Raw'; Raw=$sRaw }
            $snode.ForeColor = if ($s.Succeeded) { $c.ColOk } else { $c.ColCrit }

            $rawSegs = @(Get-JsonProperty $sRaw 'segments' @())
            for ($gi = 0; $gi -lt @($s.Segments).Count; $gi++) {
                $g    = @($s.Segments)[$gi]
                $gRaw = if ($gi -lt $rawSegs.Count) { $rawSegs[$gi] } else { $null }

                $gTxt = "segment $($gi+1) : $($g.Caller.Label) -> $($g.Callee.Label)"
                if (-not $g.Succeeded) { $gTxt += "   FAILED [$($g.FailureStage): $($g.FailureReason)]" }
                $gnode = New-Object System.Windows.Forms.TreeNode($gTxt)
                $gnode.Tag = [pscustomobject]@{ Kind='Raw'; Raw=$gRaw }
                $gnode.ForeColor = if ($g.Succeeded) { $c.ColOk } else { $c.ColCrit }

                $rawMedia = @(Get-JsonProperty $gRaw 'media' @())
                for ($mi = 0; $mi -lt @($g.Media).Count; $mi++) {
                    $m    = @($g.Media)[$mi]
                    $mRaw = if ($mi -lt $rawMedia.Count) { $rawMedia[$mi] } else { $null }

                    $mnode = New-Object System.Windows.Forms.TreeNode("media[$($m.Label)]  streams=$(@($m.Streams).Count)")
                    $mnode.Tag = [pscustomobject]@{ Kind='Raw'; Raw=$mRaw }
                    $mnode.ForeColor = if ($m.PoorStreams) { $c.ColWarn } else { $c.ColOk }

                    $rawStreams = @(Get-JsonProperty $mRaw 'streams' @())
                    for ($ti = 0; $ti -lt @($m.Streams).Count; $ti++) {
                        $t = @($m.Streams)[$ti]
                        # Codec is TWO fields on the record; concatenating them is
                        # where 'satinunknown' comes from. Show the one that
                        # matches this media label and drop 'unknown'.
                        $cd = if ($m.Label -match 'video|screen') { $t.VideoCodec } else { $t.AudioCodec }
                        $cdTxt = if ($cd -and $cd -ne 'unknown') { "  codec=$cd" } else { '' }
                        $tnode = New-Object System.Windows.Forms.TreeNode("stream $($ti+1)  dir=$($t.Direction)$cdTxt  [$($t.Verdict)]")
                        if ($ti -lt $rawStreams.Count) { $tnode.Tag = [pscustomobject]@{ Kind='Raw'; Raw=$rawStreams[$ti] } }
                        $tnode.ForeColor = switch ($t.Verdict) { 'Poor' { $c.ColWarn } 'Unrated' { $c.ColInfo } default { $c.ColOk } }
                        [void]$mnode.Nodes.Add($tnode)
                    }
                    [void]$gnode.Nodes.Add($mnode)
                }
                [void]$snode.Nodes.Add($gnode)
            }
            [void]$sn.Nodes.Add($snode)
        }
        [void]$n.Nodes.Add($sn)
        [void]$c.Tree.Nodes.Add($n)
    }

    $c.Tree.EndUpdate()
    if ($c.Tree.Nodes.Count) { $c.Tree.Nodes[0].Expand(); $c.Tree.SelectedNode = $c.Tree.Nodes[0] }

    $c.Path.Text = "$Label   ($($script:JA.Expanded.Count) record(s))"
}

function Write-JALine {
    param($Box, [string]$TextValue, $Colour, [switch]$Bold)
    $Box.SelectionStart  = $Box.TextLength
    $Box.SelectionLength = 0
    if ($Colour) { $Box.SelectionColor = $Colour }
    if ($Bold)   { $Box.SelectionFont  = New-Object System.Drawing.Font($Box.Font, [System.Drawing.FontStyle]::Bold) }
    $Box.AppendText($TextValue + "`n")
    $Box.SelectionFont = $Box.Font
}

function Update-JASelection {
<#
.SYNOPSIS
    Refresh the three right-hand panes for the selected tree node.
#>
    [CmdletBinding()]
    param($Node)

    $c = $script:JA.Ctl
    if (-not $Node) { return }

    # Raw JSON for whatever is selected.
    #
    # Explicit null test, NOT truthiness: an empty collection or a scalar 0 is
    # real content and must render, not be treated as absent.
    #
    # A blank pane is also ambiguous - it reads as "retrieval failed" when the
    # node simply has no payload of its own. Say which it is.
    $tag = $Node.Tag
    if ($null -ne $tag -and $null -ne $tag.Raw) {
        try {
            $json = $tag.Raw | ConvertTo-Json -Depth 20 -ErrorAction Stop
            if ([string]::IsNullOrWhiteSpace($json)) { $json = '(node serialized to nothing)' }
            # Normalise line endings - a TextBox renders bare LF as one long line.
            $c.Raw.Text = ($json -replace "`r`n", "`n") -replace "`n", "`r`n"
        }
        catch {
            $c.Raw.Text = "Could not serialize this node to JSON.`r`n`r`n" +
                          "  $($_.Exception.Message)`r`n`r`n" +
                          "Properties present: " + (@($tag.Raw.PSObject.Properties.Name) -join ', ')
        }
    }
    elseif ($null -ne $tag) {
        $c.Raw.Text = '(this node has no JSON of its own - select a child)'
    }
    else {
        $c.Raw.Text = '(grouping node - select a call, session, segment, media or stream)'
    }

    # Verdict and flow follow the CALL the node belongs to, so they stay
    # meaningful while drilling into a stream.
    $root = $Node; while ($root.Parent) { $root = $root.Parent }
    if (-not ($root.Tag -and $root.Tag.Kind -eq 'Call')) { return }
    $x = $root.Tag.Exp
    if ($script:JA.Current -eq $x.Id) { return }
    $script:JA.Current = $x.Id

    # ----- Verdict -----------------------------------------------------------
    $c.Verdict.Clear()
    $vCol = if ($x.Verdict -eq 'Success') { $c.ColOk } elseif ($x.Verdict -eq 'Partial') { $c.ColWarn } else { $c.ColCrit }
    Write-JALine $c.Verdict "VERDICT: $($x.Verdict.ToUpper())" $vCol -Bold

    $dur = if ($null -ne $x.DurationSeconds) { "  ($($x.DurationSeconds) s)" } else { '' }
    Write-JALine $c.Verdict ("Type       : {0}   Modalities: {1}" -f $x.Type, (@($x.Modalities) -join ',')) $null
    Write-JALine $c.Verdict ("Start/End  : {0}  ->  {1}{2}" -f $x.StartDateTime, $x.EndDateTime, $dur) $null
    Write-JALine $c.Verdict ("Organizer  : {0}   Participants: {1}" -f $x.Organizer, $x.ParticipantCount) $null

    # Worst reading across every stream, so one bad leg is not hidden by averages.
    $rated = @($x.AllStreams | Where-Object Verdict -ne 'Unrated')
    if ($rated.Count) {
        $wj = ($rated | Where-Object { $null -ne $_.AvgJitterMs }    | Measure-Object AvgJitterMs      -Maximum).Maximum
        $wl = ($rated | Where-Object { $null -ne $_.AvgPacketLossRate } | Measure-Object AvgPacketLossRate -Maximum).Maximum
        $wr = ($rated | Where-Object { $null -ne $_.AvgRoundTripMs } | Measure-Object AvgRoundTripMs  -Maximum).Maximum
        $f = { param($v,$fmt) if ($null -eq $v) { '-' } else { $fmt -f $v } }
        Write-JALine $c.Verdict ("Worst media: jitter={0}  loss={1}  rtt={2}" -f (& $f $wj '{0:N1}ms'), (& $f $wl '{0:P0}'), (& $f $wr '{0:N0}ms')) $null
    }
    else {
        Write-JALine $c.Verdict 'Worst media: no rated streams - cannot be assessed (not the same as good).' $c.ColInfo
    }

    # Diagnostic findings, highest severity first.
    $findings = @()
    try { $findings = @(Get-CallDiagnosis -CallRecord $root.Tag.Raw -MinimumConfidence Medium) } catch { }
    $act = @($findings | Where-Object Severity -ne 'Info')
    if ($act.Count) {
        Write-JALine $c.Verdict '' $null
        foreach ($fd in ($act | Select-Object -First 6)) {
            $fc = if ($fd.Severity -eq 'Critical') { $c.ColCrit } else { $c.ColWarn }
            Write-JALine $c.Verdict ("{0,-9}: {1} - {2}" -f $fd.Severity, $fd.Title, $fd.Evidence) $fc
        }
    }
    elseif ($findings.Count) {
        Write-JALine $c.Verdict '' $null
        Write-JALine $c.Verdict 'Quality    : no warnings above threshold.' $c.ColOk
    }

    # ----- Call flow ---------------------------------------------------------
    $c.Flow.Clear()
    $si = 0
    foreach ($s in @($x.Sessions)) {
        $si++
        Write-JALine $c.Flow ("SESSION {0}  {1}  ==>  {2}" -f $si, $s.Caller.Label, $s.Callee.Label) $c.ColKey -Bold
        if (-not $s.Succeeded) {
            Write-JALine $c.Flow ("    FAILED [{0}] {1}" -f $s.FailureStage, $s.FailureReason) $c.ColCrit
        }
        $gi = 0
        foreach ($g in @($s.Segments)) {
            $gi++
            Write-JALine $c.Flow ("    segment {0} : {1}  ->  {2}" -f $gi, $g.Caller.Label, $g.Callee.Label) $null
            foreach ($m in @($g.Media)) {
                foreach ($t in @($m.Streams)) {
                    $cd = if ($m.Label -match 'video|screen') { $t.VideoCodec } else { $t.AudioCodec }
                    if (-not $cd -or $cd -eq 'unknown') { $cd = '-' }
                    # Explicit null tests: a jitter of exactly 0 is the healthiest
                    # possible reading and must not render as missing data.
                    $j = if ($null -ne $t.AvgJitterMs)       { '{0:N1}ms' -f $t.AvgJitterMs }       else { '-' }
                    $l = if ($null -ne $t.AvgPacketLossRate) { '{0:P0}'   -f $t.AvgPacketLossRate } else { '-' }
                    $r = if ($null -ne $t.AvgRoundTripMs)    { '{0:N0}ms' -f $t.AvgRoundTripMs }    else { '-' }
                    $lc = switch ($t.Verdict) { 'Poor' { $c.ColWarn } 'Unrated' { $c.ColInfo } default { $null } }
                    Write-JALine $c.Flow ("        media[{0}] {1,-6} codec={2,-8} jitter={3,-8} loss={4,-5} rtt={5}" -f
                        $m.Label, $t.Direction, $cd, $j, $l, $r) $lc
                }
            }
        }
    }
    $c.Flow.SelectionStart = 0; $c.Flow.ScrollToCaret()
}

function Show-JAFleet {
<#
.SYNOPSIS
    Fleet correlation results in a modal grid.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    try {
        $rows = @(Get-CallFleetAnalysis -Path $Path -Recurse)
        if (-not $rows.Count) {
            [System.Windows.Forms.MessageBox]::Show('No rated streams found in that folder.','Fleet','OK','Warning') | Out-Null
            return
        }

        $f = New-Object System.Windows.Forms.Form
        $f.Text = "Fleet correlation - $Path"
        $f.Size = New-Object System.Drawing.Size(940,600); $f.StartPosition = 'CenterParent'

        $lv = New-Object System.Windows.Forms.ListView
        $lv.Dock = 'Fill'; $lv.View = 'Details'; $lv.FullRowSelect = $true
        foreach ($col in @(@('Dimension',110),@('Value',200),@('Streams',70),@('Poor',60),@('Rate',70),@('Lift',70),@('Verdict',130))) {
            [void]$lv.Columns.Add($col[0], $col[1])
        }

        $note = New-Object System.Windows.Forms.Label
        $note.Dock = 'Bottom'; $note.Height = 34
        $note.Text = 'Elevated = this group''s poor rate is well above baseline. InsufficientData rows show no rate on purpose: a rate over a handful of streams is noise, not a signal.'
        $note.ForeColor = [System.Drawing.Color]::FromArgb(100,100,100)

        $order = @{ Elevated=0; Typical=1; Clean=2; InsufficientData=3 }
        foreach ($r in ($rows | Sort-Object @{E={$order[$_.Verdict]}}, Dimension, Value)) {
            $it = New-Object System.Windows.Forms.ListViewItem($r.Dimension)
            foreach ($v in @($r.Value,$r.Streams,$r.PoorStreams,$r.PoorRate,$r.Lift,$r.Verdict)) { [void]$it.SubItems.Add([string]$v) }
            $it.ForeColor = switch ($r.Verdict) {
                'Elevated'         { [System.Drawing.Color]::FromArgb(192,32,32) }
                'InsufficientData' { [System.Drawing.Color]::FromArgb(150,150,150) }
                'Clean'            { [System.Drawing.Color]::FromArgb(24,110,40) }
                default            { [System.Drawing.Color]::Black }
            }
            [void]$lv.Items.Add($it)
        }

        $f.Controls.Add($lv); $f.Controls.Add($note)
        [void]$f.ShowDialog()
        $f.Dispose()
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Fleet analysis failed:`n`n$($_.Exception.Message)",'Fleet','OK','Error') | Out-Null
    }
}


# ==============================================================================
#  POLICY MIGRATION TAB
#
#  Three steps, enforced in order: load a SOURCE bundle, verify against the
#  DESTINATION tenant, then migrate the checked rows.
#
#  The verify step exists because a policy name matching is not the same as a
#  policy matching. Identical / Different / Missing are three distinct outcomes
#  and only the operator can decide what Different should mean.
# ==============================================================================

function New-PolicyMigrationTabPage {
    [CmdletBinding()]
    param(
        [string]$Text = '  Policy Migration  ',
        $BackColor,
        $ColorBlue, $ColorPurple, $ColorGreen, $ColorGray, $ColorAmber, $ColorRed
    )

    # Fall back to sane values when hosted outside the provisioning app.
    if (-not $ColorBlue)   { $ColorBlue   = [System.Drawing.Color]::FromArgb(0,120,215) }
    if (-not $ColorPurple) { $ColorPurple = [System.Drawing.Color]::FromArgb(92,60,140) }
    if (-not $ColorGreen)  { $ColorGreen  = [System.Drawing.Color]::FromArgb(16,124,16) }
    if (-not $ColorGray)   { $ColorGray   = [System.Drawing.Color]::FromArgb(96,96,96) }
    if (-not $ColorAmber)  { $ColorAmber  = [System.Drawing.Color]::FromArgb(202,80,16) }
    if (-not $ColorRed)    { $ColorRed    = [System.Drawing.Color]::FromArgb(168,0,0) }

    # Published to script scope: all four are referenced from inside the
    # deferred scriptblocks below ($renderRows, $loadBundleObject, the Verify
    # Destination handler, $runMigrate), where the bare parameter has proven
    # unreliable - same root cause as $page/$state/the button and helper
    # variables fixed earlier in this function.
    $script:TVMigColorGreen = $ColorGreen
    $script:TVMigColorGray  = $ColorGray
    $script:TVMigColorAmber = $ColorAmber
    $script:TVMigColorRed   = $ColorRed

    $styler = Get-Command Style-Button -ErrorAction SilentlyContinue
    $style  = {
        param($Btn,$Back)
        if ($styler) { Style-Button $Btn $Back }
        else {
            $Btn.FlatStyle='Flat'; $Btn.BackColor=$Back
            $Btn.ForeColor=[System.Drawing.Color]::White; $Btn.FlatAppearance.BorderSize=0
            $Btn.Font=New-Object System.Drawing.Font('Segoe UI',9,[System.Drawing.FontStyle]::Bold)
        }
    }

    $page = New-Object System.Windows.Forms.TabPage
    $script:TVMigPage = $page  # published so every handler below reads a reliable copy
    $script:TVMigPage.Text = $Text
    if ($BackColor) { $script:TVMigPage.BackColor = $BackColor }

    $state = @{ Bundle = $null; Rows = @(); Verified = $false; DestTenant = $null; SourcePath = $null }
    $script:TVMigState = $state  # published so every handler below reads a reliable copy

    # ---------- Step 1 -------------------------------------------------------
    $lbl1 = New-Object System.Windows.Forms.Label
    $lbl1.Location = New-Object System.Drawing.Point(12,10); $lbl1.Size = New-Object System.Drawing.Size(420,20)
    $lbl1.Text = 'Step 1 - Load SOURCE backup, or pull from the connected tenant'
    $lbl1.Font = New-Object System.Drawing.Font('Segoe UI',9,[System.Drawing.FontStyle]::Bold)

    $btnPull = New-Object System.Windows.Forms.Button
    $script:TVMigBtnPull = $btnPull
    $script:TVMigBtnPull.Location = New-Object System.Drawing.Point(12,34); $script:TVMigBtnPull.Size = New-Object System.Drawing.Size(190,30)
    $script:TVMigBtnPull.Text = 'Pull from RBAC Session'; & $style $script:TVMigBtnPull $ColorBlue

    $btnLoad = New-Object System.Windows.Forms.Button
    $script:TVMigBtnLoad = $btnLoad
    $script:TVMigBtnLoad.Location = New-Object System.Drawing.Point(208,34); $script:TVMigBtnLoad.Size = New-Object System.Drawing.Size(110,30)
    $script:TVMigBtnLoad.Text = 'Load Backup...'; & $style $script:TVMigBtnLoad $ColorPurple

    $btnSave = New-Object System.Windows.Forms.Button
    $script:TVMigBtnSave = $btnSave
    $script:TVMigBtnSave.Location = New-Object System.Drawing.Point(324,34); $script:TVMigBtnSave.Size = New-Object System.Drawing.Size(110,30)
    $script:TVMigBtnSave.Text = 'Save As...'; & $style $script:TVMigBtnSave $script:TVMigColorGreen

    $lblSrc = New-Object System.Windows.Forms.Label
    $script:TVMigLblSrc = $lblSrc
    # Width capped at 260, not the original 560: a Label paints its FULL bounding
    # box as an opaque background rectangle regardless of how little text is in
    # it, and this control is added to Controls BEFORE $script:TVMigGrpGuard - in WinForms,
    # earlier-added controls sit at the FRONT of the z-order by default. At the
    # original width this control's box reached to x=1004, well past grpGuard's
    # left edge at x=722, so it painted directly over the guardrails textbox
    # regardless of how short its own text was. AutoEllipsis handles the longer
    # "Loaded from backup..." status text gracefully now that it has less room.
    $script:TVMigLblSrc.Location = New-Object System.Drawing.Point(444,40); $script:TVMigLblSrc.Size = New-Object System.Drawing.Size(260,20)
    $script:TVMigLblSrc.AutoEllipsis = $true
    $script:TVMigLblSrc.Text = 'No backup loaded.'; $script:TVMigLblSrc.ForeColor = $script:TVMigColorGray

    # ---------- filter + grid ------------------------------------------------
    $lblFilter = New-Object System.Windows.Forms.Label
    $script:TVMigLblFilter = $lblFilter
    $script:TVMigLblFilter.Location = New-Object System.Drawing.Point(12,70); $script:TVMigLblFilter.Size = New-Object System.Drawing.Size(330,18)
    $script:TVMigLblFilter.Text = 'Policies in loaded backup - check the ones to migrate.'

    $cboFilter = New-Object System.Windows.Forms.ComboBox
    $script:TVMigCboFilter = $cboFilter
    $script:TVMigCboFilter.DropDownStyle = 'DropDownList'
    $script:TVMigCboFilter.Location = New-Object System.Drawing.Point(350,66); $script:TVMigCboFilter.Size = New-Object System.Drawing.Size(190,22)

    $lv = New-Object System.Windows.Forms.ListView
    $script:TVMigLv = $lv
    $script:TVMigLv.Location = New-Object System.Drawing.Point(12,92); $script:TVMigLv.Size = New-Object System.Drawing.Size(700,320)
    $script:TVMigLv.View = 'Details'; $script:TVMigLv.CheckBoxes = $true; $script:TVMigLv.FullRowSelect = $true; $script:TVMigLv.HideSelection = $false
    [void]$script:TVMigLv.Columns.Add('Policy Type',   150)
    [void]$script:TVMigLv.Columns.Add('Policy Name',   170)
    [void]$script:TVMigLv.Columns.Add('Destination',   110)
    [void]$script:TVMigLv.Columns.Add('Action',         90)
    [void]$script:TVMigLv.Columns.Add('Summary',       160)

    $btnAll   = New-Object System.Windows.Forms.Button
    $script:TVMigBtnAll = $btnAll
    $script:TVMigBtnAll.Location = New-Object System.Drawing.Point(12,418); $script:TVMigBtnAll.Size = New-Object System.Drawing.Size(80,26)
    $script:TVMigBtnAll.Text = 'Select All'; & $style $script:TVMigBtnAll $script:TVMigColorGray

    $btnNone  = New-Object System.Windows.Forms.Button
    $script:TVMigBtnNone = $btnNone
    $script:TVMigBtnNone.Location = New-Object System.Drawing.Point(98,418); $script:TVMigBtnNone.Size = New-Object System.Drawing.Size(80,26)
    $script:TVMigBtnNone.Text = 'Clear'; & $style $script:TVMigBtnNone $script:TVMigColorGray

    $btnMissing = New-Object System.Windows.Forms.Button
    $script:TVMigBtnMissing = $btnMissing
    $script:TVMigBtnMissing.Location = New-Object System.Drawing.Point(184,418); $script:TVMigBtnMissing.Size = New-Object System.Drawing.Size(110,26)
    $script:TVMigBtnMissing.Text = 'Select Missing'; & $style $script:TVMigBtnMissing $script:TVMigColorAmber

    $lblCount = New-Object System.Windows.Forms.Label
    $script:TVMigLblCount = $lblCount
    $script:TVMigLblCount.Location = New-Object System.Drawing.Point(302,423); $script:TVMigLblCount.Size = New-Object System.Drawing.Size(410,20)
    $script:TVMigLblCount.Text = 'No backup loaded.'; $script:TVMigLblCount.ForeColor = $script:TVMigColorGray

    # ---------- Step 2 -------------------------------------------------------
    $lbl2 = New-Object System.Windows.Forms.Label
    $lbl2.Location = New-Object System.Drawing.Point(12,452); $lbl2.Size = New-Object System.Drawing.Size(320,20)
    $lbl2.Text = 'Step 2 - Verify DESTINATION tenant'
    $lbl2.Font = New-Object System.Drawing.Font('Segoe UI',9,[System.Drawing.FontStyle]::Bold)

    $btnVerify = New-Object System.Windows.Forms.Button
    $script:TVMigBtnVerify = $btnVerify
    $script:TVMigBtnVerify.Location = New-Object System.Drawing.Point(12,474); $script:TVMigBtnVerify.Size = New-Object System.Drawing.Size(150,28)
    $script:TVMigBtnVerify.Text = 'Verify Destination'; & $style $script:TVMigBtnVerify $ColorBlue

    $lblVerify = New-Object System.Windows.Forms.Label
    $script:TVMigLblVerify = $lblVerify
    $script:TVMigLblVerify.Location = New-Object System.Drawing.Point(170,480); $script:TVMigLblVerify.Size = New-Object System.Drawing.Size(540,40)
    $script:TVMigLblVerify.Text = 'Destination not verified.'; $script:TVMigLblVerify.ForeColor = $script:TVMigColorGray

    # ---------- Step 3 -------------------------------------------------------
    $btnDry = New-Object System.Windows.Forms.Button
    $script:TVMigBtnDry = $btnDry
    $script:TVMigBtnDry.Location = New-Object System.Drawing.Point(12,530); $script:TVMigBtnDry.Size = New-Object System.Drawing.Size(160,30)
    $script:TVMigBtnDry.Text = 'Dry Run (WhatIf)'; & $style $script:TVMigBtnDry $script:TVMigColorAmber

    $btnMigrate = New-Object System.Windows.Forms.Button
    $script:TVMigBtnMigrate = $btnMigrate
    $script:TVMigBtnMigrate.Location = New-Object System.Drawing.Point(178,530); $script:TVMigBtnMigrate.Size = New-Object System.Drawing.Size(260,30)
    $script:TVMigBtnMigrate.Text = 'Step 3 - Migrate Checked Policies'; & $style $script:TVMigBtnMigrate $script:TVMigColorGreen
    $script:TVMigBtnMigrate.Enabled = $false

    # ---------- right pane ---------------------------------------------------
    $grpGuard = New-Object System.Windows.Forms.GroupBox
    $script:TVMigGrpGuard = $grpGuard
    # Height capped at 184, not the original +10 idea: $script:TVMigGrpDiff sits right below
    # this at y=196, and growing past 184 would overlap it again.
    $script:TVMigGrpGuard.Location = New-Object System.Drawing.Point(722,10); $script:TVMigGrpGuard.Size = New-Object System.Drawing.Size(430,184)
    $script:TVMigGrpGuard.Text = 'Guardrails / Current State'

    $txtGuard = New-Object System.Windows.Forms.TextBox
    $script:TVMigTxtGuard = $txtGuard
    $script:TVMigTxtGuard.Location = New-Object System.Drawing.Point(8,18); $script:TVMigTxtGuard.Size = New-Object System.Drawing.Size(414,156)
    $script:TVMigTxtGuard.Multiline = $true; $script:TVMigTxtGuard.ReadOnly = $true; $script:TVMigTxtGuard.ScrollBars = 'Vertical'; $script:TVMigTxtGuard.WordWrap = $true
    $script:TVMigTxtGuard.Font = New-Object System.Drawing.Font('Consolas',9)
    # WinForms TextBox/RichTextBox controls expect CRLF for hard line breaks in
    # their DISPLAYED text - a bare LF (what this here-string actually contains
    # on disk) is inconsistently treated by the underlying Win32 edit control,
    # producing exactly the merged-line, ragged-wrap rendering this caused.
    # -join with an explicit "`r`n" guarantees correct breaks regardless of the
    # source file's own line-ending convention.
    $script:TVMigTxtGuard.Text = @(
        'Load or pull a SOURCE bundle, check what you need,'
        'then Verify against the DESTINATION tenant.'
        ''
        'Verify marks each row Missing / Different / Identical'
        'and flags policies that reference tenant-local objects'
        '(SBC FQDNs, resource accounts, PSTN usages) for review -'
        'those do not travel and will create a policy that looks'
        'fine but routes nowhere.'
        ''
        'Migrate is disabled until Verify has run.'
    ) -join "`r`n" 
    $script:TVMigGrpGuard.Controls.Add($script:TVMigTxtGuard)

    $grpDiff = New-Object System.Windows.Forms.GroupBox
    $script:TVMigGrpDiff = $grpDiff
    $script:TVMigGrpDiff.Location = New-Object System.Drawing.Point(722,196); $script:TVMigGrpDiff.Size = New-Object System.Drawing.Size(430,404)
    $script:TVMigGrpDiff.Text = 'Selected Policy Settings / Diff'

    $txtDiff = New-Object System.Windows.Forms.TextBox
    $script:TVMigTxtDiff = $txtDiff
    $script:TVMigTxtDiff.Location = New-Object System.Drawing.Point(8,18); $script:TVMigTxtDiff.Size = New-Object System.Drawing.Size(414,376)
    $script:TVMigTxtDiff.Multiline = $true; $script:TVMigTxtDiff.ReadOnly = $true; $script:TVMigTxtDiff.ScrollBars = 'Both'
    $script:TVMigTxtDiff.WordWrap = $false; $script:TVMigTxtDiff.Font = New-Object System.Drawing.Font('Consolas',8.5)
    $script:TVMigGrpDiff.Controls.Add($script:TVMigTxtDiff)

    $script:TVMigPage.Controls.AddRange(@(
        $lbl1,$script:TVMigBtnPull,$script:TVMigBtnLoad,$script:TVMigBtnSave,$script:TVMigLblSrc,
        $script:TVMigLblFilter,$script:TVMigCboFilter,$script:TVMigLv,
        $script:TVMigBtnAll,$script:TVMigBtnNone,$script:TVMigBtnMissing,$script:TVMigLblCount,
        $lbl2,$script:TVMigBtnVerify,$script:TVMigLblVerify,$script:TVMigBtnDry,$script:TVMigBtnMigrate,
        $script:TVMigGrpGuard,$script:TVMigGrpDiff))

    # ==========================================================================
    #  BEHAVIOUR
    # ==========================================================================

    $renderRows = {
        $script:TVMigLv.BeginUpdate(); $script:TVMigLv.Items.Clear()
        $filter = [string]$script:TVMigCboFilter.SelectedItem

        foreach ($r in $script:TVMigState.Rows) {
            if ($filter -and $filter -ne '(All types)' -and $r.Type -ne $filter) { continue }

            $it = New-Object System.Windows.Forms.ListViewItem($r.Type)
            [void]$it.SubItems.Add($r.Name)
            [void]$it.SubItems.Add($r.Destination)
            [void]$it.SubItems.Add($r.Action)
            [void]$it.SubItems.Add($r.Summary)
            $it.Checked = $r.Checked
            $it.ForeColor = switch ($r.Destination) {
                'Missing'   { $script:TVMigColorAmber }
                'Different' { $script:TVMigColorRed }
                'Identical' { $script:TVMigColorGreen }
                default     { $script:TVMigColorGray }
            }
            $it.Tag = $r
            [void]$script:TVMigLv.Items.Add($it)
        }
        $script:TVMigLv.EndUpdate()

        $checked = @($script:TVMigState.Rows | Where-Object Checked).Count
        $script:TVMigLblCount.Text = "$($script:TVMigState.Rows.Count) policy object(s) in bundle, $checked checked."
    }
    $script:TVMigRenderRows = $renderRows

    $loadBundleObject = {
        param($Bundle, $SourceLabel)

        $rows = New-Object System.Collections.ArrayList
        foreach ($key in $Bundle.Policies.PSObject.Properties.Name) {
            $sec = $Bundle.Policies.$key
            foreach ($item in @($sec.Items)) {
                [void]$rows.Add([pscustomobject]@{
                    Type        = $key
                    Name        = $item.Name
                    Destination = '(not verified)'
                    Action      = ''
                    Summary     = "$(@($item.Settings.PSObject.Properties).Count) setting(s)"
                    Checked     = $false
                    Item        = $item
                    IsGlobal    = $item.IsGlobal
                })
            }
        }

        $script:TVMigState.Bundle   = $Bundle
        $script:TVMigState.Rows     = @($rows)
        $script:TVMigState.Verified = $false
        $script:TVMigState.DestTenant = $null
        $script:TVMigBtnMigrate.Enabled = $false

        $script:TVMigCboFilter.Items.Clear()
        [void]$script:TVMigCboFilter.Items.Add('(All types)')
        foreach ($t in ($script:TVMigState.Rows.Type | Select-Object -Unique | Sort-Object)) { [void]$script:TVMigCboFilter.Items.Add($t) }
        $script:TVMigCboFilter.SelectedIndex = 0

        $script:TVMigLblSrc.ForeColor = $script:TVMigColorGray
        $script:TVMigLblSrc.Text = "$SourceLabel  |  source tenant $($Bundle.TenantId)  |  exported $($Bundle.ExportedUtc)"
        $script:TVMigLblVerify.Text = 'Destination not verified.'; $script:TVMigLblVerify.ForeColor = $script:TVMigColorGray

        & $script:TVMigRenderRows
    }
    $script:TVMigLoadBundleObject = $loadBundleObject

    $script:TVMigBtnPull.Add_Click({
        try {
            if ($script:TVMigPage) { try { $script:TVMigPage.Cursor = 'WaitCursor' } catch {} }
            $tmp = Join-Path $env:TEMP "TVPull-$(Get-Date -Format 'yyyyMMddHHmmss')"
            $exp = Export-TeamsVoiceConfiguration -Path $tmp -Label 'source' -NoConnect -SkipCsv
            $b = Get-Content $exp.BundlePath -Raw -Encoding UTF8 | ConvertFrom-Json
            $script:TVMigState.SourcePath = $exp.BundlePath
            & $script:TVMigLoadBundleObject $b 'Pulled from current session'
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Pull failed:`n`n$($_.Exception.Message)`n`nConnect RBAC first - policy definitions are only readable through the Teams module.",
                'Policy Migration','OK','Error') | Out-Null
        }
        finally { if ($script:TVMigPage) { try { $script:TVMigPage.Cursor = 'Default' } catch {} } }
    })

    $script:TVMigBtnLoad.Add_Click({
        $dlg = New-Object System.Windows.Forms.OpenFileDialog
        $dlg.Filter = 'Voice configuration bundle (*.json)|*.json'
        if ($dlg.ShowDialog() -ne 'OK') { return }
        try {
            $txt = Get-Content $dlg.FileName -Raw -Encoding UTF8
            if ($txt -and [int][char]$txt[0] -eq 0xFEFF) { $txt = $txt.Substring(1) }
            $b = $txt | ConvertFrom-Json
            if (-not $b.PSObject.Properties['Policies']) { throw 'Not a voice configuration bundle (no Policies section).' }
            $script:TVMigState.SourcePath = $dlg.FileName
            & $script:TVMigLoadBundleObject $b (Split-Path $dlg.FileName -Leaf)
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Load failed:`n`n$($_.Exception.Message)",'Policy Migration','OK','Error') | Out-Null
        }
    })

    $script:TVMigBtnSave.Add_Click({
        if (-not $script:TVMigState.Bundle) { return }
        $dlg = New-Object System.Windows.Forms.SaveFileDialog
        $dlg.Filter = 'Voice configuration bundle (*.json)|*.json'
        $dlg.FileName = "VoiceConfiguration-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        if ($dlg.ShowDialog() -ne 'OK') { return }
        $script:TVMigState.Bundle | ConvertTo-Json -Depth 20 | Set-Content -Path $dlg.FileName -Encoding UTF8
        [System.Windows.Forms.MessageBox]::Show("Saved to $($dlg.FileName)",'Policy Migration','OK','Information') | Out-Null
    })

    $script:TVMigBtnVerify.Add_Click({
        if (-not $script:TVMigState.Bundle) {
            [System.Windows.Forms.MessageBox]::Show('Load a source bundle first.','Policy Migration','OK','Information') | Out-Null
            return
        }
        try {
            if ($script:TVMigPage) { try { $script:TVMigPage.Cursor = 'WaitCursor' } catch {} }

            # The check that matters: are we actually pointed somewhere else?
            $dest = Get-ConnectedTenantId
            if (-not $dest) { throw 'Cannot read the connected tenant. Connect RBAC to the DESTINATION tenant first.' }
            $script:TVMigState.DestTenant = $dest

            if ($dest -eq $script:TVMigState.Bundle.TenantId) {
                $script:TVMigLblVerify.ForeColor = $script:TVMigColorAmber
                $script:TVMigLblVerify.Text = "Connected tenant IS the bundle's source ($dest) - this is a restore-in-place, not a migration."
            }
            else {
                $script:TVMigLblVerify.ForeColor = $script:TVMigColorGreen
                $script:TVMigLblVerify.Text = "Destination $dest  (source $($script:TVMigState.Bundle.TenantId))"
            }

            $manifest = Get-TeamsVoicePolicyKey
            $tierMap  = @{}
            foreach ($m in $manifest) { $tierMap[$m.Key] = $m }

            foreach ($r in $script:TVMigState.Rows) {
                $mf = $tierMap[$r.Type]
                if (-not $mf -or -not $mf.CanExport) { $r.Destination='(unavailable)'; $r.Action='Skip'; continue }

                $getCmd = ($script:PolicyManifest | Where-Object Key -eq $r.Type).Get
                $existing = @()
                try { $existing = @(& $getCmd -ErrorAction Stop) } catch { }

                $match = $existing | Where-Object {
                    (Get-PolicyDisplayName -Policy $_ -IdProperty (($script:PolicyManifest | Where-Object Key -eq $r.Type).IdProperty)) -eq $r.Name
                } | Select-Object -First 1

                if (-not $match) {
                    $r.Destination='Missing'; $r.Action='Create'
                    $r.Summary="Not present in destination"
                }
                else {
                    $diffs = @()
                    foreach ($p in $r.Item.Settings.PSObject.Properties) {
                        if (-not $match.PSObject.Properties[$p.Name]) { continue }
                        $a = Get-ComparableValue $p.Value
                        $b = Get-ComparableValue $match.$($p.Name)
                        if ($a -ne $b) { $diffs += $p.Name }
                    }
                    if ($diffs.Count) {
                        $r.Destination='Different'; $r.Action='Update'
                        $r.Summary="$($diffs.Count) setting(s) differ: $(($diffs | Select-Object -First 3) -join ',')"
                    }
                    else {
                        $r.Destination='Identical'; $r.Action='None'
                        $r.Summary='Matches destination'
                    }
                    $r | Add-Member -NotePropertyName Diffs -NotePropertyValue $diffs -Force
                    $r | Add-Member -NotePropertyName DestObject -NotePropertyValue $match -Force
                }

                # Tenant-local references cannot travel. VoiceRoutingPolicy resolves to
                # PSTN usages tied to this tenant's SBC topology; CallHoldPolicy can carry
                # a custom MoH AudioFileId that only exists in the source tenant's media
                # store. Both were missing from this check even though the manifest
                # supports migrating them - added alongside the original four.
                if ($r.Type -in 'PstnGateway','SharedCallingRoutingPolicy','EmergencyCallRoutingPolicy','VoiceRoute','VoiceRoutingPolicy','CallHoldPolicy') {
                    $r.Summary = "REVIEW - references tenant-local objects. $($r.Summary)"
                }
            }

            $script:TVMigState.Verified = $true
            $script:TVMigBtnMigrate.Enabled = $true
            & $script:TVMigRenderRows
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Verify failed:`n`n$($_.Exception.Message)",'Policy Migration','OK','Error') | Out-Null
        }
        finally { if ($script:TVMigPage) { try { $script:TVMigPage.Cursor = 'Default' } catch {} } }
    })

    $runMigrate = {
        param([bool]$WhatIf)

        if (-not $script:TVMigState.Verified) {
            [System.Windows.Forms.MessageBox]::Show('Run Verify Destination first.','Policy Migration','OK','Information') | Out-Null
            return
        }
        $checked = @($script:TVMigState.Rows | Where-Object Checked)
        if (-not $checked.Count) {
            [System.Windows.Forms.MessageBox]::Show('Nothing checked.','Policy Migration','OK','Information') | Out-Null
            return
        }

        if (-not $WhatIf) {
            $answer = [System.Windows.Forms.MessageBox]::Show(
                "Write $($checked.Count) policy object(s) into tenant $($script:TVMigState.DestTenant)?`n`nThis modifies the destination tenant.",
                'Confirm migration','YesNo','Warning')
            if ($answer -ne 'Yes') { return }
        }

        try {
            if ($script:TVMigPage) { try { $script:TVMigPage.Cursor = 'WaitCursor' } catch {} }

            # Rebuild a bundle containing only the checked rows, then let the
            # engine order it by dependency tier - checkbox order is not safe.
            $sub = [ordered]@{
                SchemaVersion = $script:TVMigState.Bundle.SchemaVersion
                ExportedUtc   = $script:TVMigState.Bundle.ExportedUtc
                TenantId      = $script:TVMigState.Bundle.TenantId
                Label         = 'selection'
                Policies      = [ordered]@{}
            }
            foreach ($g in ($checked | Group-Object Type)) {
                $sub.Policies[$g.Name] = [ordered]@{
                    DisplayName = $g.Name
                    Count       = $g.Count
                    Items       = @($g.Group.Item)
                }
            }

            $tmp = Join-Path $env:TEMP "TVMigrate-$(Get-Date -Format 'yyyyMMddHHmmss').json"
            ($sub | ConvertTo-Json -Depth 20) | Set-Content -Path $tmp -Encoding UTF8

            $migArgs = @{
                BundlePath       = $tmp
                ExpectedTenantId = $script:TVMigState.DestTenant
                ContinueOnError  = $true
                NoConnect        = $true
            }
            if ($WhatIf) { $migArgs['WhatIf'] = $true }

            $results = Import-TeamsVoiceConfiguration @migArgs

            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine($(if ($WhatIf) { 'DRY RUN - nothing was written.' } else { 'MIGRATION RESULTS' }))
            [void]$sb.AppendLine(('=' * 52))
            foreach ($r in $results) {
                [void]$sb.AppendLine(("{0,-8} {1,-26} {2}" -f $r.Action, $r.Name, $r.Status))
                if ($r.Dropped) { [void]$sb.AppendLine("         dropped: $($r.Dropped)") }
            }
            $script:TVMigTxtDiff.Text = $sb.ToString()

            $fail = @($results | Where-Object { $_.Status -like 'Failed*' }).Count
            $script:TVMigLblVerify.ForeColor = if ($fail) { $script:TVMigColorRed } else { $script:TVMigColorGreen }
            $script:TVMigLblVerify.Text = "$(if ($WhatIf) { 'Dry run' } else { 'Migrated' }): $($results.Count) action(s), $fail failed."

            Remove-Item $tmp -ErrorAction SilentlyContinue
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Migration failed:`n`n$($_.Exception.Message)",'Policy Migration','OK','Error') | Out-Null
        }
        finally { if ($script:TVMigPage) { try { $script:TVMigPage.Cursor = 'Default' } catch {} } }
    }
    $script:TVMigRunMigrate = $runMigrate

    $script:TVMigBtnDry.Add_Click({     & $script:TVMigRunMigrate $true })
    $script:TVMigBtnMigrate.Add_Click({ & $script:TVMigRunMigrate $false })

    $script:TVMigBtnAll.Add_Click({   foreach ($r in $script:TVMigState.Rows) { $r.Checked = $true }; & $script:TVMigRenderRows })
    $script:TVMigBtnNone.Add_Click({  foreach ($r in $script:TVMigState.Rows) { $r.Checked = $false }; & $script:TVMigRenderRows })
    $script:TVMigBtnMissing.Add_Click({
        foreach ($r in $script:TVMigState.Rows) { $r.Checked = ($r.Destination -eq 'Missing') }
        & $script:TVMigRenderRows
    })

    $script:TVMigCboFilter.Add_SelectedIndexChanged($script:TVMigRenderRows)

    $script:TVMigLv.Add_ItemChecked({
        param($sender,$e)
        if ($e.Item.Tag) { $e.Item.Tag.Checked = $e.Item.Checked }
        $c = @($script:TVMigState.Rows | Where-Object Checked).Count
        $script:TVMigLblCount.Text = "$($script:TVMigState.Rows.Count) policy object(s) in bundle, $c checked."
    })

    $script:TVMigLv.Add_SelectedIndexChanged({
        if (-not $script:TVMigLv.SelectedItems.Count) { return }
        $r = $script:TVMigLv.SelectedItems[0].Tag
        if (-not $r) { return }

        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("$($r.Type) : $($r.Name)")
        [void]$sb.AppendLine("Destination: $($r.Destination)    Action: $($r.Action)")
        [void]$sb.AppendLine(('-' * 52))

        $diffs = if ($r.PSObject.Properties['Diffs']) { @($r.Diffs) } else { @() }
        $dest  = if ($r.PSObject.Properties['DestObject']) { $r.DestObject } else { $null }

        foreach ($p in $r.Item.Settings.PSObject.Properties) {
            $mark = if ($p.Name -in $diffs) { '>>' } else { '  ' }
            $v = if ($null -eq $p.Value) { '(null)' } else { ($p.Value | ConvertTo-Json -Depth 6 -Compress) }
            if ($v.Length -gt 90) { $v = $v.Substring(0,87) + '...' }
            [void]$sb.AppendLine(("{0} {1,-30} {2}" -f $mark, $p.Name, $v))

            if ($dest -and $p.Name -in $diffs -and $dest.PSObject.Properties[$p.Name]) {
                $dv = if ($null -eq $dest.$($p.Name)) { '(null)' } else { ($dest.$($p.Name) | ConvertTo-Json -Depth 6 -Compress) }
                if ($dv.Length -gt 90) { $dv = $dv.Substring(0,87) + '...' }
                [void]$sb.AppendLine(("{0} {1,-30} {2}" -f '  ', '  -> destination has', $dv))
            }
        }
        $script:TVMigTxtDiff.Text = $sb.ToString()
    })

    $script:TVMigPage
}


################################################################################
#  END TOOLKIT LIBRARY
################################################################################

################################################################################
#
#  PART 3  SHARED SERVICES
#
#  Everything below is used by more than one tab. It is defined here, before the
#  UI is constructed, for the same reason the toolkit library is: the tab
#  builders run during form construction, not at click time.
#
#  Nothing in this region touches module state. Cmdlet availability is resolved
#  with Get-Command only - see Test-CmdletPresent.
#
################################################################################

# ==============================================================================
# REGION S1 - PATHS AND THE OUTPUT TREE
# ==============================================================================

function Get-ToolkitRoot {
<#
.SYNOPSIS
    Script folder, resolved once. Falls back to the working directory when the
    file is run in a way that leaves $PSScriptRoot empty (ISE, paste-into-host).
#>
    if (-not [string]::IsNullOrWhiteSpace($script:ToolkitRoot)) { return $script:ToolkitRoot }
    $r = $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($r)) { $r = (Get-Location).Path }
    $script:ToolkitRoot = $r
    return $r
}

function Get-AppFolder {
<#
.SYNOPSIS
    Resolve a support-file folder (Catalogs, Docs, Scripts) beside the script, creating it lazily.
    The app script and its config files (tenant list, settings) stay in the project root.
#>
    param([Parameter(Mandatory)][ValidateSet('Catalogs','Docs','Scripts')][string]$Name)
    $dir = Join-Path (Get-ToolkitRoot) $Name
    [void](Ensure-Dir $dir)
    return $dir
}

function Move-LegacyRootFiles {
<#
.SYNOPSIS
    One-time tidy-up: move files an older build left in the project root into folders.
#>
    $r = Get-ToolkitRoot
    $out = Join-Path $r 'TeamsVoice_Output'
    $map = @(
        @{ Filter='TeamsVoice_LocationCatalog_*.csv'; Dest=(Get-AppFolder Catalogs) }
        @{ Filter='TeamsVoice_PolicyCatalog_*.csv';   Dest=(Get-AppFolder Catalogs) }
        @{ Filter='TeamsVoice_CDRReport_*.csv';       Dest=(Join-Path $out 'CDR\Reports') }
        @{ Filter='TeamsVoice_CDRPullLog_*.csv';      Dest=(Join-Path $out 'CDR\Logs') }
        @{ Filter='TeamsVoice_ChangeReport_*.csv';    Dest=(Join-Path $out 'Reports\Changes') }
        @{ Filter='*_Instructions.md';                Dest=(Get-AppFolder Docs) }
        @{ Filter='Trace-*.ps1';                      Dest=(Get-AppFolder Scripts) }
        @{ Filter='*.etl';                            Dest=(Join-Path $out 'Diagnostics') }
        @{ Filter='t.txt';                            Dest=(Join-Path $out 'Diagnostics') }
    )
    foreach ($m in $map) {
        foreach ($f in @(Get-ChildItem -LiteralPath $r -Filter $m.Filter -File -ErrorAction SilentlyContinue)) {
            try {
                [void](Ensure-Dir $m.Dest)
                $target = Join-Path $m.Dest $f.Name
                if (-not (Test-Path -LiteralPath $target)) { Move-Item -LiteralPath $f.FullName -Destination $target -ErrorAction Stop }
            } catch { }
        }
    }
    $rawOld = Join-Path $r 'TeamsVoice_CDRRaw'
    $rawNew = Join-Path $out 'CDR\RawJSON'
    if ((Test-Path -LiteralPath $rawOld) -and -not (Test-Path -LiteralPath $rawNew)) {
        try { [void](Ensure-Dir (Split-Path -Parent $rawNew)); Move-Item -LiteralPath $rawOld -Destination $rawNew -ErrorAction Stop } catch { }
    }
}

function Ensure-Dir {
    param([Parameter(Mandatory)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if (-not (Test-Path -LiteralPath $Path)) {
        [void](New-Item -ItemType Directory -Path $Path -Force -ErrorAction SilentlyContinue)
    }
    return $Path
}

function Get-EnvKey {
<#
.SYNOPSIS
    The tenant Key column, or the literal 'Tenant' when nothing is selected.
.DESCRIPTION
    Every generated filename is namespaced with this. The fallback is deliberate:
    a file written with no tenant selected must still be openable later, and a
    blank segment would collapse two tenants' output into the same name.
#>
    $k = $null
    try {
        if ($script:CurrentEnv -and $script:Environments -and $script:Environments[$script:CurrentEnv]) {
            $k = "$($script:Environments[$script:CurrentEnv].Key)"
        }
    } catch {}
    if ([string]::IsNullOrWhiteSpace($k)) { return 'Tenant' }
    return ($k -replace '[^A-Za-z0-9_\-]','')
}

function Get-Stamp { return (Get-Date).ToString('yyyyMMdd_HHmmss') }

function Get-OutputRoot { return (Join-Path (Get-ToolkitRoot) 'TeamsVoice_Output') }

function Get-OutputPath {
<#
.SYNOPSIS
    Resolve a folder in the output tree, creating it lazily.
.PARAMETER Area
    PolicyBackups | PolicyMigration | Changes | CdrReports | CdrLogs |
    CdrRawJson | CdrCheckpoints | Diagnostics
.PARAMETER File
    Optional leaf filename to join onto the resolved folder.
.NOTES
    PolicyBackups and CdrRawJson are per-tenant subfolders; the rest are flat.
    Layout is fixed - see section 6 of the technical reference.
#>
    param(
        [Parameter(Mandatory)]
        [ValidateSet('PolicyBackups','PolicyMigration','Changes','CdrReports','CdrLogs','CdrRawJson','CdrCheckpoints','Diagnostics')]
        [string]$Area,
        [string]$File,
        [string]$Stamp
    )
    $key  = Get-EnvKey
    $root = Get-OutputRoot
    if ([string]::IsNullOrWhiteSpace($Stamp)) { $Stamp = Get-Stamp }

    switch ($Area) {
        'PolicyBackups'   { $dir = Join-Path (Join-Path $root 'PolicyBackups') $key }
        'PolicyMigration' { $dir = Join-Path (Join-Path $root 'PolicyMigration') 'Results' }
        'Changes'         { $dir = Join-Path (Join-Path $root 'Reports') 'Changes' }
        'CdrReports'      { $dir = Join-Path (Join-Path $root 'CDR') 'Reports' }
        'CdrLogs'         { $dir = Join-Path (Join-Path $root 'CDR') 'Logs' }
        'CdrRawJson'      { $dir = Join-Path (Join-Path (Join-Path $root 'CDR') 'RawJSON') ("{0}_{1}" -f $key,$Stamp) }
        'CdrCheckpoints'  { $dir = Join-Path (Join-Path $root 'CDR') 'Checkpoints' }
        'Diagnostics'     { $dir = Join-Path $root 'Diagnostics' }
    }
    [void](Ensure-Dir $dir)
    if ([string]::IsNullOrWhiteSpace($File)) { return $dir }
    return (Join-Path $dir $File)
}

function Open-OutputFolder {
<#
.SYNOPSIS
    Show a folder - or a folder with one file preselected - in Explorer.
#>
    param([string]$Path,[string]$Label,[switch]$SelectFile)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    try {
        if ($SelectFile -and (Test-Path -LiteralPath $Path -PathType Leaf)) {
            Start-Process explorer.exe -ArgumentList ('/select,"{0}"' -f $Path)
        } else {
            $dir = $Path
            if (Test-Path -LiteralPath $Path -PathType Leaf) { $dir = Split-Path -Parent $Path }
            [void](Ensure-Dir $dir)
            Start-Process explorer.exe -ArgumentList ('"{0}"' -f $dir)
        }
    } catch {
        if (Get-Command Add-Status -ErrorAction SilentlyContinue) {
            Add-Status "Could not open $Label folder: $($_.Exception.Message)" ([System.Drawing.Color]::FromArgb(202,80,16))
        }
    }
}

# ==============================================================================
# REGION S2 - CMDLET RESOLUTION AND PARAMETER INTERSECTION
# ==============================================================================

function Test-CmdletPresent {
<#
.SYNOPSIS
    Is this command actually callable right now?
.DESCRIPTION
    Get-Command only, deliberately. Get-Module misses auto-loadable and
    side-loaded modules, and Get-Module -ListAvailable can surface a stale
    install that is not what would answer the call. Get-Command resolves exactly
    as PowerShell would at the prompt.

    The tool never imports or installs MicrosoftTeams. Module state belongs to
    the caller.
#>
    param([Parameter(Mandatory)][string]$Name)
    try { return [bool](Get-Command -Name $Name -CommandType Function,Cmdlet -ErrorAction SilentlyContinue) }
    catch { return $false }
}

function Select-CmdletParams {
<#
.SYNOPSIS
    Intersect a field hashtable with a cmdlet's real parameter set before splatting.
.DESCRIPTION
    Module versions differ in which parameters exist. Splatting a hashtable built
    from UI fields against an older module throws a parameter-binding error that
    names the parameter but not the cause. Intersecting first turns that into a
    silently dropped field, which is the better failure: the write still lands.

    Blank values are dropped too - passing an empty string is not the same as
    omitting the parameter, and several Cs cmdlets treat it as "clear this".
.OUTPUTS
    Hashtable safe to splat. Dropped keys are returned via -DroppedVar.
#>
    param(
        [Parameter(Mandatory)][string]$Cmdlet,
        [Parameter(Mandatory)][hashtable]$Params,
        [switch]$KeepBlank,
        [string]$DroppedVar
    )
    $out     = @{}
    $dropped = New-Object System.Collections.Generic.List[string]
    $cmd = $null
    try { $cmd = Get-Command -Name $Cmdlet -ErrorAction SilentlyContinue } catch {}
    $known = $null
    if ($cmd -and $cmd.Parameters) { $known = $cmd.Parameters.Keys }

    foreach ($k in @($Params.Keys)) {
        $v = $Params[$k]
        if (-not $KeepBlank) {
            if ($null -eq $v) { continue }
            if (($v -is [string]) -and [string]::IsNullOrWhiteSpace($v)) { continue }
        }
        if ($known -and ($known -notcontains $k)) { $dropped.Add($k) | Out-Null; continue }
        $out[$k] = $v
    }
    if (-not [string]::IsNullOrWhiteSpace($DroppedVar)) {
        Set-Variable -Name $DroppedVar -Value @($dropped) -Scope 1
    }
    return $out
}

function Get-ComparableValue {
<#
.SYNOPSIS
    Normalize a policy property value for source-vs-destination comparison.
.DESCRIPTION
    ConvertTo-Json on a live .NET enum value (e.g. ExternalLocationLookupMode)
    emits its underlying numeric backing value, not its friendly name - while
    the SAME setting read back out of a JSON-round-tripped backup bundle is
    already a plain string ("Enabled"). Comparing those two representations
    with ConvertTo-Json on both sides produces a false "Different" for a
    setting that has not actually changed. .ToString() does not have this
    asymmetry: it returns the enum's name on a live object and is a no-op on
    a string that already came from JSON, so both sides normalize the same
    way. Arrays and complex objects still need a structural JSON comparison -
    only scalars take the .ToString() path.
#>
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string] -or $Value -is [bool] -or $Value -is [System.Enum] -or
        $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or
        $Value -is [decimal] -or $Value -is [datetime]) {
        return $Value.ToString()
    }
    return ($Value | ConvertTo-Json -Depth 8 -Compress)
}

function Get-PropTolerant {
<#
.SYNOPSIS
    Read the first property that exists, trying several spellings.
.DESCRIPTION
    Get-* property casing is inconsistent across MicrosoftTeams module versions
    (BSSID vs Bssid, ChassisID vs ChassisId). Guessing one spelling produces a
    blank column that looks like missing data rather than a naming mismatch.
#>
    param($Object,[string[]]$Names,$Default = '')
    if ($null -eq $Object) { return $Default }
    foreach ($n in $Names) {
        try {
            $p = $Object.PSObject.Properties[$n]
            if ($p -and $null -ne $p.Value -and "$($p.Value)" -ne '') { return $p.Value }
        } catch {}
    }
    return $Default
}

# ==============================================================================
# REGION S3 - ERROR CLASSIFICATION AND RETRY
# ==============================================================================

# Transient: worth retrying. Anything that is a throttle, a gateway hiccup, or a
# dropped connection.
$script:RxTransient = '429|503|504|throttl|timed out|timeout|temporarily|too many requests|forcibly closed|connection was closed|service unavailable|no data of the requested type'
# Permission: never retried - the same call will be refused again. Triggers the
# API <-> RBAC method fallback instead.
$script:RxPermission = '401|403|unauthorized|forbidden|access denied|accessdenied|does not have permission|insufficient privileges|authorizationfailed|not authorized'
# Validation / duplicate: never retried. Retrying burns time and can partially
# apply bad data.
$script:RxValidation = 'invalid|not a valid|malformed|is required|cannot be null|bad request|400'
$script:RxDuplicate  = 'already exists|duplicate|conflict|409'

function Get-ErrorClass {
<#
.SYNOPSIS
    Classify a failure as Permission, Transient, Validation, Duplicate or Other.
.DESCRIPTION
    Two distinct classifiers, not one severity scale. A permission error means
    try the other method; a transient error means try the same method again.
    Conflating them either retries a refusal four times or gives up on a throttle.
#>
    param($ErrorRecord)
    $t = ''
    try {
        $t = "$($ErrorRecord.Exception.Message)"
        if ($ErrorRecord.Exception.Response) {
            try { $t += ' ' + [int]$ErrorRecord.Exception.Response.StatusCode } catch {}
        }
        if ($ErrorRecord.ErrorDetails) { $t += ' ' + "$($ErrorRecord.ErrorDetails.Message)" }
    } catch { $t = "$ErrorRecord" }

    if ($t -imatch $script:RxPermission) { return 'Permission' }
    if ($t -imatch $script:RxDuplicate)  { return 'Duplicate' }
    if ($t -imatch $script:RxTransient)  { return 'Transient' }
    if ($t -imatch $script:RxValidation) { return 'Validation' }
    return 'Other'
}

# Backoff profiles. LIS and bulk import are interactive and can afford long
# waits; the CDR engine cannot, because a slow retry stalls the drain queue.
$script:RetryProfiles = @{
    Lis        = @{ Attempts = 5; BaseMs = 500; Factor = 2; CapMs = 15000; JitterMs = 250; Fixed = $null }
    BulkImport = @{ Attempts = 4; BaseMs = 500; Factor = 2; CapMs = 15000; JitterMs = 250; Fixed = $null }
    CdrNormal  = @{ Attempts = 4; BaseMs = 250; Factor = 2; CapMs = 2000;  JitterMs = 200; Fixed = $null }
    CdrHard    = @{ Attempts = 5; BaseMs = 0;   Factor = 0; CapMs = 0;     JitterMs = 0;   Fixed = @(2,4,8,12,16) }
}

function Get-RetryDelayMs {
    param([hashtable]$Profile,[int]$Attempt)
    if ($Profile.Fixed) {
        $i = [Math]::Min($Attempt - 1, $Profile.Fixed.Count - 1)
        if ($i -lt 0) { $i = 0 }
        return ([int]$Profile.Fixed[$i]) * 1000
    }
    $ms = [double]$Profile.BaseMs * [Math]::Pow($Profile.Factor, ($Attempt - 1))
    if ($ms -gt $Profile.CapMs) { $ms = $Profile.CapMs }
    if ($Profile.JitterMs -gt 0) { $ms += (Get-Random -Minimum 0 -Maximum ([int]$Profile.JitterMs + 1)) }
    return [int]$ms
}

function Invoke-WithRetry {
<#
.SYNOPSIS
    Run a scriptblock, retrying only transient failures.
.PARAMETER RetryProfile
    Lis | BulkImport | CdrNormal | CdrHard  (see $script:RetryProfiles)
.PARAMETER CancelCheck
    Scriptblock returning $true to abandon between attempts. Long waits are slept
    in 50 ms slices so Stop stays responsive.
.PARAMETER OnRetry
    Scriptblock called as { param($Attempt,$DelayMs,$ErrorRecord) } - used to
    drive the state label without this function knowing about the UI.
.OUTPUTS
    Whatever the action returns. Re-throws the last error when every attempt fails.
#>
    param(
        [Parameter(Mandatory)][scriptblock]$Action,
        [ValidateSet('Lis','BulkImport','CdrNormal','CdrHard')][string]$RetryProfile = 'Lis',
        [int]$MaxAttempts = 0,
        [scriptblock]$OnRetry,
        [scriptblock]$CancelCheck
    )
    $p = $script:RetryProfiles[$RetryProfile]
    $max = $(if ($MaxAttempts -gt 0) { $MaxAttempts } else { [int]$p.Attempts })
    $attempt = 0
    $last = $null
    while ($attempt -lt $max) {
        $attempt++
        if ($CancelCheck -and (& $CancelCheck)) { throw "Cancelled before attempt $attempt." }
        try { return (& $Action) }
        catch {
            $last  = $_
            $class = Get-ErrorClass $_
            # Permission, validation and duplicate are terminal by design.
            if ($class -ne 'Transient') { throw }
            if ($attempt -ge $max) { throw }
            $delay = Get-RetryDelayMs -Profile $p -Attempt $attempt
            if ($OnRetry) { try { & $OnRetry $attempt $delay $_ } catch {} }
            $slept = 0
            while ($slept -lt $delay) {
                if ($CancelCheck -and (& $CancelCheck)) { throw "Cancelled during backoff." }
                Start-Sleep -Milliseconds 50
                $slept += 50
            }
        }
    }
    if ($last) { throw $last }
}

# ==============================================================================
# REGION S4 - WRITE CONFIRMATION AND RESULT SHAPE
# ==============================================================================

function Confirm-ToolkitWrite {
<#
.SYNOPSIS
    Yes/No warning dialog. Returns $true only on an explicit Yes.
.DESCRIPTION
    Every tenant write in the LIS, SBC and Bulk Import tabs routes through here.
    Defaulting to No is intentional: Enter on a focused dialog must not commit.
#>
    param([string]$Title = 'Confirm',[Parameter(Mandatory)][string]$Message)
    $r = [System.Windows.Forms.MessageBox]::Show(
            $Message, $Title,
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning,
            [System.Windows.Forms.MessageBoxDefaultButton]::Button2)
    return ($r -eq [System.Windows.Forms.DialogResult]::Yes)
}

# Country-from-dialled-number resolution is Get-CountryFromNumber, further down
# in this file - it already does this (longest-prefix match over $script:DialToIso)
# and is already wired to lblNumCountry. No second implementation needed here.


################################################################################
#
#  TAB 6  SBC / DIRECT ROUTING
#
#  Reads and most writes are covered by Teams Telephony Administrator; a few
#  tenant-scoped items - trusted IPs in particular - may require Teams
#  Administrator. Rather than assume, Sbc-Probe checks what the connected
#  identity can actually read at pull time, and a write failure is translated
#  into the specific role most likely missing rather than a raw 403.
#
################################################################################

$script:SbcGateways = @()
$script:SbcUsages    = @()
$script:SbcRoutes    = @()
$script:SbcPolicies  = @()
$script:SbcTrustedIp = @()
$script:SbcCaps      = @{}   # area -> 'OK'|'NoCmdlet'|'Denied'|'Error'

function New-SbcTabPage {
    param(
        [string]$Text = '  SBC / Direct Routing  ',
        $BackColor,$ColorBlue,$ColorPurple,$ColorGreen,$ColorGray,$ColorAmber,$ColorRed
    )

    $page = New-Object System.Windows.Forms.TabPage
    $page.Text = $Text; $page.BackColor = $BackColor

    $bar = New-Object System.Windows.Forms.Panel
    $bar.Dock='Top'; $bar.Height=64; $bar.BackColor=[System.Drawing.Color]::White

    $btnPull = New-Object System.Windows.Forms.Button
    $btnPull.Location=New-Object System.Drawing.Point(12,10); $btnPull.Size=New-Object System.Drawing.Size(150,27)
    $btnPull.Text='Pull SBC Topology'; Style-Button $btnPull $ColorPurple

    $btnValidate = New-Object System.Windows.Forms.Button
    $btnValidate.Location=New-Object System.Drawing.Point(170,10); $btnValidate.Size=New-Object System.Drawing.Size(140,27)
    $btnValidate.Text='Validate Topology'; Style-Button $btnValidate $ColorBlue

    $btnExport = New-Object System.Windows.Forms.Button
    $btnExport.Location=New-Object System.Drawing.Point(318,10); $btnExport.Size=New-Object System.Drawing.Size(150,27)
    $btnExport.Text='Export Topology'; Style-Button $btnExport $ColorGreen

    $btnFolder = New-Object System.Windows.Forms.Button
    $btnFolder.Location=New-Object System.Drawing.Point(476,10); $btnFolder.Size=New-Object System.Drawing.Size(112,27)
    $btnFolder.Text='Open Folder'; Style-Button $btnFolder $ColorGray

    $lblCaps = New-Object System.Windows.Forms.Label
    $lblCaps.Location=New-Object System.Drawing.Point(600,12); $lblCaps.Size=New-Object System.Drawing.Size(480,20)
    $lblCaps.Text=''; $lblCaps.Font=New-Object System.Drawing.Font('Segoe UI',8,[System.Drawing.FontStyle]::Bold)
    $lblCaps.ForeColor=$ColorGray

    $lblState = New-Object System.Windows.Forms.Label
    $lblState.Location=New-Object System.Drawing.Point(600,36); $lblState.Size=New-Object System.Drawing.Size(660,20)
    $lblState.Text='Not pulled.'; $lblState.ForeColor=$ColorGray
    $lblState.Font=New-Object System.Drawing.Font('Segoe UI',8,[System.Drawing.FontStyle]::Bold)

    $bar.Controls.AddRange(@($btnPull,$btnValidate,$btnExport,$btnFolder,$lblCaps,$lblState))

    $inner = New-Object System.Windows.Forms.TabControl
    $inner.Dock='Fill'

    $pgTopo   = New-Object System.Windows.Forms.TabPage; $pgTopo.Text='Topology and Health'; $pgTopo.BackColor=$BackColor
    $pgGw     = New-Object System.Windows.Forms.TabPage; $pgGw.Text='Gateways'; $pgGw.BackColor=$BackColor
    $pgUsage  = New-Object System.Windows.Forms.TabPage; $pgUsage.Text='PSTN Usages'; $pgUsage.BackColor=$BackColor
    $pgRoute  = New-Object System.Windows.Forms.TabPage; $pgRoute.Text='Voice Routes'; $pgRoute.BackColor=$BackColor
    $pgPolicy = New-Object System.Windows.Forms.TabPage; $pgPolicy.Text='Routing Policies'; $pgPolicy.BackColor=$BackColor
    $pgTrust  = New-Object System.Windows.Forms.TabPage; $pgTrust.Text='Trusted IPs'; $pgTrust.BackColor=$BackColor
    $pgSim    = New-Object System.Windows.Forms.TabPage; $pgSim.Text='Route Simulator'; $pgSim.BackColor=$BackColor
    $inner.Controls.AddRange(@($pgTopo,$pgGw,$pgUsage,$pgRoute,$pgPolicy,$pgTrust,$pgSim))

    # ---- Inner page 1: Topology and Health -----------------------------------
    $topoSplit = New-Object System.Windows.Forms.SplitContainer
    $topoSplit.Size = New-Object System.Drawing.Size(1200,900)
    $topoSplit.Dock='Fill'; $topoSplit.Orientation='Horizontal'; $topoSplit.SplitterDistance=260
    $topoSplit.Panel1MinSize=120; $topoSplit.Panel2MinSize=120
    $gridFind = New-Object System.Windows.Forms.DataGridView
    $gridFind.Dock='Fill'; $gridFind.ReadOnly=$true; $gridFind.AllowUserToAddRows=$false
    $gridFind.SelectionMode='FullRowSelect'; $gridFind.MultiSelect=$false; $gridFind.AutoSizeColumnsMode='Fill'
    $gridFind.RowHeadersVisible=$false; $gridFind.BackgroundColor=[System.Drawing.Color]::White
    foreach ($c in @('Severity','Area','Object','Finding','Impact')) { [void]$gridFind.Columns.Add($c,$c) }
    $gridFind.Columns['Severity'].FillWeight=60; $gridFind.Columns['Area'].FillWeight=80
    $gridFind.Columns['Object'].FillWeight=160; $gridFind.Columns['Finding'].FillWeight=300; $gridFind.Columns['Impact'].FillWeight=320
    $gridFind.Add_CellFormatting({
        param($s,$e)
        if ($e.RowIndex -lt 0) { return }
        $sev="$($script:SbcUi.GridFind.Rows[$e.RowIndex].Cells['Severity'].Value)"
        if ($sev -eq 'ERROR') { $e.CellStyle.BackColor=[System.Drawing.Color]::FromArgb(255,225,225) }
        elseif ($sev -eq 'WARN') { $e.CellStyle.BackColor=[System.Drawing.Color]::FromArgb(255,244,214) }
        else { $e.CellStyle.BackColor=[System.Drawing.Color]::FromArgb(238,238,238) }
    })
    $topoSplit.Panel1.Controls.Add($gridFind)
    $rtbChain = New-Object System.Windows.Forms.RichTextBox
    $rtbChain.Dock='Fill'; $rtbChain.ReadOnly=$true; $rtbChain.BackColor=[System.Drawing.Color]::White
    $rtbChain.Font=New-Object System.Drawing.Font('Consolas',9)
    $topoSplit.Panel2.Controls.Add($rtbChain)
    $pgTopo.Controls.Add($topoSplit)

    # ---- Inner page 2: Gateways ----------------------------------------------
    $gwSplit = New-Object System.Windows.Forms.SplitContainer
    $gwSplit.Size = New-Object System.Drawing.Size(1200,900)
    $gwSplit.Dock='Fill'; $gwSplit.Orientation='Horizontal'; $gwSplit.SplitterDistance=220
    $gwSplit.Panel1MinSize=120; $gwSplit.Panel2MinSize=200
    $gridGw = New-Object System.Windows.Forms.DataGridView
    $gridGw.Dock='Fill'; $gridGw.ReadOnly=$true; $gridGw.AllowUserToAddRows=$false
    $gridGw.SelectionMode='FullRowSelect'; $gridGw.MultiSelect=$false; $gridGw.AutoSizeColumnsMode='Fill'
    $gridGw.RowHeadersVisible=$false; $gridGw.BackgroundColor=[System.Drawing.Color]::White
    foreach ($c in @('FQDN','Enabled','Port','MediaBypass','MaxSessions','SendSipOptions','ForwardPai','FailoverSecs','Routes')) { [void]$gridGw.Columns.Add($c,$c) }
    $gridGw.Columns['FQDN'].FillWeight=200
    $gwSplit.Panel1.Controls.Add($gridGw)

    $gwEdit = New-Object System.Windows.Forms.Panel; $gwEdit.Dock='Fill'; $gwEdit.AutoScroll=$true; $gwEdit.BackColor=$BackColor
    $gwFields=@{}
    $gwTexts = @('Fqdn','SipSignalingPort','MaxConcurrentSessions','FailoverTimeSeconds','FailoverResponseCodes','GatewaySiteId','MediaRelayRoutingLocationOverride','InboundTeamsNumberTranslationRulesList','OutboundTeamsNumberTranslationRulesList')
    $y=10
    foreach ($f in $gwTexts) {
        $l=New-Object System.Windows.Forms.Label; $l.Location=New-Object System.Drawing.Point(10,($y+3)); $l.Size=New-Object System.Drawing.Size(280,18); $l.Text=$f
        $t=New-Object System.Windows.Forms.TextBox; $t.Location=New-Object System.Drawing.Point(296,$y); $t.Size=New-Object System.Drawing.Size(300,22)
        $gwFields[$f]=$t; $gwEdit.Controls.AddRange(@($l,$t)); $y+=27
    }
    $gwChecks = @('Enabled','MediaBypass','SendSipOptions','ForwardCallHistory','ForwardPai','PidfLoSupported','GatewaySiteLbrEnabled','ProxySbc')
    $y=10
    foreach ($f in $gwChecks) {
        $c=New-Object System.Windows.Forms.CheckBox; $c.Location=New-Object System.Drawing.Point(830,$y); $c.Size=New-Object System.Drawing.Size(180,22); $c.Text=$f
        $gwFields[$f]=$c; $gwEdit.Controls.Add($c); $y+=27
    }
    $btnGwNew=New-Object System.Windows.Forms.Button; $btnGwNew.Location=New-Object System.Drawing.Point(296,258); $btnGwNew.Size=New-Object System.Drawing.Size(96,26); $btnGwNew.Text='Clear / New'; Style-Button $btnGwNew $ColorGray
    $btnGwCreate=New-Object System.Windows.Forms.Button; $btnGwCreate.Location=New-Object System.Drawing.Point(398,258); $btnGwCreate.Size=New-Object System.Drawing.Size(104,26); $btnGwCreate.Text='Create Gateway'; Style-Button $btnGwCreate $ColorGreen
    $btnGwUpdate=New-Object System.Windows.Forms.Button; $btnGwUpdate.Location=New-Object System.Drawing.Point(508,258); $btnGwUpdate.Size=New-Object System.Drawing.Size(104,26); $btnGwUpdate.Text='Update Gateway'; Style-Button $btnGwUpdate $ColorBlue
    $btnGwDelete=New-Object System.Windows.Forms.Button; $btnGwDelete.Location=New-Object System.Drawing.Point(618,258); $btnGwDelete.Size=New-Object System.Drawing.Size(104,26); $btnGwDelete.Text='Delete Gateway'; Style-Button $btnGwDelete $ColorRed
    $gwEdit.Controls.AddRange(@($btnGwNew,$btnGwCreate,$btnGwUpdate,$btnGwDelete))
    $gwSplit.Panel2.Controls.Add($gwEdit)
    $pgGw.Controls.Add($gwSplit)

    # ---- Inner page 3: PSTN Usages -------------------------------------------
    $usageTop = New-Object System.Windows.Forms.Panel; $usageTop.Dock='Top'; $usageTop.Height=76; $usageTop.BackColor=$BackColor
    $lblUsageNote = New-Object System.Windows.Forms.Label
    $lblUsageNote.Location=New-Object System.Drawing.Point(10,6); $lblUsageNote.Size=New-Object System.Drawing.Size(900,36)
    $lblUsageNote.Text='PSTN usages are a single tenant-wide ordered list. A usage only does anything once a voice route carries it and a routing policy grants it. Removing a usage that routes or policies still reference will break those paths.'
    $lblUsageNote.ForeColor=$ColorGray
    $txtUsageName = New-Object System.Windows.Forms.TextBox; $txtUsageName.Location=New-Object System.Drawing.Point(10,46); $txtUsageName.Size=New-Object System.Drawing.Size(260,22)
    $btnUsageAdd = New-Object System.Windows.Forms.Button; $btnUsageAdd.Location=New-Object System.Drawing.Point(276,44); $btnUsageAdd.Size=New-Object System.Drawing.Size(90,26); $btnUsageAdd.Text='Add Usage'; Style-Button $btnUsageAdd $ColorGreen
    $btnUsageRemove = New-Object System.Windows.Forms.Button; $btnUsageRemove.Location=New-Object System.Drawing.Point(372,44); $btnUsageRemove.Size=New-Object System.Drawing.Size(104,26); $btnUsageRemove.Text='Remove Usage'; Style-Button $btnUsageRemove $ColorRed
    $usageTop.Controls.AddRange(@($lblUsageNote,$txtUsageName,$btnUsageAdd,$btnUsageRemove))
    $gridUsage = New-Object System.Windows.Forms.DataGridView
    $gridUsage.Dock='Fill'; $gridUsage.ReadOnly=$true; $gridUsage.AllowUserToAddRows=$false
    $gridUsage.SelectionMode='FullRowSelect'; $gridUsage.MultiSelect=$false; $gridUsage.AutoSizeColumnsMode='Fill'
    $gridUsage.RowHeadersVisible=$false; $gridUsage.BackgroundColor=[System.Drawing.Color]::White
    foreach ($c in @('Usage','UsedByRoutes','UsedByPolicies','Status')) { [void]$gridUsage.Columns.Add($c,$c) }
    $pgUsage.Controls.Add($gridUsage); $pgUsage.Controls.Add($usageTop)

    # ---- Inner page 4: Voice Routes ------------------------------------------
    $routeSplit = New-Object System.Windows.Forms.SplitContainer
    $routeSplit.Size = New-Object System.Drawing.Size(1200,900)
    $routeSplit.Dock='Fill'; $routeSplit.Orientation='Horizontal'; $routeSplit.SplitterDistance=240
    $routeSplit.Panel1MinSize=120; $routeSplit.Panel2MinSize=220
    $gridRoute = New-Object System.Windows.Forms.DataGridView
    $gridRoute.Dock='Fill'; $gridRoute.ReadOnly=$true; $gridRoute.AllowUserToAddRows=$false
    $gridRoute.SelectionMode='FullRowSelect'; $gridRoute.MultiSelect=$false; $gridRoute.AutoSizeColumnsMode='Fill'
    $gridRoute.RowHeadersVisible=$false; $gridRoute.BackgroundColor=[System.Drawing.Color]::White
    foreach ($c in @('Priority','Name','NumberPattern','PstnUsages','Gateways','Description')) { [void]$gridRoute.Columns.Add($c,$c) }
    $gridRoute.Columns['Priority'].FillWeight=50; $gridRoute.Columns['NumberPattern'].FillWeight=180
    $routeSplit.Panel1.Controls.Add($gridRoute)

    $routeEdit = New-Object System.Windows.Forms.Panel; $routeEdit.Dock='Fill'; $routeEdit.BackColor=$BackColor
    $lblRName=New-Object System.Windows.Forms.Label; $lblRName.Location=New-Object System.Drawing.Point(10,10); $lblRName.Size=New-Object System.Drawing.Size(80,18); $lblRName.Text='Name'
    $txtRName=New-Object System.Windows.Forms.TextBox; $txtRName.Location=New-Object System.Drawing.Point(96,8); $txtRName.Size=New-Object System.Drawing.Size(200,22)
    $lblRPat=New-Object System.Windows.Forms.Label; $lblRPat.Location=New-Object System.Drawing.Point(310,10); $lblRPat.Size=New-Object System.Drawing.Size(90,18); $lblRPat.Text='Number pattern'
    $txtRPat=New-Object System.Windows.Forms.TextBox; $txtRPat.Location=New-Object System.Drawing.Point(404,8); $txtRPat.Size=New-Object System.Drawing.Size(220,22)
    $lblRPri=New-Object System.Windows.Forms.Label; $lblRPri.Location=New-Object System.Drawing.Point(638,10); $lblRPri.Size=New-Object System.Drawing.Size(52,18); $lblRPri.Text='Priority'
    $numRPri=New-Object System.Windows.Forms.NumericUpDown; $numRPri.Location=New-Object System.Drawing.Point(694,8); $numRPri.Size=New-Object System.Drawing.Size(70,22); $numRPri.Minimum=0; $numRPri.Maximum=9999
    $lblRDesc=New-Object System.Windows.Forms.Label; $lblRDesc.Location=New-Object System.Drawing.Point(10,38); $lblRDesc.Size=New-Object System.Drawing.Size(80,18); $lblRDesc.Text='Description'
    $txtRDesc=New-Object System.Windows.Forms.TextBox; $txtRDesc.Location=New-Object System.Drawing.Point(96,36); $txtRDesc.Size=New-Object System.Drawing.Size(528,22)
    $lblRU=New-Object System.Windows.Forms.Label; $lblRU.Location=New-Object System.Drawing.Point(10,66); $lblRU.Size=New-Object System.Drawing.Size(160,18); $lblRU.Text='PSTN usages on this route'
    $clbRUsage=New-Object System.Windows.Forms.CheckedListBox; $clbRUsage.Location=New-Object System.Drawing.Point(10,86); $clbRUsage.Size=New-Object System.Drawing.Size(340,190); $clbRUsage.CheckOnClick=$true
    $lblRG=New-Object System.Windows.Forms.Label; $lblRG.Location=New-Object System.Drawing.Point(360,66); $lblRG.Size=New-Object System.Drawing.Size(160,18); $lblRG.Text='Gateways on this route'
    $clbRGw=New-Object System.Windows.Forms.CheckedListBox; $clbRGw.Location=New-Object System.Drawing.Point(360,86); $clbRGw.Size=New-Object System.Drawing.Size(400,190); $clbRGw.CheckOnClick=$true
    $btnRNew=New-Object System.Windows.Forms.Button; $btnRNew.Location=New-Object System.Drawing.Point(780,66); $btnRNew.Size=New-Object System.Drawing.Size(92,26); $btnRNew.Text='Clear / New'; Style-Button $btnRNew $ColorGray
    $btnRCreate=New-Object System.Windows.Forms.Button; $btnRCreate.Location=New-Object System.Drawing.Point(780,96); $btnRCreate.Size=New-Object System.Drawing.Size(92,26); $btnRCreate.Text='Create Route'; Style-Button $btnRCreate $ColorGreen
    $btnRUpdate=New-Object System.Windows.Forms.Button; $btnRUpdate.Location=New-Object System.Drawing.Point(780,126); $btnRUpdate.Size=New-Object System.Drawing.Size(92,26); $btnRUpdate.Text='Update Route'; Style-Button $btnRUpdate $ColorBlue
    $btnRDelete=New-Object System.Windows.Forms.Button; $btnRDelete.Location=New-Object System.Drawing.Point(780,156); $btnRDelete.Size=New-Object System.Drawing.Size(92,26); $btnRDelete.Text='Delete Route'; Style-Button $btnRDelete $ColorRed
    $btnRTest=New-Object System.Windows.Forms.Button; $btnRTest.Location=New-Object System.Drawing.Point(780,186); $btnRTest.Size=New-Object System.Drawing.Size(92,26); $btnRTest.Text='Test Pattern...'; Style-Button $btnRTest $ColorPurple
    $routeEdit.Controls.AddRange(@($lblRName,$txtRName,$lblRPat,$txtRPat,$lblRPri,$numRPri,$lblRDesc,$txtRDesc,$lblRU,$clbRUsage,$lblRG,$clbRGw,$btnRNew,$btnRCreate,$btnRUpdate,$btnRDelete,$btnRTest))
    $routeSplit.Panel2.Controls.Add($routeEdit)
    $pgRoute.Controls.Add($routeSplit)

    # ---- Inner page 5: Routing Policies --------------------------------------
    $polSplit = New-Object System.Windows.Forms.SplitContainer
    $polSplit.Size = New-Object System.Drawing.Size(1200,900)
    $polSplit.Dock='Fill'; $polSplit.Orientation='Horizontal'; $polSplit.SplitterDistance=220
    $polSplit.Panel1MinSize=120; $polSplit.Panel2MinSize=220
    $gridPol = New-Object System.Windows.Forms.DataGridView
    $gridPol.Dock='Fill'; $gridPol.ReadOnly=$true; $gridPol.AllowUserToAddRows=$false
    $gridPol.SelectionMode='FullRowSelect'; $gridPol.MultiSelect=$false; $gridPol.AutoSizeColumnsMode='Fill'
    $gridPol.RowHeadersVisible=$false; $gridPol.BackgroundColor=[System.Drawing.Color]::White
    foreach ($c in @('Policy','PstnUsages','ReachableGateways','Description')) { [void]$gridPol.Columns.Add($c,$c) }
    $polSplit.Panel1.Controls.Add($gridPol)

    $polEdit = New-Object System.Windows.Forms.Panel; $polEdit.Dock='Fill'; $polEdit.BackColor=$BackColor
    $lblPName=New-Object System.Windows.Forms.Label; $lblPName.Location=New-Object System.Drawing.Point(10,10); $lblPName.Size=New-Object System.Drawing.Size(60,18); $lblPName.Text='Name'
    $txtPName=New-Object System.Windows.Forms.TextBox; $txtPName.Location=New-Object System.Drawing.Point(76,8); $txtPName.Size=New-Object System.Drawing.Size(220,22)
    $lblPDesc=New-Object System.Windows.Forms.Label; $lblPDesc.Location=New-Object System.Drawing.Point(306,10); $lblPDesc.Size=New-Object System.Drawing.Size(70,18); $lblPDesc.Text='Description'
    $txtPDesc=New-Object System.Windows.Forms.TextBox; $txtPDesc.Location=New-Object System.Drawing.Point(380,8); $txtPDesc.Size=New-Object System.Drawing.Size(340,22)
    $lblPGrant=New-Object System.Windows.Forms.Label; $lblPGrant.Location=New-Object System.Drawing.Point(10,38); $lblPGrant.Size=New-Object System.Drawing.Size(70,18); $lblPGrant.Text='Grant to UPN'
    $txtPGrant=New-Object System.Windows.Forms.TextBox; $txtPGrant.Location=New-Object System.Drawing.Point(86,36); $txtPGrant.Size=New-Object System.Drawing.Size(220,22)
    $btnPGrant=New-Object System.Windows.Forms.Button; $btnPGrant.Location=New-Object System.Drawing.Point(312,35); $btnPGrant.Size=New-Object System.Drawing.Size(110,25); $btnPGrant.Text='Grant to User'; Style-Button $btnPGrant $ColorPurple
    $btnPReset=New-Object System.Windows.Forms.Button; $btnPReset.Location=New-Object System.Drawing.Point(428,35); $btnPReset.Size=New-Object System.Drawing.Size(110,25); $btnPReset.Text='Reset to Global'; Style-Button $btnPReset $ColorGray
    $lblPU=New-Object System.Windows.Forms.Label; $lblPU.Location=New-Object System.Drawing.Point(10,66); $lblPU.Size=New-Object System.Drawing.Size(400,18); $lblPU.Text='usages - evaluation order is top to bottom'
    $clbPUsage=New-Object System.Windows.Forms.CheckedListBox; $clbPUsage.Location=New-Object System.Drawing.Point(10,86); $clbPUsage.Size=New-Object System.Drawing.Size(360,190); $clbPUsage.CheckOnClick=$true
    $btnPUp=New-Object System.Windows.Forms.Button; $btnPUp.Location=New-Object System.Drawing.Point(380,86); $btnPUp.Size=New-Object System.Drawing.Size(60,26); $btnPUp.Text='Up'; Style-Button $btnPUp $ColorGray
    $btnPDown=New-Object System.Windows.Forms.Button; $btnPDown.Location=New-Object System.Drawing.Point(380,116); $btnPDown.Size=New-Object System.Drawing.Size(60,26); $btnPDown.Text='Down'; Style-Button $btnPDown $ColorGray
    $btnPNew=New-Object System.Windows.Forms.Button; $btnPNew.Location=New-Object System.Drawing.Point(460,86); $btnPNew.Size=New-Object System.Drawing.Size(92,26); $btnPNew.Text='Clear / New'; Style-Button $btnPNew $ColorGray
    $btnPCreate=New-Object System.Windows.Forms.Button; $btnPCreate.Location=New-Object System.Drawing.Point(460,116); $btnPCreate.Size=New-Object System.Drawing.Size(92,26); $btnPCreate.Text='Create Policy'; Style-Button $btnPCreate $ColorGreen
    $btnPUpdate=New-Object System.Windows.Forms.Button; $btnPUpdate.Location=New-Object System.Drawing.Point(460,146); $btnPUpdate.Size=New-Object System.Drawing.Size(92,26); $btnPUpdate.Text='Update Policy'; Style-Button $btnPUpdate $ColorBlue
    $btnPDelete=New-Object System.Windows.Forms.Button; $btnPDelete.Location=New-Object System.Drawing.Point(460,176); $btnPDelete.Size=New-Object System.Drawing.Size(92,26); $btnPDelete.Text='Delete Policy'; Style-Button $btnPDelete $ColorRed
    $polEdit.Controls.AddRange(@($lblPName,$txtPName,$lblPDesc,$txtPDesc,$lblPGrant,$txtPGrant,$btnPGrant,$btnPReset,$lblPU,$clbPUsage,$btnPUp,$btnPDown,$btnPNew,$btnPCreate,$btnPUpdate,$btnPDelete))
    $polSplit.Panel2.Controls.Add($polEdit)
    $pgPolicy.Controls.Add($polSplit)

    # ---- Inner page 6: Trusted IPs -------------------------------------------
    $trustTop = New-Object System.Windows.Forms.Panel; $trustTop.Dock='Top'; $trustTop.Height=92; $trustTop.BackColor=$BackColor
    $lblTIp=New-Object System.Windows.Forms.Label; $lblTIp.Location=New-Object System.Drawing.Point(10,10); $lblTIp.Size=New-Object System.Drawing.Size(80,18); $lblTIp.Text='IP address'
    $txtTIp=New-Object System.Windows.Forms.TextBox; $txtTIp.Location=New-Object System.Drawing.Point(96,8); $txtTIp.Size=New-Object System.Drawing.Size(160,22)
    $lblTMask=New-Object System.Windows.Forms.Label; $lblTMask.Location=New-Object System.Drawing.Point(266,10); $lblTMask.Size=New-Object System.Drawing.Size(60,18); $lblTMask.Text='Mask bits'
    $numTMask=New-Object System.Windows.Forms.NumericUpDown; $numTMask.Location=New-Object System.Drawing.Point(330,8); $numTMask.Size=New-Object System.Drawing.Size(60,22); $numTMask.Minimum=1; $numTMask.Maximum=32; $numTMask.Value=32
    $lblTDesc=New-Object System.Windows.Forms.Label; $lblTDesc.Location=New-Object System.Drawing.Point(404,10); $lblTDesc.Size=New-Object System.Drawing.Size(70,18); $lblTDesc.Text='Description'
    $txtTDesc=New-Object System.Windows.Forms.TextBox; $txtTDesc.Location=New-Object System.Drawing.Point(478,8); $txtTDesc.Size=New-Object System.Drawing.Size(260,22)
    $btnTAdd=New-Object System.Windows.Forms.Button; $btnTAdd.Location=New-Object System.Drawing.Point(748,7); $btnTAdd.Size=New-Object System.Drawing.Size(70,26); $btnTAdd.Text='Add IP'; Style-Button $btnTAdd $ColorGreen
    $btnTRemove=New-Object System.Windows.Forms.Button; $btnTRemove.Location=New-Object System.Drawing.Point(824,7); $btnTRemove.Size=New-Object System.Drawing.Size(90,26); $btnTRemove.Text='Remove IP'; Style-Button $btnTRemove $ColorRed
    $lblTNote=New-Object System.Windows.Forms.Label; $lblTNote.Location=New-Object System.Drawing.Point(10,42); $lblTNote.Size=New-Object System.Drawing.Size(1000,44)
    $lblTNote.Text='Trusted IP addresses are the external (egress) ranges location-based routing uses to decide whether a client is on the corporate network. This is a tenant-scoped setting; the capability strip above reports what the connected identity can actually read, and any write failure will name the role that was refused.'
    $lblTNote.ForeColor=$ColorGray
    $trustTop.Controls.AddRange(@($lblTIp,$txtTIp,$lblTMask,$numTMask,$lblTDesc,$txtTDesc,$btnTAdd,$btnTRemove,$lblTNote))
    $gridTrust = New-Object System.Windows.Forms.DataGridView
    $gridTrust.Dock='Fill'; $gridTrust.ReadOnly=$true; $gridTrust.AllowUserToAddRows=$false
    $gridTrust.SelectionMode='FullRowSelect'; $gridTrust.MultiSelect=$false; $gridTrust.AutoSizeColumnsMode='Fill'
    $gridTrust.RowHeadersVisible=$false; $gridTrust.BackgroundColor=[System.Drawing.Color]::White
    foreach ($c in @('IPAddress','MaskBits','Description')) { [void]$gridTrust.Columns.Add($c,$c) }
    $pgTrust.Controls.Add($gridTrust); $pgTrust.Controls.Add($trustTop)

    # ---- Inner page 7: Route Simulator ---------------------------------------
    $simTop = New-Object System.Windows.Forms.Panel; $simTop.Dock='Top'; $simTop.Height=48; $simTop.BackColor=$BackColor
    $lblSNum=New-Object System.Windows.Forms.Label; $lblSNum.Location=New-Object System.Drawing.Point(10,12); $lblSNum.Size=New-Object System.Drawing.Size(90,20); $lblSNum.Text='Dialed number'
    $txtSNum=New-Object System.Windows.Forms.TextBox; $txtSNum.Location=New-Object System.Drawing.Point(102,10); $txtSNum.Size=New-Object System.Drawing.Size(180,22)
    $lblSPol=New-Object System.Windows.Forms.Label; $lblSPol.Location=New-Object System.Drawing.Point(296,12); $lblSPol.Size=New-Object System.Drawing.Size(90,20); $lblSPol.Text='Routing policy'
    $cmbSPol=New-Object System.Windows.Forms.ComboBox; $cmbSPol.Location=New-Object System.Drawing.Point(388,10); $cmbSPol.Size=New-Object System.Drawing.Size(220,22); $cmbSPol.DropDownStyle='DropDownList'
    $btnSimLocal=New-Object System.Windows.Forms.Button; $btnSimLocal.Location=New-Object System.Drawing.Point(622,8); $btnSimLocal.Size=New-Object System.Drawing.Size(160,26); $btnSimLocal.Text='Simulate (local trace)'; Style-Button $btnSimLocal $ColorBlue
    $btnSimTenant=New-Object System.Windows.Forms.Button; $btnSimTenant.Location=New-Object System.Drawing.Point(788,8); $btnSimTenant.Size=New-Object System.Drawing.Size(150,26); $btnSimTenant.Text='Refresh + Simulate'; Style-Button $btnSimTenant $ColorPurple
    $simTop.Controls.AddRange(@($lblSNum,$txtSNum,$lblSPol,$cmbSPol,$btnSimLocal,$btnSimTenant))
    $rtbSim = New-Object System.Windows.Forms.RichTextBox
    $rtbSim.Dock='Fill'; $rtbSim.ReadOnly=$true; $rtbSim.BackColor=[System.Drawing.Color]::White
    $rtbSim.Font=New-Object System.Drawing.Font('Consolas',9)
    $pgSim.Controls.Add($rtbSim); $pgSim.Controls.Add($simTop)

    $page.Controls.Add($inner)
    $page.Controls.Add($bar)

    $script:SbcUi = @{
        State=$lblState; Caps=$lblCaps
        GridFind=$gridFind; Chain=$rtbChain
        GridGw=$gridGw; GwFields=$gwFields
        GridUsage=$gridUsage; UsageName=$txtUsageName
        GridRoute=$gridRoute; RName=$txtRName; RPat=$txtRPat; RPri=$numRPri; RDesc=$txtRDesc; RUsage=$clbRUsage; RGw=$clbRGw
        GridPol=$gridPol; PName=$txtPName; PDesc=$txtPDesc; PGrant=$txtPGrant; PUsage=$clbPUsage
        GridTrust=$gridTrust; TIp=$txtTIp; TMask=$numTMask; TDesc=$txtTDesc
        SimNum=$txtSNum; SimPol=$cmbSPol; SimOut=$rtbSim
        Pull=$btnPull; Validate=$btnValidate; Export=$btnExport; Folder=$btnFolder
        Colors=@{ Blue=$ColorBlue; Purple=$ColorPurple; Green=$ColorGreen; Gray=$ColorGray; Amber=$ColorAmber; Red=$ColorRed }
    }
    $script:SbcSelGw=$null; $script:SbcSelRoute=$null; $script:SbcSelPolicy=$null

    # ==========================================================================
    # HELPERS
    # ==========================================================================

    function script:Sbc-Say { param([string]$Text,$Color)
        $ui=$script:SbcUi; if (-not $ui) { return }
        if (-not $Color) { $Color=[System.Drawing.Color]::Black }
        $ui.Chain.SelectionStart=$ui.Chain.TextLength; $ui.Chain.SelectionLength=0
        $ui.Chain.SelectionColor=$Color
        $ui.Chain.AppendText(("[{0}] {1}`n" -f (Get-Date).ToString('HH:mm:ss'),$Text))
        $ui.Chain.SelectionColor=$ui.Chain.ForeColor; $ui.Chain.ScrollToCaret()
    }
    function script:Sbc-State { param([string]$Text,$Color) $ui=$script:SbcUi; if (-not $ui) { return }; if (-not $Color) { $Color=$ui.Colors.Gray }; $ui.State.Text=$Text; $ui.State.ForeColor=$Color; [System.Windows.Forms.Application]::DoEvents() }
    function script:Sbc-Confirm { param([string]$Message) return (Confirm-ToolkitWrite -Title 'Confirm SBC write' -Message $Message) }
    function script:Sbc-CmdParams { param([string]$Cmdlet,[hashtable]$Fields) return (Select-CmdletParams -Cmdlet $Cmdlet -Params $Fields) }
    function script:Sbc-InvokeWithRetry { param([scriptblock]$Action,[string]$What='call')
        return (Invoke-WithRetry -Action $Action -RetryProfile 'Lis' -OnRetry {
            param($Attempt,$DelayMs,$Err) Sbc-State ("{0}: transient failure, retry {1} in {2} ms" -f $What,$Attempt,$DelayMs) $script:SbcUi.Colors.Amber
        })
    }

    function script:Sbc-Probe {
    <#
    .SYNOPSIS
        OK | NoCmdlet | Denied | Error - what the connected identity can do with
        one area's Get-Cs* cmdlet, without assuming a role from its name.
    #>
        param([string]$Area,[string]$Cmdlet)
        if (-not (Test-CmdletPresent -Name $Cmdlet)) { $script:SbcCaps[$Area]='NoCmdlet'; return 'NoCmdlet' }
        try { & $Cmdlet -ErrorAction Stop | Out-Null; $script:SbcCaps[$Area]='OK'; return 'OK' }
        catch {
            $cls = Get-ErrorClass $_
            if ($cls -eq 'Permission') { $script:SbcCaps[$Area]='Denied'; return 'Denied' }
            $script:SbcCaps[$Area]='Error'; return 'Error'
        }
    }
    function script:Sbc-CapLabel { param([string]$Cap)
        switch ($Cap) { 'OK'{'available'} 'NoCmdlet'{'cmdlet not in module'} 'Denied'{'denied by role'} default {'error'} }
    }
    function script:Sbc-WriteHint {
    <#
    .SYNOPSIS
        Turn a write failure into the specific role most likely missing.
    .DESCRIPTION
        Reads and most writes are covered by Teams Telephony Administrator; a
        few tenant-scoped items - trusted IPs in particular - may need Teams
        Administrator. This does not assume which one is missing; it names both
        candidates and lets the operator narrow it down from there.
    #>
        param([string]$Area,$ErrorRecord)
        $cls = Get-ErrorClass $ErrorRecord
        if ($cls -ne 'Permission') { return "$($ErrorRecord.Exception.Message)" }
        if ($Area -eq 'TrustedIP') {
            return 'Denied. Trusted IP writes are tenant-scoped and may require Teams Administrator even when Teams Telephony Administrator covers the rest of this tab.'
        }
        return 'Denied. This write needs Teams Telephony Administrator (or Teams Administrator) on the connected identity.'
    }
    function script:Sbc-UpdateCapsLabel {
        $ui=$script:SbcUi
        $parts = foreach ($a in @('Gateway','Usage','Route','Policy','TrustedIP')) {
            $c = $script:SbcCaps[$a]; if (-not $c) { continue }
            "$a`:$(Sbc-CapLabel $c)"
        }
        $ui.Caps.Text = ($parts -join '   ')
    }

    function script:Sbc-Pull {
        $ui=$script:SbcUi
        if (-not $script:RbacConnected) { Sbc-State 'Connect RBAC first.' $ui.Colors.Amber; return }
        $ui.Pull.Enabled=$false
        try {
            Sbc-State 'Pulling gateways...' $ui.Colors.Purple
            Sbc-Probe 'Gateway' 'Get-CsOnlinePSTNGateway' | Out-Null
            $script:SbcGateways = @(Sbc-InvokeWithRetry -What 'Get-CsOnlinePSTNGateway' -Action { Get-CsOnlinePSTNGateway -ErrorAction Stop })

            Sbc-State 'Pulling PSTN usages...' $ui.Colors.Purple
            Sbc-Probe 'Usage' 'Get-CsOnlinePstnUsage' | Out-Null
            $u = Sbc-InvokeWithRetry -What 'Get-CsOnlinePstnUsage' -Action { Get-CsOnlinePstnUsage -ErrorAction Stop }
            $script:SbcUsages = @(@($u.Usage))

            Sbc-State 'Pulling voice routes...' $ui.Colors.Purple
            Sbc-Probe 'Route' 'Get-CsOnlineVoiceRoute' | Out-Null
            $script:SbcRoutes = @(Sbc-InvokeWithRetry -What 'Get-CsOnlineVoiceRoute' -Action { Get-CsOnlineVoiceRoute -ErrorAction Stop })

            Sbc-State 'Pulling routing policies...' $ui.Colors.Purple
            Sbc-Probe 'Policy' 'Get-CsOnlineVoiceRoutingPolicy' | Out-Null
            $script:SbcPolicies = @(Sbc-InvokeWithRetry -What 'Get-CsOnlineVoiceRoutingPolicy' -Action { Get-CsOnlineVoiceRoutingPolicy -ErrorAction Stop })

            Sbc-State 'Pulling trusted IPs...' $ui.Colors.Purple
            $tcap = Sbc-Probe 'TrustedIP' 'Get-CsTenantTrustedIPAddress'
            if ($tcap -eq 'OK') { $script:SbcTrustedIp = @(Sbc-InvokeWithRetry -What 'Get-CsTenantTrustedIPAddress' -Action { Get-CsTenantTrustedIPAddress -ErrorAction Stop }) }
            else { $script:SbcTrustedIp = @() }

            Sbc-UpdateCapsLabel
            Sbc-FillAllGrids
            Sbc-State ("Gateways {0}  Usages {1}  Routes {2}  Policies {3}  Trusted IPs {4}" -f `
                $script:SbcGateways.Count,$script:SbcUsages.Count,$script:SbcRoutes.Count,$script:SbcPolicies.Count,$script:SbcTrustedIp.Count) $ui.Colors.Green
        }
        catch { Sbc-State "Pull failed [$(Get-ErrorClass $_)]: $($_.Exception.Message)" $ui.Colors.Red }
        finally { $ui.Pull.Enabled=$true }
    }

    function script:Sbc-RouteUsageNames { param($Route) @(Get-PropTolerant $Route @('OnlinePstnUsages') $null) | Where-Object { $_ } }
    function script:Sbc-RouteGwNames    { param($Route) @(Get-PropTolerant $Route @('OnlinePstnGatewayList','Gateways') $null) | ForEach-Object { "$_" } }

    function script:Sbc-FillAllGrids {
        $ui=$script:SbcUi

        $ui.GridGw.Rows.Clear()
        foreach ($g in @($script:SbcGateways)) {
            $fqdn="$(Get-PropTolerant $g @('Fqdn','Identity'))"
            $usedByRoutes = @(@($script:SbcRoutes) | Where-Object { (Sbc-RouteGwNames $_) -contains $fqdn }).Count
            [void]$ui.GridGw.Rows.Add($fqdn,"$(Get-PropTolerant $g @('Enabled'))","$(Get-PropTolerant $g @('SipSignalingPort'))","$(Get-PropTolerant $g @('MediaBypass'))","$(Get-PropTolerant $g @('MaxConcurrentSessions'))","$(Get-PropTolerant $g @('SendSipOptions'))","$(Get-PropTolerant $g @('ForwardPai'))","$(Get-PropTolerant $g @('FailoverTimeSeconds'))",$usedByRoutes)
        }

        $ui.GridUsage.Rows.Clear()
        foreach ($u in @($script:SbcUsages)) {
            $byRoutes = @(@($script:SbcRoutes) | Where-Object { (Sbc-RouteUsageNames $_) -contains $u }).Count
            $byPolicies = @(@($script:SbcPolicies) | Where-Object { @(Get-PropTolerant $_ @('OnlinePstnUsages') $null) -contains $u }).Count
            [void]$ui.GridUsage.Rows.Add($u,$byRoutes,$byPolicies,$(if ($byRoutes -gt 0) {'carried'} else {'unused'}))
        }

        $ui.GridRoute.Rows.Clear()
        foreach ($r in (@($script:SbcRoutes) | Sort-Object { [int](Get-PropTolerant $_ @('Priority') 0) })) {
            [void]$ui.GridRoute.Rows.Add("$(Get-PropTolerant $r @('Priority'))","$(Get-PropTolerant $r @('Identity','Name'))","$(Get-PropTolerant $r @('NumberPattern'))",((Sbc-RouteUsageNames $r) -join ', '),((Sbc-RouteGwNames $r) -join ', '),"$(Get-PropTolerant $r @('Description'))")
        }

        $ui.GridPol.Rows.Clear()
        foreach ($p in @($script:SbcPolicies)) {
            $usages = @(Get-PropTolerant $p @('OnlinePstnUsages') $null)
            $reachable = @(@($script:SbcRoutes) | Where-Object { $ru=(Sbc-RouteUsageNames $_); ($ru | Where-Object { $usages -contains $_ }) }) | ForEach-Object { Sbc-RouteGwNames $_ } | Select-Object -Unique
            [void]$ui.GridPol.Rows.Add("$(Get-PropTolerant $p @('Identity'))",($usages -join ', '),($reachable -join ', '),"$(Get-PropTolerant $p @('Description'))")
        }

        $ui.GridTrust.Rows.Clear()
        foreach ($t in @($script:SbcTrustedIp)) {
            [void]$ui.GridTrust.Rows.Add("$(Get-PropTolerant $t @('IPAddress'))","$(Get-PropTolerant $t @('MaskBits'))","$(Get-PropTolerant $t @('Description'))")
        }

        $ui.SimPol.Items.Clear()
        foreach ($p in @($script:SbcPolicies)) { [void]$ui.SimPol.Items.Add("$(Get-PropTolerant $p @('Identity'))") }
        if ($ui.SimPol.Items.Count -gt 0) { $ui.SimPol.SelectedIndex=0 }

        $ui.RUsage.Items.Clear(); foreach ($u in @($script:SbcUsages)) { [void]$ui.RUsage.Items.Add($u) }
        $gwNames = @(@($script:SbcGateways) | ForEach-Object { "$(Get-PropTolerant $_ @('Fqdn','Identity'))" })
        $ui.RGw.Items.Clear(); foreach ($g in $gwNames) { [void]$ui.RGw.Items.Add($g) }
        $ui.PUsage.Items.Clear(); foreach ($u in @($script:SbcUsages)) { [void]$ui.PUsage.Items.Add($u) }
    }

    function script:Sbc-Validate {
    <#
    .SYNOPSIS
        Run the thirteen documented topology checks and render the routing chain.
    #>
        $ui=$script:SbcUi
        $ui.GridFind.Rows.Clear()
        function addf($sev,$area,$obj,$finding,$impact) { [void]$ui.GridFind.Rows.Add($sev,$area,$obj,$finding,$impact) }

        $gwByName = @{}
        foreach ($g in @($script:SbcGateways)) { $gwByName["$(Get-PropTolerant $g @('Fqdn','Identity'))"]=$g }

        # Gateway checks
        foreach ($g in @($script:SbcGateways)) {
            $fqdn="$(Get-PropTolerant $g @('Fqdn','Identity'))"
            $refs = @($script:SbcRoutes) | Where-Object { (Sbc-RouteGwNames $_) -contains $fqdn }
            if ($refs.Count -eq 0) { addf 'WARN' 'Gateway' $fqdn 'Not referenced by any voice route' 'Unused gateway - safe to review for removal' }
            $enabled = "$(Get-PropTolerant $g @('Enabled'))" -eq 'True'
            if (-not $enabled -and $refs.Count -gt 0) { addf 'ERROR' 'Gateway' $fqdn "Disabled but referenced by $($refs.Count) route(s)" 'Calls on those routes will fail to this gateway' }
        }

        # Route checks
        foreach ($r in @($script:SbcRoutes)) {
            $name="$(Get-PropTolerant $r @('Identity','Name'))"
            $gwList = Sbc-RouteGwNames $r
            $usageList = Sbc-RouteUsageNames $r
            if ($gwList.Count -eq 0) { addf 'ERROR' 'Route' $name 'No gateway assigned' 'Calls matching this route have nowhere to go' }
            if ($usageList.Count -eq 0) { addf 'ERROR' 'Route' $name 'No PSTN usage assigned' 'No routing policy can ever select this route' }
            foreach ($u in $usageList) { if ($script:SbcUsages -notcontains $u) { addf 'ERROR' 'Route' $name "References a usage not in the tenant usage list: $u" 'Broken reference - fix or remove' } }
            foreach ($gw in $gwList) { if (-not $gwByName.ContainsKey($gw)) { addf 'ERROR' 'Route' $name "References a gateway that does not exist: $gw" 'Broken reference - calls will fail' } }
            $pat = "$(Get-PropTolerant $r @('NumberPattern'))"
            if ([string]::IsNullOrWhiteSpace($pat)) { addf 'WARN' 'Route' $name 'Empty number pattern' 'Route will not match any dialled number' }
            else { try { [void][regex]::new($pat) } catch { addf 'ERROR' 'Route' $name "Number pattern is not a valid regular expression: $pat" 'Route will error or never match' } }
        }
        # duplicate priority within a shared usage
        $byPriUsage = @{}
        foreach ($r in @($script:SbcRoutes)) {
            $pri = "$(Get-PropTolerant $r @('Priority'))"
            foreach ($u in (Sbc-RouteUsageNames $r)) {
                $k="$u|$pri"
                if (-not $byPriUsage.ContainsKey($k)) { $byPriUsage[$k]=New-Object System.Collections.Generic.List[string] }
                $byPriUsage[$k].Add("$(Get-PropTolerant $r @('Identity','Name'))")
            }
        }
        foreach ($k in $byPriUsage.Keys) {
            if ($byPriUsage[$k].Count -gt 1) {
                $parts=$k -split '\|'
                addf 'WARN' 'Route' ($byPriUsage[$k] -join ', ') "Multiple routes share priority $($parts[1]) on usage $($parts[0])" 'Order between them is undefined'
            }
        }

        # Usage checks
        foreach ($u in @($script:SbcUsages)) {
            $carried = @(@($script:SbcRoutes) | Where-Object { (Sbc-RouteUsageNames $_) -contains $u }).Count
            if ($carried -eq 0) { addf 'WARN' 'Usage' $u 'Not carried by any voice route' 'Dead usage until a route picks it up' }
            $granted = @(@($script:SbcPolicies) | Where-Object { @(Get-PropTolerant $_ @('OnlinePstnUsages') $null) -contains $u }).Count
            if ($granted -eq 0) { addf 'INFO' 'Usage' $u 'Not referenced by any routing policy' 'No user can be granted this usage yet' }
        }

        # Policy checks
        foreach ($p in @($script:SbcPolicies)) {
            $name="$(Get-PropTolerant $p @('Identity'))"
            $usages = @(Get-PropTolerant $p @('OnlinePstnUsages') $null)
            if ($usages.Count -eq 0) { addf 'ERROR' 'Policy' $name 'No PSTN usages assigned' 'Users on this policy cannot place PSTN calls' }
            else {
                $reachable = @($script:SbcRoutes) | Where-Object { $ru=(Sbc-RouteUsageNames $_); ($ru | Where-Object { $usages -contains $_ }) -and (Sbc-RouteGwNames $_).Count -gt 0 }
                if ($reachable.Count -eq 0) { addf 'ERROR' 'Policy' $name 'Usages resolve to no reachable gateway' 'Users on this policy cannot complete PSTN calls' }
            }
        }

        # Chain rendering
        $sb=New-Object System.Text.StringBuilder
        [void]$sb.AppendLine('ROUTING CHAIN: policy -> usage -> route -> gateway')
        [void]$sb.AppendLine(('=' * 60))
        foreach ($p in @($script:SbcPolicies)) {
            $pname="$(Get-PropTolerant $p @('Identity'))"
            [void]$sb.AppendLine("POLICY $pname")
            foreach ($u in @(Get-PropTolerant $p @('OnlinePstnUsages') $null)) {
                [void]$sb.AppendLine("  USAGE $u")
                $routes = @($script:SbcRoutes) | Where-Object { (Sbc-RouteUsageNames $_) -contains $u } | Sort-Object { [int](Get-PropTolerant $_ @('Priority') 0) }
                foreach ($r in $routes) {
                    [void]$sb.AppendLine("    ROUTE $(Get-PropTolerant $r @('Identity','Name')) (priority $(Get-PropTolerant $r @('Priority')))")
                    foreach ($gw in (Sbc-RouteGwNames $r)) {
                        $g = $gwByName[$gw]
                        $state = if (-not $g) { 'MISSING' } elseif ("$(Get-PropTolerant $g @('Enabled'))" -eq 'True') { 'enabled' } else { 'disabled' }
                        $tag = if ($state -eq 'enabled') { '[OK]' } else { '[X]' }
                        [void]$sb.AppendLine("      $tag GATEWAY $gw ($state)")
                    }
                }
            }
        }
        $ui.Chain.Clear()
        $ui.Chain.SelectionColor=[System.Drawing.Color]::Black
        foreach ($line in ($sb.ToString() -split "`n")) {
            $color=[System.Drawing.Color]::Black
            if ($line -match '\[OK\]') { $color=$ui.Colors.Green }
            elseif ($line -match '\[X\]|MISSING') { $color=$ui.Colors.Red }
            $ui.Chain.SelectionColor=$color
            $ui.Chain.AppendText("$line`n")
        }
        $errCount=@($ui.GridFind.Rows | Where-Object { $_.Cells['Severity'].Value -eq 'ERROR' }).Count
        $warnCount=@($ui.GridFind.Rows | Where-Object { $_.Cells['Severity'].Value -eq 'WARN' }).Count
        Sbc-State "Validate: $errCount error(s), $warnCount warning(s)" $(if ($errCount -gt 0) { $ui.Colors.Red } elseif ($warnCount -gt 0) { $ui.Colors.Amber } else { $ui.Colors.Green })
    }

    function script:Sbc-Export {
        $ui=$script:SbcUi
        $stamp=Get-Stamp; $key=Get-EnvKey
        $snap=[ordered]@{
            Tenant=$script:CurrentEnv; TenantId=$script:TenantId; ExportedUtc=(Get-Date).ToUniversalTime().ToString('s')+'Z'
            Gateways=@($script:SbcGateways); PstnUsages=@($script:SbcUsages); VoiceRoutes=@($script:SbcRoutes)
            RoutingPolicies=@($script:SbcPolicies); TrustedIPs=@($script:SbcTrustedIp)
        }
        $path = Get-OutputPath -Area PolicyBackups -File ("SBC_Topology_{0}_{1}.json" -f $key,$stamp)
        try {
            $snap | ConvertTo-Json -Depth 30 | Set-Content -Path $path -Encoding UTF8
            Sbc-Say "Topology exported -> $([IO.Path]::GetFileName($path))" $ui.Colors.Green
            Open-OutputFolder -Path $path -Label 'SBC topology' -SelectFile
        } catch { Sbc-Say "Export failed: $($_.Exception.Message)" $ui.Colors.Red }
    }

    # ---- writes: gateways -----------------------------------------------------
    function script:Sbc-CreateGateway {
        $ui=$script:SbcUi
        if ([string]::IsNullOrWhiteSpace($ui.GwFields['Fqdn'].Text)) { Sbc-Say 'FQDN is required.' $ui.Colors.Amber; return }
        if (-not (Sbc-Confirm "Create gateway`n`n$($ui.GwFields['Fqdn'].Text)`n`nTenant: $($script:CurrentEnv)")) { return }
        $fields=@{}
        foreach ($k in $ui.GwFields.Keys) { $c=$ui.GwFields[$k]; $fields[$k]=$(if ($c -is [System.Windows.Forms.CheckBox]) { $c.Checked } else { $c.Text }) }
        $p = Sbc-CmdParams -Cmdlet 'New-CsOnlinePSTNGateway' -Fields $fields
        try {
            Sbc-InvokeWithRetry -What 'New-CsOnlinePSTNGateway' -Action { New-CsOnlinePSTNGateway @p -ErrorAction Stop } | Out-Null
            Sbc-Say "Created gateway $($ui.GwFields['Fqdn'].Text)" $ui.Colors.Green
            Sbc-Pull
        } catch { Sbc-Say "Create gateway failed: $(Sbc-WriteHint 'Gateway' $_)" $ui.Colors.Red }
    }
    function script:Sbc-UpdateGateway {
        $ui=$script:SbcUi
        if (-not $script:SbcSelGw) { Sbc-Say 'Select a gateway first.' $ui.Colors.Amber; return }
        $fqdn="$(Get-PropTolerant $script:SbcSelGw @('Fqdn','Identity'))"
        if (-not (Sbc-Confirm "Update gateway`n`n$fqdn`n`nTenant: $($script:CurrentEnv)")) { return }
        $fields=@{ Identity=$fqdn }
        foreach ($k in $ui.GwFields.Keys) { if ($k -eq 'Fqdn') { continue }; $c=$ui.GwFields[$k]; $fields[$k]=$(if ($c -is [System.Windows.Forms.CheckBox]) { $c.Checked } else { $c.Text }) }
        $p = Sbc-CmdParams -Cmdlet 'Set-CsOnlinePSTNGateway' -Fields $fields
        try {
            Sbc-InvokeWithRetry -What 'Set-CsOnlinePSTNGateway' -Action { Set-CsOnlinePSTNGateway @p -ErrorAction Stop } | Out-Null
            Sbc-Say "Updated gateway $fqdn" $ui.Colors.Green
            Sbc-Pull
        } catch { Sbc-Say "Update gateway failed: $(Sbc-WriteHint 'Gateway' $_)" $ui.Colors.Red }
    }
    function script:Sbc-DeleteGateway {
        $ui=$script:SbcUi
        if (-not $script:SbcSelGw) { Sbc-Say 'Select a gateway first.' $ui.Colors.Amber; return }
        $fqdn="$(Get-PropTolerant $script:SbcSelGw @('Fqdn','Identity'))"
        $refs = @(@($script:SbcRoutes) | Where-Object { (Sbc-RouteGwNames $_) -contains $fqdn })
        if ($refs.Count -gt 0) {
            [void][System.Windows.Forms.MessageBox]::Show("$($refs.Count) voice route(s) still reference this gateway. Remove it from those routes first.",'Delete blocked',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        if (-not (Sbc-Confirm "DELETE gateway`n`n$fqdn`n`nTenant: $($script:CurrentEnv)")) { return }
        try {
            Sbc-InvokeWithRetry -What 'Remove-CsOnlinePSTNGateway' -Action { Remove-CsOnlinePSTNGateway -Identity $fqdn -ErrorAction Stop } | Out-Null
            Sbc-Say "Deleted gateway $fqdn" $ui.Colors.Green
            Sbc-Pull
        } catch { Sbc-Say "Delete gateway failed: $(Sbc-WriteHint 'Gateway' $_)" $ui.Colors.Red }
    }

    # ---- writes: usages, routes, policies, trusted IPs ------------------------
    function script:Sbc-AddUsage {
        $ui=$script:SbcUi; $name=$ui.UsageName.Text
        if ([string]::IsNullOrWhiteSpace($name)) { return }
        if (-not (Sbc-Confirm "Add PSTN usage`n`n$name`n`nTenant: $($script:CurrentEnv)")) { return }
        try {
            $cur = Get-CsOnlinePstnUsage -ErrorAction Stop
            $list = @($cur.Usage) + @($name) | Select-Object -Unique
            Sbc-InvokeWithRetry -What 'Set-CsOnlinePstnUsage' -Action { Set-CsOnlinePstnUsage -Identity Global -Usage $list -ErrorAction Stop } | Out-Null
            Sbc-Say "Added usage $name" $ui.Colors.Green; Sbc-Pull
        } catch { Sbc-Say "Add usage failed: $(Sbc-WriteHint 'Usage' $_)" $ui.Colors.Red }
    }
    function script:Sbc-RemoveUsage {
        $ui=$script:SbcUi
        if ($ui.GridUsage.SelectedRows.Count -lt 1) { return }
        $name="$($ui.GridUsage.SelectedRows[0].Cells['Usage'].Value)"
        $byRoutes="$($ui.GridUsage.SelectedRows[0].Cells['UsedByRoutes'].Value)"
        $byPolicies="$($ui.GridUsage.SelectedRows[0].Cells['UsedByPolicies'].Value)"
        if (([int]$byRoutes -gt 0) -or ([int]$byPolicies -gt 0)) {
            if (-not (Sbc-Confirm "'$name' is still referenced by $byRoutes route(s) and $byPolicies polic(y/ies). Removing it will break those paths.`n`nRemove anyway?")) { return }
        } else {
            if (-not (Sbc-Confirm "Remove PSTN usage`n`n$name`n`nTenant: $($script:CurrentEnv)")) { return }
        }
        try {
            $cur = Get-CsOnlinePstnUsage -ErrorAction Stop
            $list = @($cur.Usage) | Where-Object { $_ -ne $name }
            Sbc-InvokeWithRetry -What 'Set-CsOnlinePstnUsage' -Action { Set-CsOnlinePstnUsage -Identity Global -Usage $list -ErrorAction Stop } | Out-Null
            Sbc-Say "Removed usage $name" $ui.Colors.Green; Sbc-Pull
        } catch { Sbc-Say "Remove usage failed: $(Sbc-WriteHint 'Usage' $_)" $ui.Colors.Red }
    }

    function script:Sbc-CreateRoute {
        $ui=$script:SbcUi
        if ([string]::IsNullOrWhiteSpace($ui.RName.Text)) { Sbc-Say 'Route name is required.' $ui.Colors.Amber; return }
        $usages = @($ui.RUsage.CheckedItems); $gws = @($ui.RGw.CheckedItems)
        if (-not (Sbc-Confirm "Create voice route`n`n$($ui.RName.Text)`n`nTenant: $($script:CurrentEnv)")) { return }
        $fields=@{ Identity=$ui.RName.Text; NumberPattern=$ui.RPat.Text; Priority=[int]$ui.RPri.Value; Description=$ui.RDesc.Text; OnlinePstnUsages=$usages; OnlinePstnGatewayList=$gws }
        $p = Sbc-CmdParams -Cmdlet 'New-CsOnlineVoiceRoute' -Fields $fields
        try {
            Sbc-InvokeWithRetry -What 'New-CsOnlineVoiceRoute' -Action { New-CsOnlineVoiceRoute @p -ErrorAction Stop } | Out-Null
            Sbc-Say "Created route $($ui.RName.Text)" $ui.Colors.Green; Sbc-Pull
        } catch { Sbc-Say "Create route failed: $(Sbc-WriteHint 'Route' $_)" $ui.Colors.Red }
    }
    function script:Sbc-UpdateRoute {
        $ui=$script:SbcUi
        if (-not $script:SbcSelRoute) { Sbc-Say 'Select a route first.' $ui.Colors.Amber; return }
        $name="$(Get-PropTolerant $script:SbcSelRoute @('Identity','Name'))"
        if (-not (Sbc-Confirm "Update voice route`n`n$name`n`nTenant: $($script:CurrentEnv)")) { return }
        $usages = @($ui.RUsage.CheckedItems); $gws = @($ui.RGw.CheckedItems)
        $fields=@{ Identity=$name; NumberPattern=$ui.RPat.Text; Priority=[int]$ui.RPri.Value; Description=$ui.RDesc.Text; OnlinePstnUsages=$usages; OnlinePstnGatewayList=$gws }
        $p = Sbc-CmdParams -Cmdlet 'Set-CsOnlineVoiceRoute' -Fields $fields
        try {
            Sbc-InvokeWithRetry -What 'Set-CsOnlineVoiceRoute' -Action { Set-CsOnlineVoiceRoute @p -ErrorAction Stop } | Out-Null
            Sbc-Say "Updated route $name" $ui.Colors.Green; Sbc-Pull
        } catch { Sbc-Say "Update route failed: $(Sbc-WriteHint 'Route' $_)" $ui.Colors.Red }
    }
    function script:Sbc-DeleteRoute {
        $ui=$script:SbcUi
        if (-not $script:SbcSelRoute) { Sbc-Say 'Select a route first.' $ui.Colors.Amber; return }
        $name="$(Get-PropTolerant $script:SbcSelRoute @('Identity','Name'))"
        if (-not (Sbc-Confirm "DELETE voice route`n`n$name`n`nTenant: $($script:CurrentEnv)")) { return }
        try {
            Sbc-InvokeWithRetry -What 'Remove-CsOnlineVoiceRoute' -Action { Remove-CsOnlineVoiceRoute -Identity $name -ErrorAction Stop } | Out-Null
            Sbc-Say "Deleted route $name" $ui.Colors.Green; Sbc-Pull
        } catch { Sbc-Say "Delete route failed: $(Sbc-WriteHint 'Route' $_)" $ui.Colors.Red }
    }
    function script:Sbc-TestPattern {
        $ui=$script:SbcUi
        $pat=$ui.RPat.Text
        $num=[Microsoft.VisualBasic.Interaction]::InputBox('Number to test the pattern against:', 'Test Pattern', '+13475551212')
        if ([string]::IsNullOrWhiteSpace($num)) { return }
        try {
            $rx=[regex]::new($pat)
            $m=$rx.IsMatch($num)
            [void][System.Windows.Forms.MessageBox]::Show("Pattern: $pat`nNumber: $num`n`nMatch: $m",'Test Pattern',[System.Windows.Forms.MessageBoxButtons]::OK,$(if($m){[System.Windows.Forms.MessageBoxIcon]::Information}else{[System.Windows.Forms.MessageBoxIcon]::Warning}))
        } catch { [void][System.Windows.Forms.MessageBox]::Show("Not a valid regular expression: $($_.Exception.Message)",'Test Pattern',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) }
    }

    function script:Sbc-CreatePolicy {
        $ui=$script:SbcUi
        if ([string]::IsNullOrWhiteSpace($ui.PName.Text)) { Sbc-Say 'Policy name is required.' $ui.Colors.Amber; return }
        $usages=@($ui.PUsage.CheckedItems)
        if (-not (Sbc-Confirm "Create routing policy`n`n$($ui.PName.Text)`n`nTenant: $($script:CurrentEnv)")) { return }
        $fields=@{ Identity=$ui.PName.Text; Description=$ui.PDesc.Text; OnlinePstnUsages=$usages }
        $p = Sbc-CmdParams -Cmdlet 'New-CsOnlineVoiceRoutingPolicy' -Fields $fields
        try {
            Sbc-InvokeWithRetry -What 'New-CsOnlineVoiceRoutingPolicy' -Action { New-CsOnlineVoiceRoutingPolicy @p -ErrorAction Stop } | Out-Null
            Sbc-Say "Created policy $($ui.PName.Text)" $ui.Colors.Green; Sbc-Pull
        } catch { Sbc-Say "Create policy failed: $(Sbc-WriteHint 'Policy' $_)" $ui.Colors.Red }
    }
    function script:Sbc-UpdatePolicy {
        $ui=$script:SbcUi
        if (-not $script:SbcSelPolicy) { Sbc-Say 'Select a policy first.' $ui.Colors.Amber; return }
        $name="$(Get-PropTolerant $script:SbcSelPolicy @('Identity'))"
        if (-not (Sbc-Confirm "Update routing policy`n`n$name`n`nTenant: $($script:CurrentEnv)")) { return }
        $usages=@($ui.PUsage.CheckedItems)
        $fields=@{ Identity=$name; Description=$ui.PDesc.Text; OnlinePstnUsages=$usages }
        $p = Sbc-CmdParams -Cmdlet 'Set-CsOnlineVoiceRoutingPolicy' -Fields $fields
        try {
            Sbc-InvokeWithRetry -What 'Set-CsOnlineVoiceRoutingPolicy' -Action { Set-CsOnlineVoiceRoutingPolicy @p -ErrorAction Stop } | Out-Null
            Sbc-Say "Updated policy $name" $ui.Colors.Green; Sbc-Pull
        } catch { Sbc-Say "Update policy failed: $(Sbc-WriteHint 'Policy' $_)" $ui.Colors.Red }
    }
    function script:Sbc-DeletePolicy {
        $ui=$script:SbcUi
        if (-not $script:SbcSelPolicy) { Sbc-Say 'Select a policy first.' $ui.Colors.Amber; return }
        $name="$(Get-PropTolerant $script:SbcSelPolicy @('Identity'))"
        if (-not (Sbc-Confirm "DELETE routing policy`n`n$name`n`nTenant: $($script:CurrentEnv)")) { return }
        try {
            Sbc-InvokeWithRetry -What 'Remove-CsOnlineVoiceRoutingPolicy' -Action { Remove-CsOnlineVoiceRoutingPolicy -Identity $name -ErrorAction Stop } | Out-Null
            Sbc-Say "Deleted policy $name" $ui.Colors.Green; Sbc-Pull
        } catch { Sbc-Say "Delete policy failed: $(Sbc-WriteHint 'Policy' $_)" $ui.Colors.Red }
    }
    function script:Sbc-GrantPolicy {
        $ui=$script:SbcUi
        if (-not $script:SbcSelPolicy) { Sbc-Say 'Select a policy first.' $ui.Colors.Amber; return }
        if ([string]::IsNullOrWhiteSpace($ui.PGrant.Text)) { return }
        $name="$(Get-PropTolerant $script:SbcSelPolicy @('Identity'))"
        if (-not (Sbc-Confirm "Grant '$name' to $($ui.PGrant.Text)?")) { return }
        try {
            Sbc-InvokeWithRetry -What 'Grant-CsOnlineVoiceRoutingPolicy' -Action { Grant-CsOnlineVoiceRoutingPolicy -Identity $ui.PGrant.Text -PolicyName $name -ErrorAction Stop } | Out-Null
            Sbc-Say "Granted $name to $($ui.PGrant.Text)" $ui.Colors.Green
        } catch { Sbc-Say "Grant failed: $(Sbc-WriteHint 'Policy' $_)" $ui.Colors.Red }
    }
    function script:Sbc-ResetPolicy {
        $ui=$script:SbcUi
        if ([string]::IsNullOrWhiteSpace($ui.PGrant.Text)) { return }
        if (-not (Sbc-Confirm "Reset $($ui.PGrant.Text) to Global routing policy?")) { return }
        try {
            Sbc-InvokeWithRetry -What 'Grant-CsOnlineVoiceRoutingPolicy' -Action { Grant-CsOnlineVoiceRoutingPolicy -Identity $ui.PGrant.Text -PolicyName $null -ErrorAction Stop } | Out-Null
            Sbc-Say "Reset $($ui.PGrant.Text) to Global" $ui.Colors.Green
        } catch { Sbc-Say "Reset failed: $(Sbc-WriteHint 'Policy' $_)" $ui.Colors.Red }
    }

    function script:Sbc-AddTrustedIp {
        $ui=$script:SbcUi
        if ([string]::IsNullOrWhiteSpace($ui.TIp.Text)) { return }
        if (-not (Sbc-Confirm "Add trusted IP`n`n$($ui.TIp.Text)/$([int]$ui.TMask.Value)`n`nTenant: $($script:CurrentEnv)")) { return }
        $fields=@{ IPAddress=$ui.TIp.Text; MaskBits=[int]$ui.TMask.Value; Description=$ui.TDesc.Text }
        $p = Sbc-CmdParams -Cmdlet 'New-CsTenantTrustedIPAddress' -Fields $fields
        try {
            Sbc-InvokeWithRetry -What 'New-CsTenantTrustedIPAddress' -Action { New-CsTenantTrustedIPAddress @p -ErrorAction Stop } | Out-Null
            Sbc-Say "Added trusted IP $($ui.TIp.Text)" $ui.Colors.Green; Sbc-Pull
        } catch { Sbc-Say "Add trusted IP failed: $(Sbc-WriteHint 'TrustedIP' $_)" $ui.Colors.Red }
    }
    function script:Sbc-RemoveTrustedIp {
        $ui=$script:SbcUi
        if ($ui.GridTrust.SelectedRows.Count -lt 1) { return }
        $ip="$($ui.GridTrust.SelectedRows[0].Cells['IPAddress'].Value)"
        $mask="$($ui.GridTrust.SelectedRows[0].Cells['MaskBits'].Value)"
        if (-not (Sbc-Confirm "Remove trusted IP`n`n$ip/$mask`n`nTenant: $($script:CurrentEnv)")) { return }
        try {
            # Remove-CsTenantTrustedIPAddress takes -Identity (the IP address
            # itself, as a string) - there is no -IPAddress/-MaskBits pair on
            # this cmdlet, unlike New-/Set-.
            Sbc-InvokeWithRetry -What 'Remove-CsTenantTrustedIPAddress' -Action { Remove-CsTenantTrustedIPAddress -Identity $ip -ErrorAction Stop } | Out-Null
            Sbc-Say "Removed trusted IP $ip/$mask" $ui.Colors.Green; Sbc-Pull
        } catch { Sbc-Say "Remove trusted IP failed: $(Sbc-WriteHint 'TrustedIP' $_)" $ui.Colors.Red }
    }

    function script:Sbc-SimulateLocal {
    <#
    .SYNOPSIS
        Evaluate the cached topology in policy + usage + route-priority order,
        entirely locally - no tenant call.
    #>
        $ui=$script:SbcUi
        $num=$ui.SimNum.Text
        $polName="$($ui.SimPol.SelectedItem)"
        if ([string]::IsNullOrWhiteSpace($num) -or [string]::IsNullOrWhiteSpace($polName)) { return }
        $pol = @($script:SbcPolicies) | Where-Object { "$(Get-PropTolerant $_ @('Identity'))" -eq $polName } | Select-Object -First 1
        $sb=New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("Local trace: $num against policy $polName")
        [void]$sb.AppendLine(('=' * 50))
        if (-not $pol) { [void]$sb.AppendLine('Policy not found in cache.'); $ui.SimOut.Text=$sb.ToString(); return }
        $usages = @(Get-PropTolerant $pol @('OnlinePstnUsages') $null)
        $matched=$false
        foreach ($u in $usages) {
            [void]$sb.AppendLine("usage: $u")
            $routes = @($script:SbcRoutes) | Where-Object { (Sbc-RouteUsageNames $_) -contains $u } | Sort-Object { [int](Get-PropTolerant $_ @('Priority') 0) }
            foreach ($r in $routes) {
                $pat="$(Get-PropTolerant $r @('NumberPattern'))"
                $isMatch=$false
                try { $isMatch=[regex]::new($pat).IsMatch($num) } catch {}
                $tag=if ($isMatch) {'MATCH'} else {'no match'}
                [void]$sb.AppendLine("  route $(Get-PropTolerant $r @('Identity','Name')) (priority $(Get-PropTolerant $r @('Priority')), pattern $pat) -> $tag")
                if ($isMatch -and -not $matched) {
                    $matched=$true
                    $gws = Sbc-RouteGwNames $r
                    [void]$sb.AppendLine("    LANDS ON: $($gws -join ', ')")
                }
            }
        }
        if (-not $matched) { [void]$sb.AppendLine('No route matched this number under this policy.') }
        $ui.SimOut.Text=$sb.ToString()
    }
    function script:Sbc-SimulateTenant {
    <#
    .SYNOPSIS
        Re-run the same local match logic against a fresh pull of the tenant's
        topology, rather than whatever is currently cached.
    .DESCRIPTION
        There is no documented Microsoft Teams module cmdlet that simulates
        routing server-side - Get-CsOnlineVoiceRoute, Get-CsOnlinePSTNGateway
        etc. are the only source of truth, and matching against them is exactly
        what Sbc-SimulateLocal already does. So "test against tenant" cannot
        mean "ask the tenant to simulate it" - it means "don't trust the cache,
        pull again, then simulate." That is a real, different guarantee (current
        data vs. possibly-stale data), not a workaround for a missing cmdlet.
    #>
        $ui=$script:SbcUi
        if (-not $script:RbacConnected) { Sbc-Say 'Connect RBAC first for a tenant-side test.' $ui.Colors.Amber; return }
        $ui.SimOut.AppendText("`nRe-pulling topology from the tenant before testing...`n")
        Sbc-Pull
        Sbc-SimulateLocal
        $ui.SimOut.AppendText("`n(tested against a fresh pull, not the prior cache)`n")
    }

    # ==========================================================================
    # HANDLERS
    # ==========================================================================
    $btnPull.Add_Click({ Sbc-Pull })
    $btnValidate.Add_Click({ Sbc-Validate })
    $btnExport.Add_Click({ Sbc-Export })
    $btnFolder.Add_Click({ Open-OutputFolder -Path (Get-OutputPath -Area PolicyBackups) -Label 'SBC output' })

    $gridGw.Add_SelectionChanged({
        if ($script:SbcUi.GridGw.SelectedRows.Count -lt 1) { return }
        $fqdn="$($script:SbcUi.GridGw.SelectedRows[0].Cells['FQDN'].Value)"
        $script:SbcSelGw = @($script:SbcGateways) | Where-Object { "$(Get-PropTolerant $_ @('Fqdn','Identity'))" -eq $fqdn } | Select-Object -First 1
        if ($script:SbcSelGw) {
            foreach ($k in $script:SbcUi.GwFields.Keys) {
                $c=$script:SbcUi.GwFields[$k]; $v=Get-PropTolerant $script:SbcSelGw @($k)
                if ($c -is [System.Windows.Forms.CheckBox]) { $c.Checked = ("$v" -eq 'True') } else { $c.Text="$v" }
            }
        }
    })
    $btnGwNew.Add_Click({ foreach ($c in $script:SbcUi.GwFields.Values) { if ($c -is [System.Windows.Forms.CheckBox]) { $c.Checked=$false } else { $c.Clear() } }; $script:SbcSelGw=$null })
    $btnGwCreate.Add_Click({ Sbc-CreateGateway })
    $btnGwUpdate.Add_Click({ Sbc-UpdateGateway })
    $btnGwDelete.Add_Click({ Sbc-DeleteGateway })

    $btnUsageAdd.Add_Click({ Sbc-AddUsage })
    $btnUsageRemove.Add_Click({ Sbc-RemoveUsage })

    $gridRoute.Add_SelectionChanged({
        if ($script:SbcUi.GridRoute.SelectedRows.Count -lt 1) { return }
        $name="$($script:SbcUi.GridRoute.SelectedRows[0].Cells['Name'].Value)"
        $script:SbcSelRoute = @($script:SbcRoutes) | Where-Object { "$(Get-PropTolerant $_ @('Identity','Name'))" -eq $name } | Select-Object -First 1
        if ($script:SbcSelRoute) {
            $ui=$script:SbcUi
            $ui.RName.Text="$(Get-PropTolerant $script:SbcSelRoute @('Identity','Name'))"
            $ui.RPat.Text="$(Get-PropTolerant $script:SbcSelRoute @('NumberPattern'))"
            $ui.RPri.Value=[Math]::Max(0,[int](Get-PropTolerant $script:SbcSelRoute @('Priority') 0))
            $ui.RDesc.Text="$(Get-PropTolerant $script:SbcSelRoute @('Description'))"
            $ru = Sbc-RouteUsageNames $script:SbcSelRoute; $rg = Sbc-RouteGwNames $script:SbcSelRoute
            for ($i=0;$i -lt $ui.RUsage.Items.Count;$i++) { $ui.RUsage.SetItemChecked($i, ($ru -contains $ui.RUsage.Items[$i])) }
            for ($i=0;$i -lt $ui.RGw.Items.Count;$i++) { $ui.RGw.SetItemChecked($i, ($rg -contains $ui.RGw.Items[$i])) }
        }
    })
    $btnRNew.Add_Click({ $ui=$script:SbcUi; $ui.RName.Clear(); $ui.RPat.Clear(); $ui.RPri.Value=0; $ui.RDesc.Clear(); for($i=0;$i -lt $ui.RUsage.Items.Count;$i++){$ui.RUsage.SetItemChecked($i,$false)}; for($i=0;$i -lt $ui.RGw.Items.Count;$i++){$ui.RGw.SetItemChecked($i,$false)}; $script:SbcSelRoute=$null })
    $btnRCreate.Add_Click({ Sbc-CreateRoute })
    $btnRUpdate.Add_Click({ Sbc-UpdateRoute })
    $btnRDelete.Add_Click({ Sbc-DeleteRoute })
    $btnRTest.Add_Click({ Sbc-TestPattern })

    $gridPol.Add_SelectionChanged({
        if ($script:SbcUi.GridPol.SelectedRows.Count -lt 1) { return }
        $name="$($script:SbcUi.GridPol.SelectedRows[0].Cells['Policy'].Value)"
        $script:SbcSelPolicy = @($script:SbcPolicies) | Where-Object { "$(Get-PropTolerant $_ @('Identity'))" -eq $name } | Select-Object -First 1
        if ($script:SbcSelPolicy) {
            $ui=$script:SbcUi
            $ui.PName.Text="$(Get-PropTolerant $script:SbcSelPolicy @('Identity'))"
            $ui.PDesc.Text="$(Get-PropTolerant $script:SbcSelPolicy @('Description'))"
            $usages=@(Get-PropTolerant $script:SbcSelPolicy @('OnlinePstnUsages') $null)
            for ($i=0;$i -lt $ui.PUsage.Items.Count;$i++) { $ui.PUsage.SetItemChecked($i, ($usages -contains $ui.PUsage.Items[$i])) }
        }
    })
    $btnPNew.Add_Click({ $ui=$script:SbcUi; $ui.PName.Clear(); $ui.PDesc.Clear(); for($i=0;$i -lt $ui.PUsage.Items.Count;$i++){$ui.PUsage.SetItemChecked($i,$false)}; $script:SbcSelPolicy=$null })
    $btnPCreate.Add_Click({ Sbc-CreatePolicy })
    $btnPUpdate.Add_Click({ Sbc-UpdatePolicy })
    $btnPDelete.Add_Click({ Sbc-DeletePolicy })
    $btnPGrant.Add_Click({ Sbc-GrantPolicy })
    $btnPReset.Add_Click({ Sbc-ResetPolicy })
    $btnPUp.Add_Click({ $lb=$script:SbcUi.PUsage; $i=$lb.SelectedIndex; if ($i -gt 0) { $item=$lb.Items[$i]; $lb.Items.RemoveAt($i); $lb.Items.Insert($i-1,$item); $lb.SelectedIndex=$i-1 } })
    $btnPDown.Add_Click({ $lb=$script:SbcUi.PUsage; $i=$lb.SelectedIndex; if ($i -ge 0 -and $i -lt $lb.Items.Count-1) { $item=$lb.Items[$i]; $lb.Items.RemoveAt($i); $lb.Items.Insert($i+1,$item); $lb.SelectedIndex=$i+1 } })

    $btnTAdd.Add_Click({ Sbc-AddTrustedIp })
    $btnTRemove.Add_Click({ Sbc-RemoveTrustedIp })

    $btnSimLocal.Add_Click({ Sbc-SimulateLocal })
    $btnSimTenant.Add_Click({ Sbc-SimulateTenant })

    return $page
}


################################################################################
#
#  TAB 7  GROUPS AND SOURCES
#
#  Read-only by design. Group policy assignment and group licensing are write
#  operations well outside the read/troubleshoot Teams roles this tool targets.
#
#  Rule that governs every trace this tab renders: direct user assignment always
#  wins (rank 0). Among groups, the lowest rank number wins. Group assignments
#  apply to direct members only, not nested groups.
#
################################################################################

$script:GroupNameCache = @{}

function New-GroupsTabPage {
    param(
        [string]$Text = '  Groups and Sources  ',
        $BackColor,$ColorBlue,$ColorPurple,$ColorGreen,$ColorGray,$ColorAmber,$ColorRed
    )

    $page = New-Object System.Windows.Forms.TabPage
    $page.Text = $Text; $page.BackColor = $BackColor

    $bar = New-Object System.Windows.Forms.Panel
    $bar.Dock='Top'; $bar.Height=76; $bar.BackColor=[System.Drawing.Color]::White

    $lblUpn=New-Object System.Windows.Forms.Label; $lblUpn.Location=New-Object System.Drawing.Point(12,12); $lblUpn.Size=New-Object System.Drawing.Size(60,20); $lblUpn.Text='User UPN'
    $txtUpn=New-Object System.Windows.Forms.TextBox; $txtUpn.Location=New-Object System.Drawing.Point(78,10); $txtUpn.Size=New-Object System.Drawing.Size(260,22)
    $btnTrace=New-Object System.Windows.Forms.Button; $btnTrace.Location=New-Object System.Drawing.Point(346,9); $btnTrace.Size=New-Object System.Drawing.Size(150,26); $btnTrace.Text='Trace This User'; Style-Button $btnTrace $ColorBlue
    $btnUseProv=New-Object System.Windows.Forms.Button; $btnUseProv.Location=New-Object System.Drawing.Point(504,9); $btnUseProv.Size=New-Object System.Drawing.Size(160,26); $btnUseProv.Text='Use Provisioning UPN'; Style-Button $btnUseProv $ColorGray
    $btnPullGroups=New-Object System.Windows.Forms.Button; $btnPullGroups.Location=New-Object System.Drawing.Point(672,9); $btnPullGroups.Size=New-Object System.Drawing.Size(180,26); $btnPullGroups.Text='Pull Group Assignments'; Style-Button $btnPullGroups $ColorPurple
    $btnExport=New-Object System.Windows.Forms.Button; $btnExport.Location=New-Object System.Drawing.Point(860,9); $btnExport.Size=New-Object System.Drawing.Size(130,26); $btnExport.Text='Export'; Style-Button $btnExport $ColorGreen

    $lblRule=New-Object System.Windows.Forms.Label
    $lblRule.Location=New-Object System.Drawing.Point(12,42); $lblRule.Size=New-Object System.Drawing.Size(1000,30)
    $lblRule.Text='Direct user assignment always wins (treated as rank 0). Among groups, the lowest rank number wins. Group assignments apply to direct members only, not nested groups.'
    $lblRule.ForeColor=$ColorGray; $lblRule.Font=New-Object System.Drawing.Font('Segoe UI',8,[System.Drawing.FontStyle]::Italic)

    $bar.Controls.AddRange(@($lblUpn,$txtUpn,$btnTrace,$btnUseProv,$btnPullGroups,$btnExport,$lblRule))

    $inner = New-Object System.Windows.Forms.TabControl
    $inner.Dock='Fill'
    $pgTrace = New-Object System.Windows.Forms.TabPage; $pgTrace.Text='User Trace'; $pgTrace.BackColor=$BackColor
    $pgGpa   = New-Object System.Windows.Forms.TabPage; $pgGpa.Text='Group Policy Assignments'; $pgGpa.BackColor=$BackColor
    $pgLic   = New-Object System.Windows.Forms.TabPage; $pgLic.Text='Licensing Groups'; $pgLic.BackColor=$BackColor
    $inner.Controls.AddRange(@($pgTrace,$pgGpa,$pgLic))

    $rtbTrace=New-Object System.Windows.Forms.RichTextBox; $rtbTrace.Dock='Fill'; $rtbTrace.ReadOnly=$true; $rtbTrace.BackColor=[System.Drawing.Color]::White; $rtbTrace.Font=New-Object System.Drawing.Font('Consolas',9)
    $pgTrace.Controls.Add($rtbTrace)

    $gridGpa=New-Object System.Windows.Forms.DataGridView
    $gridGpa.Dock='Fill'; $gridGpa.ReadOnly=$true; $gridGpa.AllowUserToAddRows=$false
    $gridGpa.SelectionMode='FullRowSelect'; $gridGpa.MultiSelect=$false; $gridGpa.AutoSizeColumnsMode='Fill'
    $gridGpa.RowHeadersVisible=$false; $gridGpa.BackgroundColor=[System.Drawing.Color]::White
    foreach ($c in @('Rank','PolicyType','PolicyName','Group','GroupId')) { [void]$gridGpa.Columns.Add($c,$c) }
    $gridGpa.Columns['Rank'].FillWeight=45; $gridGpa.Columns['PolicyType'].FillWeight=180; $gridGpa.Columns['PolicyName'].FillWeight=180
    $gridGpa.Columns['Group'].FillWeight=220; $gridGpa.Columns['GroupId'].FillWeight=200
    $gridGpa.Add_CellFormatting({
        param($s,$e)
        if ($e.RowIndex -lt 0) { return }
        $pt="$($script:GrpUi.GridGpa.Rows[$e.RowIndex].Cells['PolicyType'].Value)"
        if ($script:GroupAssignmentUnsupported -contains $pt) { $e.CellStyle.BackColor=[System.Drawing.Color]::FromArgb(255,244,214) }
    })
    $pgGpa.Controls.Add($gridGpa)

    $gridLic=New-Object System.Windows.Forms.DataGridView
    $gridLic.Dock='Fill'; $gridLic.ReadOnly=$true; $gridLic.AllowUserToAddRows=$false
    $gridLic.SelectionMode='FullRowSelect'; $gridLic.MultiSelect=$false; $gridLic.AutoSizeColumnsMode='Fill'
    $gridLic.RowHeadersVisible=$false; $gridLic.BackgroundColor=[System.Drawing.Color]::White
    foreach ($c in @('Group','GroupId','SkuIds','SkuCount')) { [void]$gridLic.Columns.Add($c,$c) }
    $pgLic.Controls.Add($gridLic)

    $page.Controls.Add($inner)
    $page.Controls.Add($bar)

    $script:GrpUi = @{
        Upn=$txtUpn; Trace=$rtbTrace; GridGpa=$gridGpa; GridLic=$gridLic
        Colors=@{ Blue=$ColorBlue; Purple=$ColorPurple; Green=$ColorGreen; Gray=$ColorGray; Amber=$ColorAmber; Red=$ColorRed }
    }
    $script:GrpGpaRows=@(); $script:GrpLicRows=@()

    function script:Grp-Say { param([string]$Text,$Color)
        $ui=$script:GrpUi; if (-not $Color) { $Color=[System.Drawing.Color]::Black }
        $ui.Trace.SelectionStart=$ui.Trace.TextLength; $ui.Trace.SelectionColor=$Color; $ui.Trace.AppendText("$Text`n"); $ui.Trace.SelectionColor=$ui.Trace.ForeColor
    }

    function script:Get-GroupDisplayName {
    <#
    .SYNOPSIS
        Resolve a group GUID to a name: Graph first, then Get-CsGroup, then the
        raw GUID. Results are cached so a missing directory read degrades the
        label rather than breaking the read.
    #>
        param([string]$GroupId)
        if ([string]::IsNullOrWhiteSpace($GroupId)) { return '' }
        if ($script:GroupNameCache.ContainsKey($GroupId)) { return $script:GroupNameCache[$GroupId] }
        $name = $GroupId
        try {
            $g = Invoke-GraphGet "$($script:Graph)/groups/$GroupId`?`$select=displayName"
            if ($g -and $g.displayName) { $name = $g.displayName }
        } catch {
            if ($script:RbacConnected -and (Test-CmdletPresent -Name 'Get-CsGroup')) {
                try { $cg = Get-CsGroup -Identity $GroupId -ErrorAction Stop; if ($cg -and $cg.DisplayName) { $name = $cg.DisplayName } } catch {}
            }
        }
        $script:GroupNameCache[$GroupId] = $name
        return $name
    }

    function script:Grp-TraceUser {
        $ui=$script:GrpUi
        $upn=$ui.Upn.Text
        if ([string]::IsNullOrWhiteSpace($upn)) { Grp-Say 'Enter a UPN first.' $ui.Colors.Amber; return }
        $ui.Trace.Clear()
        Grp-Say 'ASSIGNMENT SOURCE TRACE' $ui.Colors.Blue
        Grp-Say ('=' * 60) $ui.Colors.Gray

        # ---- group membership --------------------------------------------
        $groups=@()
        try {
            $eu=[uri]::EscapeDataString($upn)
            $r = Invoke-GraphGet "$($script:Graph)/users/$eu/memberOf?`$select=id,displayName"
            $groups = @($r.value)
        } catch { Grp-Say "  group membership read failed: $($_.Exception.Message)" $ui.Colors.Amber }

        Grp-Say "`nGROUP MEMBERSHIP ($($groups.Count))" $ui.Colors.Blue
        $gpaByGroup=@{}
        foreach ($row in $script:GrpGpaRows) { if (-not $gpaByGroup.ContainsKey($row.GroupId)) { $gpaByGroup[$row.GroupId]=New-Object System.Collections.Generic.List[object] }; $gpaByGroup[$row.GroupId].Add($row) }
        $licByGroup=@{}
        foreach ($row in $script:GrpLicRows) { $licByGroup[$row.GroupId]=$row }

        foreach ($g in $groups) {
            $gid="$($g.id)"; $gname="$($g.displayName)"
            $tags=@()
            if ($gpaByGroup.ContainsKey($gid)) { $tags += "$($gpaByGroup[$gid].Count) policy assignment(s)" }
            if ($licByGroup.ContainsKey($gid)) { $tags += 'carries licences' }
            $suffix = if ($tags.Count -gt 0) { " [$($tags -join '; ')]" } else { '' }
            Grp-Say "  $gname ($gid)" ([System.Drawing.Color]::Black)
            if ($suffix) { Grp-Say "    $suffix" $ui.Colors.Purple }
        }

        # ---- licensing ------------------------------------------------------
        Grp-Say "`nLICENSING" $ui.Colors.Blue
        try {
            $eu=[uri]::EscapeDataString($upn)
            $u = Invoke-GraphGet "$($script:Graph)/users/$eu`?`$select=usageLocation,assignedLicenses"
            $loc="$($u.usageLocation)"
            if ([string]::IsNullOrWhiteSpace($loc)) {
                Grp-Say "  UsageLocation: (not set) - group licence assignment will fail without it" $ui.Colors.Amber
            } else {
                Grp-Say "  UsageLocation: $loc" ([System.Drawing.Color]::Black)
            }
            foreach ($sku in @($u.assignedLicenses)) {
                $path = if ($licByGroup.Count -gt 0) {
                    $viaGroup = $licByGroup.Values | Where-Object { @($_.SkuIds -split ',') -contains "$($sku.skuId)" } | Select-Object -First 1
                    if ($viaGroup) { "via group $($viaGroup.Group)" } else { 'direct' }
                } else { 'direct' }
                Grp-Say "  SKU $($sku.skuId) - $path" ([System.Drawing.Color]::Black)
            }
        } catch { Grp-Say "  licensing read failed: $($_.Exception.Message)" $ui.Colors.Amber }
    }

    function script:Grp-PullGroupAssignments {
        $ui=$script:GrpUi
        $ui.GridGpa.Rows.Clear(); $ui.GridLic.Rows.Clear()
        $script:GrpGpaRows=@(); $script:GrpLicRows=@()

        # ---- group policy assignments: each data source degrades independently
        if (Test-CmdletPresent -Name 'Get-CsGroupPolicyAssignment') {
            try {
                $rows = Get-CsGroupPolicyAssignment -ErrorAction Stop
                $out = foreach ($r in @($rows)) {
                    $gname = Get-GroupDisplayName "$($r.GroupId)"
                    [pscustomobject]@{ Rank=[int](Get-PropTolerant $r @('Rank') 0); PolicyType="$(Get-PropTolerant $r @('PolicyType'))"; PolicyName="$(Get-PropTolerant $r @('PolicyName'))"; Group=$gname; GroupId="$($r.GroupId)" }
                }
                $script:GrpGpaRows = @($out | Sort-Object PolicyType,Rank)
                foreach ($row in $script:GrpGpaRows) { [void]$ui.GridGpa.Rows.Add($row.Rank,$row.PolicyType,$row.PolicyName,$row.Group,$row.GroupId) }
                # Microsoft does not support group assignment for these types. A row
                # here for one of them is surprising tenant data, not routine - flag it
                # rather than display it as if it were an ordinary group assignment.
                $unsupportedSeen = @($script:GrpGpaRows | Where-Object { $script:GroupAssignmentUnsupported -contains $_.PolicyType })
                if ($unsupportedSeen.Count -gt 0) {
                    Grp-Say "  $($unsupportedSeen.Count) row(s) show group assignment for a type Microsoft documents as unsupported ($(($unsupportedSeen.PolicyType | Select-Object -Unique) -join ', ')) - worth a closer look." $ui.Colors.Amber
                }
                Grp-Say "Group policy assignments: $($script:GrpGpaRows.Count)" $ui.Colors.Green
            } catch { Grp-Say "Group policy assignments unavailable: $($_.Exception.Message)" $ui.Colors.Amber }
        } else { Grp-Say "Get-CsGroupPolicyAssignment not in the loaded module - group policy assignments skipped." $ui.Colors.Amber }

        # ---- licensing groups: Graph, ConsistencyLevel: eventual required for $count
        try {
            $uri = "$($script:Graph)/groups?`$filter=assignedLicenses/`$count ne 0&`$count=true&`$select=id,displayName,assignedLicenses&`$top=999"
            $r = Invoke-GraphGet $uri -Headers @{ ConsistencyLevel='eventual' }
            $out = foreach ($g in @($r.value)) {
                $skus = @($g.assignedLicenses | ForEach-Object { "$($_.skuId)" })
                [pscustomobject]@{ Group="$($g.displayName)"; GroupId="$($g.id)"; SkuIds=($skus -join ','); SkuCount=$skus.Count }
            }
            $script:GrpLicRows = @($out)
            foreach ($row in $script:GrpLicRows) { [void]$ui.GridLic.Rows.Add($row.Group,$row.GroupId,$row.SkuIds,$row.SkuCount); $script:GroupNameCache[$row.GroupId]=$row.Group }
            Grp-Say "Licensing groups: $($script:GrpLicRows.Count)" $ui.Colors.Green
        } catch { Grp-Say "Licensing groups read failed (needs a directory read): $($_.Exception.Message)" $ui.Colors.Amber }
    }

    function script:Grp-Export {
        $stamp=Get-Stamp; $key=Get-EnvKey
        $path = Get-OutputPath -Area Changes -File ("TeamsVoice_GroupSources_{0}_{1}.csv" -f $key,$stamp)
        try {
            $script:GrpGpaRows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
            Grp-Say "Exported -> $([IO.Path]::GetFileName($path))" $script:GrpUi.Colors.Green
            Open-OutputFolder -Path $path -Label 'Group sources export' -SelectFile
        } catch { Grp-Say "Export failed: $($_.Exception.Message)" $script:GrpUi.Colors.Red }
    }

    $btnTrace.Add_Click({ Grp-TraceUser })
    $btnUseProv.Add_Click({ if ($txtUser) { $script:GrpUi.Upn.Text = $txtUser.Text } })
    $btnPullGroups.Add_Click({ Grp-PullGroupAssignments })
    $btnExport.Add_Click({ Grp-Export })

    return $page
}


################################################################################
#
#  TAB 8  BULK IMPORT
#
#  Two independent importers sharing one shape: load CSV -> validate (no writes)
#  -> run -> retry failed rows -> export results + generated IDs. RBAC required
#  for both - there is no Graph v1.0 surface for civic addresses, locations or
#  the wiremap.
#
################################################################################

$script:ImpColumns = @('CivicKey','CompanyName','HouseNumber','StreetName','City','StateOrProvince','PostalCode','CountryOrRegion','CivicDescription','Latitude','Longitude','LocationName','Elin')
$script:WimColumns = @('WireType','Key1','Key2','Description','LocationId','CivicKey','LocationName')

$script:ImpRows = @()
$script:ImpCancel = $false
$script:WimRows = @()
$script:WimCancel = $false

function New-BulkImportTabPage {
    param(
        [string]$Text = '  Bulk Import  ',
        $BackColor,$ColorBlue,$ColorPurple,$ColorGreen,$ColorGray,$ColorAmber,$ColorRed
    )

    $page = New-Object System.Windows.Forms.TabPage
    $page.Text = $Text; $page.BackColor = $BackColor

    $inner = New-Object System.Windows.Forms.TabControl
    $inner.Dock='Fill'
    $pgLoc = New-Object System.Windows.Forms.TabPage; $pgLoc.Text='Locations'; $pgLoc.BackColor=$BackColor
    $pgWim = New-Object System.Windows.Forms.TabPage; $pgWim.Text='Network Wiremap'; $pgWim.BackColor=$BackColor
    $inner.Controls.AddRange(@($pgLoc,$pgWim))
    $page.Controls.Add($inner)

    # ==========================================================================
    # Shared UI factory - both sub-tabs use the same top-bar shape
    # ==========================================================================
    function New-ImporterBar {
        param($Parent,[bool]$ShowRefreshLis)
        $bar = New-Object System.Windows.Forms.Panel
        $bar.Dock='Top'; $bar.Height=104; $bar.BackColor=[System.Drawing.Color]::White

        $btnTemplate=New-Object System.Windows.Forms.Button; $btnTemplate.Location=New-Object System.Drawing.Point(12,8); $btnTemplate.Size=New-Object System.Drawing.Size(120,27); $btnTemplate.Text='Save CSV Template'; Style-Button $btnTemplate $ColorGray
        $btnLoad=New-Object System.Windows.Forms.Button; $btnLoad.Location=New-Object System.Drawing.Point(138,8); $btnLoad.Size=New-Object System.Drawing.Size(100,27); $btnLoad.Text='Load CSV...'; Style-Button $btnLoad $ColorBlue
        $btnValidate=New-Object System.Windows.Forms.Button; $btnValidate.Location=New-Object System.Drawing.Point(244,8); $btnValidate.Size=New-Object System.Drawing.Size(150,27); $btnValidate.Text='Validate (no writes)'; Style-Button $btnValidate $ColorPurple; $btnValidate.Enabled=$false
        $btnRun=New-Object System.Windows.Forms.Button; $btnRun.Location=New-Object System.Drawing.Point(400,8); $btnRun.Size=New-Object System.Drawing.Size(96,27); $btnRun.Text='Run Import'; Style-Button $btnRun $ColorGreen; $btnRun.Enabled=$false
        $btnRetry=New-Object System.Windows.Forms.Button; $btnRetry.Location=New-Object System.Drawing.Point(502,8); $btnRetry.Size=New-Object System.Drawing.Size(110,27); $btnRetry.Text='Retry Failed Rows'; Style-Button $btnRetry $ColorAmber; $btnRetry.Enabled=$false
        $btnStop=New-Object System.Windows.Forms.Button; $btnStop.Location=New-Object System.Drawing.Point(618,8); $btnStop.Size=New-Object System.Drawing.Size(70,27); $btnStop.Text='Stop'; Style-Button $btnStop $ColorRed; $btnStop.Enabled=$false
        $btnExport=New-Object System.Windows.Forms.Button; $btnExport.Location=New-Object System.Drawing.Point(694,8); $btnExport.Size=New-Object System.Drawing.Size(120,27); $btnExport.Text='Export Results + IDs'; Style-Button $btnExport $ColorGreen; $btnExport.Enabled=$false
        $bar.Controls.AddRange(@($btnTemplate,$btnLoad,$btnValidate,$btnRun,$btnRetry,$btnStop,$btnExport))

        $x0=12
        if ($ShowRefreshLis) {
            $btnRefreshLis=New-Object System.Windows.Forms.Button; $btnRefreshLis.Location=New-Object System.Drawing.Point(820,8); $btnRefreshLis.Size=New-Object System.Drawing.Size(150,27); $btnRefreshLis.Text='Refresh LIS Cache'; Style-Button $btnRefreshLis $ColorPurple
            $bar.Controls.Add($btnRefreshLis)
        } else { $btnRefreshLis=$null }

        $lblDelay=New-Object System.Windows.Forms.Label; $lblDelay.Location=New-Object System.Drawing.Point($x0,44); $lblDelay.Size=New-Object System.Drawing.Size(88,20); $lblDelay.Text='Delay/write (ms)'
        $numDelay=New-Object System.Windows.Forms.NumericUpDown; $numDelay.Location=New-Object System.Drawing.Point(($x0+92),42); $numDelay.Size=New-Object System.Drawing.Size(70,22); $numDelay.Minimum=0; $numDelay.Maximum=10000; $numDelay.Increment=50; $numDelay.Value=$(if($ShowRefreshLis){200}else{250})
        $lblAttempts=New-Object System.Windows.Forms.Label; $lblAttempts.Location=New-Object System.Drawing.Point(($x0+176),44); $lblAttempts.Size=New-Object System.Drawing.Size(74,20); $lblAttempts.Text='Max attempts'
        $numAttempts=New-Object System.Windows.Forms.NumericUpDown; $numAttempts.Location=New-Object System.Drawing.Point(($x0+254),42); $numAttempts.Size=New-Object System.Drawing.Size(50,22); $numAttempts.Minimum=1; $numAttempts.Maximum=10; $numAttempts.Value=4
        $chkReuse=New-Object System.Windows.Forms.CheckBox
        if ($ShowRefreshLis) { $chkReuse.Text='Reassign a key that already exists on another location'; $chkReuse.Location=New-Object System.Drawing.Point(($x0+316),44); $chkReuse.Size=New-Object System.Drawing.Size(400,20); $chkReuse.Checked=$true }
        else { $chkReuse.Text='Reuse existing civic address when one matches'; $chkReuse.Location=New-Object System.Drawing.Point(($x0+316),44); $chkReuse.Size=New-Object System.Drawing.Size(320,20); $chkReuse.Checked=$true }
        $chkStopOnErr=New-Object System.Windows.Forms.CheckBox; $chkStopOnErr.Text='Stop on first non-transient error'; $chkStopOnErr.Location=New-Object System.Drawing.Point(($x0+716),44); $chkStopOnErr.Size=New-Object System.Drawing.Size(260,20); $chkStopOnErr.Checked=$false
        $bar.Controls.AddRange(@($lblDelay,$numDelay,$lblAttempts,$numAttempts,$chkReuse,$chkStopOnErr))

        $prog=New-Object System.Windows.Forms.ProgressBar; $prog.Location=New-Object System.Drawing.Point($x0,74); $prog.Size=New-Object System.Drawing.Size(700,20); $prog.Style='Continuous'
        $lblState=New-Object System.Windows.Forms.Label; $lblState.Location=New-Object System.Drawing.Point(($x0+716),74); $lblState.Size=New-Object System.Drawing.Size(400,20); $lblState.Text='No file loaded.'; $lblState.ForeColor=$ColorGray
        $bar.Controls.AddRange(@($prog,$lblState))

        $Parent.Controls.Add($bar)
        return @{
            Bar=$bar; Template=$btnTemplate; Load=$btnLoad; Validate=$btnValidate; Run=$btnRun; Retry=$btnRetry; Stop=$btnStop; Export=$btnExport
            RefreshLis=$btnRefreshLis; Delay=$numDelay; Attempts=$numAttempts; Reuse=$chkReuse; StopOnErr=$chkStopOnErr
            Progress=$prog; State=$lblState
        }
    }

    function New-ImporterBody {
        param($Parent,[string[]]$Columns)
        $split = New-Object System.Windows.Forms.SplitContainer
        $split.Size = New-Object System.Drawing.Size(1200,900)
        $split.Dock='Fill'; $split.Orientation='Horizontal'; $split.SplitterDistance=280
        $split.Panel1MinSize=150; $split.Panel2MinSize=150
        $grid = New-Object System.Windows.Forms.DataGridView
        $grid.Dock='Fill'; $grid.ReadOnly=$true; $grid.AllowUserToAddRows=$false; $grid.AllowUserToDeleteRows=$false
        $grid.SelectionMode='FullRowSelect'; $grid.MultiSelect=$false; $grid.AutoSizeColumnsMode='Fill'
        $grid.RowHeadersVisible=$false; $grid.BackgroundColor=[System.Drawing.Color]::White
        foreach ($c in $Columns) { [void]$grid.Columns.Add($c,$c) }
        $split.Panel1.Controls.Add($grid)
        $rtb=New-Object System.Windows.Forms.RichTextBox; $rtb.Dock='Fill'; $rtb.ReadOnly=$true; $rtb.BackColor=[System.Drawing.Color]::White; $rtb.Font=New-Object System.Drawing.Font('Consolas',9)
        $split.Panel2.Controls.Add($rtb)
        $Parent.Controls.Add($split)
        return @{ Grid=$grid; Log=$rtb }
    }

    # ==========================================================================
    # LOCATIONS SUB-TAB
    # ==========================================================================
    $impBar  = New-ImporterBar -Parent $pgLoc -ShowRefreshLis $false
    $impBody = New-ImporterBody -Parent $pgLoc -Columns @('Row','Status','Civic','Location','CivicAddressId','LocationId','Tries','Detail')
    $impBody.Grid.Columns['Detail'].FillWeight=260
    $script:ImpUi = $impBar + $impBody + @{ Colors=@{ Blue=$ColorBlue; Purple=$ColorPurple; Green=$ColorGreen; Gray=$ColorGray; Amber=$ColorAmber; Red=$ColorRed } }

    function script:Imp-Say { param([string]$Text,$Color) $ui=$script:ImpUi; if (-not $Color) { $Color=[System.Drawing.Color]::Black }
        $ui.Log.SelectionStart=$ui.Log.TextLength; $ui.Log.SelectionColor=$Color; $ui.Log.AppendText("[$((Get-Date).ToString('HH:mm:ss'))] $Text`n"); $ui.Log.SelectionColor=$ui.Log.ForeColor; $ui.Log.ScrollToCaret()
    }
    function script:Imp-State { param([string]$Text,$Color) $ui=$script:ImpUi; if (-not $Color) { $Color=$ui.Colors.Gray }; $ui.State.Text=$Text; $ui.State.ForeColor=$Color; [System.Windows.Forms.Application]::DoEvents() }

    # Transient classification for both importers is Get-ErrorClass (shared
    # services region) - 429|503|504|throttl|timed out|timeout|temporarily|too
    # many requests|forcibly closed|connection was closed|service unavailable|
    # no data of the requested type. Validation and duplicate errors are
    # deliberately never retried - retrying them just burns time and can
    # partially apply bad data. No per-tab wrapper needed; Wim-RunImport uses
    # the same shared classifier directly.

    function script:Imp-CivicKey {
    <#
    .SYNOPSIS
        The explicit CivicKey (lower-cased) when present; otherwise a normalised
        fingerprint of the address fields, collapsing whitespace and lower-casing.
    .DESCRIPTION
        Without this, ten floors in one building would create ten duplicate
        civics - one per row, all at the same address.
    #>
        param($Row)
        if (-not [string]::IsNullOrWhiteSpace($Row.CivicKey)) { return $Row.CivicKey.Trim().ToLowerInvariant() }
        $parts = @($Row.HouseNumber,$Row.StreetName,$Row.City,$Row.StateOrProvince,$Row.PostalCode,$Row.CountryOrRegion) | ForEach-Object { "$_".Trim() }
        $fp = ($parts -join '|') -replace '\s+',' '
        return $fp.ToLowerInvariant()
    }

    function script:Imp-SaveTemplate {
        $sfd=New-Object System.Windows.Forms.SaveFileDialog; $sfd.Filter='CSV (*.csv)|*.csv'; $sfd.FileName='TeamsVoice_LocationImport_Template.csv'
        if ($sfd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
        $rows = @(
            [pscustomobject]@{ CivicKey='NC1-826'; CompanyName=''; HouseNumber='988'; StreetName='West Trade Street'; City='Charlotte'; StateOrProvince='NC'; PostalCode='28202'; CountryOrRegion='US'; CivicDescription='HQ Building'; Latitude=''; Longitude=''; LocationName='Floor 01'; Elin='' }
            [pscustomobject]@{ CivicKey='NC1-826'; CompanyName=''; HouseNumber='988'; StreetName='West Trade Street'; City='Charlotte'; StateOrProvince='NC'; PostalCode='28202'; CountryOrRegion='US'; CivicDescription='HQ Building'; Latitude=''; Longitude=''; LocationName='Floor 02'; Elin='' }
            [pscustomobject]@{ CivicKey='NJ-JC-101'; CompanyName=''; HouseNumber='101'; StreetName='Hudson Street'; City='Jersey City'; StateOrProvince='NJ'; PostalCode='07302'; CountryOrRegion='US'; CivicDescription=''; Latitude=''; Longitude=''; LocationName=''; Elin='' }
        )
        $rows | Select-Object $script:ImpColumns | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8
        Imp-Say "Template saved -> $([IO.Path]::GetFileName($sfd.FileName))" $script:ImpUi.Colors.Green
        Imp-Say "One row per location. Rows sharing a CivicKey create the civic once and attach every location to it." $script:ImpUi.Colors.Gray
        Imp-Say "Leave LocationName blank to create a civic address with no dispatchable location." $script:ImpUi.Colors.Gray
    }

    function script:Imp-LoadCsv {
        $ofd=New-Object System.Windows.Forms.OpenFileDialog; $ofd.Filter='CSV (*.csv)|*.csv'
        if ($ofd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
        try {
            $raw = Import-Csv -Path $ofd.FileName
            $script:ImpRows = @()
            $i=0
            foreach ($r in $raw) {
                $i++
                $script:ImpRows += [pscustomobject]@{
                    Row=$i; Status='Pending'; Civic=''; Location="$($r.LocationName)"; CivicAddressId=''; LocationId=''; Tries=0; Detail=''
                    Data=$r; CivicKey=(Imp-CivicKey $r)
                }
            }
            Imp-FillGrid
            $script:ImpUi.Validate.Enabled = ($script:ImpRows.Count -gt 0)
            $script:ImpUi.Run.Enabled=$false; $script:ImpUi.Retry.Enabled=$false; $script:ImpUi.Export.Enabled=$false
            Imp-State "Loaded $($script:ImpRows.Count) row(s) from $([IO.Path]::GetFileName($ofd.FileName))." $script:ImpUi.Colors.Blue
        } catch { Imp-Say "Load failed: $($_.Exception.Message)" $script:ImpUi.Colors.Red }
    }

    function script:Imp-FillGrid {
        $ui=$script:ImpUi; $ui.Grid.Rows.Clear()
        foreach ($r in $script:ImpRows) { [void]$ui.Grid.Rows.Add($r.Row,$r.Status,$r.Civic,$r.Location,$r.CivicAddressId,$r.LocationId,$r.Tries,$r.Detail) }
    }

    function script:Imp-Validate {
        $ui=$script:ImpUi
        $bad=0
        foreach ($r in $script:ImpRows) {
            $d=$r.Data
            $problems=@()
            if ([string]::IsNullOrWhiteSpace($d.CountryOrRegion)) { $problems+='CountryOrRegion required' }
            if ([string]::IsNullOrWhiteSpace($d.City)) { $problems+='City required' }
            if ([string]::IsNullOrWhiteSpace($d.StreetName)) { $problems+='StreetName required' }
            if ($problems.Count -gt 0) { $r.Status='SKIP'; $r.Detail=($problems -join '; '); $bad++ }
        }
        Imp-FillGrid
        $ui.Run.Enabled = ($script:ImpRows.Count -gt $bad)
        Imp-State "Validated: $bad row(s) would be skipped, $($script:ImpRows.Count-$bad) would proceed." $(if ($bad -gt 0) { $ui.Colors.Amber } else { $ui.Colors.Green })
        Imp-Say "Validate (no writes) complete." $ui.Colors.Purple
    }

    function script:Imp-RunImport {
        param([switch]$RetryOnly)
        $ui=$script:ImpUi
        $ui.Stop.Enabled=$true; $ui.Run.Enabled=$false; $ui.Retry.Enabled=$false; $ui.Load.Enabled=$false
        $script:ImpCancel=$false
        $delay=[int]$ui.Delay.Value; $maxAttempts=[int]$ui.Attempts.Value
        $reuse=$ui.Reuse.Checked; $stopOnErr=$ui.StopOnErr.Checked

        $targets = if ($RetryOnly) { @($script:ImpRows | Where-Object { $_.Status -eq 'Failed' }) } else { @($script:ImpRows | Where-Object { $_.Status -ne 'SKIP' }) }
        if ($targets.Count -eq 0) { Imp-Say 'Nothing to import.' $ui.Colors.Amber; $ui.Stop.Enabled=$false; $ui.Load.Enabled=$true; return }

        $verb = if ($RetryOnly) { 'Retry' } else { 'Import' }
        if (-not (Confirm-ToolkitWrite -Title 'Confirm bulk import' -Message "$verb $($targets.Count) location row(s) into $($script:CurrentEnv)?`n`nThis changes how Teams clients resolve to an emergency location.")) {
            $ui.Stop.Enabled=$false; $ui.Run.Enabled=$true; $ui.Load.Enabled=$true; return
        }

        $ui.Progress.Maximum=$targets.Count; $ui.Progress.Value=0
        $civicIdByKey=@{}
        # Seed from rows already created this session so repeated floors in the
        # same run reuse the civic instead of re-creating it.
        foreach ($r in $script:ImpRows) { if ($r.CivicAddressId) { $civicIdByKey[$r.CivicKey]=$r.CivicAddressId } }

        $n=0
        foreach ($r in $targets) {
            $n++
            if ($script:ImpCancel) { Imp-Say "Stopped - remaining rows untouched." $ui.Colors.Amber; break }
            $ui.Progress.Value=$n
            Imp-State "Row $($r.Row) of $($script:ImpRows.Count) ($n/$($targets.Count) this run)..." $ui.Colors.Blue
            $d=$r.Data
            $ok=$true
            try {
                # ---- civic: create once per CivicKey ------------------------
                $civId = $civicIdByKey[$r.CivicKey]
                if (-not $civId -and $reuse) {
                    $existing = @($script:LisCivic) | Where-Object {
                        "$(Get-PropTolerant $_ @('City'))" -eq "$($d.City)" -and
                        "$(Get-PropTolerant $_ @('StreetName'))" -eq "$($d.StreetName)" -and
                        "$(Get-PropTolerant $_ @('HouseNumber'))" -eq "$($d.HouseNumber)"
                    } | Select-Object -First 1
                    if ($existing) { $civId="$(Get-PropTolerant $existing @('CivicAddressId','CivicAddressid'))" }
                }
                if (-not $civId) {
                    $fields=@{ CompanyName="$($d.CompanyName)"; HouseNumber="$($d.HouseNumber)"; StreetName="$($d.StreetName)"; City="$($d.City)"; StateOrProvince="$($d.StateOrProvince)"; PostalCode="$($d.PostalCode)"; CountryOrRegion="$($d.CountryOrRegion)"; Description="$($d.CivicDescription)"; Latitude="$($d.Latitude)"; Longitude="$($d.Longitude)" }
                    $p = Select-CmdletParams -Cmdlet 'New-CsOnlineLisCivicAddress' -Params $fields
                    $new = Invoke-WithRetry -RetryProfile 'BulkImport' -MaxAttempts $maxAttempts `
                        -CancelCheck { $script:ImpCancel } `
                        -OnRetry { param($a,$dl,$er) Imp-Say "  row $($r.Row): transient failure, retry $a in $dl ms" $ui.Colors.Amber } `
                        -Action { New-CsOnlineLisCivicAddress @p -ErrorAction Stop }
                    $civId = "$(Get-PropTolerant $new @('CivicAddressId','CivicAddressid'))"
                    $civicIdByKey[$r.CivicKey]=$civId
                    Imp-Say "  row $($r.Row): created civic $civId" $ui.Colors.Green
                }
                $r.CivicAddressId=$civId; $r.Civic="$($d.City) / $($d.CivicKey)"

                # ---- location: only if LocationName was given ----------------
                if (-not [string]::IsNullOrWhiteSpace($d.LocationName)) {
                    $lfields=@{ CivicAddressId=$civId; Location="$($d.LocationName)"; Elin="$($d.Elin)" }
                    $lp = Select-CmdletParams -Cmdlet 'New-CsOnlineLisLocation' -Params $lfields
                    $newLoc = Invoke-WithRetry -RetryProfile 'BulkImport' -MaxAttempts $maxAttempts `
                        -CancelCheck { $script:ImpCancel } `
                        -OnRetry { param($a,$dl,$er) Imp-Say "  row $($r.Row): transient failure, retry $a in $dl ms" $ui.Colors.Amber } `
                        -Action { New-CsOnlineLisLocation @lp -ErrorAction Stop }
                    $r.LocationId = "$(Get-PropTolerant $newLoc @('LocationId','Locationid'))"
                }
                $r.Status='Created'; $r.Detail=''
            }
            catch {
                $ok=$false
                $r.Tries = [int]$r.Tries + 1
                $cls = Get-ErrorClass $_
                $r.Status = 'Failed'
                $r.Detail = "[$cls] $($_.Exception.Message)"
                Imp-Say "  row $($r.Row) FAILED [$cls]: $($_.Exception.Message)" $ui.Colors.Red
                if ($stopOnErr -and $cls -ne 'Transient') { Imp-Say "Stop on first non-transient error - halting." $ui.Colors.Red; Imp-FillGrid; break }
            }
            Imp-FillGrid
            if ($delay -gt 0) { $slept=0; while ($slept -lt $delay) { Start-Sleep -Milliseconds 50; $slept+=50; [System.Windows.Forms.Application]::DoEvents() } }
        }

        $failed = @($script:ImpRows | Where-Object { $_.Status -eq 'Failed' }).Count
        $created = @($script:ImpRows | Where-Object { $_.Status -eq 'Created' }).Count
        Imp-State "$verb complete: $created created, $failed failed." $(if ($failed -gt 0) { $ui.Colors.Amber } else { $ui.Colors.Green })
        $ui.Retry.Enabled = ($failed -gt 0)
        $ui.Export.Enabled = $true
        $ui.Stop.Enabled=$false; $ui.Run.Enabled=$true; $ui.Load.Enabled=$true
        $script:ImpCancel=$false
    }

    function script:Imp-Export {
        $ui=$script:ImpUi
        $stamp=Get-Stamp; $key=Get-EnvKey
        $rows = $script:ImpRows | Select-Object Row,Status,Civic,Location,CivicAddressId,LocationId,Tries,Detail
        $path = Get-OutputPath -Area Changes -File ("TeamsVoice_BulkLocationImport_{0}_{1}.csv" -f $key,$stamp)
        try {
            $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
            Imp-Say "Exported results -> $([IO.Path]::GetFileName($path))" $ui.Colors.Green
            Open-OutputFolder -Path $path -Label 'Bulk import results' -SelectFile
        } catch { Imp-Say "Export failed: $($_.Exception.Message)" $ui.Colors.Red }
    }

    $impBar.Template.Add_Click({ Imp-SaveTemplate })
    $impBar.Load.Add_Click({ Imp-LoadCsv })
    $impBar.Validate.Add_Click({ Imp-Validate })
    $impBar.Run.Add_Click({ Imp-RunImport })
    $impBar.Retry.Add_Click({ Imp-RunImport -RetryOnly })
    $impBar.Stop.Add_Click({ $script:ImpCancel=$true; Imp-Say 'Stop requested - remaining rows will be left untouched.' $script:ImpUi.Colors.Amber })
    $impBar.Export.Add_Click({ Imp-Export })

    # ==========================================================================
    # NETWORK WIREMAP SUB-TAB
    # ==========================================================================
    $wimBar  = New-ImporterBar -Parent $pgWim -ShowRefreshLis $true
    $wimBar.Delay.Value = 200
    $wimBody = New-ImporterBody -Parent $pgWim -Columns @('Row','Status','Type','Key1','Key2','Location','LocationId','Tries','Detail')
    $wimBody.Grid.Columns['Detail'].FillWeight=280
    $script:WimUi = $wimBar + $wimBody + @{ Colors=@{ Blue=$ColorBlue; Purple=$ColorPurple; Green=$ColorGreen; Gray=$ColorGray; Amber=$ColorAmber; Red=$ColorRed } }

    function script:Wim-Say { param([string]$Text,$Color) $ui=$script:WimUi; if (-not $Color) { $Color=[System.Drawing.Color]::Black }
        $ui.Log.SelectionStart=$ui.Log.TextLength; $ui.Log.SelectionColor=$Color; $ui.Log.AppendText("[$((Get-Date).ToString('HH:mm:ss'))] $Text`n"); $ui.Log.SelectionColor=$ui.Log.ForeColor; $ui.Log.ScrollToCaret()
    }
    function script:Wim-State { param([string]$Text,$Color) $ui=$script:WimUi; if (-not $Color) { $Color=$ui.Colors.Gray }; $ui.State.Text=$Text; $ui.State.ForeColor=$Color; [System.Windows.Forms.Application]::DoEvents() }

    function script:Wim-NormalizeKey {
    <#
    .SYNOPSIS
        For WAP: strip non-hex characters; if exactly 12 hex digits remain,
        re-join as XX-XX-XX-XX-XX-XX upper-case.
    .DESCRIPTION
        Separator style varies by vendor export (colon, hyphen, dot, none).
        Canonicalising prevents the same access point being written twice under
        two spellings - the usual cause of a WAP that imports cleanly but never
        resolves for clients.
    #>
        param([string]$Type,[string]$Value)
        if ($Type -ne 'wap') { return @{ Value=$Value; Note=$null } }
        $hex = ($Value -replace '[^0-9A-Fa-f]','')
        if ($hex.Length -ne 12) { return @{ Value=$Value; Note=$null } }
        $norm = ($hex.ToUpperInvariant() -split '(?<=\G.{2})(?!$)') -join '-'
        if ($norm -ne $Value) { return @{ Value=$norm; Note="normalized from '$Value'" } }
        return @{ Value=$norm; Note=$null }
    }

    function script:Wim-ResolveLocationId {
    <#
    .SYNOPSIS
        Explicit LocationId wins; otherwise resolve against locations created
        earlier in this session or against the LIS cache, by CivicKey + LocationName.
    #>
        param($Row)
        if (-not [string]::IsNullOrWhiteSpace($Row.LocationId)) { return @{ Id=$Row.LocationId; Method='explicit' } }
        $created = @($script:ImpRows) | Where-Object { "$($_.Data.LocationName)" -eq "$($Row.LocationName)" -and $_.LocationId } | Select-Object -First 1
        if ($created) { return @{ Id=$created.LocationId; Method='session import' } }
        $cached = @($script:LisLoc) | Where-Object { "$(Get-PropTolerant $_ @('Location','Description'))" -eq "$($Row.LocationName)" } | Select-Object -First 1
        if ($cached) { return @{ Id="$(Get-PropTolerant $cached @('LocationId','Locationid'))"; Method='LIS cache' } }
        return @{ Id=$null; Method=$null }
    }

    function script:Wim-SaveTemplate {
        $sfd=New-Object System.Windows.Forms.SaveFileDialog; $sfd.Filter='CSV (*.csv)|*.csv'; $sfd.FileName='TeamsVoice_WiremapImport_Template.csv'
        if ($sfd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
        $rows = @(
            [pscustomobject]@{ WireType='wap'; Key1='00-11-22-33-44-55'; Key2=''; Description='AP-CLT-01-F1'; LocationId=''; CivicKey='NC1-826'; LocationName='Floor 01' }
            [pscustomobject]@{ WireType='subnet'; Key1='10.20.30.0'; Key2=''; Description='Floor 1 data'; LocationId=''; CivicKey='NC1-826'; LocationName='Floor 01' }
            [pscustomobject]@{ WireType='switch'; Key1='0004f2e1a2b3'; Key2=''; Description='IDF-1 core'; LocationId=''; CivicKey='NC1-826'; LocationName='Floor 01' }
            [pscustomobject]@{ WireType='port'; Key1='0004f2e1a2b3'; Key2='Gi1/0/12'; Description='Desk 1042'; LocationId=''; CivicKey='NC1-826'; LocationName='Floor 01' }
        )
        $rows | Select-Object $script:WimColumns | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8
        Wim-Say "Template saved -> $([IO.Path]::GetFileName($sfd.FileName))" $script:WimUi.Colors.Green
        Wim-Say "Key1 is the primary key for the type; Key2 is the port ID and applies to Port only." $script:WimUi.Colors.Gray
        Wim-Say "Leave LocationId blank to resolve the location from CivicKey + LocationName instead." $script:WimUi.Colors.Gray
    }

    function script:Wim-LoadCsv {
        $ofd=New-Object System.Windows.Forms.OpenFileDialog; $ofd.Filter='CSV (*.csv)|*.csv'
        if ($ofd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
        try {
            $raw = Import-Csv -Path $ofd.FileName
            $script:WimRows=@(); $i=0
            foreach ($r in $raw) {
                $i++
                $script:WimRows += [pscustomobject]@{ Row=$i; Status='Pending'; Type="$($r.WireType)"; Key1="$($r.Key1)"; Key2="$($r.Key2)"; Location="$($r.LocationName)"; LocationId="$($r.LocationId)"; Tries=0; Detail=''; Data=$r }
            }
            Wim-FillGrid
            $script:WimUi.Validate.Enabled = ($script:WimRows.Count -gt 0)
            $script:WimUi.Run.Enabled=$false; $script:WimUi.Retry.Enabled=$false; $script:WimUi.Export.Enabled=$false
            Wim-State "Loaded $($script:WimRows.Count) row(s) from $([IO.Path]::GetFileName($ofd.FileName))." $script:WimUi.Colors.Blue
        } catch { Wim-Say "Load failed: $($_.Exception.Message)" $script:WimUi.Colors.Red }
    }

    function script:Wim-FillGrid {
        $ui=$script:WimUi; $ui.Grid.Rows.Clear()
        foreach ($r in $script:WimRows) { [void]$ui.Grid.Rows.Add($r.Row,$r.Status,$r.Type,$r.Key1,$r.Key2,$r.Location,$r.LocationId,$r.Tries,$r.Detail) }
    }

    function script:Wim-Validate {
        $ui=$script:WimUi; $bad=0
        foreach ($r in $script:WimRows) {
            $problems=@()
            if ($r.Type -notin @('wap','subnet','switch','port')) { $problems+="unknown WireType '$($r.Type)'" }
            if ([string]::IsNullOrWhiteSpace($r.Key1)) { $problems+='Key1 required' }
            if ($r.Type -eq 'port' -and [string]::IsNullOrWhiteSpace($r.Key2)) { $problems+='Key2 (port ID) required for Port' }
            $loc = Wim-ResolveLocationId $r
            if (-not $loc.Id) { $problems+='could not resolve a location (no LocationId, no CivicKey+LocationName match)' }
            if ($problems.Count -gt 0) { $r.Status='SKIP'; $r.Detail=($problems -join '; '); $bad++ }
        }
        Wim-FillGrid
        $ui.Run.Enabled = ($script:WimRows.Count -gt $bad)
        Wim-State "Validated: $bad row(s) would be skipped, $($script:WimRows.Count-$bad) would proceed." $(if ($bad -gt 0) { $ui.Colors.Amber } else { $ui.Colors.Green })
        Wim-Say "Validate (no writes) complete." $ui.Colors.Purple
    }

    function script:Wim-RunImport {
        param([switch]$RetryOnly)
        $ui=$script:WimUi
        $ui.Stop.Enabled=$true; $ui.Run.Enabled=$false; $ui.Retry.Enabled=$false; $ui.Load.Enabled=$false
        $script:WimCancel=$false
        $delay=[int]$ui.Delay.Value; $maxAttempts=[int]$ui.Attempts.Value; $allowReassign=$ui.Reuse.Checked; $stopOnErr=$ui.StopOnErr.Checked

        $targets = if ($RetryOnly) { @($script:WimRows | Where-Object { $_.Status -eq 'Failed' }) } else { @($script:WimRows | Where-Object { $_.Status -ne 'SKIP' }) }
        if ($targets.Count -eq 0) { Wim-Say 'Nothing to import.' $ui.Colors.Amber; $ui.Stop.Enabled=$false; $ui.Load.Enabled=$true; return }
        $verb = if ($RetryOnly) { 'Retry' } else { 'Import' }
        if (-not (Confirm-ToolkitWrite -Title 'Confirm wiremap import' -Message "$verb $($targets.Count) wiremap row(s) into $($script:CurrentEnv)?`n`nThis changes how Teams clients resolve to an emergency location.")) {
            $ui.Stop.Enabled=$false; $ui.Run.Enabled=$true; $ui.Load.Enabled=$true; return
        }
        $ui.Progress.Maximum=$targets.Count; $ui.Progress.Value=0
        $n=0
        foreach ($r in $targets) {
            $n++
            if ($script:WimCancel) { Wim-Say "Stopped - remaining rows untouched." $ui.Colors.Amber; break }
            $ui.Progress.Value=$n
            Wim-State "Row $($r.Row) of $($script:WimRows.Count) ($n/$($targets.Count) this run)..." $ui.Colors.Blue
            try {
                $m = $script:LisWireMeta[$r.Type]
                if (-not $m) { throw "unknown WireType '$($r.Type)'" }
                $loc = Wim-ResolveLocationId $r
                if (-not $loc.Id) { throw "could not resolve a location" }

                $norm = Wim-NormalizeKey -Type $r.Type -Value $r.Key1
                $fields = @{ LocationId=$loc.Id; Description="$($r.Data.Description)" }
                $fields[$m.KeyParam] = $norm.Value
                if ($m.Key2) { $fields[$m.Key2Param] = $r.Key2 }

                $exists = @($script:LisWire[$r.Type]) | Where-Object { "$(Get-PropTolerant $_ $m.Keys)" -eq $norm.Value } | Select-Object -First 1
                $existsElsewhere = $exists -and ("$(Get-PropTolerant $exists @('LocationId','Locationid'))" -ne $loc.Id)
                if ($existsElsewhere -and -not $allowReassign) { throw "key already assigned to another location - enable reassign to move it" }

                $p = Select-CmdletParams -Cmdlet $m.Set -Params $fields
                $setCmd = $m.Set
                Invoke-WithRetry -RetryProfile 'BulkImport' -MaxAttempts $maxAttempts `
                    -CancelCheck { $script:WimCancel } `
                    -OnRetry { param($a,$dl,$er) Wim-Say "  row $($r.Row): transient failure, retry $a in $dl ms" $ui.Colors.Amber } `
                    -Action { & $setCmd @p -ErrorAction Stop } | Out-Null

                $r.LocationId=$loc.Id
                $r.Status = if ($existsElsewhere) { 'Reassigned' } elseif ($exists) { 'Updated' } else { 'Created' }
                $note = if ($norm.Note) { $norm.Note } elseif ($loc.Method -ne 'explicit') { "resolved by $($loc.Method)" } else { '' }
                $r.Detail = $note
                Wim-Say "  row $($r.Row): $($r.Status) $($m.Label) $($norm.Value) -> $($r.Location)$(if($note){' ('+$note+')'})" $ui.Colors.Green
            }
            catch {
                $r.Tries=[int]$r.Tries+1
                $cls=Get-ErrorClass $_
                $r.Status='Failed'; $r.Detail="[$cls] $($_.Exception.Message)"
                Wim-Say "  row $($r.Row) FAILED [$cls]: $($_.Exception.Message)" $ui.Colors.Red
                if ($stopOnErr -and $cls -ne 'Transient') { Wim-Say "Stop on first non-transient error - halting." $ui.Colors.Red; Wim-FillGrid; break }
            }
            Wim-FillGrid
            if ($delay -gt 0) { $slept=0; while ($slept -lt $delay) { Start-Sleep -Milliseconds 50; $slept+=50; [System.Windows.Forms.Application]::DoEvents() } }
        }
        $failed=@($script:WimRows | Where-Object { $_.Status -eq 'Failed' }).Count
        $done=@($script:WimRows | Where-Object { $_.Status -in @('Created','Updated','Reassigned') }).Count
        Wim-State "$verb complete: $done applied, $failed failed." $(if ($failed -gt 0) { $ui.Colors.Amber } else { $ui.Colors.Green })
        $ui.Retry.Enabled=($failed -gt 0); $ui.Export.Enabled=$true
        $ui.Stop.Enabled=$false; $ui.Run.Enabled=$true; $ui.Load.Enabled=$true
        $script:WimCancel=$false
        foreach ($t in @('wap','subnet','switch','port')) { Lis-RefreshWireType $t }
    }

    function script:Wim-Export {
        $ui=$script:WimUi; $stamp=Get-Stamp; $key=Get-EnvKey
        $rows = $script:WimRows | Select-Object Row,Status,Type,Key1,Key2,Location,LocationId,Tries,Detail
        $path = Get-OutputPath -Area Changes -File ("TeamsVoice_BulkWiremapImport_{0}_{1}.csv" -f $key,$stamp)
        try { $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8; Wim-Say "Exported results -> $([IO.Path]::GetFileName($path))" $ui.Colors.Green; Open-OutputFolder -Path $path -Label 'Wiremap import results' -SelectFile }
        catch { Wim-Say "Export failed: $($_.Exception.Message)" $ui.Colors.Red }
    }

    $wimBar.Template.Add_Click({ Wim-SaveTemplate })
    $wimBar.Load.Add_Click({ Wim-LoadCsv })
    $wimBar.Validate.Add_Click({ Wim-Validate })
    $wimBar.Run.Add_Click({ Wim-RunImport })
    $wimBar.Retry.Add_Click({ Wim-RunImport -RetryOnly })
    $wimBar.Stop.Add_Click({ $script:WimCancel=$true; Wim-Say 'Stop requested - remaining rows will be left untouched.' $script:WimUi.Colors.Amber })
    $wimBar.Export.Add_Click({ Wim-Export })
    if ($wimBar.RefreshLis) {
        $wimBar.RefreshLis.Add_Click({
            if (-not $script:RbacConnected) { Wim-Say 'Connect RBAC first.' $script:WimUi.Colors.Amber; return }
            foreach ($t in @('wap','subnet','switch','port')) { Lis-RefreshWireType $t }
            $script:LisLoc = @(Lis-InvokePagedCollection -Cmdlet 'Get-CsOnlineLisLocation' -PageSize 500 -DelayMs 0)
            Wim-Say "LIS cache refreshed." $script:WimUi.Colors.Green
        })
    }

    return $page
}


################################################################################
#
#  TAB 5  LIS / CIVIC MANAGER
#
#  RBAC-only. There is no Graph v1.0 surface for civic addresses, dispatchable
#  locations or the network wiremap - every call here is a Cs cmdlet.
#
#  A note on empty results: the LIS cmdlets return EMPTY rather than throwing
#  when the identity lacks a directory role. An empty civic list is therefore
#  ambiguous, and the state label says so rather than reporting "0 addresses"
#  as if it were a fact about the tenant.
#
################################################################################

# Wiremap metadata. Multiple spelling candidates per key because Get-* property
# casing is inconsistent across module versions - Lis-Prop resolves tolerantly.
$script:LisWireMeta = [ordered]@{
    wap = @{
        Label='WAP'; Get='Get-CsOnlineLisWirelessAccessPoint'; Set='Set-CsOnlineLisWirelessAccessPoint'
        Remove='Remove-CsOnlineLisWirelessAccessPoint'
        Keys=@('BSSID','Bssid'); KeyParam='BSSID'; Key2=$null; Key2Param=$null
        Hint='MAC-style BSSID, e.g. 00-11-22-33-44-55'
    }
    subnet = @{
        Label='Subnet'; Get='Get-CsOnlineLisSubnet'; Set='Set-CsOnlineLisSubnet'
        Remove='Remove-CsOnlineLisSubnet'
        Keys=@('Subnet'); KeyParam='Subnet'; Key2=$null; Key2Param=$null
        Hint='Subnet address, e.g. 10.10.20.0'
    }
    switch = @{
        Label='Switch'; Get='Get-CsOnlineLisSwitch'; Set='Set-CsOnlineLisSwitch'
        Remove='Remove-CsOnlineLisSwitch'
        Keys=@('ChassisID','ChassisId'); KeyParam='ChassisID'; Key2=$null; Key2Param=$null
        Hint='Switch chassis ID (LLDP)'
    }
    port = @{
        Label='Port'; Get='Get-CsOnlineLisPort'; Set='Set-CsOnlineLisPort'
        Remove='Remove-CsOnlineLisPort'
        Keys=@('ChassisID','ChassisId'); KeyParam='ChassisID'; Key2=@('PortID','PortId'); Key2Param='PortID'
        Hint='Chassis ID + port ID (LLDP)'
    }
}

$script:LisCivic  = @()
$script:LisLoc    = @()
$script:LisWire   = @{ wap=@(); subnet=@(); switch=@(); port=@() }
$script:LisCancel = $false

function New-LisTabPage {
<#
.SYNOPSIS
    Build the LIS / Civic Manager tab and return it.
.DESCRIPTION
    Helper functions are defined with the script: scope prefix so the event
    handlers below can reach them after this builder has returned - the builder's
    own local scope is gone by the time anything is clicked.
#>
    param(
        [string]$Text = '  LIS / Civic Manager  ',
        $BackColor,$ColorBlue,$ColorPurple,$ColorGreen,$ColorGray,$ColorAmber,$ColorRed
    )

    $page = New-Object System.Windows.Forms.TabPage
    $page.Text = $Text
    $page.BackColor = $BackColor

    # ---- top bar -------------------------------------------------------------
    $bar = New-Object System.Windows.Forms.Panel
    $bar.Dock='Top'; $bar.Height=76; $bar.BackColor=[System.Drawing.Color]::White

    $btnPull   = New-Object System.Windows.Forms.Button
    $btnPull.Location=New-Object System.Drawing.Point(12,10); $btnPull.Size=New-Object System.Drawing.Size(126,27)
    $btnPull.Text='Pull LIS Inventory'; Style-Button $btnPull $ColorPurple

    $btnStop   = New-Object System.Windows.Forms.Button
    $btnStop.Location=New-Object System.Drawing.Point(144,10); $btnStop.Size=New-Object System.Drawing.Size(76,27)
    $btnStop.Text='Stop Pull'; Style-Button $btnStop $ColorAmber; $btnStop.Enabled=$false

    $btnExpLoc = New-Object System.Windows.Forms.Button
    $btnExpLoc.Location=New-Object System.Drawing.Point(226,10); $btnExpLoc.Size=New-Object System.Drawing.Size(168,27)
    $btnExpLoc.Text='Export Locations (CSV)'; Style-Button $btnExpLoc $ColorGreen

    $btnExpSnap= New-Object System.Windows.Forms.Button
    $btnExpSnap.Location=New-Object System.Drawing.Point(400,10); $btnExpSnap.Size=New-Object System.Drawing.Size(148,27)
    $btnExpSnap.Text='Export Full Snapshot'; Style-Button $btnExpSnap $ColorBlue

    $btnFolder = New-Object System.Windows.Forms.Button
    $btnFolder.Location=New-Object System.Drawing.Point(554,10); $btnFolder.Size=New-Object System.Drawing.Size(112,27)
    $btnFolder.Text='Open Folder'; Style-Button $btnFolder $ColorGray

    $btnWire   = New-Object System.Windows.Forms.Button
    $btnWire.Location=New-Object System.Drawing.Point(672,10); $btnWire.Size=New-Object System.Drawing.Size(140,27)
    $btnWire.Text='Wiremap Detail...'; Style-Button $btnWire $ColorPurple

    $lblPage = New-Object System.Windows.Forms.Label
    $lblPage.Location=New-Object System.Drawing.Point(12,46); $lblPage.Size=New-Object System.Drawing.Size(62,20); $lblPage.Text='Page size'
    $numPage = New-Object System.Windows.Forms.NumericUpDown
    $numPage.Location=New-Object System.Drawing.Point(78,44); $numPage.Size=New-Object System.Drawing.Size(70,22)
    $numPage.Minimum=50; $numPage.Maximum=2000; $numPage.Increment=50; $numPage.Value=500

    $lblDelay = New-Object System.Windows.Forms.Label
    $lblDelay.Location=New-Object System.Drawing.Point(158,46); $lblDelay.Size=New-Object System.Drawing.Size(92,20); $lblDelay.Text='Delay/page (ms)'
    $numDelay = New-Object System.Windows.Forms.NumericUpDown
    $numDelay.Location=New-Object System.Drawing.Point(252,44); $numDelay.Size=New-Object System.Drawing.Size(70,22)
    $numDelay.Minimum=0; $numDelay.Maximum=10000; $numDelay.Increment=50; $numDelay.Value=200

    $lblTip = New-Object System.Windows.Forms.Label
    $lblTip.Location=New-Object System.Drawing.Point(332,46); $lblTip.Size=New-Object System.Drawing.Size(310,20)
    $lblTip.Text='double-click a location row to open its wiremap'
    $lblTip.ForeColor=$ColorGray; $lblTip.Font=New-Object System.Drawing.Font('Segoe UI',8,[System.Drawing.FontStyle]::Italic)

    $lblState = New-Object System.Windows.Forms.Label
    $lblState.Location=New-Object System.Drawing.Point(830,12); $lblState.Size=New-Object System.Drawing.Size(430,52)
    $lblState.Text='Not pulled.'; $lblState.ForeColor=$ColorGray
    $lblState.Font=New-Object System.Drawing.Font('Segoe UI',8,[System.Drawing.FontStyle]::Bold)

    $bar.Controls.AddRange(@($btnPull,$btnStop,$btnExpLoc,$btnExpSnap,$btnFolder,$btnWire,
                             $lblPage,$numPage,$lblDelay,$numDelay,$lblTip,$lblState))

    # ---- split layout --------------------------------------------------------
    $split = New-Object System.Windows.Forms.SplitContainer
    # SplitterDistance/Panel1MinSize/Panel2MinSize are all validated against the
    # control's CURRENT Size at the moment each is set - before this is added to
    # a parent, that is still whatever small default WinForms gives a freshly
    # constructed control, not the eventual Dock=Fill size. Setting an adequate
    # Size first (Dock=Fill overrides it once actually parented and shown) is
    # what avoids "SplitterDistance must be between Panel1MinSize and Width -
    # Panel2MinSize" at property-set time.
    $split.Size = New-Object System.Drawing.Size(1200,900)
    $split.Dock='Fill'; $split.Orientation='Horizontal'; $split.SplitterDistance=300
    $split.Panel1MinSize=160; $split.Panel2MinSize=200

    $gridSplit = New-Object System.Windows.Forms.SplitContainer
    $gridSplit.Size = New-Object System.Drawing.Size(1200,900)
    $gridSplit.Dock='Fill'; $gridSplit.Orientation='Vertical'; $gridSplit.SplitterDistance=520
    $gridSplit.Panel1MinSize=200; $gridSplit.Panel2MinSize=200
    $split.Panel1.Controls.Add($gridSplit)

    # civic side
    $pnlCivFilter = New-Object System.Windows.Forms.Panel
    $pnlCivFilter.Dock='Top'; $pnlCivFilter.Height=28; $pnlCivFilter.BackColor=$BackColor
    $lblCivF = New-Object System.Windows.Forms.Label
    $lblCivF.Location=New-Object System.Drawing.Point(4,6); $lblCivF.Size=New-Object System.Drawing.Size(96,18)
    $lblCivF.Text='Civic addresses'; $lblCivF.Font=New-Object System.Drawing.Font('Segoe UI',8,[System.Drawing.FontStyle]::Bold)
    $txtCivF = New-Object System.Windows.Forms.TextBox
    $txtCivF.Location=New-Object System.Drawing.Point(104,4); $txtCivF.Size=New-Object System.Drawing.Size(180,22)
    $pnlCivFilter.Controls.AddRange(@($lblCivF,$txtCivF))

    $gridCivic = New-Object System.Windows.Forms.DataGridView
    $gridCivic.Dock='Fill'; $gridCivic.ReadOnly=$true; $gridCivic.AllowUserToAddRows=$false
    $gridCivic.AllowUserToDeleteRows=$false; $gridCivic.SelectionMode='FullRowSelect'
    $gridCivic.MultiSelect=$false; $gridCivic.AutoSizeColumnsMode='Fill'
    $gridCivic.RowHeadersVisible=$false; $gridCivic.BackgroundColor=[System.Drawing.Color]::White
    foreach ($c in @('Description','Address','City','State','Postal','Status','CivicAddressId')) {
        [void]$gridCivic.Columns.Add($c,$c)
    }
    $gridCivic.Columns['CivicAddressId'].Visible=$false
    $gridCivic.Columns['Description'].FillWeight=140
    $gridCivic.Columns['Address'].FillWeight=180
    $gridSplit.Panel1.Controls.Add($gridCivic); $gridSplit.Panel1.Controls.Add($pnlCivFilter)

    # location side
    $pnlLocFilter = New-Object System.Windows.Forms.Panel
    $pnlLocFilter.Dock='Top'; $pnlLocFilter.Height=28; $pnlLocFilter.BackColor=$BackColor
    $lblLocF = New-Object System.Windows.Forms.Label
    $lblLocF.Location=New-Object System.Drawing.Point(4,6); $lblLocF.Size=New-Object System.Drawing.Size(96,18)
    $lblLocF.Text='Locations'; $lblLocF.Font=New-Object System.Drawing.Font('Segoe UI',8,[System.Drawing.FontStyle]::Bold)
    $txtLocF = New-Object System.Windows.Forms.TextBox
    $txtLocF.Location=New-Object System.Drawing.Point(104,4); $txtLocF.Size=New-Object System.Drawing.Size(180,22)
    $pnlLocFilter.Controls.AddRange(@($lblLocF,$txtLocF))

    $gridLoc = New-Object System.Windows.Forms.DataGridView
    $gridLoc.Dock='Fill'; $gridLoc.ReadOnly=$true; $gridLoc.AllowUserToAddRows=$false
    $gridLoc.AllowUserToDeleteRows=$false; $gridLoc.SelectionMode='FullRowSelect'
    $gridLoc.MultiSelect=$false; $gridLoc.AutoSizeColumnsMode='Fill'
    $gridLoc.RowHeadersVisible=$false; $gridLoc.BackgroundColor=[System.Drawing.Color]::White
    foreach ($c in @('Location','ELIN','Latitude','Longitude','WAP','Subnet','Switch','Port','LocationId')) {
        [void]$gridLoc.Columns.Add($c,$c)
    }
    $gridLoc.Columns['LocationId'].Visible=$false
    $gridLoc.Columns['Location'].FillWeight=150
    foreach ($c in @('WAP','Subnet','Switch','Port')) { $gridLoc.Columns[$c].FillWeight=43 }
    $gridSplit.Panel2.Controls.Add($gridLoc); $gridSplit.Panel2.Controls.Add($pnlLocFilter)

    # ---- editors -------------------------------------------------------------
    $grpCivic = New-Object System.Windows.Forms.GroupBox
    $grpCivic.Text=' Civic Address '; $grpCivic.Location=New-Object System.Drawing.Point(8,6)
    $grpCivic.Size=New-Object System.Drawing.Size(700,210)

    $civFields = @{}
    $civLeft  = @('Description','CompanyName','HouseNumber','StreetName','City')
    $civRight = @('StateOrProvince','PostalCode','CountryOrRegion','Latitude','Longitude')
    $y=22
    foreach ($f in $civLeft) {
        $l=New-Object System.Windows.Forms.Label; $l.Location=New-Object System.Drawing.Point(10,($y+3)); $l.Size=New-Object System.Drawing.Size(104,18); $l.Text=$f
        $t=New-Object System.Windows.Forms.TextBox; $t.Location=New-Object System.Drawing.Point(118,$y); $t.Size=New-Object System.Drawing.Size(200,22)
        $civFields[$f]=$t; $grpCivic.Controls.AddRange(@($l,$t)); $y+=28
    }
    $y=22
    foreach ($f in $civRight) {
        $l=New-Object System.Windows.Forms.Label; $l.Location=New-Object System.Drawing.Point(338,($y+3)); $l.Size=New-Object System.Drawing.Size(110,18); $l.Text=$f
        $t=New-Object System.Windows.Forms.TextBox; $t.Location=New-Object System.Drawing.Point(452,$y); $t.Size=New-Object System.Drawing.Size(200,22)
        $civFields[$f]=$t; $grpCivic.Controls.AddRange(@($l,$t)); $y+=28
    }
    $btnCivNew = New-Object System.Windows.Forms.Button
    $btnCivNew.Location=New-Object System.Drawing.Point(118,170); $btnCivNew.Size=New-Object System.Drawing.Size(96,26)
    $btnCivNew.Text='Clear / New'; Style-Button $btnCivNew $ColorGray
    $btnCivCreate = New-Object System.Windows.Forms.Button
    $btnCivCreate.Location=New-Object System.Drawing.Point(220,170); $btnCivCreate.Size=New-Object System.Drawing.Size(104,26)
    $btnCivCreate.Text='Create Civic'; Style-Button $btnCivCreate $ColorGreen
    $btnCivUpdate = New-Object System.Windows.Forms.Button
    $btnCivUpdate.Location=New-Object System.Drawing.Point(330,170); $btnCivUpdate.Size=New-Object System.Drawing.Size(104,26)
    $btnCivUpdate.Text='Update Civic'; Style-Button $btnCivUpdate $ColorBlue
    $btnCivDelete = New-Object System.Windows.Forms.Button
    $btnCivDelete.Location=New-Object System.Drawing.Point(440,170); $btnCivDelete.Size=New-Object System.Drawing.Size(104,26)
    $btnCivDelete.Text='Delete Civic'; Style-Button $btnCivDelete $ColorRed
    $grpCivic.Controls.AddRange(@($btnCivNew,$btnCivCreate,$btnCivUpdate,$btnCivDelete))

    $grpLoc = New-Object System.Windows.Forms.GroupBox
    $grpLoc.Text=' Dispatchable Location / ERL '; $grpLoc.Location=New-Object System.Drawing.Point(716,6)
    $grpLoc.Size=New-Object System.Drawing.Size(520,210)

    $locFields = @{}
    $y=22
    foreach ($f in @('Location','Elin','Latitude','Longitude')) {
        $l=New-Object System.Windows.Forms.Label; $l.Location=New-Object System.Drawing.Point(10,($y+3)); $l.Size=New-Object System.Drawing.Size(80,18); $l.Text=$f
        $t=New-Object System.Windows.Forms.TextBox; $t.Location=New-Object System.Drawing.Point(96,$y); $t.Size=New-Object System.Drawing.Size(220,22)
        $locFields[$f]=$t; $grpLoc.Controls.AddRange(@($l,$t)); $y+=28
    }
    $lblParent = New-Object System.Windows.Forms.Label
    $lblParent.Location=New-Object System.Drawing.Point(96,138); $lblParent.Size=New-Object System.Drawing.Size(400,18)
    $lblParent.Text='No parent civic address selected.'; $lblParent.ForeColor=$ColorPurple
    $lblParent.Font=New-Object System.Drawing.Font('Segoe UI',8,[System.Drawing.FontStyle]::Bold)
    $grpLoc.Controls.Add($lblParent)

    $btnLocNew = New-Object System.Windows.Forms.Button
    $btnLocNew.Location=New-Object System.Drawing.Point(10,170); $btnLocNew.Size=New-Object System.Drawing.Size(92,26)
    $btnLocNew.Text='Clear / New'; Style-Button $btnLocNew $ColorGray
    $btnLocCreate = New-Object System.Windows.Forms.Button
    $btnLocCreate.Location=New-Object System.Drawing.Point(108,170); $btnLocCreate.Size=New-Object System.Drawing.Size(104,26)
    $btnLocCreate.Text='Create Location'; Style-Button $btnLocCreate $ColorGreen
    $btnLocUpdate = New-Object System.Windows.Forms.Button
    $btnLocUpdate.Location=New-Object System.Drawing.Point(218,170); $btnLocUpdate.Size=New-Object System.Drawing.Size(104,26)
    $btnLocUpdate.Text='Update Location'; Style-Button $btnLocUpdate $ColorBlue
    $btnLocDelete = New-Object System.Windows.Forms.Button
    $btnLocDelete.Location=New-Object System.Drawing.Point(328,170); $btnLocDelete.Size=New-Object System.Drawing.Size(104,26)
    $btnLocDelete.Text='Delete Location'; Style-Button $btnLocDelete $ColorRed
    $btnLocWire = New-Object System.Windows.Forms.Button
    $btnLocWire.Location=New-Object System.Drawing.Point(10,140); $btnLocWire.Size=New-Object System.Drawing.Size(80,24)
    $btnLocWire.Text='Wiremap'; Style-Button $btnLocWire $ColorPurple
    $grpLoc.Controls.AddRange(@($btnLocNew,$btnLocCreate,$btnLocUpdate,$btnLocDelete,$btnLocWire))

    $pnlEdit = New-Object System.Windows.Forms.Panel
    $pnlEdit.Dock='Fill'; $pnlEdit.BackColor=$BackColor; $pnlEdit.AutoScroll=$true
    $pnlEdit.Controls.AddRange(@($grpCivic,$grpLoc))

    $rtb = New-Object System.Windows.Forms.RichTextBox
    $rtb.Dock='Bottom'; $rtb.Height=120; $rtb.ReadOnly=$true; $rtb.BackColor=[System.Drawing.Color]::White
    $rtb.Font=New-Object System.Drawing.Font('Consolas',9)

    $split.Panel2.Controls.Add($pnlEdit)
    $split.Panel2.Controls.Add($rtb)

    $page.Controls.Add($split)
    $page.Controls.Add($bar)

    # ---- published handles ---------------------------------------------------
    $script:LisUi = @{
        Log=$rtb; State=$lblState; GridCivic=$gridCivic; GridLoc=$gridLoc
        CivFields=$civFields; LocFields=$locFields; Parent=$lblParent
        PageSize=$numPage; Delay=$numDelay; Stop=$btnStop; Pull=$btnPull
        CivFilter=$txtCivF; LocFilter=$txtLocF
        Colors=@{ Blue=$ColorBlue; Purple=$ColorPurple; Green=$ColorGreen; Gray=$ColorGray; Amber=$ColorAmber; Red=$ColorRed }
    }
    $script:LisSelectedCivic = $null
    $script:LisSelectedLoc   = $null

    # ==========================================================================
    # HELPERS - script scope so the handlers below survive this builder returning
    # ==========================================================================

    function script:Lis-Say {
        param([string]$Text,$Color)
        $ui=$script:LisUi; if (-not $ui) { return }
        if (-not $Color) { $Color=[System.Drawing.Color]::Black }
        $ui.Log.SelectionStart=$ui.Log.TextLength; $ui.Log.SelectionLength=0
        $ui.Log.SelectionColor=$Color
        $ui.Log.AppendText(("[{0}] {1}`n" -f (Get-Date).ToString('HH:mm:ss'),$Text))
        $ui.Log.SelectionColor=$ui.Log.ForeColor
        $ui.Log.ScrollToCaret()
    }

    function script:Lis-State {
        param([string]$Text,$Color)
        $ui=$script:LisUi; if (-not $ui) { return }
        if (-not $Color) { $Color=$ui.Colors.Gray }
        $ui.State.Text=$Text; $ui.State.ForeColor=$Color
        [System.Windows.Forms.Application]::DoEvents()
    }

    function script:Lis-RequireRbac {
        if ($script:RbacConnected) { return $true }
        [void][System.Windows.Forms.MessageBox]::Show(
            "The LIS / Civic Manager is RBAC-only. There is no Graph v1.0 surface for civic addresses, locations or the wiremap.`n`nConnect RBAC (Teams PowerShell) first.",
            'RBAC required',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information)
        return $false
    }

    function script:Lis-Confirm { param([string]$Message) return (Confirm-ToolkitWrite -Title 'Confirm LIS write' -Message $Message) }

    function script:Lis-Prop { param($Object,[string[]]$Names,$Default='') return (Get-PropTolerant -Object $Object -Names $Names -Default $Default) }

    function script:Lis-CmdParams {
        param([string]$Cmdlet,[hashtable]$Fields)
        $dropped=@()
        $p = Select-CmdletParams -Cmdlet $Cmdlet -Params $Fields -DroppedVar 'dropped'
        if ($dropped -and $dropped.Count -gt 0) {
            Lis-Say ("  note: {0} does not accept {1} on this module version - dropped" -f $Cmdlet,($dropped -join ', ')) $script:LisUi.Colors.Gray
        }
        return $p
    }

    function script:Lis-InvokeWithRetry {
        param([scriptblock]$Action,[string]$What='call')
        return (Invoke-WithRetry -Action $Action -RetryProfile 'Lis' `
            -CancelCheck { $script:LisCancel } `
            -OnRetry {
                param($Attempt,$DelayMs,$Err)
                Lis-State ("{0}: transient failure, retry {1} in {2} ms" -f $What,$Attempt,$DelayMs) $script:LisUi.Colors.Amber
            })
    }

    function script:Lis-InvokePagedCollection {
    <#
    .SYNOPSIS
        Pull a whole LIS collection, paged when the cmdlet supports it.
    .DESCRIPTION
        Not every Cs LIS cmdlet exposes ResultSize / NumberOfResultsToSkip. When
        both are missing this makes one unpaged call rather than pretending to
        page. When they are present it loops until a short batch comes back.

        The inter-page delay is slept in 50 ms slices so Stop Pull is responsive
        instead of blocking for the whole delay.
    #>
        param([string]$Cmdlet,[int]$PageSize=500,[int]$DelayMs=200,[scriptblock]$OnProgress)
        $out = New-Object System.Collections.Generic.List[object]
        if (-not (Test-CmdletPresent -Name $Cmdlet)) {
            Lis-Say "  $Cmdlet is not available in the loaded module - skipped." $script:LisUi.Colors.Amber
            return @()
        }
        $cmd = Get-Command -Name $Cmdlet -ErrorAction SilentlyContinue
        $canPage = $false
        if ($cmd -and $cmd.Parameters) {
            $canPage = ($cmd.Parameters.Keys -contains 'ResultSize') -and ($cmd.Parameters.Keys -contains 'NumberOfResultsToSkip')
        }

        if (-not $canPage) {
            $batch = Lis-InvokeWithRetry -What $Cmdlet -Action { & $Cmdlet -ErrorAction Stop }
            foreach ($b in @($batch)) { $out.Add($b) | Out-Null }
            if ($OnProgress) { & $OnProgress $out.Count }
            return @($out)
        }

        $skip = 0
        while ($true) {
            if ($script:LisCancel) { Lis-Say "  stopped after $($out.Count) row(s)." $script:LisUi.Colors.Amber; break }
            $s = $skip
            # NumberOfResultsToSkip rejects 0 outright (SkipNegativeOrZeroException) -
            # it means "skip past what a PRIOR call already returned", so the first
            # page must omit it entirely rather than pass a literal zero.
            $p = @{ ResultSize = $PageSize; ErrorAction = 'Stop' }
            if ($s -gt 0) { $p['NumberOfResultsToSkip'] = $s }
            $batch = @(Lis-InvokeWithRetry -What $Cmdlet -Action { & $Cmdlet @p })
            foreach ($b in $batch) { $out.Add($b) | Out-Null }
            if ($OnProgress) { & $OnProgress $out.Count }
            if ($batch.Count -lt $PageSize) { break }
            $skip += $PageSize
            $slept=0
            while ($slept -lt $DelayMs) {
                if ($script:LisCancel) { break }
                Start-Sleep -Milliseconds 50; $slept += 50
                [System.Windows.Forms.Application]::DoEvents()
            }
        }
        return @($out)
    }

    function script:Lis-WireCounts {
    <#
    .SYNOPSIS
        Per-location counts of each wiremap object type, keyed by LocationId.
    #>
        $map=@{}
        foreach ($t in $script:LisWireMeta.Keys) {
            foreach ($w in @($script:LisWire[$t])) {
                $lid = "$(Lis-Prop $w @('LocationId','Locationid'))"
                if ([string]::IsNullOrWhiteSpace($lid)) { continue }
                if (-not $map.ContainsKey($lid)) { $map[$lid]=@{ wap=0; subnet=0; switch=0; port=0 } }
                $map[$lid][$t] = [int]$map[$lid][$t] + 1
            }
        }
        return $map
    }

    function script:Lis-RowMatches {
    <#
    .SYNOPSIS
        Live filter test. Serialises the record and matches the escaped filter text.
    .DESCRIPTION
        Serialising means the filter hits any field including ones not shown as a
        column. Escaping means a filter containing '.' or '(' is treated as text,
        not as a pattern the user did not intend to write.
    #>
        param($Record,[string]$Filter)
        if ([string]::IsNullOrWhiteSpace($Filter)) { return $true }
        $json=''
        try { $json = ($Record | ConvertTo-Json -Depth 5 -Compress) } catch { $json = "$Record" }
        return ($json -imatch [regex]::Escape($Filter))
    }

    function script:Lis-FillCivicGrid {
        $ui=$script:LisUi; $g=$ui.GridCivic; $f=$ui.CivFilter.Text
        $g.SuspendLayout(); $g.Rows.Clear()
        foreach ($c in @($script:LisCivic)) {
            if (-not (Lis-RowMatches $c $f)) { continue }
            $addr = @(
                (Lis-Prop $c @('HouseNumber')),
                (Lis-Prop $c @('StreetName')),
                (Lis-Prop $c @('StreetSuffix'))
            ) | Where-Object { "$_" -ne '' }
            [void]$g.Rows.Add(
                "$(Lis-Prop $c @('Description','CompanyName'))",
                ($addr -join ' '),
                "$(Lis-Prop $c @('City'))",
                "$(Lis-Prop $c @('StateOrProvince','State'))",
                "$(Lis-Prop $c @('PostalCode','Zip'))",
                "$(Lis-Prop $c @('ValidationStatus','Status'))",
                "$(Lis-Prop $c @('CivicAddressId','CivicAddressid'))"
            )
        }
        $g.ResumeLayout()
    }

    function script:Lis-FillLocGrid {
        param([string]$CivicId)
        $ui=$script:LisUi; $g=$ui.GridLoc; $f=$ui.LocFilter.Text
        $counts = Lis-WireCounts
        $g.SuspendLayout(); $g.Rows.Clear()
        foreach ($l in @($script:LisLoc)) {
            if (-not [string]::IsNullOrWhiteSpace($CivicId)) {
                if ("$(Lis-Prop $l @('CivicAddressId','CivicAddressid'))" -ne $CivicId) { continue }
            }
            if (-not (Lis-RowMatches $l $f)) { continue }
            $lid = "$(Lis-Prop $l @('LocationId','Locationid'))"
            $c = $counts[$lid]
            if (-not $c) { $c=@{ wap=0; subnet=0; switch=0; port=0 } }
            [void]$g.Rows.Add(
                "$(Lis-Prop $l @('Location','Description'))",
                "$(Lis-Prop $l @('Elin','ELIN'))",
                "$(Lis-Prop $l @('Latitude'))",
                "$(Lis-Prop $l @('Longitude'))",
                $c.wap,$c.subnet,$c.switch,$c.port,$lid
            )
        }
        $g.ResumeLayout()
    }

    function script:Lis-FindCivic { param([string]$Id)
        return (@($script:LisCivic) | Where-Object { "$(Lis-Prop $_ @('CivicAddressId','CivicAddressid'))" -eq $Id } | Select-Object -First 1)
    }
    function script:Lis-FindLoc { param([string]$Id)
        return (@($script:LisLoc) | Where-Object { "$(Lis-Prop $_ @('LocationId','Locationid'))" -eq $Id } | Select-Object -First 1)
    }

    function script:Lis-PullAll {
    <#
    .SYNOPSIS
        Pull civic addresses, locations and all four wiremap types.
    #>
        if (-not (Lis-RequireRbac)) { return }
        $ui=$script:LisUi
        $script:LisCancel=$false
        $ui.Stop.Enabled=$true; $ui.Pull.Enabled=$false
        $ps=[int]$ui.PageSize.Value; $dl=[int]$ui.Delay.Value
        try {
            Lis-Say "Pulling LIS inventory (page size $ps, delay $dl ms)..." $ui.Colors.Purple

            Lis-State 'Civic addresses...' $ui.Colors.Purple
            $script:LisCivic = @(Lis-InvokePagedCollection -Cmdlet 'Get-CsOnlineLisCivicAddress' -PageSize $ps -DelayMs $dl `
                -OnProgress { param($n) Lis-State "Civic addresses: $n" $script:LisUi.Colors.Purple })
            Lis-Say "  civic addresses: $($script:LisCivic.Count)" $ui.Colors.Blue

            if (-not $script:LisCancel) {
                Lis-State 'Locations...' $ui.Colors.Purple
                $script:LisLoc = @(Lis-InvokePagedCollection -Cmdlet 'Get-CsOnlineLisLocation' -PageSize $ps -DelayMs $dl `
                    -OnProgress { param($n) Lis-State "Locations: $n" $script:LisUi.Colors.Purple })
                Lis-Say "  locations: $($script:LisLoc.Count)" $ui.Colors.Blue
            }

            foreach ($t in @($script:LisWireMeta.Keys)) {
                if ($script:LisCancel) { break }
                $m=$script:LisWireMeta[$t]
                Lis-State "$($m.Label) objects..." $ui.Colors.Purple
                $script:LisWire[$t] = @(Lis-InvokePagedCollection -Cmdlet $m.Get -PageSize $ps -DelayMs $dl)
                Lis-Say "  $($m.Label): $($script:LisWire[$t].Count)" $ui.Colors.Blue
            }

            Lis-FillCivicGrid
            Lis-FillLocGrid ''
            $total = $script:LisCivic.Count + $script:LisLoc.Count
            if ($total -eq 0) {
                # Empty is ambiguous here - say so rather than asserting the tenant is empty.
                Lis-State "0 civic addresses and 0 locations returned.`nThe LIS cmdlets return empty rather than throwing when the identity lacks a directory role - check the role before concluding the tenant is empty." $ui.Colors.Amber
                Lis-Say "Empty result. This is what a missing directory role looks like; it is not proof the tenant has no LIS data." $ui.Colors.Amber
            } else {
                Lis-State ("Civic {0}  Locations {1}  WAP {2}  Subnet {3}  Switch {4}  Port {5}" -f `
                    $script:LisCivic.Count,$script:LisLoc.Count,$script:LisWire.wap.Count,$script:LisWire.subnet.Count,$script:LisWire.switch.Count,$script:LisWire.port.Count) $ui.Colors.Green
            }
        }
        catch {
            $cls = Get-ErrorClass $_
            Lis-Say "Pull failed [$cls]: $($_.Exception.Message)" $ui.Colors.Red
            Lis-State "Pull failed ($cls)." $ui.Colors.Red
        }
        finally { $ui.Stop.Enabled=$false; $ui.Pull.Enabled=$true; $script:LisCancel=$false }
    }

    function script:Lis-RefreshWireType {
    <#
    .SYNOPSIS
        Re-pull one wiremap type and splice it into the cache.
    .DESCRIPTION
        After a wiremap edit the per-location counts are stale. Re-pulling one
        type keeps them truthful without the cost of a full inventory pull.
    #>
        param([string]$Type)
        $m=$script:LisWireMeta[$Type]; if (-not $m) { return }
        try {
            $script:LisWire[$Type] = @(Lis-InvokePagedCollection -Cmdlet $m.Get -PageSize ([int]$script:LisUi.PageSize.Value) -DelayMs 0)
            Lis-Say "  $($m.Label) cache refreshed: $($script:LisWire[$Type].Count)" $script:LisUi.Colors.Gray
        } catch { Lis-Say "  $($m.Label) refresh failed: $($_.Exception.Message)" $script:LisUi.Colors.Amber }
    }

    # ---- writes --------------------------------------------------------------

    function script:Lis-CreateCivic {
        if (-not (Lis-RequireRbac)) { return }
        $ui=$script:LisUi; $f=$ui.CivFields
        foreach ($req in @('CountryOrRegion','City','StreetName')) {
            if ([string]::IsNullOrWhiteSpace($f[$req].Text)) {
                Lis-Say "Create civic: $req is required." $ui.Colors.Amber; return
            }
        }
        $desc = $f['Description'].Text
        if (-not (Lis-Confirm ("Create civic address`n`n{0}`n{1} {2}, {3} {4} {5}`n`nTenant: {6}" -f `
            $desc,$f['HouseNumber'].Text,$f['StreetName'].Text,$f['City'].Text,$f['StateOrProvince'].Text,$f['CountryOrRegion'].Text,$script:CurrentEnv))) { return }

        $fields=@{}
        foreach ($k in $f.Keys) { $fields[$k]=$f[$k].Text }
        $p = Lis-CmdParams -Cmdlet 'New-CsOnlineLisCivicAddress' -Fields $fields
        try {
            $new = Lis-InvokeWithRetry -What 'New-CsOnlineLisCivicAddress' -Action { New-CsOnlineLisCivicAddress @p -ErrorAction Stop }
            $script:LisCivic = @($script:LisCivic) + @($new)
            Lis-FillCivicGrid
            Lis-Say "Created civic $(Lis-Prop $new @('CivicAddressId','CivicAddressid'))" $ui.Colors.Green
        } catch {
            $cls=Get-ErrorClass $_
            Lis-Say "Create civic failed [$cls]: $($_.Exception.Message)" $ui.Colors.Red
        }
    }

    function script:Lis-UpdateCivic {
        if (-not (Lis-RequireRbac)) { return }
        $ui=$script:LisUi
        if (-not $script:LisSelectedCivic) { Lis-Say 'Select a civic address first.' $ui.Colors.Amber; return }
        $id = "$(Lis-Prop $script:LisSelectedCivic @('CivicAddressId','CivicAddressid'))"
        if (-not (Lis-Confirm "Update civic address`n`n$id`n`nTenant: $($script:CurrentEnv)")) { return }
        $fields=@{ CivicAddressId=$id }
        foreach ($k in $ui.CivFields.Keys) { $fields[$k]=$ui.CivFields[$k].Text }
        $p = Lis-CmdParams -Cmdlet 'Set-CsOnlineLisCivicAddress' -Fields $fields
        try {
            Lis-InvokeWithRetry -What 'Set-CsOnlineLisCivicAddress' -Action { Set-CsOnlineLisCivicAddress @p -ErrorAction Stop } | Out-Null
            Lis-Say "Updated civic $id" $ui.Colors.Green
            Lis-PullCivicOnly
        } catch { Lis-Say "Update civic failed [$(Get-ErrorClass $_)]: $($_.Exception.Message)" $ui.Colors.Red }
    }

    function script:Lis-PullCivicOnly {
        $script:LisCivic = @(Lis-InvokePagedCollection -Cmdlet 'Get-CsOnlineLisCivicAddress' -PageSize ([int]$script:LisUi.PageSize.Value) -DelayMs 0)
        Lis-FillCivicGrid
    }
    function script:Lis-PullLocOnly {
        $script:LisLoc = @(Lis-InvokePagedCollection -Cmdlet 'Get-CsOnlineLisLocation' -PageSize ([int]$script:LisUi.PageSize.Value) -DelayMs 0)
        $cid=''
        if ($script:LisSelectedCivic) { $cid="$(Lis-Prop $script:LisSelectedCivic @('CivicAddressId','CivicAddressid'))" }
        Lis-FillLocGrid $cid
    }

    function script:Lis-DeleteCivic {
        if (-not (Lis-RequireRbac)) { return }
        $ui=$script:LisUi
        if (-not $script:LisSelectedCivic) { Lis-Say 'Select a civic address first.' $ui.Colors.Amber; return }
        $id = "$(Lis-Prop $script:LisSelectedCivic @('CivicAddressId','CivicAddressid'))"
        # Guardrail: a civic with children cannot be deleted cleanly, and the
        # tenant-side error does not say which locations are in the way.
        $kids = @(@($script:LisLoc) | Where-Object { "$(Lis-Prop $_ @('CivicAddressId','CivicAddressid'))" -eq $id })
        if ($kids.Count -gt 0) {
            Lis-Say "Delete blocked: $($kids.Count) child location(s) still reference this civic address. Remove or move them first." $ui.Colors.Red
            [void][System.Windows.Forms.MessageBox]::Show(
                "This civic address has $($kids.Count) dispatchable location(s) under it.`n`nRemove or move them first.",
                'Delete blocked',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        if (-not (Lis-Confirm "DELETE civic address`n`n$id`n`nThis cannot be undone.`nTenant: $($script:CurrentEnv)")) { return }
        try {
            Lis-InvokeWithRetry -What 'Remove-CsOnlineLisCivicAddress' -Action { Remove-CsOnlineLisCivicAddress -CivicAddressId $id -ErrorAction Stop } | Out-Null
            $script:LisCivic = @(@($script:LisCivic) | Where-Object { "$(Lis-Prop $_ @('CivicAddressId','CivicAddressid'))" -ne $id })
            $script:LisSelectedCivic=$null
            Lis-FillCivicGrid
            Lis-Say "Deleted civic $id" $ui.Colors.Green
        } catch { Lis-Say "Delete civic failed [$(Get-ErrorClass $_)]: $($_.Exception.Message)" $ui.Colors.Red }
    }

    function script:Lis-CreateLocation {
        if (-not (Lis-RequireRbac)) { return }
        $ui=$script:LisUi
        if (-not $script:LisSelectedCivic) { Lis-Say 'Select the parent civic address first.' $ui.Colors.Amber; return }
        if ([string]::IsNullOrWhiteSpace($ui.LocFields['Location'].Text)) { Lis-Say 'Create location: Location name is required.' $ui.Colors.Amber; return }
        $cid="$(Lis-Prop $script:LisSelectedCivic @('CivicAddressId','CivicAddressid'))"
        if (-not (Lis-Confirm ("Create dispatchable location`n`n{0}`nunder civic {1}`n`nTenant: {2}" -f $ui.LocFields['Location'].Text,$cid,$script:CurrentEnv))) { return }
        $fields=@{ CivicAddressId=$cid }
        foreach ($k in $ui.LocFields.Keys) { $fields[$k]=$ui.LocFields[$k].Text }
        $p = Lis-CmdParams -Cmdlet 'New-CsOnlineLisLocation' -Fields $fields
        try {
            $new = Lis-InvokeWithRetry -What 'New-CsOnlineLisLocation' -Action { New-CsOnlineLisLocation @p -ErrorAction Stop }
            $script:LisLoc = @($script:LisLoc) + @($new)
            Lis-FillLocGrid $cid
            Lis-Say "Created location $(Lis-Prop $new @('LocationId','Locationid'))" $ui.Colors.Green
        } catch { Lis-Say "Create location failed [$(Get-ErrorClass $_)]: $($_.Exception.Message)" $ui.Colors.Red }
    }

    function script:Lis-UpdateLocation {
        if (-not (Lis-RequireRbac)) { return }
        $ui=$script:LisUi
        if (-not $script:LisSelectedLoc) { Lis-Say 'Select a location first.' $ui.Colors.Amber; return }
        $lid="$(Lis-Prop $script:LisSelectedLoc @('LocationId','Locationid'))"
        if (-not (Lis-Confirm "Update dispatchable location`n`n$lid`n`nTenant: $($script:CurrentEnv)")) { return }
        $fields=@{ LocationId=$lid }
        foreach ($k in $ui.LocFields.Keys) { $fields[$k]=$ui.LocFields[$k].Text }
        $p = Lis-CmdParams -Cmdlet 'Set-CsOnlineLisLocation' -Fields $fields
        try {
            Lis-InvokeWithRetry -What 'Set-CsOnlineLisLocation' -Action { Set-CsOnlineLisLocation @p -ErrorAction Stop } | Out-Null
            Lis-Say "Updated location $lid" $ui.Colors.Green
            Lis-PullLocOnly
        } catch { Lis-Say "Update location failed [$(Get-ErrorClass $_)]: $($_.Exception.Message)" $ui.Colors.Red }
    }

    function script:Lis-DeleteLocation {
        if (-not (Lis-RequireRbac)) { return }
        $ui=$script:LisUi
        if (-not $script:LisSelectedLoc) { Lis-Say 'Select a location first.' $ui.Colors.Amber; return }
        $lid="$(Lis-Prop $script:LisSelectedLoc @('LocationId','Locationid'))"
        # Guardrail: wiremap objects pointing at a deleted location leave clients
        # resolving to nothing, and the reference is invisible from the location.
        $refs=0
        foreach ($t in $script:LisWireMeta.Keys) {
            $refs += @(@($script:LisWire[$t]) | Where-Object { "$(Lis-Prop $_ @('LocationId','Locationid'))" -eq $lid }).Count
        }
        if ($refs -gt 0) {
            Lis-Say "Delete blocked: $refs wiremap object(s) still reference this location. Open Wiremap Detail to reassign or remove them first." $ui.Colors.Red
            [void][System.Windows.Forms.MessageBox]::Show(
                "$refs wiremap object(s) still point at this location.`n`nOpen Wiremap Detail to reassign or remove them first.",
                'Delete blocked',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        if (-not (Lis-Confirm "DELETE dispatchable location`n`n$lid`n`nThis cannot be undone.`nTenant: $($script:CurrentEnv)")) { return }
        try {
            Lis-InvokeWithRetry -What 'Remove-CsOnlineLisLocation' -Action { Remove-CsOnlineLisLocation -LocationId $lid -ErrorAction Stop } | Out-Null
            $script:LisLoc = @(@($script:LisLoc) | Where-Object { "$(Lis-Prop $_ @('LocationId','Locationid'))" -ne $lid })
            $script:LisSelectedLoc=$null
            $cid=''
            if ($script:LisSelectedCivic) { $cid="$(Lis-Prop $script:LisSelectedCivic @('CivicAddressId','CivicAddressid'))" }
            Lis-FillLocGrid $cid
            Lis-Say "Deleted location $lid" $ui.Colors.Green
        } catch { Lis-Say "Delete location failed [$(Get-ErrorClass $_)]: $($_.Exception.Message)" $ui.Colors.Red }
    }

    # ---- wiremap detail dialog ----------------------------------------------

    function script:Lis-ShowWiremapDialog {
        param([string]$LocationId)
        if (-not (Lis-RequireRbac)) { return }
        $ui=$script:LisUi
        if ([string]::IsNullOrWhiteSpace($LocationId)) { Lis-Say 'Select a location first.' $ui.Colors.Amber; return }
        $loc = Lis-FindLoc $LocationId
        $locName = "$(Lis-Prop $loc @('Location','Description'))"

        $dlg=New-Object System.Windows.Forms.Form
        $dlg.Text="Wiremap - $locName"
        $dlg.Size=New-Object System.Drawing.Size(880,560); $dlg.StartPosition='CenterParent'
        $dlg.BackColor=$script:LisUi.Colors.Gray; $dlg.BackColor=[System.Drawing.Color]::FromArgb(245,246,248)

        $top=New-Object System.Windows.Forms.Panel; $top.Dock='Top'; $top.Height=92; $top.BackColor=[System.Drawing.Color]::White
        $lblType=New-Object System.Windows.Forms.Label; $lblType.Location=New-Object System.Drawing.Point(12,14); $lblType.Size=New-Object System.Drawing.Size(40,20); $lblType.Text='Type'
        $cmbType=New-Object System.Windows.Forms.ComboBox
        $script:LisWireDlgCmbType = $cmbType
        $script:LisWireDlgCmbType.Location=New-Object System.Drawing.Point(56,12); $script:LisWireDlgCmbType.Size=New-Object System.Drawing.Size(140,22); $script:LisWireDlgCmbType.DropDownStyle='DropDownList'
        foreach ($t in $script:LisWireMeta.Keys) { [void]$script:LisWireDlgCmbType.Items.Add($script:LisWireMeta[$t].Label) }
        $script:LisWireDlgCmbType.SelectedIndex=0
        $lblK1=New-Object System.Windows.Forms.Label; $lblK1.Location=New-Object System.Drawing.Point(206,14); $lblK1.Size=New-Object System.Drawing.Size(40,20); $lblK1.Text='Key'
        $txtK1=New-Object System.Windows.Forms.TextBox
        $script:LisWireDlgTxtK1 = $txtK1
        $script:LisWireDlgTxtK1.Location=New-Object System.Drawing.Point(248,12); $script:LisWireDlgTxtK1.Size=New-Object System.Drawing.Size(180,22)
        $lblK2=New-Object System.Windows.Forms.Label; $lblK2.Location=New-Object System.Drawing.Point(438,14); $lblK2.Size=New-Object System.Drawing.Size(48,20); $lblK2.Text='Port ID'
        $txtK2=New-Object System.Windows.Forms.TextBox
        $script:LisWireDlgTxtK2 = $txtK2
        $script:LisWireDlgTxtK2.Location=New-Object System.Drawing.Point(488,12); $script:LisWireDlgTxtK2.Size=New-Object System.Drawing.Size(120,22); $script:LisWireDlgTxtK2.Enabled=$false
        $lblD=New-Object System.Windows.Forms.Label; $lblD.Location=New-Object System.Drawing.Point(12,46); $lblD.Size=New-Object System.Drawing.Size(70,20); $lblD.Text='Description'
        $txtD=New-Object System.Windows.Forms.TextBox
        $script:LisWireDlgTxtD = $txtD
        $script:LisWireDlgTxtD.Location=New-Object System.Drawing.Point(88,44); $script:LisWireDlgTxtD.Size=New-Object System.Drawing.Size(340,22)
        $lblHint=New-Object System.Windows.Forms.Label
        $script:LisWireDlgLblHint = $lblHint
        $script:LisWireDlgLblHint.Location=New-Object System.Drawing.Point(438,46); $script:LisWireDlgLblHint.Size=New-Object System.Drawing.Size(400,20)
        $script:LisWireDlgLblHint.ForeColor=$ui.Colors.Gray; $script:LisWireDlgLblHint.Font=New-Object System.Drawing.Font('Segoe UI',8,[System.Drawing.FontStyle]::Italic)
        $script:LisWireDlgLblHint.Text=$script:LisWireMeta.wap.Hint

        $btnAdd=New-Object System.Windows.Forms.Button; $btnAdd.Location=New-Object System.Drawing.Point(620,10); $btnAdd.Size=New-Object System.Drawing.Size(110,26)
        $btnAdd.Text='Add / Reassign'; Style-Button $btnAdd $ui.Colors.Green
        $btnRem=New-Object System.Windows.Forms.Button; $btnRem.Location=New-Object System.Drawing.Point(736,10); $btnRem.Size=New-Object System.Drawing.Size(92,26)
        $btnRem.Text='Remove'; Style-Button $btnRem $ui.Colors.Red
        $top.Controls.AddRange(@($lblType,$script:LisWireDlgCmbType,$lblK1,$script:LisWireDlgTxtK1,$lblK2,$script:LisWireDlgTxtK2,$lblD,$script:LisWireDlgTxtD,$script:LisWireDlgLblHint,$btnAdd,$btnRem))

        $grid=New-Object System.Windows.Forms.DataGridView
        $script:LisWireDlgGrid = $grid
        $script:LisWireDlgGrid.Dock='Fill'; $script:LisWireDlgGrid.ReadOnly=$true; $script:LisWireDlgGrid.AllowUserToAddRows=$false; $script:LisWireDlgGrid.SelectionMode='FullRowSelect'
        $script:LisWireDlgGrid.MultiSelect=$false; $script:LisWireDlgGrid.AutoSizeColumnsMode='Fill'; $script:LisWireDlgGrid.RowHeadersVisible=$false
        $script:LisWireDlgGrid.BackgroundColor=[System.Drawing.Color]::White
        foreach ($c in @('Type','Key1','Key2','Description')) { [void]$script:LisWireDlgGrid.Columns.Add($c,$c) }
        $script:LisWireDlgGrid.Columns['Description'].FillWeight=200

        $fill = {
            $script:LisWireDlgGrid.Rows.Clear()
            foreach ($t in $script:LisWireMeta.Keys) {
                $m=$script:LisWireMeta[$t]
                foreach ($w in @($script:LisWire[$t])) {
                    if ("$(Lis-Prop $w @('LocationId','Locationid'))" -ne $LocationId) { continue }
                    $k2=''
                    if ($m.Key2) { $k2="$(Lis-Prop $w $m.Key2)" }
                    [void]$script:LisWireDlgGrid.Rows.Add($m.Label,"$(Lis-Prop $w $m.Keys)",$k2,"$(Lis-Prop $w @('Description'))")
                }
            }
        }
        & $fill

        $script:LisWireDlgCmbType.Add_SelectedIndexChanged({
            $key = @($script:LisWireMeta.Keys)[$script:LisWireDlgCmbType.SelectedIndex]
            $script:LisWireDlgTxtK2.Enabled = [bool]$script:LisWireMeta[$key].Key2
            $script:LisWireDlgLblHint.Text  = $script:LisWireMeta[$key].Hint
        })

        $btnAdd.Add_Click({
            $key = @($script:LisWireMeta.Keys)[$script:LisWireDlgCmbType.SelectedIndex]
            $m   = $script:LisWireMeta[$key]
            if ([string]::IsNullOrWhiteSpace($script:LisWireDlgTxtK1.Text)) { return }
            if ($m.Key2 -and [string]::IsNullOrWhiteSpace($script:LisWireDlgTxtK2.Text)) { return }
            $desc=$script:LisWireDlgTxtK1.Text
            if (-not (Lis-Confirm ("Point {0} '{1}' at location`n{2}`n`nThis changes how Teams clients resolve to an emergency location." -f $m.Label,$desc,$locName))) { return }
            $fields=@{ LocationId=$LocationId; Description=$script:LisWireDlgTxtD.Text }
            $fields[$m.KeyParam]=$script:LisWireDlgTxtK1.Text
            if ($m.Key2) { $fields[$m.Key2Param]=$script:LisWireDlgTxtK2.Text }
            $p = Lis-CmdParams -Cmdlet $m.Set -Fields $fields
            try {
                $setCmd=$m.Set
                Lis-InvokeWithRetry -What $setCmd -Action { & $setCmd @p -ErrorAction Stop } | Out-Null
                Lis-Say "  $($m.Label) $($script:LisWireDlgTxtK1.Text) -> $locName" $script:LisUi.Colors.Green
                Lis-RefreshWireType $key
                & $fill
                $cid=''
                if ($script:LisSelectedCivic) { $cid="$(Lis-Prop $script:LisSelectedCivic @('CivicAddressId','CivicAddressid'))" }
                Lis-FillLocGrid $cid
            } catch { Lis-Say "  $($m.Label) write failed [$(Get-ErrorClass $_)]: $($_.Exception.Message)" $script:LisUi.Colors.Red }
        })

        $btnRem.Add_Click({
            if ($script:LisWireDlgGrid.SelectedRows.Count -lt 1) { return }
            $row=$script:LisWireDlgGrid.SelectedRows[0]
            $label="$($row.Cells['Type'].Value)"; $k1="$($row.Cells['Key1'].Value)"; $k2="$($row.Cells['Key2'].Value)"
            $key=$null
            foreach ($t in $script:LisWireMeta.Keys) { if ($script:LisWireMeta[$t].Label -eq $label) { $key=$t; break } }
            if (-not $key) { return }
            $m=$script:LisWireMeta[$key]
            if (-not (Lis-Confirm ("Remove {0} '{1}' from the wiremap?`n`nClients matching it will stop resolving to {2}." -f $m.Label,$k1,$locName))) { return }
            $fields=@{}
            $fields[$m.KeyParam]=$k1
            if ($m.Key2) { $fields[$m.Key2Param]=$k2 }
            $p = Lis-CmdParams -Cmdlet $m.Remove -Fields $fields
            try {
                $remCmd=$m.Remove
                Lis-InvokeWithRetry -What $remCmd -Action { & $remCmd @p -ErrorAction Stop } | Out-Null
                Lis-Say "  removed $($m.Label) $k1" $script:LisUi.Colors.Green
                Lis-RefreshWireType $key
                & $fill
                $cid=''
                if ($script:LisSelectedCivic) { $cid="$(Lis-Prop $script:LisSelectedCivic @('CivicAddressId','CivicAddressid'))" }
                Lis-FillLocGrid $cid
            } catch { Lis-Say "  remove failed [$(Get-ErrorClass $_)]: $($_.Exception.Message)" $script:LisUi.Colors.Red }
        })

        $dlg.Controls.Add($script:LisWireDlgGrid); $dlg.Controls.Add($top)
        # This dialog is opened repeatedly in normal use - the documented
        # interaction is double-clicking any location row - so an undisposed
        # Form here accumulates GDI handles over a session rather than a
        # one-off leak.
        [void]$dlg.ShowDialog()
        $dlg.Dispose()
    }

    # ---- exports -------------------------------------------------------------

    function script:Lis-ExportLocations {
        $ui=$script:LisUi
        if (@($script:LisLoc).Count -eq 0) { Lis-Say 'Nothing to export - pull the inventory first.' $ui.Colors.Amber; return }
        $counts = Lis-WireCounts
        $civById=@{}
        foreach ($c in @($script:LisCivic)) { $civById["$(Lis-Prop $c @('CivicAddressId','CivicAddressid'))"]=$c }
        $stamp=Get-Stamp; $key=Get-EnvKey
        $rows = foreach ($l in @($script:LisLoc)) {
            $lid="$(Lis-Prop $l @('LocationId','Locationid'))"
            $cid="$(Lis-Prop $l @('CivicAddressId','CivicAddressid'))"
            $c=$civById[$cid]
            $cnt=$counts[$lid]; if (-not $cnt) { $cnt=@{ wap=0; subnet=0; switch=0; port=0 } }
            $addr = @("$(Lis-Prop $c @('HouseNumber'))","$(Lis-Prop $c @('StreetName'))","$(Lis-Prop $c @('City'))") | Where-Object { "$_" -ne '' }
            [pscustomobject]@{
                LocationName     = "$(Lis-Prop $l @('Location','Description'))"
                LocationId       = $lid
                Elin             = "$(Lis-Prop $l @('Elin','ELIN'))"
                CivicAddressId   = $cid
                CivicDescription = "$(Lis-Prop $c @('Description','CompanyName'))"
                Address          = ($addr -join ', ')
                HouseNumber      = "$(Lis-Prop $c @('HouseNumber'))"
                StreetName       = "$(Lis-Prop $c @('StreetName'))"
                City             = "$(Lis-Prop $c @('City'))"
                StateOrProvince  = "$(Lis-Prop $c @('StateOrProvince','State'))"
                PostalCode       = "$(Lis-Prop $c @('PostalCode','Zip'))"
                CountryOrRegion  = "$(Lis-Prop $c @('CountryOrRegion','Country'))"
                CompanyName      = "$(Lis-Prop $c @('CompanyName'))"
                Latitude         = "$(Lis-Prop $l @('Latitude'))"
                Longitude        = "$(Lis-Prop $l @('Longitude'))"
                WapCount         = $cnt.wap
                SubnetCount      = $cnt.subnet
                SwitchCount      = $cnt.switch
                PortCount        = $cnt.port
                Tenant           = "$($script:CurrentEnv)"
                TenantId         = "$($script:TenantId)"
                ExportedUtc      = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
            }
        }
        $default = Get-OutputPath -Area PolicyBackups -File ("LIS_Locations_{0}_{1}.csv" -f $key,$stamp)
        $sfd=New-Object System.Windows.Forms.SaveFileDialog
        $sfd.Filter='CSV (*.csv)|*.csv'; $sfd.FileName=[IO.Path]::GetFileName($default)
        $sfd.InitialDirectory=[IO.Path]::GetDirectoryName($default)
        if ($sfd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
        try {
            $rows | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8
            Lis-Say "Exported $(@($rows).Count) location row(s) -> $([IO.Path]::GetFileName($sfd.FileName))" $ui.Colors.Green
            if (Confirm-ToolkitWrite -Title 'Export complete' -Message "Open the containing folder?") {
                Open-OutputFolder -Path $sfd.FileName -Label 'LIS export' -SelectFile
            }
        } catch { Lis-Say "Export failed: $($_.Exception.Message)" $ui.Colors.Red }
    }

    function script:Lis-ExportSnapshot {
        $ui=$script:LisUi
        if (@($script:LisCivic).Count -eq 0 -and @($script:LisLoc).Count -eq 0) { Lis-Say 'Nothing to export - pull the inventory first.' $ui.Colors.Amber; return }
        $stamp=Get-Stamp; $key=Get-EnvKey
        $path = Get-OutputPath -Area PolicyBackups -File ("LIS_Snapshot_{0}_{1}.json" -f $key,$stamp)
        $snap=[ordered]@{
            Tenant         = "$($script:CurrentEnv)"
            TenantId       = "$($script:TenantId)"
            ExportedUtc    = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
            CivicAddresses = @($script:LisCivic)
            Locations      = @($script:LisLoc)
            Wiremap        = $script:LisWire
        }
        try {
            # Depth 50: the Cs objects nest deeply and a truncated snapshot is
            # worse than none - it looks complete.
            $snap | ConvertTo-Json -Depth 50 | Set-Content -Path $path -Encoding UTF8
            Lis-Say "Snapshot -> $([IO.Path]::GetFileName($path))" $ui.Colors.Green
            Open-OutputFolder -Path $path -Label 'LIS snapshot' -SelectFile
        } catch { Lis-Say "Snapshot failed: $($_.Exception.Message)" $ui.Colors.Red }
    }

    # ==========================================================================
    # HANDLERS
    # ==========================================================================

    $btnPull.Add_Click({ Lis-PullAll })
    $btnStop.Add_Click({ $script:LisCancel=$true; Lis-Say 'Stop requested - finishing the current page...' $script:LisUi.Colors.Amber })
    $btnExpLoc.Add_Click({ Lis-ExportLocations })
    $btnExpSnap.Add_Click({ Lis-ExportSnapshot })
    $btnFolder.Add_Click({ Open-OutputFolder -Path (Get-OutputPath -Area PolicyBackups) -Label 'LIS output' })
    $btnWire.Add_Click({
        if ($script:LisSelectedLoc) { Lis-ShowWiremapDialog "$(Lis-Prop $script:LisSelectedLoc @('LocationId','Locationid'))" }
        else { Lis-Say 'Select a location first.' $script:LisUi.Colors.Amber }
    })
    $btnLocWire.Add_Click({
        if ($script:LisSelectedLoc) { Lis-ShowWiremapDialog "$(Lis-Prop $script:LisSelectedLoc @('LocationId','Locationid'))" }
        else { Lis-Say 'Select a location first.' $script:LisUi.Colors.Amber }
    })

    $txtCivF.Add_TextChanged({ Lis-FillCivicGrid })
    $txtLocF.Add_TextChanged({
        $cid=''
        if ($script:LisSelectedCivic) { $cid="$(Lis-Prop $script:LisSelectedCivic @('CivicAddressId','CivicAddressid'))" }
        Lis-FillLocGrid $cid
    })

    $gridCivic.Add_SelectionChanged({
        if ($script:LisUi.GridCivic.SelectedRows.Count -lt 1) { return }
        $id="$($script:LisUi.GridCivic.SelectedRows[0].Cells['CivicAddressId'].Value)"
        $script:LisSelectedCivic = Lis-FindCivic $id
        $c=$script:LisSelectedCivic
        if ($c) {
            $f=$script:LisUi.CivFields
            $f['Description'].Text     = "$(Lis-Prop $c @('Description'))"
            $f['CompanyName'].Text     = "$(Lis-Prop $c @('CompanyName'))"
            $f['HouseNumber'].Text     = "$(Lis-Prop $c @('HouseNumber'))"
            $f['StreetName'].Text      = "$(Lis-Prop $c @('StreetName'))"
            $f['City'].Text            = "$(Lis-Prop $c @('City'))"
            $f['StateOrProvince'].Text = "$(Lis-Prop $c @('StateOrProvince','State'))"
            $f['PostalCode'].Text      = "$(Lis-Prop $c @('PostalCode','Zip'))"
            $f['CountryOrRegion'].Text = "$(Lis-Prop $c @('CountryOrRegion','Country'))"
            $f['Latitude'].Text        = "$(Lis-Prop $c @('Latitude'))"
            $f['Longitude'].Text       = "$(Lis-Prop $c @('Longitude'))"
            $script:LisUi.Parent.Text  = "Parent civic: $(Lis-Prop $c @('Description','CompanyName')) [$id]"
        }
        Lis-FillLocGrid $id
    })

    $gridLoc.Add_SelectionChanged({
        if ($script:LisUi.GridLoc.SelectedRows.Count -lt 1) { return }
        $id="$($script:LisUi.GridLoc.SelectedRows[0].Cells['LocationId'].Value)"
        $script:LisSelectedLoc = Lis-FindLoc $id
        $l=$script:LisSelectedLoc
        if ($l) {
            $f=$script:LisUi.LocFields
            $f['Location'].Text  = "$(Lis-Prop $l @('Location','Description'))"
            $f['Elin'].Text      = "$(Lis-Prop $l @('Elin','ELIN'))"
            $f['Latitude'].Text  = "$(Lis-Prop $l @('Latitude'))"
            $f['Longitude'].Text = "$(Lis-Prop $l @('Longitude'))"
        }
    })

    $gridLoc.Add_CellDoubleClick({
        param($s,$e)
        if ($e.RowIndex -lt 0) { return }
        $id="$($script:LisUi.GridLoc.Rows[$e.RowIndex].Cells['LocationId'].Value)"
        Lis-ShowWiremapDialog $id
    })

    $btnCivNew.Add_Click({
        foreach ($k in $script:LisUi.CivFields.Keys) { $script:LisUi.CivFields[$k].Clear() }
        $script:LisSelectedCivic=$null
        $script:LisUi.Parent.Text='No parent civic address selected.'
    })
    $btnCivCreate.Add_Click({ Lis-CreateCivic })
    $btnCivUpdate.Add_Click({ Lis-UpdateCivic })
    $btnCivDelete.Add_Click({ Lis-DeleteCivic })

    $btnLocNew.Add_Click({ foreach ($k in $script:LisUi.LocFields.Keys) { $script:LisUi.LocFields[$k].Clear() }; $script:LisSelectedLoc=$null })
    $btnLocCreate.Add_Click({ Lis-CreateLocation })
    $btnLocUpdate.Add_Click({ Lis-UpdateLocation })
    $btnLocDelete.Add_Click({ Lis-DeleteLocation })

    return $page
}


################################################################################
#
#  SHARED HELPERS FOR THE POLICY MANAGER AND PHONE LINES TABS
#
################################################################################

function Resolve-CsParamName {
<#
.SYNOPSIS
    First of the candidate names (or aliases) that the cmdlet really exposes.
.DESCRIPTION
    Set-/Remove-CsPhoneNumberAssignment spell the number parameters differently
    across module versions (-TelephoneNumber/-NumberType vs -PhoneNumber/-PhoneNumberType,
    one being an alias of the other). Resolve against the loaded module instead of guessing.
#>
    param([Parameter(Mandatory)][string]$Cmdlet,[Parameter(Mandatory)][string[]]$Candidates)
    $c = Get-Command -Name $Cmdlet -ErrorAction SilentlyContinue
    if (-not $c) { return $null }
    foreach ($n in $Candidates) {
        if ($c.Parameters.ContainsKey($n)) { return $n }
        foreach ($p in $c.Parameters.Values) { if ($p.Aliases -contains $n) { return $p.Name } }
    }
    return $null
}

function Write-ChangeLog {
<#
.SYNOPSIS
    Append one row to the per-tenant, per-day change log under Reports\Changes.
#>
    param([string]$Source,[string]$Action,[string]$Target,[string]$Detail,[string]$Result)
    try {
        $path = Get-OutputPath -Area Changes -File ("TeamsVoice_{0}_{1}_{2}.csv" -f $Source,(Get-EnvKey),(Get-Date -Format 'yyyyMMdd'))
        [pscustomobject]@{ Time=(Get-Date).ToString('s'); Environment=(Get-EnvKey); Action=$Action; Target=$Target; Detail=$Detail; Result=$Result } |
            Export-Csv -LiteralPath $path -Append -NoTypeInformation -Encoding UTF8
    } catch { }
}

function ConvertTo-PolicyParamValue {
<#
.SYNOPSIS
    Turn the text typed in a settings grid into the type the Set-Cs* parameter wants.
#>
    param([string]$Text,[type]$Type)
    $t = $Type
    if ($null -eq $t) { return $Text }
    $u = [Nullable]::GetUnderlyingType($t); if ($u) { $t = $u }
    if ($t -eq [bool] -or $t -eq [System.Management.Automation.SwitchParameter]) { return [bool]::Parse($Text.Trim()) }
    if ($t.IsEnum) { return [Enum]::Parse($t, $Text.Trim(), $true) }
    if ($t -eq [string]) { return $Text }
    if ($t.IsArray -or ($t.IsGenericType -and [System.Collections.IList].IsAssignableFrom($t))) {
        $el = [string]
        if ($t.IsArray) { $el = $t.GetElementType() } elseif ($t.IsGenericType) { $el = $t.GetGenericArguments()[0] }
        $items = @($Text -split '\s*,\s*' | Where-Object { $_ -ne '' })
        if ($el -eq [string]) { return ,([string[]]$items) }
        return ,@($items | ForEach-Object { [System.Convert]::ChangeType($_, $el) })
    }
    try { return [System.Convert]::ChangeType($Text.Trim(), $t) } catch { return $Text }
}

function Test-ScalarValue {
    param($v)
    return ($null -eq $v -or $v -is [string] -or $v -is [bool] -or $v -is [System.Enum] -or $v -is [int] -or
            $v -is [long] -or $v -is [double] -or $v -is [decimal] -or $v -is [datetime] -or $v -is [guid] -or $v -is [timespan])
}

function Test-SimpleValue {
<#
.SYNOPSIS
    True for a scalar or a collection of scalars - the shapes a text grid can edit.
#>
    param($v)
    if (Test-ScalarValue $v) { return $true }
    if ($v -is [System.Collections.IEnumerable]) {
        foreach ($i in $v) { if (-not (Test-ScalarValue $i)) { return $false } }
        return $true
    }
    return $false
}

$script:CfgGuidRx = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

function Show-PickList {
<#
.SYNOPSIS
    Small modal list chooser. Returns the chosen item's text, or $null on cancel.
#>
    param([string]$Title,[string[]]$Items)
    $f = New-Object System.Windows.Forms.Form
    $f.Text = $Title; $f.Size = New-Object System.Drawing.Size(560,380); $f.StartPosition = 'CenterParent'
    $lb = New-Object System.Windows.Forms.ListBox; $lb.Dock = 'Fill'; $lb.Font = New-Object System.Drawing.Font('Consolas',9)
    foreach ($i in $Items) { [void]$lb.Items.Add($i) }
    if ($lb.Items.Count -gt 0) { $lb.SelectedIndex = 0 }
    $pn = New-Object System.Windows.Forms.Panel; $pn.Dock = 'Bottom'; $pn.Height = 40
    $ok = New-Object System.Windows.Forms.Button; $ok.Text = 'Select'; $ok.DialogResult = 'OK'; $ok.Location = New-Object System.Drawing.Point(360,8)
    $cn = New-Object System.Windows.Forms.Button; $cn.Text = 'Cancel'; $cn.DialogResult = 'Cancel'; $cn.Location = New-Object System.Drawing.Point(444,8)
    $pn.Controls.AddRange(@($ok,$cn)); $f.Controls.Add($lb); $f.Controls.Add($pn)
    $f.AcceptButton = $ok; $f.CancelButton = $cn
    $lb.Add_DoubleClick({ $this.FindForm().DialogResult = 'OK' })
    $res = $f.ShowDialog()
    $sel = $null; if ($res -eq 'OK' -and $lb.SelectedItem) { $sel = "$($lb.SelectedItem)" }
    $f.Dispose()
    return $sel
}

################################################################################
#
#  POLICY MANAGER TAB
#
#  Edits any Teams policy through the generic Get-/New-/Set-/Remove-/Grant-Cs<Type>
#  cmdlets and manages group policy assignments (New/Set/Remove-CsGroupPolicyAssignment).
#  <Type> is also the -PolicyType value group assignments use, so one list drives both.
#  Everything is RBAC (Teams PowerShell); nothing here has a Graph equivalent.
#
################################################################################

$script:PmPolicyTypes = @(
    'TeamsCallingPolicy','TeamsCallParkPolicy','TeamsCallHoldPolicy','CallingLineIdentity','TenantDialPlan',
    'OnlineVoiceRoutingPolicy','OnlineVoicemailPolicy','OnlineDialOutPolicy','TeamsEmergencyCallingPolicy',
    'TeamsEmergencyCallRoutingPolicy','TeamsMobilityPolicy','TeamsSharedCallingRoutingPolicy','TeamsVoiceApplicationsPolicy',
    'TeamsIPPhonePolicy','TeamsAudioConferencingPolicy','TeamsSurvivableBranchAppliancePolicy','TeamsRoomVideoTeleConferencingPolicy',
    'TeamsMeetingPolicy','TeamsMeetingBroadcastPolicy','TeamsMeetingBrandingPolicy','TeamsMessagingPolicy','TeamsChannelsPolicy',
    'TeamsAppSetupPolicy','TeamsAppPermissionPolicy','TeamsUpdateManagementPolicy','TeamsUpgradePolicy','TeamsEventsPolicy',
    'TeamsFeedbackPolicy','TeamsVideoInteropServicePolicy','TeamsEnhancedEncryptionPolicy','TeamsComplianceRecordingPolicy',
    'TeamsVdiPolicy','TeamsShiftsPolicy','TeamsWorkLoadPolicy','TeamsTemplatePermissionPolicy','TeamsEducationAssignmentsAppPolicy',
    'TeamsNetworkRoamingPolicy','ExternalAccessPolicy','ExternalUserCommunicationPolicy','TeamsClientConfiguration'
)

# Types with no group assignment. Mirrors $script:GroupAssignmentUnsupported (the Groups tab list).
function Test-PmGroupAssignable { param([string]$Type); return (-not ($script:GroupAssignmentUnsupported -contains $Type)) }

function Pm-Say {
    param([string]$Text,$Color)
    $pm = $script:Pm; if (-not $pm) { return }
    if (-not $Color) { $Color = [System.Drawing.Color]::Black }
    $pm.Log.SelectionStart = $pm.Log.TextLength; $pm.Log.SelectionColor = $Color
    $pm.Log.AppendText(("[{0:HH:mm:ss}] {1}`n" -f (Get-Date),$Text)); $pm.Log.SelectionColor = $pm.Log.ForeColor
    $pm.Log.ScrollToCaret()
}

function Pm-Require {
    param([string[]]$Cmdlets)
    if (-not $script:RbacConnected) { Pm-Say 'Connect RBAC first - policy management uses the Teams PowerShell module.' $script:Pm.Colors.Amber; return $false }
    foreach ($c in $Cmdlets) {
        if (-not (Test-CmdletPresent -Name $c)) { Pm-Say "$c is not available in the loaded module." $script:Pm.Colors.Amber; return $false }
    }
    return $true
}

function Pm-Confirm {
    param([string]$Message)
    $r = [System.Windows.Forms.MessageBox]::Show("Tenant: $($script:CurrentEnv)`n`n$Message",'Policy Manager','YesNo','Warning')
    return ($r -eq [System.Windows.Forms.DialogResult]::Yes)
}

function Pm-CurrentType {
    $t = "$($script:Pm.CmbType.Text)".Trim()
    if ($t -notmatch '^[A-Za-z0-9]+$') { return $null }
    return $t
}

function Pm-SelectedPolicy {
    $i = $script:Pm.Lst.SelectedIndex
    if ($i -lt 0 -or $i -ge @($script:Pm.Policies).Count) { return $null }
    return @($script:Pm.Policies)[$i]
}

function Pm-LoadPolicies {
    $pm = $script:Pm
    $type = Pm-CurrentType
    if (-not $type) { Pm-Say 'Enter a policy type (letters and digits only), e.g. TeamsCallingPolicy.' $pm.Colors.Amber; return }
    $get = "Get-Cs$type"
    if (-not (Pm-Require @($get))) { return }
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        $items = @(& $get -ErrorAction Stop | Sort-Object { "$($_.Identity)" })
    } catch {
        Pm-Say "$get failed: $($_.Exception.Message)" $pm.Colors.Red; return
    } finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }
    $pm.Type = $type; $pm.Policies = $items
    $pm.Lst.Items.Clear(); $pm.CmbGrpPolicy.Items.Clear()
    foreach ($p in $items) {
        $n = Get-PolicyDisplayName -Policy $p
        if (-not $n) { $n = "$($p.Identity)" }
        [void]$pm.Lst.Items.Add($n)
        if ($n -ne 'Global') { [void]$pm.CmbGrpPolicy.Items.Add($n) }
    }
    $pm.Grid.Rows.Clear(); $pm.Original = @{}
    $pm.BtnNew.Enabled    = (Test-CmdletPresent -Name "New-Cs$type")
    $pm.BtnDelete.Enabled = (Test-CmdletPresent -Name "Remove-Cs$type")
    $pm.BtnGrant.Enabled  = (Test-CmdletPresent -Name "Grant-Cs$type")
    $pm.BtnSave.Enabled   = (Test-CmdletPresent -Name "Set-Cs$type")
    Pm-Say "$($items.Count) $type object(s) loaded." $pm.Colors.Green
    if (Test-PmGroupAssignable $type) { Pm-LoadGroups } else { $pm.GrpGrid.Rows.Clear(); Pm-Say "$type does not support group assignment." $pm.Colors.Gray }
}

function Pm-ShowDetails {
    $pm = $script:Pm
    $pm.Grid.Rows.Clear(); $pm.Original = @{}
    $p = Pm-SelectedPolicy; if (-not $p) { return }
    $setCmd = Get-Command -Name "Set-Cs$($pm.Type)" -ErrorAction SilentlyContinue
    foreach ($prop in $p.PSObject.Properties) {
        $n = $prop.Name
        if ($script:CommonParameters -contains $n) { continue }
        if (($script:NeverExport -contains $n) -and $n -ne 'Identity') { continue }
        $v = $prop.Value
        $complex = $false; $text = ''
        if ($null -eq $v) { $text = '' }
        elseif (Test-ScalarValue $v) { $text = $v.ToString() }
        elseif ($v -is [System.Collections.IEnumerable]) {
            $arr = @($v)
            if (@($arr | Where-Object { -not (Test-ScalarValue $_) }).Count -eq 0) { $text = ($arr | ForEach-Object { "$_" }) -join ', ' }
            else { $complex = $true; $text = '(complex - edit with PowerShell)' }
        }
        else { $complex = $true; $text = '(complex - edit with PowerShell)' }
        $writable = [bool]($setCmd -and $setCmd.Parameters.ContainsKey($n) -and $n -ne 'Identity' -and -not $complex)
        $idx = $pm.Grid.Rows.Add($n, $text, $(if ($writable) { 'editable' } else { 'read-only' }))
        $row = $pm.Grid.Rows[$idx]
        if ($writable) { $pm.Original[$n] = $text }
        else { $row.Cells['Value'].ReadOnly = $true; $row.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Gray }
    }
}

function Pm-SaveSettings {
    $pm = $script:Pm
    $p = Pm-SelectedPolicy; if (-not $p) { Pm-Say 'Select a policy first.' $pm.Colors.Amber; return }
    $set = "Set-Cs$($pm.Type)"
    if (-not (Pm-Require @($set))) { return }
    $cmd = Get-Command -Name $set
    $changes = [ordered]@{}
    foreach ($row in $pm.Grid.Rows) {
        $n = "$($row.Cells['Property'].Value)"
        if (-not $pm.Original.ContainsKey($n)) { continue }
        $new = "$($row.Cells['Value'].Value)"
        if ($new -ne $pm.Original[$n]) { $changes[$n] = $new }
    }
    if ($changes.Count -eq 0) { Pm-Say 'No changes to save.' $pm.Colors.Gray; return }
    $summary = ($changes.Keys | ForEach-Object { "  $_ : '$($pm.Original[$_])' -> '$($changes[$_])'" }) -join "`n"
    if (-not (Pm-Confirm "Update $($pm.Type) '$(Get-PolicyDisplayName -Policy $p)'?`n`n$summary")) { return }
    $params = @{ Identity = "$($p.Identity)"; ErrorAction = 'Stop' }
    try {
        foreach ($k in $changes.Keys) { $params[$k] = ConvertTo-PolicyParamValue -Text $changes[$k] -Type $cmd.Parameters[$k].ParameterType }
    } catch { Pm-Say "Invalid value: $($_.Exception.Message)" $pm.Colors.Red; return }
    try {
        & $set @params
        Pm-Say "Saved $($changes.Count) change(s) to $(Get-PolicyDisplayName -Policy $p)." $pm.Colors.Green
        Write-ChangeLog -Source 'PolicyManager' -Action "Set-Cs$($pm.Type)" -Target (Get-PolicyDisplayName -Policy $p) -Detail (($changes.Keys | ForEach-Object { "$_=$($changes[$_])" }) -join '; ') -Result 'OK'
        $sel = $pm.Lst.SelectedIndex; Pm-LoadPolicies; if ($sel -ge 0 -and $sel -lt $pm.Lst.Items.Count) { $pm.Lst.SelectedIndex = $sel }
    } catch {
        Pm-Say "Save failed: $($_.Exception.Message)" $pm.Colors.Red
        Write-ChangeLog -Source 'PolicyManager' -Action "Set-Cs$($pm.Type)" -Target (Get-PolicyDisplayName -Policy $p) -Detail '' -Result "FAIL: $($_.Exception.Message)"
    }
}

function Pm-NewPolicy {
    $pm = $script:Pm
    $new = "New-Cs$($pm.Type)"
    if (-not (Pm-Require @($new))) { return }
    $name = [Microsoft.VisualBasic.Interaction]::InputBox("Name for the new $($pm.Type):",'New policy','')
    if ([string]::IsNullOrWhiteSpace($name)) { return }
    $name = $name.Trim()
    $params = @{ Identity = $name; ErrorAction = 'Stop' }
    $src = Pm-SelectedPolicy
    if ($src -and (Pm-Confirm "Copy the editable settings of '$(Get-PolicyDisplayName -Policy $src)' into the new policy?`n`n(No creates it with service defaults.)")) {
        $cmd = Get-Command -Name $new
        foreach ($prop in $src.PSObject.Properties) {
            $n = $prop.Name
            if ($n -eq 'Identity' -or ($script:NeverExport -contains $n) -or -not $cmd.Parameters.ContainsKey($n)) { continue }
            $v = $prop.Value
            if ($null -eq $v -or -not (Test-SimpleValue $v)) { continue }
            try { $params[$n] = ConvertTo-PolicyParamValue -Text (($v | ForEach-Object { "$_" }) -join ', ') -Type $cmd.Parameters[$n].ParameterType } catch { }
        }
    }
    try {
        & $new @params | Out-Null
        Pm-Say "Created $($pm.Type) '$name'." $pm.Colors.Green
        Write-ChangeLog -Source 'PolicyManager' -Action $new -Target $name -Detail '' -Result 'OK'
        Pm-LoadPolicies
    } catch {
        Pm-Say "Create failed: $($_.Exception.Message)" $pm.Colors.Red
        Write-ChangeLog -Source 'PolicyManager' -Action $new -Target $name -Detail '' -Result "FAIL: $($_.Exception.Message)"
    }
}

function Pm-DeletePolicy {
    $pm = $script:Pm
    $p = Pm-SelectedPolicy; if (-not $p) { Pm-Say 'Select a policy first.' $pm.Colors.Amber; return }
    $name = Get-PolicyDisplayName -Policy $p
    if ($name -eq 'Global') { Pm-Say 'The Global policy cannot be deleted.' $pm.Colors.Amber; return }
    $rm = "Remove-Cs$($pm.Type)"
    if (-not (Pm-Require @($rm))) { return }
    if (-not (Pm-Confirm "DELETE $($pm.Type) '$name'?`n`nThe service refuses this while the policy is still assigned to users or groups.")) { return }
    try {
        & $rm -Identity "$($p.Identity)" -Confirm:$false -ErrorAction Stop
        Pm-Say "Deleted $name." $pm.Colors.Green
        Write-ChangeLog -Source 'PolicyManager' -Action $rm -Target $name -Detail '' -Result 'OK'
        Pm-LoadPolicies
    } catch {
        Pm-Say "Delete failed: $($_.Exception.Message)" $pm.Colors.Red
        Write-ChangeLog -Source 'PolicyManager' -Action $rm -Target $name -Detail '' -Result "FAIL: $($_.Exception.Message)"
    }
}

function Pm-GrantPolicy {
    $pm = $script:Pm
    $p = Pm-SelectedPolicy; if (-not $p) { Pm-Say 'Select a policy first.' $pm.Colors.Amber; return }
    $grant = "Grant-Cs$($pm.Type)"
    if (-not (Pm-Require @($grant))) { return }
    $upn = [Microsoft.VisualBasic.Interaction]::InputBox("User UPN to assign '$(Get-PolicyDisplayName -Policy $p)' to (Global resets the user to the tenant default):",'Assign to user',"$($script:CurrentUpn)")
    if ([string]::IsNullOrWhiteSpace($upn)) { return }
    $upn = $upn.Trim()
    $name = Get-PolicyDisplayName -Policy $p
    $pn = Resolve-CsParamName -Cmdlet $grant -Candidates @('PolicyName')
    if (-not $pn) { Pm-Say "$grant has no -PolicyName parameter in this module version." $pm.Colors.Amber; return }
    if (-not (Pm-Confirm "Assign $($pm.Type) '$name' directly to $upn?")) { return }
    try {
        $args2 = @{ Identity = $upn; ErrorAction = 'Stop' }
        $args2[$pn] = $(if ($name -eq 'Global') { $null } else { $name })
        & $grant @args2
        Pm-Say "Assigned $name to $upn." $pm.Colors.Green
        Write-ChangeLog -Source 'PolicyManager' -Action $grant -Target $upn -Detail $name -Result 'OK'
    } catch {
        Pm-Say "Assign failed: $($_.Exception.Message)" $pm.Colors.Red
        Write-ChangeLog -Source 'PolicyManager' -Action $grant -Target $upn -Detail $name -Result "FAIL: $($_.Exception.Message)"
    }
}

function Pm-GroupName {
    param([string]$GroupId)
    if ([string]::IsNullOrWhiteSpace($GroupId)) { return '' }
    if ($script:GroupNameCache.ContainsKey($GroupId)) { return $script:GroupNameCache[$GroupId] }
    $name = $GroupId
    if ($script:Token) {
        try { $g = Invoke-GraphGet "$($script:Graph)/groups/$GroupId`?`$select=displayName"; if ($g -and $g.displayName) { $name = $g.displayName } } catch { }
    }
    $script:GroupNameCache[$GroupId] = $name
    return $name
}

function Pm-LoadGroups {
    $pm = $script:Pm
    $pm.GrpGrid.Rows.Clear()
    if (-not (Pm-Require @('Get-CsGroupPolicyAssignment'))) { return }
    $type = $pm.Type
    if (-not $pm.ChkAllTypes.Checked -and -not (Test-PmGroupAssignable $type)) { Pm-Say "$type does not support group assignment." $pm.Colors.Gray; return }
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        $rows = if ($pm.ChkAllTypes.Checked) { @(Get-CsGroupPolicyAssignment -ErrorAction Stop) } else { @(Get-CsGroupPolicyAssignment -PolicyType $type -ErrorAction Stop) }
    } catch { Pm-Say "Group assignments unavailable: $($_.Exception.Message)" $pm.Colors.Amber; return }
    finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }
    foreach ($r in ($rows | Sort-Object { [int](Get-PropTolerant $_ @('Rank') 0) })) {
        $gid = "$(Get-PropTolerant $r @('GroupId'))"
        [void]$pm.GrpGrid.Rows.Add((Pm-GroupName $gid), $gid, "$(Get-PropTolerant $r @('PolicyType'))", "$(Get-PropTolerant $r @('PolicyName'))", "$(Get-PropTolerant $r @('Rank'))")
    }
    Pm-Say "$($pm.GrpGrid.Rows.Count) group assignment(s)." $pm.Colors.Gray
}

function Pm-FindGroup {
    $pm = $script:Pm
    $q = $pm.TxtGroup.Text.Trim()
    if (-not $q) { Pm-Say 'Type part of a group name (or paste a GUID) first.' $pm.Colors.Amber; return }
    if ($q -match $script:CfgGuidRx) { Pm-Say "GUID accepted: $(Pm-GroupName $q)" $pm.Colors.Gray; return }
    $useTeams = Use-TeamsFirst
    if (-not $useTeams -and -not $script:Token) { Pm-Say 'Searching by name needs the API token (Connect API) with Group.Read.All, or a Teams RBAC connection. Paste the group GUID instead.' $pm.Colors.Amber; return }
    try {
        if ($useTeams) {
            $rows = @(Find-CsGroup -SearchQuery $q -MaxResults 50 -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ id = "$($_.Id)"; displayName = "$($_.DisplayName)" } })
        } else {
            $f = [uri]::EscapeDataString("startswith(displayName,'" + ($q -replace "'","''") + "')")
            $res = Invoke-GraphGet "$($script:Graph)/groups?`$filter=$f&`$select=id,displayName&`$top=50"
            $rows = @($res.value)
        }
        $items = @($rows | ForEach-Object { "{0}   [{1}]" -f $_.displayName,$_.id })
        if ($items.Count -eq 0) { Pm-Say "No group starts with '$q'." $pm.Colors.Amber; return }
        $sel = Show-PickList -Title 'Select group' -Items $items
        if ($sel -match '\[([0-9a-fA-F-]{36})\]$') { $pm.TxtGroup.Text = $Matches[1] }
    } catch { Pm-Say "Group search failed: $($_.Exception.Message)" $pm.Colors.Red }
}

function Pm-GroupWrite {
    param([ValidateSet('New','Set','Remove')][string]$Verb)
    $pm = $script:Pm
    $type = $pm.Type
    if (-not $type -or -not (Test-PmGroupAssignable $type)) { Pm-Say 'Load a group-assignable policy type first.' $pm.Colors.Amber; return }
    $cmd = "$Verb-CsGroupPolicyAssignment"
    if (-not (Pm-Require @($cmd))) { return }
    $gid = $pm.TxtGroup.Text.Trim()
    if ($Verb -ne 'New' -and $pm.GrpGrid.SelectedRows.Count -gt 0) {
        $sr = $pm.GrpGrid.SelectedRows[0]
        $gid = "$($sr.Cells['GroupId'].Value)"
        $type = "$($sr.Cells['PolicyType'].Value)"
    }
    if ($gid -notmatch $script:CfgGuidRx) { Pm-Say 'Enter a group GUID (use Find to look one up) or select an existing assignment.' $pm.Colors.Amber; return }
    $policy = "$($pm.CmbGrpPolicy.Text)".Trim()
    $rank = [int]$pm.NumRank.Value
    $params = @{ GroupId = $gid; PolicyType = $type; ErrorAction = 'Stop' }
    if ($Verb -ne 'Remove') {
        if (-not $policy) { Pm-Say 'Choose the policy to assign.' $pm.Colors.Amber; return }
        $params.PolicyName = $policy; $params.Rank = $rank
    }
    $gname = Pm-GroupName $gid
    $detail = if ($Verb -eq 'Remove') { "remove $type assignment from group '$gname'" } else { "$type '$policy' rank $rank for group '$gname'" }
    if (-not (Pm-Confirm "$Verb group policy assignment:`n`n$detail")) { return }
    try {
        & $cmd @params | Out-Null
        Pm-Say "$cmd OK: $detail" $pm.Colors.Green
        Write-ChangeLog -Source 'PolicyManager' -Action $cmd -Target "$gname ($gid)" -Detail $detail -Result 'OK'
        Pm-LoadGroups
    } catch {
        Pm-Say "$cmd failed: $($_.Exception.Message)" $pm.Colors.Red
        Write-ChangeLog -Source 'PolicyManager' -Action $cmd -Target "$gname ($gid)" -Detail $detail -Result "FAIL: $($_.Exception.Message)"
    }
}

function New-PolicyManagerTabPage {
    param(
        [string]$Text = '  Policy Manager  ',
        $BackColor,$ColorBlue,$ColorPurple,$ColorGreen,$ColorGray,$ColorAmber,$ColorRed
    )
    $page = New-Object System.Windows.Forms.TabPage
    $page.Text = $Text; $page.BackColor = $BackColor
    $pm = @{ Type=''; Policies=@(); Original=@{}; Colors=@{ Green=$ColorGreen; Amber=$ColorAmber; Red=$ColorRed; Gray=$ColorGray; Blue=$ColorBlue } }
    $script:Pm = $pm

    function Pm-Btn($t,$x,$y,$w,$c) { $b=New-Object System.Windows.Forms.Button; $b.Text=$t; $b.Location=New-Object System.Drawing.Point($x,$y); $b.Size=New-Object System.Drawing.Size($w,26); Style-Button $b $c; $b }
    function Pm-Lbl($t,$x,$y,$w) { $l=New-Object System.Windows.Forms.Label; $l.Text=$t; $l.Location=New-Object System.Drawing.Point($x,$y); $l.Size=New-Object System.Drawing.Size($w,20); $l }

    # ---- top bar -----------------------------------------------------------
    $bar = New-Object System.Windows.Forms.Panel; $bar.Dock='Top'; $bar.Height=44; $bar.BackColor=[System.Drawing.Color]::White
    $pm.CmbType = New-Object System.Windows.Forms.ComboBox; $pm.CmbType.Location=New-Object System.Drawing.Point(86,10); $pm.CmbType.Size=New-Object System.Drawing.Size(300,24); $pm.CmbType.DropDownStyle='DropDown'
    foreach ($t in $script:PmPolicyTypes) { [void]$pm.CmbType.Items.Add($t) }
    $pm.CmbType.SelectedIndex = 0
    $btnLoad = Pm-Btn 'Load Policies' 396 9 120 $ColorBlue
    $note = Pm-Lbl 'Requires Connect RBAC. Type any other policy type name (the part after Get-Cs) to manage it too.' 528 13 740; $note.ForeColor=$ColorGray
    $bar.Controls.AddRange(@((Pm-Lbl 'Policy type' 12 13 70),$pm.CmbType,$btnLoad,$note))

    # ---- left: policy list ---------------------------------------------------
    $left = New-Object System.Windows.Forms.Panel; $left.Dock='Left'; $left.Width=320
    $pm.Lst = New-Object System.Windows.Forms.ListBox; $pm.Lst.Dock='Fill'
    $lp = New-Object System.Windows.Forms.Panel; $lp.Dock='Bottom'; $lp.Height=76
    $pm.BtnNew    = Pm-Btn 'New Policy...' 6 6 150 $ColorGreen
    $pm.BtnDelete = Pm-Btn 'Delete' 162 6 150 $ColorRed
    $pm.BtnGrant  = Pm-Btn 'Assign To User...' 6 40 150 $ColorPurple
    $lp.Controls.AddRange(@($pm.BtnNew,$pm.BtnDelete,$pm.BtnGrant))
    $left.Controls.Add($pm.Lst); $left.Controls.Add($lp)

    # ---- log -----------------------------------------------------------------
    $pm.Log = New-Object System.Windows.Forms.RichTextBox; $pm.Log.Dock='Bottom'; $pm.Log.Height=120; $pm.Log.ReadOnly=$true
    $pm.Log.BackColor=[System.Drawing.Color]::White; $pm.Log.Font=New-Object System.Drawing.Font('Consolas',9)

    # ---- inner tabs ------------------------------------------------------------
    $inner = New-Object System.Windows.Forms.TabControl; $inner.Dock='Fill'
    $pgSet = New-Object System.Windows.Forms.TabPage; $pgSet.Text='Settings'; $pgSet.BackColor=$BackColor
    $pgGrp = New-Object System.Windows.Forms.TabPage; $pgGrp.Text='Group Assignments'; $pgGrp.BackColor=$BackColor
    $inner.Controls.AddRange(@($pgSet,$pgGrp))

    $pm.Grid = New-Object System.Windows.Forms.DataGridView
    $pm.Grid.Dock='Fill'; $pm.Grid.AllowUserToAddRows=$false; $pm.Grid.AllowUserToDeleteRows=$false; $pm.Grid.RowHeadersVisible=$false
    $pm.Grid.BackgroundColor=[System.Drawing.Color]::White; $pm.Grid.AutoSizeColumnsMode='Fill'
    [void]$pm.Grid.Columns.Add('Property','Property'); [void]$pm.Grid.Columns.Add('Value','Value'); [void]$pm.Grid.Columns.Add('Access','Access')
    $pm.Grid.Columns['Property'].ReadOnly=$true; $pm.Grid.Columns['Access'].ReadOnly=$true
    $pm.Grid.Columns['Property'].FillWeight=40; $pm.Grid.Columns['Value'].FillWeight=50; $pm.Grid.Columns['Access'].FillWeight=10
    $sp = New-Object System.Windows.Forms.Panel; $sp.Dock='Bottom'; $sp.Height=40
    $pm.BtnSave = Pm-Btn 'Save Changes' 6 7 130 $ColorGreen
    $btnRevert = Pm-Btn 'Revert' 144 7 100 $ColorGray
    $h = Pm-Lbl 'Edit the Value column. Arrays: comma-separated. Booleans: True / False. Only changed rows are sent.' 256 11 700; $h.ForeColor=$ColorGray
    $sp.Controls.AddRange(@($pm.BtnSave,$btnRevert,$h))
    $pgSet.Controls.Add($pm.Grid); $pgSet.Controls.Add($sp)

    $pm.GrpGrid = New-Object System.Windows.Forms.DataGridView
    $pm.GrpGrid.Dock='Fill'; $pm.GrpGrid.ReadOnly=$true; $pm.GrpGrid.AllowUserToAddRows=$false; $pm.GrpGrid.RowHeadersVisible=$false
    $pm.GrpGrid.SelectionMode='FullRowSelect'; $pm.GrpGrid.MultiSelect=$false; $pm.GrpGrid.BackgroundColor=[System.Drawing.Color]::White; $pm.GrpGrid.AutoSizeColumnsMode='Fill'
    foreach ($c in 'Group','GroupId','PolicyType','PolicyName','Rank') { [void]$pm.GrpGrid.Columns.Add($c,$c) }
    $pm.GrpGrid.Columns['Rank'].FillWeight=15
    $gp = New-Object System.Windows.Forms.Panel; $gp.Dock='Top'; $gp.Height=112; $gp.BackColor=[System.Drawing.Color]::White
    $pm.TxtGroup = New-Object System.Windows.Forms.TextBox; $pm.TxtGroup.Location=New-Object System.Drawing.Point(150,10); $pm.TxtGroup.Size=New-Object System.Drawing.Size(360,22)
    $btnFind = Pm-Btn 'Find...' 518 8 90 $ColorPurple
    $pm.CmbGrpPolicy = New-Object System.Windows.Forms.ComboBox; $pm.CmbGrpPolicy.Location=New-Object System.Drawing.Point(150,40); $pm.CmbGrpPolicy.Size=New-Object System.Drawing.Size(360,22); $pm.CmbGrpPolicy.DropDownStyle='DropDown'
    $pm.NumRank = New-Object System.Windows.Forms.NumericUpDown; $pm.NumRank.Location=New-Object System.Drawing.Point(150,70); $pm.NumRank.Size=New-Object System.Drawing.Size(80,22); $pm.NumRank.Minimum=1; $pm.NumRank.Maximum=1000; $pm.NumRank.Value=1
    $btnGAdd = Pm-Btn 'Assign Group' 250 68 120 $ColorGreen
    $btnGUpd = Pm-Btn 'Update Selected' 378 68 130 $ColorBlue
    $btnGRem = Pm-Btn 'Remove Selected' 516 68 130 $ColorRed
    $btnGRef = Pm-Btn 'Refresh' 654 68 90 $ColorGray
    $pm.ChkAllTypes = New-Object System.Windows.Forms.CheckBox; $pm.ChkAllTypes.Location=New-Object System.Drawing.Point(626,10); $pm.ChkAllTypes.Size=New-Object System.Drawing.Size(240,22); $pm.ChkAllTypes.Text='Show all policy types'
    $gn = Pm-Lbl 'Lowest rank wins when a user is in several groups. Group assignments apply to direct members only.' 626 42 640; $gn.ForeColor=$ColorGray
    $gp.Controls.AddRange(@((Pm-Lbl 'Group (name or GUID)' 12 12 136),$pm.TxtGroup,$btnFind,(Pm-Lbl 'Policy' 12 42 136),$pm.CmbGrpPolicy,(Pm-Lbl 'Rank' 12 72 136),$pm.NumRank,$btnGAdd,$btnGUpd,$btnGRem,$btnGRef,$pm.ChkAllTypes,$gn))
    $pgGrp.Controls.Add($pm.GrpGrid); $pgGrp.Controls.Add($gp)

    $page.Controls.Add($inner); $page.Controls.Add($left); $page.Controls.Add($pm.Log); $page.Controls.Add($bar)

    # ---- behaviour -----------------------------------------------------------
    $btnLoad.Add_Click({ Pm-LoadPolicies })
    $pm.CmbType.Add_KeyDown({ if ($_.KeyCode -eq 'Enter') { Pm-LoadPolicies; $_.SuppressKeyPress = $true } })
    $pm.Lst.Add_SelectedIndexChanged({ Pm-ShowDetails })
    $pm.BtnSave.Add_Click({ Pm-SaveSettings })
    $btnRevert.Add_Click({ Pm-ShowDetails })
    $pm.BtnNew.Add_Click({ Pm-NewPolicy })
    $pm.BtnDelete.Add_Click({ Pm-DeletePolicy })
    $pm.BtnGrant.Add_Click({ Pm-GrantPolicy })
    $btnFind.Add_Click({ Pm-FindGroup })
    $btnGAdd.Add_Click({ Pm-GroupWrite -Verb New })
    $btnGUpd.Add_Click({ Pm-GroupWrite -Verb Set })
    $btnGRem.Add_Click({ Pm-GroupWrite -Verb Remove })
    $btnGRef.Add_Click({ Pm-LoadGroups })
    $pm.ChkAllTypes.Add_CheckedChanged({ if ($script:Pm.Type) { Pm-LoadGroups } })
    $pm.GrpGrid.Add_SelectionChanged({
        $g = $script:Pm.GrpGrid
        if ($g.SelectedRows.Count -eq 0) { return }
        $r = $g.SelectedRows[0]
        $script:Pm.TxtGroup.Text = "$($r.Cells['GroupId'].Value)"
        $script:Pm.CmbGrpPolicy.Text = "$($r.Cells['PolicyName'].Value)"
        $rk = 0; if ([int]::TryParse("$($r.Cells['Rank'].Value)",[ref]$rk) -and $rk -ge 1 -and $rk -le 1000) { $script:Pm.NumRank.Value = $rk }
    })
    Pm-Say 'Connect RBAC, pick a policy type and click Load Policies.' $ColorGray
    return $page
}

################################################################################
#
#  PHONE LINES PANEL (Provisioning tab) - more than one telephone line per user (multi-line)
#
#  Microsoft's multi-line feature: one primary line, one private line, and up to
#  nine alternate lines per user, any mix of Calling Plan / Direct Routing /
#  Operator Connect. Graph does not manage alternate lines yet, so this tab uses
#  Set-/Remove-CsPhoneNumberAssignment (-AssignmentCategory Alternate) and
#  Set-CsPhoneNumberPolicyAssignment, which need MicrosoftTeams 7.6.0 or later.
#  The primary line is still provisioned on the Provisioning tab.
#
################################################################################

$script:PlPolicyTypes = [ordered]@{
    'Tenant dial plan'              = 'TenantDialPlan'
    'Voice routing policy'          = 'OnlineVoiceRoutingPolicy'
    'Emergency call routing policy' = 'TeamsEmergencyCallRoutingPolicy'
    'Emergency calling policy'      = 'TeamsEmergencyCallingPolicy'
    'Caller ID policy'              = 'CallingLineIdentity'
    'Dial-out policy'               = 'OnlineDialOutPolicy'
    'Shared calling routing policy' = 'TeamsSharedCallingRoutingPolicy'
}
$script:PlMaxLines = 11

function Pl-Say {
    param([string]$Text,$Color)
    $pl = $script:Pl; if (-not $pl) { return }
    if (-not $Color) { $Color = [System.Drawing.Color]::Black }
    $pl.Log.SelectionStart = $pl.Log.TextLength; $pl.Log.SelectionColor = $Color
    $pl.Log.AppendText(("[{0:HH:mm:ss}] {1}`n" -f (Get-Date),$Text)); $pl.Log.SelectionColor = $pl.Log.ForeColor
    $pl.Log.ScrollToCaret()
}

function Pl-NormalizeNumber {
<#
.SYNOPSIS
    E.164 with an optional ;ext= suffix preserved (ToE164 alone would strip it).
#>
    param([string]$Number)
    $parts = $Number.Trim() -split ';',2
    $n = ToE164 $parts[0]
    if ($parts.Count -gt 1 -and $parts[1].Trim()) { $n += ';' + $parts[1].Trim() }
    return $n
}

function Pl-Require {
    param([string[]]$Cmdlets)
    if (-not $script:RbacConnected) { Pl-Say 'Connect RBAC first - alternate lines are managed through the Teams PowerShell module.' $script:Pl.Colors.Amber; return $false }
    foreach ($c in $Cmdlets) { if (-not (Test-CmdletPresent -Name $c)) { Pl-Say "$c is not available in the loaded module (multi-line needs MicrosoftTeams 7.6.0+)." $script:Pl.Colors.Amber; return $false } }
    return $true
}

function Pl-GetLines {
<#
.SYNOPSIS
    Every line assigned to the user: RBAC first (sees alternate lines), Graph fallback (primary only).
#>
    param([string]$Upn)
    $lines = New-Object System.Collections.Generic.List[object]
    if ($script:RbacConnected -and (Test-CmdletPresent -Name 'Get-CsPhoneNumberAssignment')) {
        $rows = @(Get-CsPhoneNumberAssignment -AssignedPstnTargetId $Upn -ErrorAction Stop)
        foreach ($r in $rows) {
            $cat = "$(Get-PropTolerant $r @('AssignmentCategory'))"
            if (-not $cat) { $cat = 'Primary' }
            $lines.Add([pscustomobject]@{
                Number   = "$(Get-PropTolerant $r @('TelephoneNumber'))"
                Type     = "$(Get-PropTolerant $r @('NumberType'))"
                Category = $cat
                Status   = "$(Get-PropTolerant $r @('PstnAssignmentStatus'))"
                Location = "$(Get-PropTolerant $r @('LocationId'))"
                Source   = 'RBAC'
            })
        }
        return $lines.ToArray()
    }
    if ($script:Token) {
        $u = Invoke-GraphGet "$($script:Graph)/users/$([uri]::EscapeDataString($Upn))?`$select=id"
        $f = [uri]::EscapeDataString("assignmentTargetId eq '$($u.id)'")
        foreach ($r in @((Invoke-GraphGet "$($script:Graph)/admin/teams/telephoneNumberManagement/numberAssignments?`$filter=$f").value)) {
            $lines.Add([pscustomobject]@{ Number="$($r.telephoneNumber)"; Type="$($r.numberType)"; Category="$($r.assignmentCategory)"; Status="$($r.assignmentStatus)"; Location="$($r.locationId)"; Source='Graph (alternate lines not shown)' })
        }
    }
    return $lines.ToArray()
}

function Pl-ReadLines {
    $pl = $script:Pl
    $upn = "$($txtUser.Text)".Trim()
    if (-not $upn) { Pl-Say 'Enter a user UPN on the left.' $pl.Colors.Amber; return }
    $pl.Grid.Rows.Clear()
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try { $lines = @(Pl-GetLines -Upn $upn) }
    catch { Pl-Say "Read failed: $($_.Exception.Message)" $pl.Colors.Red; return }
    finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }
    $pl.Lines = @($lines)
    foreach ($l in ($lines | Sort-Object { switch -Regex ($_.Category) { '^Primary' {0} '^Private' {1} default {2} } }, Number)) {
        $locName = $l.Location
        $loc = @($script:allLocations | Where-Object { $_.LocationId -eq $l.Location }) | Select-Object -First 1
        if ($loc) { $locName = $loc.LocationName }
        [void]$pl.Grid.Rows.Add($l.Number,$l.Type,$l.Category,$l.Status,$locName,$l.Source)
    }
    $alt = @($lines | Where-Object { $_.Category -match '^Alternate' }).Count
    Pl-Say ("{0}: {1} line(s) - {2} primary, {3} private, {4} alternate." -f $upn,$lines.Count,@($lines | Where-Object { $_.Category -match '^Primary' }).Count,@($lines | Where-Object { $_.Category -match '^Private' }).Count,$alt) $pl.Colors.Green
    $script:CurrentUpn = $upn
}

function Pl-ReadNumberPolicies {
    $pl = $script:Pl
    if ($pl.Grid.SelectedRows.Count -eq 0) { Pl-Say 'Select a line first.' $pl.Colors.Amber; return }
    $num = "$($pl.Grid.SelectedRows[0].Cells['Number'].Value)"
    if (-not (Pl-Require @('Get-CsPhoneNumberPolicyAssignment'))) { return }
    try {
        $rows = @(Get-CsPhoneNumberPolicyAssignment -TelephoneNumber ($num -replace '^\+','') -ErrorAction Stop)
        if ($rows.Count -eq 0) { Pl-Say "$num has no number-level policies assigned." $pl.Colors.Gray; return }
        foreach ($r in $rows) { Pl-Say ("  {0,-34} {1}" -f "$(Get-PropTolerant $r @('PolicyType'))","$(Get-PropTolerant $r @('PolicyName'))") $pl.Colors.Gray }
    } catch { Pl-Say "Policy read failed: $($_.Exception.Message)" $pl.Colors.Red }
}

function Pl-SelectedPolicies {
<#
.SYNOPSIS
    PolicyType -> name for every policy combo the operator filled in. '(none)' maps to $null (clear).
#>
    $out = [ordered]@{}
    foreach ($label in $script:PlPolicyTypes.Keys) {
        $t = "$($script:Pl.PolicyCombos[$label].Text)".Trim()
        if (-not $t) { continue }
        $out[$script:PlPolicyTypes[$label]] = $(if ($t -eq '(none)') { $null } else { $t })
    }
    return $out
}

function Pl-ApplyPolicies {
    param([string]$Number,$Policies)
    $pl = $script:Pl
    if ($Policies.Count -eq 0) { return $true }
    if (-not (Pl-Require @('Set-CsPhoneNumberPolicyAssignment'))) { return $false }
    $tn = Resolve-CsParamName -Cmdlet 'Set-CsPhoneNumberPolicyAssignment' -Candidates @('TelephoneNumber','PhoneNumber')
    $ok = $true
    $base = ($Number -split ';')[0]
    foreach ($type in $Policies.Keys) {
        try {
            $p = @{ PolicyType = $type; PolicyName = $Policies[$type]; ErrorAction = 'Stop' }
            $p[$tn] = $base
            Set-CsPhoneNumberPolicyAssignment @p
            Pl-Say "  policy $type = $(if ($Policies[$type]) { $Policies[$type] } else { '(cleared)' })" $pl.Colors.Green
            Write-ChangeLog -Source 'PhoneLines' -Action 'Set-CsPhoneNumberPolicyAssignment' -Target $base -Detail "$type=$($Policies[$type])" -Result 'OK'
        } catch {
            $ok = $false
            Pl-Say "  policy $type failed: $($_.Exception.Message)" $pl.Colors.Red
            Write-ChangeLog -Source 'PhoneLines' -Action 'Set-CsPhoneNumberPolicyAssignment' -Target $base -Detail "$type=$($Policies[$type])" -Result "FAIL: $($_.Exception.Message)"
        }
    }
    return $ok
}

function Pl-AddLine {
    $pl = $script:Pl
    $upn = "$($txtUser.Text)".Trim()
    $number = Pl-NormalizeNumber $pl.TxtNumber.Text
    $type = "$($pl.CmbType.SelectedItem)"
    $category = "$($pl.CmbCategory.SelectedItem)"
    if (-not $upn) { Pl-Say 'Enter a user UPN.' $pl.Colors.Amber; return }
    if ($number -notmatch '^\+\d{6,15}(;ext=\d+)?$') { Pl-Say 'Enter the number in E.164 format, e.g. +14255551234 (optional ;ext=1234 for Direct Routing).' $pl.Colors.Amber; return }
    if (-not (Pl-Require @('Set-CsPhoneNumberAssignment','Get-CsPhoneNumberAssignment'))) { return }
    $setCmd = 'Set-CsPhoneNumberAssignment'
    if (-not (Resolve-CsParamName -Cmdlet $setCmd -Candidates @('AssignmentCategory'))) { Pl-Say "$setCmd has no -AssignmentCategory parameter - update MicrosoftTeams to 7.6.0 or later." $pl.Colors.Red; return }
    $pnParam = Resolve-CsParamName -Cmdlet $setCmd -Candidates @('PhoneNumber','TelephoneNumber')
    $ptParam = Resolve-CsParamName -Cmdlet $setCmd -Candidates @('PhoneNumberType','NumberType')
    if (-not $pnParam -or -not $ptParam) { Pl-Say "Could not resolve the number parameters on $setCmd." $pl.Colors.Red; return }

    try { $lines = @(Pl-GetLines -Upn $upn) } catch { Pl-Say "Could not read the user's current lines: $($_.Exception.Message)" $pl.Colors.Red; return }
    if (@($lines | Where-Object { $_.Category -match '^Primary' }).Count -eq 0) { Pl-Say "$upn has no primary line. Provision the primary number on the Provisioning tab first - alternate and private lines need one." $pl.Colors.Amber; return }
    if ($lines.Count -ge $script:PlMaxLines) { Pl-Say "$upn already has $($lines.Count) lines; the limit is $($script:PlMaxLines) (1 primary + 1 private + 9 alternate)." $pl.Colors.Amber; return }
    if ($category -eq 'Private' -and @($lines | Where-Object { $_.Category -match '^Private' }).Count -gt 0) { Pl-Say 'The user already has a private line (maximum one).' $pl.Colors.Amber; return }
    if ($category -eq 'Alternate' -and @($lines | Where-Object { $_.Category -match '^Alternate' }).Count -ge 9) { Pl-Say 'The user already has 9 alternate lines (maximum).' $pl.Colors.Amber; return }
    if (@($lines | Where-Object { $_.Number -eq $number }).Count -gt 0) { Pl-Say 'That number is already assigned to this user.' $pl.Colors.Amber; return }

    $policies = Pl-SelectedPolicies
    if ($category -eq 'Alternate' -and $type -eq 'DirectRouting') {
        foreach ($need in @(@('OnlineVoiceRoutingPolicy','voice routing policy'),@('TeamsEmergencyCallRoutingPolicy','emergency call routing policy'))) {
            if (-not $policies.Contains($need[0]) -or -not $policies[$need[0]]) {
                Pl-Say "A Direct Routing alternate line requires a $($need[1]) set at number level (calls fail without it, and it does not fall back to the user's policy)." $pl.Colors.Amber; return
            }
        }
    }
    if ($category -eq 'Private' -and $policies.Count -gt 0) { Pl-Say 'Policies can only be set on alternate lines, not private lines - policy selections are ignored.' $pl.Colors.Amber; $policies = [ordered]@{} }

    $locationId = ''
    if ($type -eq 'CallingPlan') {
        $li = $pl.CmbLocation.SelectedIndex
        if ($li -lt 0 -or $li -ge @($pl.LocationRows).Count) { Pl-Say 'A Calling Plan line needs an emergency location. Load the location catalog (Catalogs tab) and choose one.' $pl.Colors.Amber; return }
        $loc = @($pl.LocationRows)[$li]; $locationId = "$($loc.LocationId)"
        $numIso = Get-CountryFromNumber $number; $locIso = Get-LocationCountry $loc
        if ($numIso -and $locIso -and $numIso -ne $locIso) { Pl-Say "Number country ($numIso) does not match the location country ($locIso)." $pl.Colors.Amber; return }
    }

    $polText = if ($policies.Count) { ($policies.Keys | ForEach-Object { "  $_ = $(if ($policies[$_]) { $policies[$_] } else { '(none)' })" }) -join "`n" } else { '  (none)' }
    $msg = "Assign $category line to $upn`n`n  Number : $number`n  Type   : $type`n  Location: $(if ($locationId) { $pl.CmbLocation.Text } else { 'n/a' })`n`nNumber-level policies:`n$polText"
    if (-not (Pm-Confirm $msg)) { return }

    $params = @{ Identity = $upn; AssignmentCategory = $category; ErrorAction = 'Stop' }
    $params[$pnParam] = $number; $params[$ptParam] = $type
    if ($locationId) { $params.LocationId = $locationId }
    if ($pl.ChkNotify.Checked -and (Resolve-CsParamName -Cmdlet $setCmd -Candidates @('Notify'))) { $params.Notify = $true }
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        Pl-Say "Assigning $number ($type, $category) to $upn ..." $pl.Colors.Blue
        Set-CsPhoneNumberAssignment @params
        Write-ChangeLog -Source 'PhoneLines' -Action 'Set-CsPhoneNumberAssignment' -Target $upn -Detail "$number $type $category" -Result 'OK'
        $confirmed = $false
        for ($i = 0; $i -lt 8; $i++) {
            Start-Sleep -Seconds 5
            try { $now = @(Pl-GetLines -Upn $upn); if (@($now | Where-Object { $_.Number -eq $number -or ($_.Number -replace '^\+','') -eq (($number -split ';')[0] -replace '^\+','') }).Count -gt 0) { $confirmed = $true; break } } catch { }
        }
        if ($confirmed) { Pl-Say 'Assignment confirmed.' $pl.Colors.Green } else { Pl-Say 'Assignment accepted but not visible yet - it can take a few minutes. Press Read Settings to re-check.' $pl.Colors.Amber }
        if ($policies.Count -gt 0) { [void](Pl-ApplyPolicies -Number $number -Policies $policies) }
    } catch {
        Pl-Say "Assign failed: $($_.Exception.Message)" $pl.Colors.Red
        Write-ChangeLog -Source 'PhoneLines' -Action 'Set-CsPhoneNumberAssignment' -Target $upn -Detail "$number $type $category" -Result "FAIL: $($_.Exception.Message)"
    } finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }
    Pl-ReadLines
}

function Pl-RemoveLine {
    $pl = $script:Pl
    if ($pl.Grid.SelectedRows.Count -eq 0) { Pl-Say 'Select a line first.' $pl.Colors.Amber; return }
    $r = $pl.Grid.SelectedRows[0]
    $number = "$($r.Cells['Number'].Value)"; $type = "$($r.Cells['Type'].Value)"; $cat = "$($r.Cells['Category'].Value)"
    $upn = "$($txtUser.Text)".Trim()
    if (-not (Pl-Require @('Remove-CsPhoneNumberAssignment'))) { return }
    if ($cat -match '^Primary' -and @($pl.Lines | Where-Object { $_.Category -notmatch '^Primary' }).Count -gt 0) {
        Pl-Say 'The primary line cannot be removed while the user has alternate or private lines. Remove those first.' $pl.Colors.Amber; return
    }
    if (-not (Pm-Confirm "Remove the $cat line $number ($type) from $upn?`n`nNumber-level policies on an alternate line are removed with it.")) { return }
    $pn = Resolve-CsParamName -Cmdlet 'Remove-CsPhoneNumberAssignment' -Candidates @('PhoneNumber','TelephoneNumber')
    $pt = Resolve-CsParamName -Cmdlet 'Remove-CsPhoneNumberAssignment' -Candidates @('PhoneNumberType','NumberType')
    if (-not $pn -or -not $pt) { Pl-Say 'Could not resolve the number parameters on Remove-CsPhoneNumberAssignment.' $pl.Colors.Red; return }
    $p = @{ Identity = $upn; ErrorAction = 'Stop' }; $p[$pn] = $number; $p[$pt] = $type
    try {
        Remove-CsPhoneNumberAssignment @p
        Pl-Say "Removed $number from $upn." $pl.Colors.Green
        Write-ChangeLog -Source 'PhoneLines' -Action 'Remove-CsPhoneNumberAssignment' -Target $upn -Detail "$number $type $cat" -Result 'OK'
    } catch {
        Pl-Say "Remove failed: $($_.Exception.Message)" $pl.Colors.Red
        Write-ChangeLog -Source 'PhoneLines' -Action 'Remove-CsPhoneNumberAssignment' -Target $upn -Detail "$number $type $cat" -Result "FAIL: $($_.Exception.Message)"
    }
    Pl-ReadLines
}

function Pl-ApplyToSelected {
    $pl = $script:Pl
    if ($pl.Grid.SelectedRows.Count -eq 0) { Pl-Say 'Select an alternate line first.' $pl.Colors.Amber; return }
    $r = $pl.Grid.SelectedRows[0]
    $number = "$($r.Cells['Number'].Value)"; $cat = "$($r.Cells['Category'].Value)"
    if ($cat -notmatch '^Alternate') { Pl-Say 'Number-level policies can only be set on alternate lines.' $pl.Colors.Amber; return }
    $policies = Pl-SelectedPolicies
    if ($policies.Count -eq 0) { Pl-Say 'Pick at least one policy (or "(none)" to clear it).' $pl.Colors.Amber; return }
    $polText = ($policies.Keys | ForEach-Object { "  $_ = $(if ($policies[$_]) { $policies[$_] } else { '(none)' })" }) -join "`n"
    if (-not (Pm-Confirm "Set number-level policies on $number`:`n`n$polText")) { return }
    [void](Pl-ApplyPolicies -Number $number -Policies $policies)
}

function Pl-RefreshLocations {
    $pl = $script:Pl
    $pl.CmbLocation.Items.Clear()
    $pl.LocationRows = @($script:allLocations)
    foreach ($loc in $pl.LocationRows) {
        $c = Get-LocationCountry $loc
        [void]$pl.CmbLocation.Items.Add($(if ($c) { "$($loc.LocationName)  [$c]" } else { "$($loc.LocationName)" }))
    }
    if ($pl.CmbLocation.Items.Count -gt 0) { $pl.CmbLocation.SelectedIndex = 0 }
}

function Pl-RefreshPolicyChoices {
    $pl = $script:Pl
    foreach ($label in $script:PlPolicyTypes.Keys) {
        $combo = $pl.PolicyCombos[$label]; $combo.Items.Clear()
        [void]$combo.Items.Add('(none)')
        foreach ($n in @($script:catalog | Where-Object { $_.PolicyType -eq $script:PlPolicyTypes[$label] -and $_.PolicyName -ne 'Global' } | Select-Object -ExpandProperty PolicyName)) { [void]$combo.Items.Add($n) }
        $combo.Text = ''
    }
}

function Pl-Layout {
    # Sizes the panel from its current width so the lines grid and forms stretch with the window.
    $pl = $script:Pl; if (-not $pl -or -not $pl.Page) { return }
    $w = [Math]::Max(640, $pl.Page.ClientSize.Width)
    $inner = $w - 16
    $pl.Rule.Size = New-Object System.Drawing.Size($inner, 36)
    $pl.LblLines.Size = New-Object System.Drawing.Size($inner, 20)
    $pl.Grid.Size = New-Object System.Drawing.Size($inner, 150)
    $pl.Mid.Location = New-Object System.Drawing.Point(0, 222)
    $pl.Mid.Size = New-Object System.Drawing.Size($w, 520)
    $pl.GAdd.Size = New-Object System.Drawing.Size($inner, 240)
    $pl.GPol.Size = New-Object System.Drawing.Size($inner, 250)
    $fieldW = $inner - 110 - 16
    $pl.TxtNumber.Size = New-Object System.Drawing.Size($fieldW, 22)
    $pl.CmbLocation.Size = New-Object System.Drawing.Size($fieldW, 22)
    $pl.Hint.Size = New-Object System.Drawing.Size(($inner - 24), 28)
    $pl.BtnApply.Location = New-Object System.Drawing.Point(($inner - 200), 24)
    $pl.BtnShowPol.Location = New-Object System.Drawing.Point(($inner - 200), 56)
    $pl.Note.Location = New-Object System.Drawing.Point(($inner - 200), 92)
    $pl.Note.Size = New-Object System.Drawing.Size(190, 110)
    $comboW = $inner - 206 - 216
    foreach ($cb in $pl.PolicyCombos.Values) { $cb.Size = New-Object System.Drawing.Size($comboW, 22) }
}

function New-PhoneLinesPanel {
    param(
        # The Provisioning status box, so line results and provisioning output share one log.
        [System.Windows.Forms.RichTextBox]$LogBox,
        $BackColor,$ColorBlue,$ColorPurple,$ColorGreen,$ColorGray,$ColorAmber,$ColorRed
    )
    $page = New-Object System.Windows.Forms.Panel
    $page.BackColor = $BackColor; $page.AutoScroll = $true
    $pl = @{ Lines=@(); LocationRows=@(); PolicyCombos=@{}; Log=$LogBox; Colors=@{ Green=$ColorGreen; Amber=$ColorAmber; Red=$ColorRed; Gray=$ColorGray; Blue=$ColorBlue } }
    $script:Pl = $pl

    function Pl-Btn($t,$x,$y,$w,$c) { $b=New-Object System.Windows.Forms.Button; $b.Text=$t; $b.Location=New-Object System.Drawing.Point($x,$y); $b.Size=New-Object System.Drawing.Size($w,26); Style-Button $b $c; $b }
    function Pl-Lbl($t,$x,$y,$w) { $l=New-Object System.Windows.Forms.Label; $l.Text=$t; $l.Location=New-Object System.Drawing.Point($x,$y); $l.Size=New-Object System.Drawing.Size($w,20); $l }

    # The user is the UPN on the Provisioning tab; Read Settings loads this grid, so the panel has no UPN box or read button of its own.
    $rule = Pl-Lbl 'Up to 11 lines per user: 1 primary + 1 private + 9 alternate, any mix of Calling Plan / Direct Routing / Operator Connect. A primary line must exist first. Alternate lines need MicrosoftTeams 7.6.0+ and are managed by RBAC (Graph does not support them yet). User must not be in India.' 8 4 700 36
    $rule.ForeColor=$ColorGray; $rule.Font=New-Object System.Drawing.Font('Segoe UI',8,[System.Drawing.FontStyle]::Italic)
    $lblLines = Pl-Lbl 'Assigned phone lines (loaded by Read Settings)' 8 42 700 20
    $lblLines.Font = New-Object System.Drawing.Font('Segoe UI',9,[System.Drawing.FontStyle]::Bold)

    $pl.Grid = New-Object System.Windows.Forms.DataGridView
    $pl.Grid.Location=New-Object System.Drawing.Point(8,64); $pl.Grid.Size=New-Object System.Drawing.Size(744,150); $pl.Grid.ReadOnly=$true; $pl.Grid.AllowUserToAddRows=$false; $pl.Grid.RowHeadersVisible=$false
    $pl.Grid.SelectionMode='FullRowSelect'; $pl.Grid.MultiSelect=$false; $pl.Grid.BackgroundColor=[System.Drawing.Color]::White; $pl.Grid.AutoSizeColumnsMode='Fill'
    foreach ($c in 'Number','Type','Category','Status','Location','Source') { [void]$pl.Grid.Columns.Add($c,$c) }

    $mid = New-Object System.Windows.Forms.Panel; $mid.Location=New-Object System.Drawing.Point(0,222); $mid.Size=New-Object System.Drawing.Size(760,520); $mid.BackColor=$BackColor
    $gAdd = New-Object System.Windows.Forms.GroupBox; $gAdd.Text='Add a line'; $gAdd.Location=New-Object System.Drawing.Point(8,4); $gAdd.Size=New-Object System.Drawing.Size(744,240)
    $pl.TxtNumber = New-Object System.Windows.Forms.TextBox; $pl.TxtNumber.Location=New-Object System.Drawing.Point(110,24); $pl.TxtNumber.Size=New-Object System.Drawing.Size(390,22)
    $pl.CmbType = New-Object System.Windows.Forms.ComboBox; $pl.CmbType.Location=New-Object System.Drawing.Point(110,54); $pl.CmbType.Size=New-Object System.Drawing.Size(200,22); $pl.CmbType.DropDownStyle='DropDownList'
    foreach ($t in 'DirectRouting','CallingPlan','OperatorConnect') { [void]$pl.CmbType.Items.Add($t) }; $pl.CmbType.SelectedIndex = 0
    $pl.CmbCategory = New-Object System.Windows.Forms.ComboBox; $pl.CmbCategory.Location=New-Object System.Drawing.Point(110,84); $pl.CmbCategory.Size=New-Object System.Drawing.Size(200,22); $pl.CmbCategory.DropDownStyle='DropDownList'
    foreach ($t in 'Alternate','Private') { [void]$pl.CmbCategory.Items.Add($t) }; $pl.CmbCategory.SelectedIndex = 0
    $pl.CmbLocation = New-Object System.Windows.Forms.ComboBox; $pl.CmbLocation.Location=New-Object System.Drawing.Point(110,114); $pl.CmbLocation.Size=New-Object System.Drawing.Size(390,22); $pl.CmbLocation.DropDownStyle='DropDownList'
    $pl.ChkNotify = New-Object System.Windows.Forms.CheckBox; $pl.ChkNotify.Location=New-Object System.Drawing.Point(110,144); $pl.ChkNotify.Size=New-Object System.Drawing.Size(300,22); $pl.ChkNotify.Text='Email the user the new number'
    $btnAdd = Pl-Btn 'Add Line' 110 176 130 $ColorGreen
    $btnRem = Pl-Btn 'Remove Selected' 248 176 150 $ColorRed
    $hint = Pl-Lbl 'Calling Plan needs a location (from the Catalogs tab). Extensions: +14255551000;ext=1234 (Direct Routing).' 12 208 500 28; $hint.ForeColor=$ColorGray
    $gAdd.Controls.AddRange(@((Pl-Lbl 'Phone number' 12 26 96),$pl.TxtNumber,(Pl-Lbl 'Number type' 12 56 96),$pl.CmbType,(Pl-Lbl 'Line category' 12 86 96),$pl.CmbCategory,(Pl-Lbl 'Location' 12 116 96),$pl.CmbLocation,$pl.ChkNotify,$btnAdd,$btnRem,$hint))

    $gPol = New-Object System.Windows.Forms.GroupBox; $gPol.Text='Number-level policies (alternate lines only - these do not fall back to the user''s policies)'; $gPol.Location=New-Object System.Drawing.Point(8,252); $gPol.Size=New-Object System.Drawing.Size(744,250)
    $pl.PolicyLabels = @()
    $y = 24
    foreach ($label in $script:PlPolicyTypes.Keys) {
        $pl.PolicyLabels += ,(Pl-Lbl $label 12 ($y+2) 190)
        $cb = New-Object System.Windows.Forms.ComboBox; $cb.Location=New-Object System.Drawing.Point(206,$y); $cb.Size=New-Object System.Drawing.Size(300,22); $cb.DropDownStyle='DropDown'
        $pl.PolicyCombos[$label] = $cb; $y += 28
    }
    $gPol.Controls.AddRange(@($pl.PolicyLabels))
    $gPol.Controls.AddRange(@($pl.PolicyCombos.Values))
    $btnApply = Pl-Btn 'Apply To Selected Line' 0 24 190 $ColorBlue
    $btnShowPol = Pl-Btn 'Show Line Policies' 0 56 190 $ColorPurple
    $pn = Pl-Lbl 'Blank = leave unchanged. (none) = clear. Direct Routing alternate lines require a voice routing policy and an emergency call routing policy.' 0 92 190 110; $pn.ForeColor=$ColorGray
    $gPol.Controls.AddRange(@($btnApply,$btnShowPol,$pn))
    $mid.Controls.AddRange(@($gAdd,$gPol))

    $pl.Page=$page; $pl.Mid=$mid; $pl.GAdd=$gAdd; $pl.GPol=$gPol; $pl.Rule=$rule; $pl.Hint=$hint; $pl.BtnApply=$btnApply; $pl.BtnShowPol=$btnShowPol; $pl.Note=$pn; $pl.LblLines=$lblLines; $pl.BtnRem=$btnRem; $pl.BtnAdd=$btnAdd
    $page.Controls.Add($lblLines); $page.Controls.Add($rule); $page.Controls.Add($pl.Grid); $page.Controls.Add($mid)
    $page.Add_Resize({ Pl-Layout })
    $btnAdd.Add_Click({ Pl-AddLine })
    $btnRem.Add_Click({ Pl-RemoveLine })
    $btnApply.Add_Click({ Pl-ApplyToSelected })
    $btnShowPol.Add_Click({ Pl-ReadNumberPolicies })
    $pl.CmbType.Add_SelectedIndexChanged({ $script:Pl.CmbLocation.Enabled = ("$($script:Pl.CmbType.SelectedItem)" -eq 'CallingPlan') })
    $pl.CmbLocation.Enabled = $false
    Pl-Layout
    Pl-Say 'Enter the UPN on the left and click Read Settings to load its lines and policies.' $ColorGray
    return $page
}

################################################################################
#
#  CONFIGURATION TAB - tenants and the MicrosoftTeams module source
#
#  Settings live in TeamsVoice_Settings.json beside the script (config files stay
#  in the project root; only support files go in subfolders).
#
################################################################################

$script:AppSettings = @{ TeamsModulePath = ''; AutoImportTeamsModule = $false; PreferTeamsModule = $true }

function Get-SettingsPath { return (Join-Path (Get-ToolkitRoot) 'TeamsVoice_Settings.json') }

function Load-AppSettings {
    $p = Get-SettingsPath
    if (-not (Test-Path -LiteralPath $p)) { return }
    try {
        $j = Get-Content -LiteralPath $p -Raw -ErrorAction Stop | ConvertFrom-Json
        if ($j.PSObject.Properties['TeamsModulePath'])       { $script:AppSettings.TeamsModulePath = [string]$j.TeamsModulePath }
        if ($j.PSObject.Properties['AutoImportTeamsModule']) { $script:AppSettings.AutoImportTeamsModule = [bool]$j.AutoImportTeamsModule }
        if ($j.PSObject.Properties['PreferTeamsModule'])     { $script:AppSettings.PreferTeamsModule = [bool]$j.PreferTeamsModule }
    } catch { }
}

function Save-AppSettings {
    try {
        $script:AppSettings | ConvertTo-Json | Set-Content -LiteralPath (Get-SettingsPath) -Encoding UTF8 -ErrorAction Stop
        return $true
    } catch { return $false }
}

function Resolve-TeamsModuleManifest {
<#
.SYNOPSIS
    Find MicrosoftTeams.psd1 from a folder or file the operator picked.
.DESCRIPTION
    Accepts the manifest itself, the version folder holding it, the MicrosoftTeams
    folder (version subfolders inside), or a Modules folder containing MicrosoftTeams.
    When several versions are found the highest version folder wins.
#>
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $Path = $Path.Trim().Trim('"')
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        if ($Path -like '*.psd1') { return (Resolve-Path -LiteralPath $Path).Path }
        return $null
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $null }
    $found = @()
    foreach ($base in @($Path, (Join-Path $Path 'MicrosoftTeams'))) {
        if (-not (Test-Path -LiteralPath $base -PathType Container)) { continue }
        $direct = Join-Path $base 'MicrosoftTeams.psd1'
        if (Test-Path -LiteralPath $direct) { $found += Get-Item -LiteralPath $direct }
        foreach ($d in @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue)) {
            $m = Join-Path $d.FullName 'MicrosoftTeams.psd1'
            if (Test-Path -LiteralPath $m) { $found += Get-Item -LiteralPath $m }
        }
    }
    if ($found.Count -eq 0) { return $null }
    $best = $found | Sort-Object {
        $v = [version]'0.0'
        [void][version]::TryParse($_.Directory.Name, [ref]$v)
        $v
    } -Descending | Select-Object -First 1
    return $best.FullName
}

function Get-TeamsModuleSummary {
    $m = Get-Module -Name MicrosoftTeams | Select-Object -First 1
    if ($m) { return ("v{0}  -  {1}" -f $m.Version, $m.ModuleBase) }
    return 'not loaded'
}

function Import-TeamsModuleFromPath {
<#
.SYNOPSIS
    Import MicrosoftTeams from a chosen location instead of the default install.
.OUTPUTS
    Success / Changed / Message. Changed is true when a module was (re)loaded, which
    invalidates any existing Teams session.
.NOTES
    If a different copy is already loaded it is removed first. The Teams module
    ships native/.NET assemblies that cannot be swapped inside a running process,
    so a version change can fail with an assembly conflict. Enable the auto-import
    checkbox and restart the tool - the chosen module then loads before anything else.
#>
    param([Parameter(Mandatory)][string]$Path)
    $manifest = Resolve-TeamsModuleManifest -Path $Path
    if (-not $manifest) {
        return [pscustomobject]@{ Success=$false; Changed=$false; Message="No MicrosoftTeams.psd1 found under '$Path'. Pick the folder that contains MicrosoftTeams.psd1 (or its version folders)." }
    }
    $dir = (Split-Path -Parent $manifest).TrimEnd('\')
    $loaded = Get-Module -Name MicrosoftTeams | Select-Object -First 1
    if ($loaded -and ($loaded.ModuleBase.TrimEnd('\') -ieq $dir)) {
        return [pscustomobject]@{ Success=$true; Changed=$false; Message="Already loaded from this location: $(Get-TeamsModuleSummary)" }
    }
    # Removing the loaded module drops the live Teams session, so refuse while connected.
    if ($loaded -and $script:RbacConnected) {
        return [pscustomobject]@{ Success=$false; Changed=$false; Message="Connected to Teams with $(Get-TeamsModuleSummary). Disconnect first, or keep this module - switching now would drop the session. The chosen module will load on the next start." }
    }
    try {
        if ($loaded) { Remove-Module -Name MicrosoftTeams -Force -ErrorAction Stop }
        Import-Module -Name $manifest -Force -Global -ErrorAction Stop
        return [pscustomobject]@{ Success=$true; Changed=$true; Message="Imported $(Get-TeamsModuleSummary)" }
    } catch {
        return [pscustomobject]@{ Success=$false; Changed=$false; Message="Import failed: $($_.Exception.Message)`r`nIf this is an assembly conflict, tick 'Import automatically', save, and restart the tool so the module loads first." }
    }
}

function Ensure-ConfiguredTeamsModule {
<#
.SYNOPSIS
    Honour the Configuration window: when auto-import is on, make sure the chosen module is loaded.
.OUTPUTS
    $null when auto-import is off; otherwise the Import-TeamsModuleFromPath result.
#>
    if (-not $script:AppSettings.AutoImportTeamsModule) { return $null }
    if ([string]::IsNullOrWhiteSpace($script:AppSettings.TeamsModulePath)) { return $null }
    if ($script:RbacConnected) { return $null }
    return (Import-TeamsModuleFromPath -Path $script:AppSettings.TeamsModulePath)
}

Load-AppSettings
$script:StartupModuleResult = Ensure-ConfiguredTeamsModule

function Get-TeamsModuleInstallRoot {
<#
.SYNOPSIS
    Modules folder that the running PowerShell edition searches by default.
.NOTES
    CurrentUser = Documents\PowerShell\Modules (pwsh 7) or Documents\WindowsPowerShell\Modules (5.1).
    AllUsers    = Program Files equivalent (needs an elevated session).
#>
    param([ValidateSet('CurrentUser','AllUsers')][string]$Scope = 'CurrentUser')
    $edition = if ($PSVersionTable.PSEdition -eq 'Core') { 'PowerShell' } else { 'WindowsPowerShell' }
    if ($Scope -eq 'AllUsers') { return (Join-Path $env:ProgramFiles "$edition\Modules") }
    return (Join-Path ([Environment]::GetFolderPath('MyDocuments')) "$edition\Modules")
}

function Test-IsAdministrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Copy-TeamsModuleToScope {
<#
.SYNOPSIS
    Copy MicrosoftTeams into the default modules location using the flat layout.
.OUTPUTS
    Success / Message / Path (the copied folder, which holds MicrosoftTeams.psd1 directly).
.NOTES
    Destination is <ModulesRoot>\MicrosoftTeams\ with the module files directly inside, as in
    Microsoft's "Installing a PowerShell Module" guidance (no version subfolder).
    Staging happens at the Modules root, so the module folder is never nested inside itself.
#>
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [ValidateSet('CurrentUser','AllUsers')][string]$Scope = 'CurrentUser'
    )
    $manifest = Resolve-TeamsModuleManifest -Path $SourcePath
    if (-not $manifest) {
        return [pscustomobject]@{ Success=$false; Path=$null; Message="No MicrosoftTeams.psd1 found under '$SourcePath'." }
    }
    $src = (Split-Path -Parent $manifest).TrimEnd('\')
    $version = [string](Import-PowerShellDataFile -LiteralPath $manifest).ModuleVersion
    $modulesRoot = Get-TeamsModuleInstallRoot -Scope $Scope
    $dest = Join-Path $modulesRoot 'MicrosoftTeams'
    # Stage first, so a source that is already the destination is never deleted before it is copied.
    $stage = Join-Path $modulesRoot ('.staging_' + [guid]::NewGuid().ToString('N'))
    try {
        New-Item -ItemType Directory -Path $modulesRoot -Force -ErrorAction Stop | Out-Null
        Copy-Item -LiteralPath $src -Destination $stage -Recurse -Force -ErrorAction Stop
        if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force -ErrorAction Stop }
        Move-Item -LiteralPath $stage -Destination $dest -ErrorAction Stop
    } catch {
        if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
        return [pscustomobject]@{ Success=$false; Path=$null; Message="Copy to '$dest' failed: $($_.Exception.Message)`r`nClose any PowerShell session that has the module loaded, and run the tool as administrator for Program Files." }
    }
    return [pscustomobject]@{ Success=$true; Path=$dest; Message="Copied MicrosoftTeams $version to $dest (flat layout)" }
}

function New-ConfigurationTabPage {
    param(
        [string]$Text = 'Configuration',
        $BackColor,$ColorBlue,$ColorPurple,$ColorGreen,$ColorGray,$ColorAmber,$ColorRed
    )
    $page = New-Object System.Windows.Forms.Form
    $page.Text = $Text; $page.BackColor = $BackColor; $page.AutoScroll = $true
    $page.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
    $page.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $page.MaximizeBox = $false; $page.MinimizeBox = $false; $page.ShowInTaskbar = $false
    $page.ClientSize = New-Object System.Drawing.Size(1296,530)
    $cfg = @{}; $script:Cfg = $cfg
    $cfg.Colors = @{ Green=$ColorGreen; Amber=$ColorAmber; Red=$ColorRed; Gray=$ColorGray }

    function Cfg-Label($t,$x,$y,$w=110) { $l=New-Object System.Windows.Forms.Label; $l.Text=$t; $l.Location=New-Object System.Drawing.Point($x,$y); $l.Size=New-Object System.Drawing.Size($w,20); $l }
    function Cfg-Text($x,$y,$w) { $t=New-Object System.Windows.Forms.TextBox; $t.Location=New-Object System.Drawing.Point($x,$y); $t.Size=New-Object System.Drawing.Size($w,22); $t }
    function Cfg-Button($t,$x,$y,$w,$color) { $b=New-Object System.Windows.Forms.Button; $b.Text=$t; $b.Location=New-Object System.Drawing.Point($x,$y); $b.Size=New-Object System.Drawing.Size($w,28); Style-Button $b $color; $b }

    # ---- Tenants -------------------------------------------------------------
    $gT = New-Object System.Windows.Forms.GroupBox; $gT.Text='Tenants'; $gT.Location=New-Object System.Drawing.Point(12,10); $gT.Size=New-Object System.Drawing.Size(640,470)
    $cfg.Lst = New-Object System.Windows.Forms.ListBox; $cfg.Lst.Location=New-Object System.Drawing.Point(12,24); $cfg.Lst.Size=New-Object System.Drawing.Size(614,120); $cfg.Lst.Font=New-Object System.Drawing.Font('Consolas',9)
    $gT.Controls.Add($cfg.Lst)
    $fields = @(
        @('Label','Label'), @('Tenant Id','TenantId'), @('Client Id','ClientId'), @('App name','App'),
        @('Default UPN','DefaultUpn'), @('Default number','DefaultNumber'), @('Default CDR filter','DefaultCdrFilter')
    )
    $cfg.Fields = @{}
    $y = 158
    foreach ($f in $fields) {
        $gT.Controls.Add((Cfg-Label $f[0] 12 ($y+2) 120))
        $tb = Cfg-Text 138 $y 488; $cfg.Fields[$f[1]] = $tb; $gT.Controls.Add($tb)
        $y += 30
    }
    $cfg.LblErr = Cfg-Label '' 12 ($y+2) 614; $cfg.LblErr.ForeColor=$ColorRed; $gT.Controls.Add($cfg.LblErr)
    $y += 28
    $btnAdd = Cfg-Button 'Add / Update' 12 $y 130 $ColorGreen
    $btnNew = Cfg-Button 'Clear Form' 150 $y 100 $ColorGray
    $btnRemove = Cfg-Button 'Remove Selected' 258 $y 130 $ColorAmber
    $btnUse = Cfg-Button 'Use As Active' 396 $y 130 $ColorBlue
    $gT.Controls.AddRange(@($btnAdd,$btnNew,$btnRemove,$btnUse))
    $nt = Cfg-Label 'Client secrets are never stored. Defaults pre-fill the Provisioning and CDR tabs for that tenant.' 12 ($y+36) 614; $nt.ForeColor=$ColorGray; $gT.Controls.Add($nt)

    # ---- MicrosoftTeams module ----------------------------------------------
    $gM = New-Object System.Windows.Forms.GroupBox; $gM.Text='Microsoft Teams PowerShell module'; $gM.Location=New-Object System.Drawing.Point(664,10); $gM.Size=New-Object System.Drawing.Size(620,370)
    $gM.Controls.Add((Cfg-Label 'Module folder' 12 30 90))
    $cfg.TxtModule = Cfg-Text 106 28 400; $cfg.TxtModule.Text = $script:AppSettings.TeamsModulePath
    $btnBrowse = Cfg-Button 'Browse...' 514 26 92 $ColorPurple
    $hint = Cfg-Label 'Pick the folder containing MicrosoftTeams.psd1 (flat layout: Modules\MicrosoftTeams). Recommended: MicrosoftTeams 7.8. Leave blank to use the default installed module.' 12 58 596; $hint.ForeColor=$ColorGray
    $cfg.ChkAuto = New-Object System.Windows.Forms.CheckBox; $cfg.ChkAuto.Location=New-Object System.Drawing.Point(12,84); $cfg.ChkAuto.Size=New-Object System.Drawing.Size(590,22)
    $cfg.ChkAuto.Text='Import this module path automatically (at startup and before Connect RBAC)'; $cfg.ChkAuto.Checked=[bool]$script:AppSettings.AutoImportTeamsModule
    $btnImport = Cfg-Button 'Import Now' 12 114 120 $ColorBlue
    $btnDefault = Cfg-Button 'Use Default Module' 140 114 160 $ColorGray
    $cfg.LblLoaded = Cfg-Label '' 12 150 596; $cfg.LblLoaded.Font=New-Object System.Drawing.Font('Segoe UI',8,[System.Drawing.FontStyle]::Bold); $cfg.LblLoaded.ForeColor=$ColorPurple
    $cfg.Log = New-Object System.Windows.Forms.TextBox; $cfg.Log.Multiline=$true; $cfg.Log.ReadOnly=$true; $cfg.Log.ScrollBars='Vertical'
    $cfg.Log.Location=New-Object System.Drawing.Point(12,176); $cfg.Log.Size=New-Object System.Drawing.Size(594,96); $cfg.Log.Font=New-Object System.Drawing.Font('Consolas',9); $cfg.Log.BackColor=[System.Drawing.Color]::White
    $lblCopy = Cfg-Label 'Copy to:' 12 286 60
    $cfg.RadDocs = New-Object System.Windows.Forms.RadioButton; $cfg.RadDocs.Text='My Documents module folder (current user)'; $cfg.RadDocs.Location=New-Object System.Drawing.Point(76,284); $cfg.RadDocs.Size=New-Object System.Drawing.Size(290,22); $cfg.RadDocs.Checked=$true
    $cfg.RadProgFiles = New-Object System.Windows.Forms.RadioButton; $cfg.RadProgFiles.Text='Program Files (all users, needs admin)'; $cfg.RadProgFiles.Location=New-Object System.Drawing.Point(370,284); $cfg.RadProgFiles.Size=New-Object System.Drawing.Size(240,22)
    $btnCopy = Cfg-Button 'Copy Module and Import' 12 314 200 $ColorGreen
    $cfg.LblCopyHint = Cfg-Label ("Documents target: " + (Get-TeamsModuleInstallRoot -Scope CurrentUser)) 220 320 386; $cfg.LblCopyHint.ForeColor=$ColorGray
    $cfg.BtnImport = $btnImport
    $gM.Controls.AddRange(@($cfg.TxtModule,$btnBrowse,$hint,$cfg.ChkAuto,$btnImport,$btnDefault,$cfg.LblLoaded,$cfg.Log,$lblCopy,$cfg.RadDocs,$cfg.RadProgFiles,$btnCopy,$cfg.LblCopyHint))
    $cfg.ChkPrefer = New-Object System.Windows.Forms.CheckBox; $cfg.ChkPrefer.Location=New-Object System.Drawing.Point(12,342); $cfg.ChkPrefer.Size=New-Object System.Drawing.Size(596,22)
    $cfg.ChkPrefer.Text='Prefer the Teams module over Graph for number, user and group lookups (when connected to RBAC)'; $cfg.ChkPrefer.Checked=[bool]$script:AppSettings.PreferTeamsModule
    $gM.Controls.Add($cfg.ChkPrefer)
    $cfg.ChkPrefer.Add_CheckedChanged({
        $script:AppSettings.PreferTeamsModule = [bool]$script:Cfg.ChkPrefer.Checked
        if (-not (Save-AppSettings)) { Cfg-Log 'Could not save settings.' $true }
    })

    # ---- Folders --------------------------------------------------------------
    $gF = New-Object System.Windows.Forms.GroupBox; $gF.Text='Project folders'; $gF.Location=New-Object System.Drawing.Point(664,390); $gF.Size=New-Object System.Drawing.Size(620,130)
    $fl = Cfg-Label ("Root (app + config): " + (Get-ToolkitRoot) + "`r`nCatalogs: locations and policy catalogs   |   Docs: operator guide`r`nScripts: helper scripts   |   TeamsVoice_Output: CDR, reports, backups, diagnostics") 12 22 596
    $fl.Size = New-Object System.Drawing.Size(596,50)
    $bRoot = Cfg-Button 'Open Root' 12 84 110 $ColorGray; $bCat = Cfg-Button 'Open Catalogs' 130 84 120 $ColorGray; $bOut = Cfg-Button 'Open Output' 258 84 120 $ColorGray
    $gF.Controls.AddRange(@($fl,$bRoot,$bCat,$bOut))
    $page.Controls.AddRange(@($gT,$gM,$gF))

    # ---- behaviour --------------------------------------------------------------
    $guidRx=$script:CfgGuidRx

    $btnBrowse.Add_Click({
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.Description = 'Select the folder that contains the MicrosoftTeams module (MicrosoftTeams.psd1 or its version folders).'
        $dlg.ShowNewFolderButton = $false
        $cur = $script:Cfg.TxtModule.Text.Trim()
        if ($cur -and (Test-Path -LiteralPath $cur -PathType Container)) { $dlg.SelectedPath = $cur }
        if ($dlg.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
        $script:Cfg.TxtModule.Text = $dlg.SelectedPath
        $m = Resolve-TeamsModuleManifest -Path $dlg.SelectedPath
        if ($m) { Cfg-Log "Found manifest: $m" } else { Cfg-Log "No MicrosoftTeams.psd1 found under that folder." $true }
    })
    $cfg.ChkAuto.Add_CheckedChanged({
        $script:AppSettings.AutoImportTeamsModule = [bool]$script:Cfg.ChkAuto.Checked
        $script:AppSettings.TeamsModulePath = $script:Cfg.TxtModule.Text.Trim()
        if (-not (Save-AppSettings)) { Cfg-Log 'Could not save settings.' $true }
    })
    $btnImport.Add_Click({
        $path = $script:Cfg.TxtModule.Text.Trim()
        if (-not $path) { Cfg-Log 'Choose a module folder first.' $true; return }
        $script:AppSettings.TeamsModulePath = $path
        $script:AppSettings.AutoImportTeamsModule = [bool]$script:Cfg.ChkAuto.Checked
        [void](Save-AppSettings)
        $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        try { $r = Import-TeamsModuleFromPath -Path $path } finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }
        Cfg-Log $r.Message (-not $r.Success)
        Cfg-RefreshLoaded
    })
    $btnDefault.Add_Click({
        $script:Cfg.TxtModule.Text=''; $script:Cfg.ChkAuto.Checked=$false
        $script:AppSettings.TeamsModulePath=''; $script:AppSettings.AutoImportTeamsModule=$false
        [void](Save-AppSettings)
        Cfg-Log 'Custom module path cleared. The default installed module is used from the next launch (a module already loaded in this session stays loaded).'
    })
    $btnCopy.Add_Click({
        $path = $script:Cfg.TxtModule.Text.Trim()
        if (-not $path) { Cfg-Log 'Choose a module folder first.' $true; return }
        $scope = if ($script:Cfg.RadProgFiles.Checked) { 'AllUsers' } else { 'CurrentUser' }
        if ($scope -eq 'AllUsers' -and -not (Test-IsAdministrator)) {
            Cfg-Log 'Program Files needs an elevated session. Restart the tool as administrator, or choose My Documents.' $true; return
        }
        $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        try { $r = Copy-TeamsModuleToScope -SourcePath $path -Scope $scope } finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }
        if (-not $r.Success) { Cfg-Log $r.Message $true; return }
        Cfg-Log $r.Message
        $script:Cfg.TxtModule.Text = $r.Path
        if ($script:RbacConnected) {
            Cfg-Log 'Session is connected, so the copy was not loaded. It loads the next time the tool starts.'
            return
        }
        # Point the setting at the copy and import it, exactly as Import Now does.
        $script:Cfg.BtnImport.PerformClick()
    })
    $bRoot.Add_Click({ Open-OutputFolder -Path (Get-ToolkitRoot) -Label 'Project' })
    $bCat.Add_Click({ Open-OutputFolder -Path (Get-AppFolder Catalogs) -Label 'Catalogs' })
    $bOut.Add_Click({ Open-OutputFolder -Path (Get-OutputRoot) -Label 'Output' })

    $cfg.Lst.Add_SelectedIndexChanged({
        $i = $script:Cfg.Lst.SelectedIndex
        if ($i -lt 0) { return }
        $label = @($script:Environments.Keys)[$i]; $e = $script:Environments[$label]
        $script:Cfg.Fields.Label.Text = $label
        foreach ($k in 'TenantId','ClientId','App','DefaultUpn','DefaultNumber','DefaultCdrFilter') { $script:Cfg.Fields[$k].Text = "$($e[$k])" }
        $script:Cfg.LblErr.Text = ''
    })
    $btnNew.Add_Click({ $script:Cfg.Lst.ClearSelected(); foreach ($k in @($script:Cfg.Fields.Keys)) { $script:Cfg.Fields[$k].Clear() }; $script:Cfg.LblErr.Text='' })
    $btnAdd.Add_Click({
        $f = $script:Cfg.Fields; $err = $script:Cfg.LblErr; $err.ForeColor = $script:Cfg.Colors.Red
        $label=$f.Label.Text.Trim(); $tenant=$f.TenantId.Text.Trim().Trim('{','}'); $client=$f.ClientId.Text.Trim().Trim('{','}'); $app=$f.App.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($label)) { $err.Text='Label is required.'; return }
        if ($tenant -notmatch $script:CfgGuidRx) { $err.Text='Tenant Id must be a GUID.'; return }
        if ($client -notmatch $script:CfgGuidRx) { $err.Text='Client Id must be a GUID.'; return }
        if ([string]::IsNullOrWhiteSpace($app)) { $app=$label }
        $key = if ($script:Environments.Contains($label)) { $script:Environments[$label].Key } else { Get-SafeEnvKey $label }
        $script:Environments[$label] = @{
            Key=$key; TenantId=$tenant; ClientId=$client; App=$app
            DefaultUpn=$f.DefaultUpn.Text.Trim(); DefaultNumber=$f.DefaultNumber.Text.Trim(); DefaultCdrFilter=$f.DefaultCdrFilter.Text.Trim()
        }
        Save-Environments; Cfg-RefreshEnvList; Refresh-EnvCombo
        $err.ForeColor = $script:Cfg.Colors.Green; $err.Text = "Saved '$label'."
        if (-not $script:CurrentEnv) { Switch-Environment $label }
    })
    $btnRemove.Add_Click({
        $err = $script:Cfg.LblErr; $err.ForeColor = $script:Cfg.Colors.Red
        $i = $script:Cfg.Lst.SelectedIndex
        if ($i -lt 0) { $err.Text='Select a tenant in the list first.'; return }
        $label = @($script:Environments.Keys)[$i]
        $c = [System.Windows.Forms.MessageBox]::Show("Remove tenant '$label'?`n`n(Its saved catalog CSVs are left on disk.)",'Confirm Remove','YesNo','Warning')
        if ($c -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        $wasCurrent = ($script:CurrentEnv -eq $label)
        $script:Environments.Remove($label); Save-Environments; Cfg-RefreshEnvList; Refresh-EnvCombo
        foreach ($k in @($script:Cfg.Fields.Keys)) { $script:Cfg.Fields[$k].Clear() }
        $err.ForeColor = $script:Cfg.Colors.Green; $err.Text = "Removed '$label'."
        if ($wasCurrent) { if ($script:Environments.Count -gt 0) { Switch-Environment @($script:Environments.Keys)[0] } else { Clear-EnvironmentUI } }
    })
    $btnUse.Add_Click({
        $err = $script:Cfg.LblErr; $err.ForeColor = $script:Cfg.Colors.Red
        $i = $script:Cfg.Lst.SelectedIndex
        if ($i -lt 0) { $err.Text='Select a tenant in the list first.'; return }
        $cmbEnv.SelectedItem = @($script:Environments.Keys)[$i]
    })

    Cfg-RefreshEnvList
    Cfg-RefreshLoaded
    return $page
}

function Cfg-Log {
    param([string]$Message,[bool]$IsError=$false)
    if (-not $script:Cfg) { return }
    $script:Cfg.Log.AppendText(("[{0:HH:mm:ss}] {1}{2}{3}" -f (Get-Date), $(if ($IsError) { 'ERROR: ' } else { '' }), $Message, "`r`n"))
}
function Cfg-RefreshLoaded {
    if (-not $script:Cfg) { return }
    $script:Cfg.LblLoaded.Text = "Loaded now: $(Get-TeamsModuleSummary)"
    $m = Get-Module -Name MicrosoftTeams | Select-Object -First 1
    if ($m -and $m.Version -lt [version]'7.8.0') {
        $script:Cfg.LblLoaded.ForeColor = $script:Cfg.Colors.Amber
        Cfg-Log "Loaded MicrosoftTeams $($m.Version) is below the recommended 7.8. Import 7.8 to match the tested behaviour." $true
    }
}
function Cfg-RefreshEnvList {
    if (-not $script:Cfg) { return }
    $script:Cfg.Lst.Items.Clear()
    foreach ($k in $script:Environments.Keys) { $e=$script:Environments[$k]; [void]$script:Cfg.Lst.Items.Add(("{0,-22} [{1,-18}]  tenant={2}" -f $k,$e.Key,$e.TenantId)) }
}

# ===============================================
# Teams Voice Provisioning - multi-environment
# Environments (Label / Tenant Id / Client Id / App name) are NOT hardcoded.
# They are entered at runtime via the "Manage Envs" button and persisted to
# TeamsVoice_Environments.csv next to this script.
# This build adds:
#   * Target Type selector (Auto / User / Resource Account) - RA detected via
#     MCOEV_VIRTUALUSER* service plan.
#   * Voice licensing: accepts ANY Teams Phone plan (MCOEV*) per Microsoft guidance,
#     not just E5. Reports explicitly when no voice-capable license is present.
#   * Inspect Number - numberType, capabilities(usage), status, target, and the
#     resolved EMERGENCY LOCATION (locationId -> catalog). Native 'city' relabeled.
#   * Usage-vs-target capability guard before assignNumber (DR skipped).
#   * Read Settings - grouped number "summary card".
#   * DR Inventory panel (Catalogs tab) - Add / Check order / Release Direct
#     Routing numbers via MicrosoftTeams cmdlets. DORMANT until the SPN has Teams
#     admin RBAC (there is no Graph v1.0 endpoint for DR number upload).
#   * CDR engine: background runspace, phased 'version' capture, latency (auto only).
# ===============================================

$root = Get-ToolkitRoot
Move-LegacyRootFiles
# TeamsVoice_Tenants.csv is the documented name. The older
# TeamsVoice_Environments.csv is still read when it is the only file present, so
# an existing install does not come up with an empty dropdown after an upgrade.
$script:TenantsCsvPath   = Join-Path $root "TeamsVoice_Tenants.csv"
$script:LegacyEnvCsvPath = Join-Path $root "TeamsVoice_Environments.csv"
$script:EnvCsvPath = $(
    if (Test-Path $script:TenantsCsvPath) { $script:TenantsCsvPath }
    elseif (Test-Path $script:LegacyEnvCsvPath) { $script:LegacyEnvCsvPath }
    else { $script:TenantsCsvPath })

function Get-SafeEnvKey {
    param([string]$Label)
    $k=($Label -replace '[^A-Za-z0-9]','').ToUpper(); if ([string]::IsNullOrWhiteSpace($k)) { $k="ENV$(Get-Random -Maximum 9999)" }
    $base=$k; $n=1; $used=@($script:Environments.Values | ForEach-Object { $_.Key })
    while ($used -contains $k) { $n++; $k="$base$n" }
    return $k
}
function Get-CsvValue {
    # Tolerant column read: older CSVs predate the three Default columns, and a
    # missing column must not throw - it just means no default.
    param($Row,[string[]]$Names)
    foreach ($n in $Names) {
        try { if (($Row.PSObject.Properties.Name -contains $n) -and -not [string]::IsNullOrWhiteSpace($Row.$n)) { return "$($Row.$n)" } } catch {}
    }
    return ''
}
function Load-Environments {
<#
.SYNOPSIS
    Read the tenant list. Rows with a blank Name are skipped.
.NOTES
    If the file is absent or yields no usable rows the tool writes nothing - it
    leaves the environment empty and prints the Manage Tenants prompt. Writing a
    stub file here would mean a fresh install inherits a shape it never asked for.
#>
    $script:Environments=[ordered]@{}
    if (Test-Path $script:EnvCsvPath) {
        try {
            foreach ($r in (Import-Csv $script:EnvCsvPath)) {
                $name = Get-CsvValue $r @('Name','Label')
                if ([string]::IsNullOrWhiteSpace($name)) { continue }
                $script:Environments[$name]=@{
                    Key              = Get-CsvValue $r @('Key')
                    TenantId         = Get-CsvValue $r @('TenantId')
                    ClientId         = Get-CsvValue $r @('ClientId')
                    App              = Get-CsvValue $r @('App')
                    DefaultUpn       = Get-CsvValue $r @('DefaultUpn')
                    DefaultNumber    = Get-CsvValue $r @('DefaultNumber')
                    DefaultCdrFilter = Get-CsvValue $r @('DefaultCdrFilter')
                }
            }
        } catch {}
    }
}
function Save-Environments {
<#
.SYNOPSIS
    Write all eight columns to TeamsVoice_Tenants.csv.
.NOTES
    A write failure is surfaced, never swallowed. Silently losing the tenant list
    means the next launch starts empty with no explanation for why.
#>
    $rows=foreach ($name in $script:Environments.Keys) {
        $e=$script:Environments[$name]
        [pscustomobject]@{
            Name             = $name
            Key              = $e.Key
            TenantId         = $e.TenantId
            ClientId         = $e.ClientId
            App              = $e.App
            DefaultUpn       = $e.DefaultUpn
            DefaultNumber    = $e.DefaultNumber
            DefaultCdrFilter = $e.DefaultCdrFilter
        }
    }
    try {
        if ($rows) {
            $rows | Export-Csv $script:TenantsCsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            $script:EnvCsvPath = $script:TenantsCsvPath
        }
        elseif (Test-Path $script:EnvCsvPath) { Remove-Item $script:EnvCsvPath -Force -ErrorAction Stop }
    }
    catch {
        $msg = "Could not save the tenant list to $($script:TenantsCsvPath): $($_.Exception.Message)"
        if (Get-Command Add-Status -ErrorAction SilentlyContinue) { Add-Status $msg ([System.Drawing.Color]::Firebrick) }
        else { [void][System.Windows.Forms.MessageBox]::Show($msg,'Tenant list not saved',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) }
    }
}
function Get-EnvDefault {
    # Per-tenant pre-fill value, empty when unset.
    param([string]$Field)
    if (-not $script:CurrentEnv) { return '' }
    $e=$script:Environments[$script:CurrentEnv]
    if (-not $e) { return '' }
    $v="$($e[$Field])"
    if ($Field -eq 'DefaultCdrFilter' -and [string]::IsNullOrWhiteSpace($v)) { $v="$($e['DefaultUpn'])" }
    return $v
}
Load-Environments
$script:CurrentEnv = if ($script:Environments.Count -gt 0) { @($script:Environments.Keys)[0] } else { $null }
$script:TenantId = if ($script:CurrentEnv) { $script:Environments[$script:CurrentEnv].TenantId } else { $null }
$script:ClientId = if ($script:CurrentEnv) { $script:Environments[$script:CurrentEnv].ClientId } else { $null }
$script:Graph='https://graph.microsoft.com/v1.0'
$script:Token=$null; $script:RbacConnected=$false; $script:LastUserId=$null; $script:CurrentUpn=$null; $script:LastAssignOk=$false
$script:catalog=@(); $script:allLocations=@(); $script:locations=@()
$script:report=[Collections.Generic.List[object]]::new()
$script:cdrLog=[Collections.Generic.List[object]]::new()
$script:LastCdrReport=$null; $script:rbacChk=@{}; $script:provChk=@{}
$script:cdrRows=[Collections.Generic.List[object]]::new()
$script:cdrSessionCsv=$null; $script:cdrPrevCount=0

$script:cdrState = [hashtable]::Synchronized(@{ Stop=$false; Running=$false; Queue=[System.Collections.Queue]::Synchronized([System.Collections.Queue]::new()); CycleCount=0 })
$script:cdrRs=$null; $script:cdrPs=$null; $script:cdrAsync=$null

$script:rbacGrant=@{ TenantDialPlan='Grant-CsTenantDialPlan';
CallingLineIdentity='Grant-CsCallingLineIdentity';
TeamsCallingPolicy='Grant-CsTeamsCallingPolicy';
TeamsCallParkPolicy='Grant-CsTeamsCallParkPolicy';
OnlineVoiceRoutingPolicy='Grant-CsOnlineVoiceRoutingPolicy';
TeamsEmergencyCallingPolicy='Grant-CsTeamsEmergencyCallingPolicy';
TeamsEmergencyCallRoutingPolicy='Grant-CsTeamsEmergencyCallRoutingPolicy';
TeamsMobilityPolicy='Grant-CsTeamsMobilityPolicy';
OnlineVoicemailPolicy='Grant-CsOnlineVoicemailPolicy';
TeamsSharedCallingRoutingPolicy='Grant-CsTeamsSharedCallingRoutingPolicy';
TeamsVoiceApplicationsPolicy='Grant-CsTeamsVoiceApplicationsPolicy';
TeamsIPPhonePolicy='Grant-CsTeamsIPPhonePolicy';
TeamsCallHoldPolicy='Grant-CsTeamsCallHoldPolicy' }
$script:rbacGet=@{ TenantDialPlan='Get-CsTenantDialPlan';
CallingLineIdentity='Get-CsCallingLineIdentity';
TeamsCallingPolicy='Get-CsTeamsCallingPolicy';
TeamsCallParkPolicy='Get-CsTeamsCallParkPolicy';
OnlineVoiceRoutingPolicy='Get-CsOnlineVoiceRoutingPolicy';
TeamsEmergencyCallingPolicy='Get-CsTeamsEmergencyCallingPolicy';
TeamsEmergencyCallRoutingPolicy='Get-CsTeamsEmergencyCallRoutingPolicy';
TeamsMobilityPolicy='Get-CsTeamsMobilityPolicy';
OnlineVoicemailPolicy='Get-CsOnlineVoicemailPolicy';
TeamsSharedCallingRoutingPolicy='Get-CsTeamsSharedCallingRoutingPolicy';
TeamsVoiceApplicationsPolicy='Get-CsTeamsVoiceApplicationsPolicy';
TeamsIPPhonePolicy='Get-CsTeamsIPPhonePolicy';
TeamsCallHoldPolicy='Get-CsTeamsCallHoldPolicy' }
$script:PolicyTypes=@('TenantDialPlan','CallingLineIdentity','TeamsCallingPolicy','TeamsCallParkPolicy','OnlineVoiceRoutingPolicy','TeamsEmergencyCallingPolicy','TeamsEmergencyCallRoutingPolicy','TeamsMobilityPolicy','OnlineVoicemailPolicy','TeamsSharedCallingRoutingPolicy','TeamsVoiceApplicationsPolicy','TeamsIPPhonePolicy','TeamsCallHoldPolicy')

# Greyed out in the UI and skipped on Provision: there is no API permission and
# no RBAC role for it here. Re-enabling is one line - remove it from this list.
$script:DisabledPolicyTypes=@('TeamsIPPhonePolicy')

# Never portable across tenants. See the Policy Migration tab's Verify step
# (search: "Tenant-local references cannot travel") for the actual list, keyed
# to $script:PolicyManifest's Key values - a different taxonomy from
# $script:PolicyTypes above, because the migration engine predates and is
# broader than the 13-type Provisioning manifest.

# Group assignment is not supported for these - a group-sourced result here means
# something else is going on, not a group grant.
$script:GroupAssignmentUnsupported=@('TeamsEmergencyCallRoutingPolicy','TeamsVoiceApplicationsPolicy','TeamsUpgradePolicy','TeamsAppPermissionPolicy','TeamsNetworkRoamingPolicy')
$script:ucMap=@{ TenantDialPlan=1; CallingLineIdentity=1; TeamsCallingPolicy=1; TeamsCallParkPolicy=1; OnlineVoiceRoutingPolicy=1; TeamsEmergencyCallingPolicy=1; TeamsEmergencyCallRoutingPolicy=1; TeamsMobilityPolicy=1; OnlineVoicemailPolicy=1; TeamsSharedCallingRoutingPolicy=1; TeamsVoiceApplicationsPolicy=1; TeamsCallHoldPolicy=1 }
$script:UsStates=@('AL','AK','AZ','AR','CA','CO','CT','DE','DC','FL','GA','HI','ID','IL','IN','IA','KS','KY','LA','ME','MD','MA','MI','MN','MS','MO','MT','NE','NV','NH','NJ','NM','NY','NC','ND','OH','OK','OR','PA','RI','SC','SD','TN','TX','UT','VT','VA','WA','WV','WI','WY','PR','GU','VI','AS','MP')
$script:DialToIso=[ordered]@{ '+1'='US'; '+44'='GB'; '+353'='IE'; '+33'='FR'; '+49'='DE'; '+34'='ES'; '+39'='IT'; '+31'='NL'; '+41'='CH'; '+61'='AU'; '+64'='NZ'; '+91'='IN'; '+65'='SG'; '+852'='HK'; '+81'='JP'; '+52'='MX'; '+55'='BR' }

$script:cdrRawRoot = Join-Path (Join-Path (Get-OutputRoot) 'CDR') 'RawJSON'


$clrBanner=[System.Drawing.Color]::FromArgb(16,74,140);
$clrBlue=[System.Drawing.Color]::FromArgb(0,120,215)
$clrGreen=[System.Drawing.Color]::FromArgb(16,124,16);
$clrAmber=[System.Drawing.Color]::FromArgb(202,80,16)
$clrPurple=[System.Drawing.Color]::FromArgb(92,60,140);
$clrGray=[System.Drawing.Color]::FromArgb(96,96,96)
$clrLight=[System.Drawing.Color]::FromArgb(245,246,248);
$clrRed=[System.Drawing.Color]::FromArgb(168,0,0)

function Style-Button { param($Btn,$Back,$Fore=[System.Drawing.Color]::White); $Btn.FlatStyle='Flat'; $Btn.BackColor=$Back; $Btn.ForeColor=$Fore; $Btn.FlatAppearance.BorderSize=0; $Btn.Font=New-Object System.Drawing.Font("Segoe UI",9,[System.Drawing.FontStyle]::Bold) }

$form=New-Object System.Windows.Forms.Form
$form.Text="TeamsVoiceTool v$script:AppVersion - Enterprise Voice Toolkit"
$form.StartPosition="CenterScreen"; $form.BackColor=$clrLight
$form.Font=New-Object System.Drawing.Font("Segoe UI",9);

# Size to a true 16:9 rectangle, clamped to the ACTUAL screen's working area
# (screen bounds minus taskbar) rather than a fixed pixel guess. A fixed
# 1300x890 looks fine on some displays and runs off the bottom of others -
# especially with Windows display scaling above 100%, where the effective
# working area is smaller than the nominal resolution suggests. Computing
# this against the real screen at launch is the only way to guarantee it
# fits regardless of the machine it runs on.
$workArea = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
$idealW = 1600; $idealH = 900   # 16:9
$marginPx = 60
$targetH = [Math]::Min($idealH, $workArea.Height - $marginPx)
$targetW = [Math]::Min([int]($targetH * 16 / 9), $workArea.Width - $marginPx)
$form.Size = New-Object System.Drawing.Size($targetW, $targetH)
$form.MinimumSize = New-Object System.Drawing.Size(1024, 680)

$banner=New-Object System.Windows.Forms.Panel; $banner.Dock="Top";
$banner.Height=46; $banner.BackColor=$clrBanner
$lblTitle=New-Object System.Windows.Forms.Label; $lblTitle.Text="   Teams Voice Provisioning  -  Enterprise Voice Toolkit";
$lblTitle.ForeColor=[System.Drawing.Color]::White; $lblTitle.Font=New-Object System.Drawing.Font("Segoe UI",13,[System.Drawing.FontStyle]::Bold);
$lblTitle.Dock="Fill"; $lblTitle.TextAlign="MiddleLeft";
$banner.Controls.Add($lblTitle)

$spnBar=New-Object System.Windows.Forms.Panel; $spnBar.Dock="Top";
$spnBar.Height=112; $spnBar.BackColor=[System.Drawing.Color]::White
$lblEnv=New-Object System.Windows.Forms.Label; $lblEnv.Location=New-Object System.Drawing.Point(14,12); $lblEnv.Size=New-Object System.Drawing.Size(96,20);
$lblEnv.Text="Environment"
$cmbEnv=New-Object System.Windows.Forms.ComboBox; $cmbEnv.Location=New-Object System.Drawing.Point(116,10); $cmbEnv.Size=New-Object System.Drawing.Size(160,22);
$cmbEnv.DropDownStyle="DropDownList"
foreach ($k in $script:Environments.Keys) { [void]$cmbEnv.Items.Add($k) };
$cmbEnv.SelectedItem=$script:CurrentEnv
$btnManageEnv=New-Object System.Windows.Forms.Button; $btnManageEnv.Location=New-Object System.Drawing.Point(282,9); $btnManageEnv.Size=New-Object System.Drawing.Size(96,24); $btnManageEnv.Text="Configuration"; Style-Button $btnManageEnv $clrPurple
$lblEnvInfo=New-Object System.Windows.Forms.Label; $lblEnvInfo.Location=New-Object System.Drawing.Point(386,12); $lblEnvInfo.Size=New-Object System.Drawing.Size(885,20); $lblEnvInfo.AutoEllipsis=$true;
$lblEnvInfo.ForeColor=$clrPurple; $lblEnvInfo.Font=New-Object System.Drawing.Font("Segoe UI",8,[System.Drawing.FontStyle]::Bold);
$lblEnvInfo.Text=""
$lblSecret=New-Object System.Windows.Forms.Label; $lblSecret.Location=New-Object System.Drawing.Point(14,46); $lblSecret.Size=New-Object System.Drawing.Size(96,20);
$lblSecret.Text="SPN Secret (API)"
$txtSecret=New-Object System.Windows.Forms.TextBox; $txtSecret.Location=New-Object System.Drawing.Point(116,44); $txtSecret.Size=New-Object System.Drawing.Size(210,22); $txtSecret.UseSystemPasswordChar=$true
$btnConnect=New-Object System.Windows.Forms.Button; $btnConnect.Location=New-Object System.Drawing.Point(334,42); $btnConnect.Size=New-Object System.Drawing.Size(96,26); $btnConnect.Text="Connect API"; Style-Button $btnConnect $clrBlue
# Client credentials has no refresh token - the secret IS the renewal
# mechanism. So auto-renew and discarding the secret are mutually exclusive,
# and the operator can opt out of that trade with this checkbox.
#
# ON (default) keeps the secret in memory so the token renews itself. Unchecking
# wipes the secret after the first mint, and an expired token has to be
# re-entered by hand.
$chkKeepSecret=New-Object System.Windows.Forms.CheckBox
$chkKeepSecret.Location=New-Object System.Drawing.Point(556,45); $chkKeepSecret.Size=New-Object System.Drawing.Size(210,22)
$chkKeepSecret.Text="Keep secret in memory (auto-renew)"
$chkKeepSecret.Checked=$true

$lblTokenState=New-Object System.Windows.Forms.Label;
$lblTokenState.Location=New-Object System.Drawing.Point(772,46);
$lblTokenState.Size=New-Object System.Drawing.Size(420,20); $lblTokenState.AutoEllipsis=$true; $lblTokenState.Text="API Token: not acquired  (primary - required)";
$lblTokenState.ForeColor=[System.Drawing.Color]::Firebrick
$lblThumb=New-Object System.Windows.Forms.Label; $lblThumb.Location=New-Object System.Drawing.Point(14,80); $lblThumb.Size=New-Object System.Drawing.Size(312,20);
$lblThumb.Text="RBAC reuses the SPN secret above (mints 2 tokens)";
$lblThumb.ForeColor=$clrGray
$btnConnectRbac=New-Object System.Windows.Forms.Button;
$btnConnectRbac.Location=New-Object System.Drawing.Point(334,76);
$btnConnectRbac.Size=New-Object System.Drawing.Size(96,26);
$btnConnectRbac.Text="Connect RBAC"; Style-Button $btnConnectRbac $clrPurple
$btnTestRbac=New-Object System.Windows.Forms.Button;
$btnTestRbac.Location=New-Object System.Drawing.Point(434,76);
$btnTestRbac.Size=New-Object System.Drawing.Size(74,26); $btnTestRbac.Text="Test RBAC"; Style-Button $btnTestRbac $clrGray
# RBAC sign-in mode. App-only covers essentially every Cs cmdlet from module
# 4.7.1+ - the usual blocker is RBAC, not capability: the service principal needs
# the Teams Administrator DIRECTORY ROLE, not just Graph API permissions. The
# giveaway is cmdlets returning EMPTY rather than throwing.
# User sign-in exists for the cases app-only cannot cover: Set-CsOnlineApplicationInstance
# (resource accounts) is excluded under app auth everywhere, and operators who
# must act under their own identity for audit.
$lblRbacAs=New-Object System.Windows.Forms.Label
$lblRbacAs.Location=New-Object System.Drawing.Point(12,80); $lblRbacAs.Size=New-Object System.Drawing.Size(58,20)
$lblRbacAs.Text="RBAC as"
$cboRbacMode=New-Object System.Windows.Forms.ComboBox
$cboRbacMode.DropDownStyle='DropDownList'
$cboRbacMode.Location=New-Object System.Drawing.Point(72,78); $cboRbacMode.Size=New-Object System.Drawing.Size(150,22)
[void]$cboRbacMode.Items.AddRange(@('SPN (app-only)','User (interactive)','User (device code)'))
$cboRbacMode.SelectedIndex=0
$lblRbacState=New-Object System.Windows.Forms.Label;
$lblRbacState.Location=New-Object System.Drawing.Point(674,80);
$lblRbacState.Size=New-Object System.Drawing.Size(380,20); $lblRbacState.AutoEllipsis=$true; $lblRbacState.Text="RBAC (Teams PS): not connected  (optional)"; $lblRbacState.ForeColor=$clrGray
# Two connections stay independent (API and RBAC expose different
# capabilities and can be connected/disconnected separately) - this button is
# a convenience that fires both, not a replacement for either.
$btnConnectAll=New-Object System.Windows.Forms.Button
$btnConnectAll.Location=New-Object System.Drawing.Point(438,42); $btnConnectAll.Size=New-Object System.Drawing.Size(110,26)
$btnConnectAll.Text="Connect All"; Style-Button $btnConnectAll $clrBanner
$toolTipConnectAll=New-Object System.Windows.Forms.ToolTip
$toolTipConnectAll.SetToolTip($btnConnectAll, "Runs Connect API then Connect RBAC with the current secret and RBAC mode above.")

$spnBar.Controls.AddRange(@($lblEnv,$cmbEnv,$btnManageEnv,$lblEnvInfo,$lblSecret,$txtSecret,$btnConnect,$chkKeepSecret,$lblTokenState,$lblRbacAs,$cboRbacMode,$btnConnectRbac,$btnTestRbac,$lblRbacState,$btnConnectAll))
$btnConnectAll.Add_Click({
    # Connect API clears $txtSecret right after acquiring a token, regardless
    # of whether "Keep secret in memory" is checked - that's correct for the
    # button on its own, but it means a naive PerformClick-then-PerformClick
    # here would leave RBAC's SPN branch with nothing to read: the secret is
    # gone from both the textbox and memory by the time it runs, and it fails
    # silently (a label change, no popup) rather than with anything you'd
    # notice. Capture the secret once up front and put it back for RBAC.
    $capturedSecret = $txtSecret.Text
    $btnConnect.PerformClick()
    if (-not [string]::IsNullOrWhiteSpace($capturedSecret) -and "$($cboRbacMode.SelectedItem)" -eq 'SPN (app-only)') {
        $txtSecret.Text = $capturedSecret
    }
    $capturedSecret = $null
    $btnConnectRbac.PerformClick()
    $txtSecret.Clear()
})


# The hint has to change with the mode - "reuses the SPN secret" is false the
# moment the operator picks a user sign-in.
$script:SetRbacHint={
    switch -Wildcard ([string]$cboRbacMode.SelectedItem) {
        'SPN*'    { $lblRbacState.Text="RBAC (Teams PS): not connected  -  reuses the SPN secret above (mints 2 tokens). Needs the Teams Administrator directory role."; $lblRbacState.ForeColor=$clrGray }
        '*device*'{ $lblRbacState.Text="RBAC (Teams PS): not connected  -  device code will print in the PowerShell console; enter it at microsoft.com/devicelogin."; $lblRbacState.ForeColor=$clrGray }
        default   { $lblRbacState.Text="RBAC (Teams PS): not connected  -  a browser tab will open. Open a guest window first if your default browser is SSO-pinned."; $lblRbacState.ForeColor=$clrGray }
    }
}

$chkKeepSecret.Add_CheckedChanged({
    if (-not $chkKeepSecret.Checked -and $script:TokenSecure) {
        Clear-AppSecret
        if (Get-Command Add-Status -ErrorAction SilentlyContinue) { Add-Status "Retained secret cleared. The current token still works until it expires." $clrAmber }
    }
})
$cboRbacMode.Add_SelectedIndexChanged({ & $script:SetRbacHint })
& $script:SetRbacHint


# --- SECRET RETENTION BANNER + IDLE EXPIRY -----------------------------------
# A cleared text box used to mean the secret was gone. With retention on it is
# not, so the UI has to say so plainly rather than leave the old implication
# standing.
$script:SecretIdleMinutes=30
$script:LastSecretUse=[datetime]::MinValue

# Idle expiry. Deliberately NOT tied to form deactivate: alt-tabbing to a
# browser or the console is normal during a session, and clearing on every
# focus loss would make retention useless in practice.
$script:SecretTimer=New-Object System.Windows.Forms.Timer
$script:SecretTimer.Interval=60000
$script:SecretTimer.Add_Tick({
    if (-not $script:TokenSecure) { return }
    if ($script:cdrState -and $script:cdrState.Running) { return }   # a live CDR run is activity
    if ($script:LastSecretUse -eq [datetime]::MinValue) { return }
    if (((Get-Date) - $script:LastSecretUse).TotalMinutes -ge $script:SecretIdleMinutes) {
        Clear-AppSecret
        $lblTokenState.Text="API Token: secret cleared (idle) - re-enter to renew"
        $lblTokenState.ForeColor=$clrAmber
        if (Get-Command Add-Status -ErrorAction SilentlyContinue) {
            Add-Status ("Secret cleared after {0} minutes idle." -f $script:SecretIdleMinutes) $clrAmber
        }
    }
})
$script:SecretTimer.Start()

# RBAC keep-alive. Client-credentials tokens carry no refresh token, and
# Connect-MicrosoftTeams has no refresh API (see Confirm-TeamsConnection's own
# note on this) - so "keeping the session alive" means silently redoing the
# whole SPN connect before the ~1h token expires, not refreshing anything in
# place. Scoped deliberately narrow:
#   - SPN mode only. Interactive/device-code sessions need a live user in the
#     loop; silently reconnecting one in the background would either pop a
#     browser window unannounced or just fail with nothing to replay non-
#     interactively. Those still go stale after ~45 min and need a manual
#     reconnect, same as before this feature existed.
#   - Only when the secret is retained (chkKeepSecret checked) - exactly the
#     same condition that already gates the Graph token's own auto-renew, so
#     the two "auto-renew" toggles mean the same thing to the operator.
# 40-minute interval: comfortably inside the ~60-minute token lifetime, and
# matches the 45-minute staleness window Confirm-TeamsConnection already uses
# elsewhere in this file.
$script:RbacKeepAliveTimer=New-Object System.Windows.Forms.Timer
$script:RbacKeepAliveTimer.Interval=40*60*1000
$script:RbacKeepAliveTimer.Add_Tick({
    if (-not $script:RbacConnected) { return }
    if ("$($script:AuthContext.TeamsAuthMode)" -ne 'AccessToken') { return }
    if (-not $chkKeepSecret.Checked) { return }
    $s=Get-PlainSecret
    if ([string]::IsNullOrWhiteSpace($s)) { return }
    [void](Invoke-RbacSpnConnect -Secret $s -Silent)
    $s=$null
})
$script:RbacKeepAliveTimer.Start()

# Shows when the API token next renews. Get-LiveToken renews lazily, on the
# first API call within 5 minutes of expiry, so the countdown runs to that point.
$script:AutoRenewTimer=New-Object System.Windows.Forms.Timer
$script:AutoRenewTimer.Interval=1000
$script:AutoRenewTimer.Add_Tick({
    if (-not $script:TokenSecure -or $script:TokenExpiry -eq [datetime]::MinValue) { return }
    $left=$script:TokenExpiry.AddMinutes(-5) - (Get-Date)
    if ($left.TotalSeconds -gt 0) { $when="renews in {0:mm\:ss}" -f $left } else { $when="renews on next API call" }
    $lblTokenState.Text="API Token: acquired ($($script:CurrentEnv))  auto-renew ON - $when"
    $lblTokenState.ForeColor=$clrGreen
})
$script:AutoRenewTimer.Start()

$form.Add_FormClosing({ Clear-AppSecret; if ($script:SecretTimer) { $script:SecretTimer.Stop() }; if ($script:RbacKeepAliveTimer) { $script:RbacKeepAliveTimer.Stop() }; if ($script:AutoRenewTimer) { $script:AutoRenewTimer.Stop() } })

# ===== Resource Accounts (Provisioning > Resource Accounts) =====
# Application IDs of the two Teams resource-account types, per Microsoft's AA/CQ setup docs.
$script:RaAppIds = @{ AutoAttendant='ce933385-9390-45d1-9512-c8d228074e07'; CallQueue='11cd3e2e-fccb-42ad-ad00-878b93575e07' }

function Ra-Say {
    param([string]$Text)
    if (-not $script:RA) { return }
    $script:RA.Log.AppendText(("[{0:HH:mm:ss}] {1}`r`n" -f (Get-Date),$Text)); $script:RA.Log.ScrollToCaret()
}

function Ra-Require {
    param([string[]]$Cmdlets)
    if (-not $script:RbacConnected) { Ra-Say 'Connect RBAC first - resource accounts are managed through the Teams PowerShell module.'; return $false }
    foreach ($c in $Cmdlets) { if (-not (Test-CmdletPresent -Name $c)) { Ra-Say "$c is not available in the loaded module."; return $false } }
    return $true
}

function Ra-TypeOf {
    param([string]$AppId)
    if ($AppId -eq $script:RaAppIds.AutoAttendant) { return 'Auto attendant' }
    if ($AppId -eq $script:RaAppIds.CallQueue) { return 'Call queue' }
    return 'Other'
}

function Ra-Selected {
    $g=$script:RA.Grid; if ($g.SelectedRows.Count -eq 0) { return $null }
    $upn="$($g.SelectedRows[0].Cells[1].Value)"
    return (@($script:RA.Items | Where-Object { $_.Upn -eq $upn }) | Select-Object -First 1)
}

function Ra-ApplyFilter {
    $ra=$script:RA; $q="$($ra.Search.Text)".Trim()
    $ra.Grid.Rows.Clear()
    foreach ($it in $ra.Items) {
        if ($q -and $it.Name.IndexOf($q,[StringComparison]::OrdinalIgnoreCase) -lt 0 -and $it.Upn.IndexOf($q,[StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        [void]$ra.Grid.Rows.Add($it.Name,$it.Upn,(Ra-TypeOf $it.AppId),$it.ObjectId)
    }
    $ra.Count.Text="$($ra.Grid.Rows.Count) shown of $($ra.Items.Count)"
}

function Ra-LoadTargets {
    $cb=$script:RA.Target; $cb.Items.Clear()
    if (-not $script:RbacConnected) { return }
    if (Test-CmdletPresent -Name 'Get-CsAutoAttendant') {
        try { foreach ($a in @(Get-CsAutoAttendant -ErrorAction Stop)) { [void]$cb.Items.Add([pscustomobject]@{ Label="AA: $($a.Name)"; Id="$($a.Identity)"; Type='AutoAttendant' }) } }
        catch { Ra-Say "Auto attendant list: $($_.Exception.Message)" }
    }
    if (Test-CmdletPresent -Name 'Get-CsCallQueue') {
        try { foreach ($q in @(Get-CsCallQueue -ErrorAction Stop)) { [void]$cb.Items.Add([pscustomobject]@{ Label="CQ: $($q.Name)"; Id="$($q.Identity)"; Type='CallQueue' }) } }
        catch { Ra-Say "Call queue list: $($_.Exception.Message)" }
    }
    if ($cb.Items.Count -gt 0) { $cb.SelectedIndex=0 }
}

function Ra-Refresh {
    if (-not (Ra-Require @('Get-CsOnlineApplicationInstance'))) { return }
    try { $rows=@(Get-CsOnlineApplicationInstance -ErrorAction Stop) }
    catch { Ra-Say "Refresh failed: $($_.Exception.Message)"; return }
    $script:RA.Items=@(foreach ($r in $rows) {
        [pscustomobject]@{
            Name     = "$(Get-PropTolerant $r @('DisplayName'))"
            Upn      = "$(Get-PropTolerant $r @('UserPrincipalName'))"
            ObjectId = "$(Get-PropTolerant $r @('ObjectId','ObjectID','Id'))"
            AppId    = "$(Get-PropTolerant $r @('ApplicationId','ApplicationID'))"
        }
    })
    Ra-ApplyFilter
    Ra-LoadTargets
    Ra-Say "Loaded $($script:RA.Items.Count) resource account(s)."
}

function Ra-LoadSelected {
    $ra=$script:RA; $it=Ra-Selected
    if (-not $it) { return }
    $ra.EditName.Text=$it.Name; $ra.EditUpn.Text=$it.Upn
    $ra.SelLabel.Text="$($it.Upn)  -  $(Ra-TypeOf $it.AppId)"
    $ra.PhoneNow.Text='Current number: (loading)'; $ra.AssocNow.Text='Associated: (loading)'
    if (-not $script:RbacConnected) { $ra.PhoneNow.Text=''; $ra.AssocNow.Text=''; return }
    try {
        $u=Get-CsOnlineUser -Identity $it.Upn -ErrorAction Stop
        $tel="$(Get-PropTolerant $u @('LineURI','OnlinePhoneNumber','TelephoneNumber'))" -replace '^tel:',''
        $ra.PhoneNow.Text=$(if ($tel) { "Current number: $tel" } else { 'Current number: (none)' })
    } catch { $ra.PhoneNow.Text="Current number: unavailable" }
    try {
        $as=Get-CsOnlineApplicationInstanceAssociation -Identity $it.ObjectId -ErrorAction Stop
        $cfg="$(Get-PropTolerant $as @('ConfigurationId'))"
        $ra.AssocNow.Text=$(if ($cfg) { "Associated: $(Ra-TypeOf $it.AppId) ($cfg)" } else { 'Associated: (none)' })
    } catch { $ra.AssocNow.Text='Associated: (none)' }
}

function Ra-Create {
    $ra=$script:RA
    $name="$($ra.NewName.Text)".Trim(); $upn="$($ra.NewUpn.Text)".Trim()
    if (-not $name -or -not $upn) { Ra-Say 'Enter a display name and a UPN.'; return }
    if ($upn -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { Ra-Say 'UPN must look like name@domain.com.'; return }
    $appId=$(if ("$($ra.NewType.SelectedItem)" -eq 'Call queue') { $script:RaAppIds.CallQueue } else { $script:RaAppIds.AutoAttendant })
    if (-not (Ra-Require @('New-CsOnlineApplicationInstance'))) { return }
    if (-not (Pm-Confirm "Create resource account $upn ($name)?`n`nBefore a number can be assigned it needs a Teams Phone Resource Account license and a usage location.")) { return }
    try {
        New-CsOnlineApplicationInstance -UserPrincipalName $upn -DisplayName $name -ApplicationId $appId -ErrorAction Stop | Out-Null
        Ra-Say "Created $upn."
        Write-ChangeLog -Source 'ResourceAccounts' -Action 'New-CsOnlineApplicationInstance' -Target $upn -Detail "$name $appId" -Result 'OK'
        Ra-Refresh
    } catch {
        Ra-Say "Create failed: $($_.Exception.Message)"
        Write-ChangeLog -Source 'ResourceAccounts' -Action 'New-CsOnlineApplicationInstance' -Target $upn -Detail $name -Result "FAIL: $($_.Exception.Message)"
    }
}

function Ra-Save {
    $ra=$script:RA; $it=Ra-Selected
    if (-not $it) { Ra-Say 'Select a resource account first.'; return }
    $newName="$($ra.EditName.Text)".Trim(); $newUpn="$($ra.EditUpn.Text)".Trim()
    $nameChanged=($newName -and $newName -ne $it.Name)
    $upnChanged=($newUpn -and $newUpn -ne $it.Upn)
    if (-not $nameChanged -and -not $upnChanged) { Ra-Say 'No changes to save.'; return }
    if ($nameChanged) {
        if (-not (Ra-Require @('Set-CsOnlineApplicationInstance'))) { return }
        try {
            Set-CsOnlineApplicationInstance -Identity $it.Upn -DisplayName $newName -ErrorAction Stop
            Ra-Say "Display name set to '$newName'."
            Write-ChangeLog -Source 'ResourceAccounts' -Action 'Set-CsOnlineApplicationInstance' -Target $it.Upn -Detail "DisplayName=$newName" -Result 'OK'
        } catch {
            Ra-Say "Display name change failed: $($_.Exception.Message)"
            Write-ChangeLog -Source 'ResourceAccounts' -Action 'Set-CsOnlineApplicationInstance' -Target $it.Upn -Detail "DisplayName=$newName" -Result "FAIL: $($_.Exception.Message)"
        }
    }
    if ($upnChanged) {
        if (-not (Pm-Confirm "Change the UPN of $($it.Upn) to $newUpn?`n`nThe account's sign-in name changes immediately.")) { return }
        try {
            Invoke-GraphRequest -Method PATCH -Uri "users/$($it.ObjectId)" -Body @{ userPrincipalName=$newUpn } | Out-Null
            Ra-Say "UPN changed to $newUpn."
            Write-ChangeLog -Source 'ResourceAccounts' -Action 'Graph PATCH users (UPN)' -Target $it.Upn -Detail "UPN=$newUpn" -Result 'OK'
        } catch {
            Ra-Say "UPN change failed: $($_.Exception.Message)"
            Write-ChangeLog -Source 'ResourceAccounts' -Action 'Graph PATCH users (UPN)' -Target $it.Upn -Detail "UPN=$newUpn" -Result "FAIL: $($_.Exception.Message)"
        }
    }
    Ra-Refresh
}

function Ra-Delete {
    $it=Ra-Selected
    if (-not $it) { Ra-Say 'Select a resource account first.'; return }
    if (-not (Pm-Confirm "Delete resource account $($it.Upn)?`n`nUnassign its phone number first. Deleting cannot be undone from this tool.")) { return }
    try {
        if (Test-CmdletPresent -Name 'Remove-CsOnlineApplicationInstance') { Remove-CsOnlineApplicationInstance -Identity $it.Upn -ErrorAction Stop }
        else { Invoke-GraphRequest -Method DELETE -Uri "users/$($it.ObjectId)" | Out-Null }
        Ra-Say "Deleted $($it.Upn)."
        Write-ChangeLog -Source 'ResourceAccounts' -Action 'Delete resource account' -Target $it.Upn -Detail $it.Name -Result 'OK'
        Ra-Refresh
    } catch {
        Ra-Say "Delete failed: $($_.Exception.Message)"
        Write-ChangeLog -Source 'ResourceAccounts' -Action 'Delete resource account' -Target $it.Upn -Detail $it.Name -Result "FAIL: $($_.Exception.Message)"
    }
}

function Ra-Associate {
    $ra=$script:RA; $it=Ra-Selected; $t=$ra.Target.SelectedItem
    if (-not $it) { Ra-Say 'Select a resource account first.'; return }
    if (-not $t) { Ra-Say 'Pick an auto attendant or call queue first.'; return }
    if (-not (Ra-Require @('New-CsOnlineApplicationInstanceAssociation'))) { return }
    try {
        New-CsOnlineApplicationInstanceAssociation -Identities @($it.ObjectId) -ConfigurationId $t.Id -ConfigurationType $t.Type -ErrorAction Stop | Out-Null
        Ra-Say "Associated $($it.Upn) with $($t.Label)."
        Write-ChangeLog -Source 'ResourceAccounts' -Action 'New-CsOnlineApplicationInstanceAssociation' -Target $it.Upn -Detail "$($t.Type) $($t.Id)" -Result 'OK'
        Ra-LoadSelected
    } catch {
        Ra-Say "Associate failed: $($_.Exception.Message)"
        Write-ChangeLog -Source 'ResourceAccounts' -Action 'New-CsOnlineApplicationInstanceAssociation' -Target $it.Upn -Detail "$($t.Type) $($t.Id)" -Result "FAIL: $($_.Exception.Message)"
    }
}

function Ra-PhoneParams {
    param([string]$Cmdlet)
    $pn=Resolve-CsParamName -Cmdlet $Cmdlet -Candidates @('PhoneNumber','TelephoneNumber')
    $pt=Resolve-CsParamName -Cmdlet $Cmdlet -Candidates @('PhoneNumberType','NumberType')
    if (-not $pn -or -not $pt) { return $null }
    return @{ Name=$pn; Type=$pt }
}

function Ra-AssignNumber {
    param([bool]$Assign)
    $ra=$script:RA; $it=Ra-Selected
    if (-not $it) { Ra-Say 'Select a resource account first.'; return }
    $num=ToE164 ($ra.Number.Text.Trim())
    if ($num -notmatch '^\+\d{6,15}$') { Ra-Say 'Enter the number in E.164 format, e.g. +14255551234.'; return }
    $type="$($ra.NumType.SelectedItem)"
    $cmd=$(if ($Assign) { 'Set-CsPhoneNumberAssignment' } else { 'Remove-CsPhoneNumberAssignment' })
    if (-not (Ra-Require @($cmd))) { return }
    $pp=Ra-PhoneParams -Cmdlet $cmd
    if (-not $pp) { Ra-Say "Could not resolve the number parameters on $cmd."; return }
    if (-not $Assign -and -not (Pm-Confirm "Unassign $num ($type) from $($it.Upn)?")) { return }
    $p=@{ Identity=$it.Upn; ErrorAction='Stop' }; $p[$pp.Name]=$num; $p[$pp.Type]=$type
    $verb=$(if ($Assign) { 'Assigned' } else { 'Unassigned' })
    try {
        & $cmd @p | Out-Null
        Ra-Say "$verb $num ($type) $(if ($Assign) { 'to' } else { 'from' }) $($it.Upn)."
        Write-ChangeLog -Source 'ResourceAccounts' -Action $cmd -Target $it.Upn -Detail "$num $type" -Result 'OK'
        Ra-LoadSelected
    } catch {
        Ra-Say "$cmd failed: $($_.Exception.Message)"
        Write-ChangeLog -Source 'ResourceAccounts' -Action $cmd -Target $it.Upn -Detail "$num $type" -Result "FAIL: $($_.Exception.Message)"
    }
}

function New-ResourceAccountsPanel {
    param([System.Drawing.Color]$BackColor)
    $script:RA=@{ Items=@() }
    $ra=$script:RA
    $root=New-Object System.Windows.Forms.Panel; $root.Dock='Fill'; $root.BackColor=$BackColor

    # Grid first so Top, Right and Bottom dock around it.
    $ra.Grid=New-Object System.Windows.Forms.DataGridView
    $ra.Grid.Dock='Fill'; $ra.Grid.ReadOnly=$true; $ra.Grid.AllowUserToAddRows=$false; $ra.Grid.AllowUserToDeleteRows=$false
    $ra.Grid.SelectionMode='FullRowSelect'; $ra.Grid.MultiSelect=$false; $ra.Grid.RowHeadersVisible=$false
    $ra.Grid.AutoSizeColumnsMode='Fill'; $ra.Grid.BackgroundColor=[System.Drawing.Color]::White
    foreach ($c in @(@('Name','Display name'),@('Upn','UPN'),@('Type','Type'),@('ObjectId','Object ID'))) {
        $col=New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $col.Name=$c[0]; $col.HeaderText=$c[1]; [void]$ra.Grid.Columns.Add($col)
    }
    $ra.Grid.Add_SelectionChanged({ Ra-LoadSelected })

    # Right: action groups in a scrollable column.
    $right=New-Object System.Windows.Forms.Panel; $right.Dock='Right'; $right.Width=380; $right.AutoScroll=$true; $right.BackColor=$BackColor

    $gCreate=New-Object System.Windows.Forms.GroupBox; $gCreate.Text='Create resource account'; $gCreate.Location=New-Object System.Drawing.Point(8,8); $gCreate.Size=New-Object System.Drawing.Size(360,200)
    $lbl=New-Object System.Windows.Forms.Label; $lbl.Text='Display name'; $lbl.Location=New-Object System.Drawing.Point(12,24); $lbl.AutoSize=$true; $gCreate.Controls.Add($lbl)
    $ra.NewName=New-Object System.Windows.Forms.TextBox; $ra.NewName.Location=New-Object System.Drawing.Point(12,42); $ra.NewName.Width=330; $gCreate.Controls.Add($ra.NewName)
    $lbl=New-Object System.Windows.Forms.Label; $lbl.Text='UPN (name@domain.com)'; $lbl.Location=New-Object System.Drawing.Point(12,70); $lbl.AutoSize=$true; $gCreate.Controls.Add($lbl)
    $ra.NewUpn=New-Object System.Windows.Forms.TextBox; $ra.NewUpn.Location=New-Object System.Drawing.Point(12,88); $ra.NewUpn.Width=330; $gCreate.Controls.Add($ra.NewUpn)
    $lbl=New-Object System.Windows.Forms.Label; $lbl.Text='Type'; $lbl.Location=New-Object System.Drawing.Point(12,116); $lbl.AutoSize=$true; $gCreate.Controls.Add($lbl)
    $ra.NewType=New-Object System.Windows.Forms.ComboBox; $ra.NewType.DropDownStyle='DropDownList'; $ra.NewType.Location=New-Object System.Drawing.Point(12,134); $ra.NewType.Width=160
    [void]$ra.NewType.Items.Add('Auto attendant'); [void]$ra.NewType.Items.Add('Call queue'); $ra.NewType.SelectedIndex=0; $gCreate.Controls.Add($ra.NewType)
    $ra.Create=New-Object System.Windows.Forms.Button; $ra.Create.Text='Create'; $ra.Create.Location=New-Object System.Drawing.Point(190,132); $ra.Create.Size=New-Object System.Drawing.Size(152,28); Style-Button $ra.Create $clrGreen
    $ra.Create.Add_Click({ Ra-Create }); $gCreate.Controls.Add($ra.Create)
    $right.Controls.Add($gCreate)

    $gSel=New-Object System.Windows.Forms.GroupBox; $gSel.Text='Selected account'; $gSel.Location=New-Object System.Drawing.Point(8,216); $gSel.Size=New-Object System.Drawing.Size(360,226)
    $ra.SelLabel=New-Object System.Windows.Forms.Label; $ra.SelLabel.Text='Select an account in the list.'; $ra.SelLabel.Location=New-Object System.Drawing.Point(12,22); $ra.SelLabel.Size=New-Object System.Drawing.Size(336,18); $ra.SelLabel.AutoEllipsis=$true; $gSel.Controls.Add($ra.SelLabel)
    $lbl=New-Object System.Windows.Forms.Label; $lbl.Text='Display name'; $lbl.Location=New-Object System.Drawing.Point(12,44); $lbl.AutoSize=$true; $gSel.Controls.Add($lbl)
    $ra.EditName=New-Object System.Windows.Forms.TextBox; $ra.EditName.Location=New-Object System.Drawing.Point(12,62); $ra.EditName.Width=330; $gSel.Controls.Add($ra.EditName)
    $lbl=New-Object System.Windows.Forms.Label; $lbl.Text='UPN'; $lbl.Location=New-Object System.Drawing.Point(12,90); $lbl.AutoSize=$true; $gSel.Controls.Add($lbl)
    $ra.EditUpn=New-Object System.Windows.Forms.TextBox; $ra.EditUpn.Location=New-Object System.Drawing.Point(12,108); $ra.EditUpn.Width=330; $gSel.Controls.Add($ra.EditUpn)
    $ra.Save=New-Object System.Windows.Forms.Button; $ra.Save.Text='Save changes'; $ra.Save.Location=New-Object System.Drawing.Point(12,138); $ra.Save.Size=New-Object System.Drawing.Size(160,28); Style-Button $ra.Save $clrBlue
    $ra.Save.Add_Click({ Ra-Save }); $gSel.Controls.Add($ra.Save)
    $ra.Delete=New-Object System.Windows.Forms.Button; $ra.Delete.Text='Delete account'; $ra.Delete.Location=New-Object System.Drawing.Point(182,138); $ra.Delete.Size=New-Object System.Drawing.Size(160,28); Style-Button $ra.Delete $clrRed
    $ra.Delete.Add_Click({ Ra-Delete }); $gSel.Controls.Add($ra.Delete)
    $ra.PhoneNow=New-Object System.Windows.Forms.Label; $ra.PhoneNow.Location=New-Object System.Drawing.Point(12,176); $ra.PhoneNow.Size=New-Object System.Drawing.Size(336,18); $ra.PhoneNow.AutoEllipsis=$true; $gSel.Controls.Add($ra.PhoneNow)
    $ra.AssocNow=New-Object System.Windows.Forms.Label; $ra.AssocNow.Location=New-Object System.Drawing.Point(12,198); $ra.AssocNow.Size=New-Object System.Drawing.Size(336,18); $ra.AssocNow.AutoEllipsis=$true; $gSel.Controls.Add($ra.AssocNow)
    $right.Controls.Add($gSel)

    $gAssoc=New-Object System.Windows.Forms.GroupBox; $gAssoc.Text='Associate with auto attendant or call queue'; $gAssoc.Location=New-Object System.Drawing.Point(8,450); $gAssoc.Size=New-Object System.Drawing.Size(360,108)
    $ra.Target=New-Object System.Windows.Forms.ComboBox; $ra.Target.DropDownStyle='DropDownList'; $ra.Target.DisplayMember='Label'; $ra.Target.Location=New-Object System.Drawing.Point(12,24); $ra.Target.Width=330; $gAssoc.Controls.Add($ra.Target)
    $ra.Assoc=New-Object System.Windows.Forms.Button; $ra.Assoc.Text='Associate'; $ra.Assoc.Location=New-Object System.Drawing.Point(12,60); $ra.Assoc.Size=New-Object System.Drawing.Size(160,28); Style-Button $ra.Assoc $clrBlue
    $ra.Assoc.Add_Click({ Ra-Associate }); $gAssoc.Controls.Add($ra.Assoc)
    $right.Controls.Add($gAssoc)

    $gNum=New-Object System.Windows.Forms.GroupBox; $gNum.Text='Phone number'; $gNum.Location=New-Object System.Drawing.Point(8,566); $gNum.Size=New-Object System.Drawing.Size(360,166)
    $lbl=New-Object System.Windows.Forms.Label; $lbl.Text='Number (E.164)'; $lbl.Location=New-Object System.Drawing.Point(12,24); $lbl.AutoSize=$true; $gNum.Controls.Add($lbl)
    $ra.Number=New-Object System.Windows.Forms.TextBox; $ra.Number.Location=New-Object System.Drawing.Point(12,42); $ra.Number.Width=200; $gNum.Controls.Add($ra.Number)
    $lbl=New-Object System.Windows.Forms.Label; $lbl.Text='Number type'; $lbl.Location=New-Object System.Drawing.Point(12,72); $lbl.AutoSize=$true; $gNum.Controls.Add($lbl)
    $ra.NumType=New-Object System.Windows.Forms.ComboBox; $ra.NumType.DropDownStyle='DropDownList'; $ra.NumType.Location=New-Object System.Drawing.Point(12,90); $ra.NumType.Width=160
    [void]$ra.NumType.Items.Add('CallingPlan'); [void]$ra.NumType.Items.Add('DirectRouting'); [void]$ra.NumType.Items.Add('OperatorConnect'); $ra.NumType.SelectedIndex=0; $gNum.Controls.Add($ra.NumType)
    $ra.AssignNum=New-Object System.Windows.Forms.Button; $ra.AssignNum.Text='Assign number'; $ra.AssignNum.Location=New-Object System.Drawing.Point(12,126); $ra.AssignNum.Size=New-Object System.Drawing.Size(160,28); Style-Button $ra.AssignNum $clrGreen
    $ra.AssignNum.Add_Click({ Ra-AssignNumber -Assign $true }); $gNum.Controls.Add($ra.AssignNum)
    $ra.UnassignNum=New-Object System.Windows.Forms.Button; $ra.UnassignNum.Text='Unassign number'; $ra.UnassignNum.Location=New-Object System.Drawing.Point(182,126); $ra.UnassignNum.Size=New-Object System.Drawing.Size(160,28); Style-Button $ra.UnassignNum $clrRed
    $ra.UnassignNum.Add_Click({ Ra-AssignNumber -Assign $false }); $gNum.Controls.Add($ra.UnassignNum)
    $right.Controls.Add($gNum)

    $ra.Log=New-Object System.Windows.Forms.TextBox; $ra.Log.Multiline=$true; $ra.Log.ReadOnly=$true; $ra.Log.ScrollBars='Vertical'
    $ra.Log.Dock='Bottom'; $ra.Log.Height=120; $ra.Log.Font=New-Object System.Drawing.Font('Consolas',9)

    $top=New-Object System.Windows.Forms.Panel; $top.Dock='Top'; $top.Height=44; $top.BackColor=$BackColor
    $lbl=New-Object System.Windows.Forms.Label; $lbl.Text='Search:'; $lbl.Location=New-Object System.Drawing.Point(10,13); $lbl.AutoSize=$true; $top.Controls.Add($lbl)
    $ra.Search=New-Object System.Windows.Forms.TextBox; $ra.Search.Location=New-Object System.Drawing.Point(70,10); $ra.Search.Width=260; $top.Controls.Add($ra.Search)
    $ra.Refresh=New-Object System.Windows.Forms.Button; $ra.Refresh.Text='Refresh list'; $ra.Refresh.Location=New-Object System.Drawing.Point(340,8); $ra.Refresh.Size=New-Object System.Drawing.Size(120,28); Style-Button $ra.Refresh $clrBlue
    $ra.Refresh.Add_Click({ Ra-Refresh }); $top.Controls.Add($ra.Refresh)
    $ra.Count=New-Object System.Windows.Forms.Label; $ra.Count.Location=New-Object System.Drawing.Point(472,13); $ra.Count.AutoSize=$true; $top.Controls.Add($ra.Count)
    $ra.Search.Add_TextChanged({ Ra-ApplyFilter })

    [void]$root.Controls.Add($ra.Grid)
    [void]$root.Controls.Add($right)
    [void]$root.Controls.Add($ra.Log)
    [void]$root.Controls.Add($top)
    return $root
}

$tabs=New-Object System.Windows.Forms.TabControl; $tabs.Dock="Fill";
$tabs.Padding=New-Object System.Drawing.Point(12,4)
$tabProv=New-Object System.Windows.Forms.TabPage; $tabProv.Text="  Provisioning  ";
$tabProv.BackColor=$clrLight
$tabCdr=New-Object System.Windows.Forms.TabPage; $tabCdr.Text="  CDR Report  ";
$tabCdr.BackColor=$clrLight
$tabCat=New-Object System.Windows.Forms.TabPage; $tabCat.Text="  Catalogs  ";
$tabCat.BackColor=$clrLight
$tabMig=New-PolicyMigrationTabPage -BackColor $clrLight `
    -ColorBlue $clrBlue -ColorPurple $clrPurple -ColorGreen $clrGreen `
    -ColorGray $clrGray -ColorAmber $clrAmber -ColorRed $clrRed
$tabLis=New-LisTabPage -Text "  LIS / Civic Manager  " -BackColor $clrLight `
    -ColorBlue $clrBlue -ColorPurple $clrPurple -ColorGreen $clrGreen `
    -ColorGray $clrGray -ColorAmber $clrAmber -ColorRed $clrRed
$tabSbc=New-SbcTabPage -Text "  SBC / Direct Routing  " -BackColor $clrLight `
    -ColorBlue $clrBlue -ColorPurple $clrPurple -ColorGreen $clrGreen `
    -ColorGray $clrGray -ColorAmber $clrAmber -ColorRed $clrRed
$tabGrp=New-GroupsTabPage -Text "  Groups and Sources  " -BackColor $clrLight `
    -ColorBlue $clrBlue -ColorPurple $clrPurple -ColorGreen $clrGreen `
    -ColorGray $clrGray -ColorAmber $clrAmber -ColorRed $clrRed
$tabBulk=New-BulkImportTabPage -Text "  Bulk Import  " -BackColor $clrLight `
    -ColorBlue $clrBlue -ColorPurple $clrPurple -ColorGreen $clrGreen `
    -ColorGray $clrGray -ColorAmber $clrAmber -ColorRed $clrRed
$tabDiag=New-DiagnosticsTabPage -Text "  JSON Analyzer  "
$tabDiag.BackColor=$clrLight
$tabPol=New-PolicyManagerTabPage -Text "  Policy Manager  " -BackColor $clrLight `
    -ColorBlue $clrBlue -ColorPurple $clrPurple -ColorGreen $clrGreen `
    -ColorGray $clrGray -ColorAmber $clrAmber -ColorRed $clrRed
# Documented tab order: Provisioning (with the Phone Lines panel), CDR Reports, Catalogs,
# Policy Manager, Policy Migration, LIS / Civic Manager, SBC / Direct Routing, Groups and Sources,
# Bulk Import, JSON Analyzer, Configuration.
$tabs.Controls.AddRange(@($tabProv,$tabCdr,$tabCat,$tabPol,$tabMig,$tabLis,$tabSbc,$tabGrp,$tabBulk,$tabDiag))
$tabs.Add_SelectedIndexChanged({ if ($tabs.SelectedTab -eq $tabProv) { Pl-RefreshLocations; Pl-RefreshPolicyChoices } })

# ===== Provisioning tab =====
$lblUser=New-Object System.Windows.Forms.Label; $lblUser.Location=New-Object System.Drawing.Point(46,16); $lblUser.Size=New-Object System.Drawing.Size(100,20);
$lblUser.Text="User / RA UPN"
$txtUser=New-Object System.Windows.Forms.TextBox; $txtUser.Location=New-Object System.Drawing.Point(150,14); $txtUser.Size=New-Object System.Drawing.Size(180,22);
$txtUser.Text=""
$btnRead=New-Object System.Windows.Forms.Button; $btnRead.Location=New-Object System.Drawing.Point(338,12); $btnRead.Size=New-Object System.Drawing.Size(96,26);
$btnRead.Text="Read Settings"; Style-Button $btnRead $clrBlue
$lblTargetType=New-Object System.Windows.Forms.Label;
$lblTargetType.Location=New-Object System.Drawing.Point(46,40);
$lblTargetType.Size=New-Object System.Drawing.Size(100,20);
$lblTargetType.Text="Target Type"
$cmbTargetType=New-Object System.Windows.Forms.ComboBox;
$cmbTargetType.Location=New-Object System.Drawing.Point(150,40);
$cmbTargetType.Size=New-Object System.Drawing.Size(160,22);
$cmbTargetType.DropDownStyle="DropDownList"
[void]$cmbTargetType.Items.Add("Auto-detect");
[void]$cmbTargetType.Items.Add("User"); [void]$cmbTargetType.Items.Add("Resource Account"); $cmbTargetType.SelectedIndex=0
$lblTargetDetected=New-Object System.Windows.Forms.Label;
$lblTargetDetected.Location=New-Object System.Drawing.Point(316,42);
$lblTargetDetected.Size=New-Object System.Drawing.Size(118,20);
$lblTargetDetected.Text=""; $lblTargetDetected.ForeColor=$clrPurple;
$lblTargetDetected.Font=New-Object System.Drawing.Font("Segoe UI",8,[System.Drawing.FontStyle]::Bold)
$lblVoice=New-Object System.Windows.Forms.Label; $lblVoice.Location=New-Object System.Drawing.Point(46,64); $lblVoice.Size=New-Object System.Drawing.Size(100,20);
$lblVoice.Text="Voice Type"
$cmbVoice=New-Object System.Windows.Forms.ComboBox; $cmbVoice.Location=New-Object System.Drawing.Point(150,64); $cmbVoice.Size=New-Object System.Drawing.Size(160,22);
$cmbVoice.DropDownStyle="DropDownList"
[void]$cmbVoice.Items.Add("directRouting");
[void]$cmbVoice.Items.Add("callingPlan");
[void]$cmbVoice.Items.Add("operatorConnect"); $cmbVoice.SelectedIndex=0
$chkNumberOn=New-Object System.Windows.Forms.CheckBox;
$chkNumberOn.Location=New-Object System.Drawing.Point(20,89);
$chkNumberOn.Size=New-Object System.Drawing.Size(22,20); $chkNumberOn.Checked=$true
$lblNumber=New-Object System.Windows.Forms.Label; $lblNumber.Location=New-Object System.Drawing.Point(46,88); $lblNumber.Size=New-Object System.Drawing.Size(100,20); $lblNumber.Text="Phone Number"
$txtNumber=New-Object System.Windows.Forms.TextBox; $txtNumber.Location=New-Object System.Drawing.Point(150,88); $txtNumber.Size=New-Object System.Drawing.Size(160,22)
$lblNumCountry=New-Object System.Windows.Forms.Label;
$lblNumCountry.Location=New-Object System.Drawing.Point(316,90);
$lblNumCountry.Size=New-Object System.Drawing.Size(40,20); $lblNumCountry.Text="";
$lblNumCountry.ForeColor=$clrBlue; $lblNumCountry.Font=New-Object System.Drawing.Font("Segoe UI",8,[System.Drawing.FontStyle]::Bold)
$btnInspect=New-Object System.Windows.Forms.Button; $btnInspect.Location=New-Object System.Drawing.Point(360,86); $btnInspect.Size=New-Object System.Drawing.Size(74,26); $btnInspect.Text="Inspect"; Style-Button $btnInspect $clrGray
$chkLocationOn=New-Object System.Windows.Forms.CheckBox;
$chkLocationOn.Location=New-Object System.Drawing.Point(20,113);
$chkLocationOn.Size=New-Object System.Drawing.Size(22,20);
$chkLocationOn.Checked=$true
$lblLocation=New-Object System.Windows.Forms.Label; $lblLocation.Location=New-Object System.Drawing.Point(46,112); $lblLocation.Size=New-Object System.Drawing.Size(100,20); $lblLocation.Text="Location"
$cmbLocation=New-Object System.Windows.Forms.ComboBox;
$cmbLocation.Location=New-Object System.Drawing.Point(150,112);
$cmbLocation.Size=New-Object System.Drawing.Size(284,22);
$cmbLocation.DropDownStyle="DropDownList"
$lblLocationId=New-Object System.Windows.Forms.Label;
$lblLocationId.Location=New-Object System.Drawing.Point(46,136);
$lblLocationId.Size=New-Object System.Drawing.Size(100,20);
$lblLocationId.Text="Location ID"
$txtLocation=New-Object System.Windows.Forms.TextBox;
$txtLocation.Location=New-Object System.Drawing.Point(150,136);
$txtLocation.Size=New-Object System.Drawing.Size(284,22);
$txtLocation.ReadOnly=$true;
$txtLocation.BackColor=[System.Drawing.Color]::WhiteSmoke
$lblAddressCap=New-Object System.Windows.Forms.Label;
$lblAddressCap.Location=New-Object System.Drawing.Point(46,160);
$lblAddressCap.Size=New-Object System.Drawing.Size(100,20);
$lblAddressCap.Text="Address"
$lblAddress=New-Object System.Windows.Forms.Label; $lblAddress.Location=New-Object System.Drawing.Point(150,160); $lblAddress.Size=New-Object System.Drawing.Size(284,30); $lblAddress.ForeColor=[System.Drawing.Color]::DimGray
$lblProvCol=New-Object System.Windows.Forms.Label; $lblProvCol.Location=New-Object System.Drawing.Point(16,196); $lblProvCol.Size=New-Object System.Drawing.Size(30,20); $lblProvCol.Text="On"; $lblProvCol.ForeColor=$clrGreen;
$lblProvCol.Font=New-Object System.Drawing.Font("Segoe UI",8,[System.Drawing.FontStyle]::Bold)
$lblRbacCol=New-Object System.Windows.Forms.Label; $lblRbacCol.Location=New-Object System.Drawing.Point(414,196); $lblRbacCol.Size=New-Object System.Drawing.Size(44,20); $lblRbacCol.Text="RBAC";
$lblRbacCol.ForeColor=$clrPurple; $lblRbacCol.Font=New-Object System.Drawing.Font("Segoe UI",8,[System.Drawing.FontStyle]::Bold)
# ===== Provisioning layout =====
# Split + dock, the same shape as the LIS tab. The controls keep their absolute
# coordinates - they are just inside a panel now instead of directly on the tab.
#
# What this fixes: at 1300x890 the policy column runs to y=646 and the buttons to
# y=560. On a shorter screen, or at any display scaling above 100%, the bottom of
# both columns used to be simply unreachable - clipped, with no scrollbar. AutoScroll
# on the left panel and Dock=Fill on the status pane make the tab usable at the
# 1060x790 minimum instead of merely opening at it.
$provSplit=New-Object System.Windows.Forms.SplitContainer
# Same reason as the LIS tab's split: give it a real Size before setting
# SplitterDistance/MinSize, or the validation runs against the tiny
# un-parented default instead of the eventual Dock=Fill size and throws.
$provSplit.Size = New-Object System.Drawing.Size(1280,860)
$provSplit.Dock='Fill'; $provSplit.Orientation='Vertical'
$provSplit.SplitterDistance=496; $provSplit.Panel1MinSize=430; $provSplit.Panel2MinSize=430
# FixedPanel=Panel1: the input column has a fixed natural width, so widening the
# window should give the extra pixels to the status pane, not stretch the form.
$provSplit.FixedPanel='Panel1'

$provLeft=New-Object System.Windows.Forms.Panel
$provLeft.Dock='Fill'; $provLeft.AutoScroll=$true; $provLeft.BackColor=$clrLight
$provSplit.Panel1.Controls.Add($provLeft)

$provRight=New-Object System.Windows.Forms.Panel
$provRight.Dock='Fill'; $provRight.BackColor=$clrLight
$provSplit.Panel2.Controls.Add($provRight)

# Actions strip pinned to the bottom of the right pane. The status box sits above it, and the
# Phone Lines panel fills the remaining space and scrolls.
$provActions=New-Object System.Windows.Forms.Panel
$provActions.Dock='Bottom'; $provActions.Height=178; $provActions.BackColor=$clrLight

$provLeft.Controls.Add($lblProvCol); $provLeft.Controls.Add($lblRbacCol)

function New-PolicyDropdown {
    param([string]$Label,[int]$Top,[string]$Type)
    $prov=New-Object System.Windows.Forms.CheckBox; $prov.Location=New-Object System.Drawing.Point(20,($Top+1)); $prov.Size=New-Object System.Drawing.Size(22,20); $prov.Checked=$true
    $lbl=New-Object System.Windows.Forms.Label; $lbl.Location=New-Object System.Drawing.Point(46,$Top); $lbl.Size=New-Object System.Drawing.Size(100,20); $lbl.Text=$Label
    $cmb=New-Object System.Windows.Forms.ComboBox; $cmb.Location=New-Object System.Drawing.Point(150,$Top); $cmb.Size=New-Object System.Drawing.Size(284,22); $cmb.DropDownStyle="DropDownList"
    $chk=New-Object System.Windows.Forms.CheckBox; $chk.Location=New-Object System.Drawing.Point(446,($Top+1)); $chk.Size=New-Object System.Drawing.Size(28,20)
    $provLeft.Controls.Add($prov); $provLeft.Controls.Add($lbl); $provLeft.Controls.Add($cmb); $provLeft.Controls.Add($chk)
    if ($script:DisabledPolicyTypes -contains $Type) {
        # Greyed rather than hidden: an operator looking for the row should find
        # it and see that it is off on purpose, not wonder where it went.
        $prov.Checked=$false; $prov.Enabled=$false; $chk.Enabled=$false; $cmb.Enabled=$false
        $lbl.ForeColor=[System.Drawing.SystemColors]::GrayText
    }
    $script:provChk[$Type]=$prov; $script:rbacChk[$Type]=$chk
    return $cmb
}
$cmbDialPlan=New-PolicyDropdown "Dial Plan"  216 'TenantDialPlan'
$cmbCallerId=New-PolicyDropdown "Caller ID"  244 'CallingLineIdentity'
$cmbCallingPolicy=New-PolicyDropdown "Calling Policy" 272 'TeamsCallingPolicy'
$cmbCallPark=New-PolicyDropdown "Call Park" 300 'TeamsCallParkPolicy'
$cmbVoiceRouting=New-PolicyDropdown "Voice Routing" 328 'OnlineVoiceRoutingPolicy'
$cmbEmergencyCalling=New-PolicyDropdown "Emergency Calling" 356 'TeamsEmergencyCallingPolicy'
$cmbEmergencyRouting=New-PolicyDropdown "Emergency Routing" 384 'TeamsEmergencyCallRoutingPolicy'
$cmbMobility=New-PolicyDropdown "Mobility" 412 'TeamsMobilityPolicy'
$cmbVoicemail=New-PolicyDropdown "Voicemail" 440 'OnlineVoicemailPolicy'
$cmbSharedCalling=New-PolicyDropdown "Shared Calling" 468 'TeamsSharedCallingRoutingPolicy'
$cmbVoiceApps=New-PolicyDropdown "Voice Apps" 496 'TeamsVoiceApplicationsPolicy'
$cmbIpPhone=New-PolicyDropdown "IP Phone" 524 'TeamsIPPhonePolicy'
$cmbCallHold=New-PolicyDropdown "Call Hold" 552 'TeamsCallHoldPolicy'
$btnAllOn=New-Object System.Windows.Forms.Button; $btnAllOn.Location=New-Object System.Drawing.Point(150,582); $btnAllOn.Size=New-Object System.Drawing.Size(70,24);
$btnAllOn.Text="All On"; Style-Button $btnAllOn $clrGray
$btnAllOff=New-Object System.Windows.Forms.Button; $btnAllOff.Location=New-Object System.Drawing.Point(226,582); $btnAllOff.Size=New-Object System.Drawing.Size(70,24); $btnAllOff.Text="All Off"; Style-Button $btnAllOff $clrGray
$btnAllOn.Add_Click({ $chkNumberOn.Checked=$true; if ($chkLocationOn.Enabled) { $chkLocationOn.Checked=$true }; foreach ($c in $script:provChk.Values) { $c.Checked=$true } })
$btnAllOff.Add_Click({ $chkNumberOn.Checked=$false; if ($chkLocationOn.Enabled) { $chkLocationOn.Checked=$false }; foreach ($c in $script:provChk.Values) { $c.Checked=$false } })
$txtStatus=New-Object System.Windows.Forms.RichTextBox;
$txtStatus.Dock='Bottom'; $txtStatus.Height=150; $txtStatus.ReadOnly=$true;
$txtStatus.BackColor=[System.Drawing.Color]::White
$txtStatus.Font=New-Object System.Drawing.Font("Consolas",9)
$chkFallback=New-Object System.Windows.Forms.CheckBox;
$chkFallback.Location=New-Object System.Drawing.Point(6,8);
$chkFallback.Size=New-Object System.Drawing.Size(500,22); $chkFallback.Text="On a policy role/permission error, try the other method"; $chkFallback.Checked=$true
$lblMethodNote=New-Object System.Windows.Forms.Label;
$lblMethodNote.Location=New-Object System.Drawing.Point(6,34);
$lblMethodNote.Size=New-Object System.Drawing.Size(760,32);
# Anchored right so the note re-wraps with the pane instead of being cut off.
$lblMethodNote.Anchor=[System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right;
$lblMethodNote.ForeColor=$clrGray; $lblMethodNote.Text="Target Type auto-detects User vs Resource Account.  Inspect shows a number's type/usage + emergency location.  Calling Plan locks Location ON and country-filters it."
$btnValidate=New-Object System.Windows.Forms.Button;
$btnValidate.Location=New-Object System.Drawing.Point(6,74);
$btnValidate.Size=New-Object System.Drawing.Size(130,42);
$btnValidate.Text="Validate"; Style-Button $btnValidate $clrBlue
$btnProvision=New-Object System.Windows.Forms.Button;
$btnProvision.Location=New-Object System.Drawing.Point(146,74);
$btnProvision.Size=New-Object System.Drawing.Size(130,42);
$btnProvision.Text="Provision"; Style-Button $btnProvision $clrGreen
$btnRollback=New-Object System.Windows.Forms.Button;
$btnRollback.Location=New-Object System.Drawing.Point(286,74);
$btnRollback.Size=New-Object System.Drawing.Size(130,42);
$btnRollback.Text="Rollback"; Style-Button $btnRollback $clrAmber
$btnRemoveNum=New-Object System.Windows.Forms.Button;
$btnRemoveNum.Location=New-Object System.Drawing.Point(6,124);
$btnRemoveNum.Size=New-Object System.Drawing.Size(130,42);
$btnRemoveNum.Text="Remove Number"; Style-Button $btnRemoveNum $clrAmber
$btnDeprovision=New-Object System.Windows.Forms.Button;
$btnDeprovision.Location=New-Object System.Drawing.Point(146,124);
$btnDeprovision.Size=New-Object System.Drawing.Size(180,42);
$btnDeprovision.Text="Deprovision User"; Style-Button $btnDeprovision $clrRed
$provLeft.Controls.AddRange(@($lblUser,$txtUser,$btnRead,$lblTargetType,$cmbTargetType,$lblTargetDetected,$lblVoice,$cmbVoice,$chkNumberOn,$lblNumber,$txtNumber,$lblNumCountry,$btnInspect,$chkLocationOn,$lblLocation,$cmbLocation,$lblLocationId,$txtLocation,$lblAddressCap,$lblAddress,$btnAllOn,$btnAllOff))
$provActions.Controls.AddRange(@($chkFallback,$lblMethodNote,$btnValidate,$btnProvision,$btnRollback,$btnRemoveNum,$btnDeprovision))
$phoneLines=New-PhoneLinesPanel -LogBox $txtStatus -BackColor $clrLight `
    -ColorBlue $clrBlue -ColorPurple $clrPurple -ColorGreen $clrGreen `
    -ColorGray $clrGray -ColorAmber $clrAmber -ColorRed $clrRed
$phoneLines.Dock='Fill'
$provRight.Controls.Add($phoneLines)
$provRight.Controls.Add($txtStatus)
$provRight.Controls.Add($provActions)
$provInner=New-Object System.Windows.Forms.TabControl; $provInner.Dock='Fill'
$pgUser=New-Object System.Windows.Forms.TabPage; $pgUser.Text='  User Provisioning  '; $pgUser.BackColor=$clrLight
$pgUser.Controls.Add($provSplit)
$pgRa=New-Object System.Windows.Forms.TabPage; $pgRa.Text='  Resource Accounts  '; $pgRa.BackColor=$clrLight
$pgRa.Controls.Add((New-ResourceAccountsPanel -BackColor $clrLight))
$provInner.Controls.AddRange(@($pgUser,$pgRa))
$tabProv.Controls.Add($provInner)

# ===== CDR tab =====
$lblCdrHead=New-Object System.Windows.Forms.Label; $lblCdrHead.Location=New-Object System.Drawing.Point(20,16); $lblCdrHead.Size=New-Object System.Drawing.Size(1200,20); $lblCdrHead.Text="Call Detail Records";
$lblCdrHead.Font=New-Object System.Drawing.Font("Segoe UI",9,[System.Drawing.FontStyle]::Bold)
$lblCdrUser=New-Object System.Windows.Forms.Label; $lblCdrUser.Location=New-Object System.Drawing.Point(20,48); $lblCdrUser.Size=New-Object System.Drawing.Size(120,20); $lblCdrUser.Text="User (UPN or #)"
$txtCdrUser=New-Object System.Windows.Forms.TextBox; $txtCdrUser.Location=New-Object System.Drawing.Point(150,45); $txtCdrUser.Size=New-Object System.Drawing.Size(260,22); $txtCdrUser.Text=""
$lblFrom=New-Object System.Windows.Forms.Label; $lblFrom.Location=New-Object System.Drawing.Point(20,80); $lblFrom.Size=New-Object System.Drawing.Size(120,20); $lblFrom.Text="From date (Pull)"
$dtFrom=New-Object System.Windows.Forms.DateTimePicker; $dtFrom.Location=New-Object System.Drawing.Point(150,77); $dtFrom.Size=New-Object System.Drawing.Size(180,22); $dtFrom.Format="Short"; $dtFrom.Value=(Get-Date).AddDays(-7)
$lblTo=New-Object System.Windows.Forms.Label; $lblTo.Location=New-Object System.Drawing.Point(20,112); $lblTo.Size=New-Object System.Drawing.Size(120,20); $lblTo.Text="To date  (Pull)"
$dtTo=New-Object System.Windows.Forms.DateTimePicker; $dtTo.Location=New-Object System.Drawing.Point(150,109); $dtTo.Size=New-Object System.Drawing.Size(180,22); $dtTo.Format="Short"; $dtTo.Value=(Get-Date)
$chkDR=New-Object System.Windows.Forms.CheckBox; $chkDR.Location=New-Object System.Drawing.Point(150,140); $chkDR.Size=New-Object System.Drawing.Size(150,22); $chkDR.Checked=$true
$chkDR.Text="Direct Routing";
$chkPstn=New-Object System.Windows.Forms.CheckBox; $chkPstn.Location=New-Object System.Drawing.Point(310,140); $chkPstn.Size=New-Object System.Drawing.Size(160,22);
$chkPstn.Text="Calling Plan (PSTN)"; $chkPstn.Checked=$true
$chkFullCallRecords=New-Object System.Windows.Forms.CheckBox;
$chkFullCallRecords.Location=New-Object System.Drawing.Point(486,140);
$chkFullCallRecords.Size=New-Object System.Drawing.Size(220,22);
$chkFullCallRecords.Text="Full callRecords detail";
$chkFullCallRecords.Checked=$true
$btnPullCdr=New-Object System.Windows.Forms.Button; $btnPullCdr.Location=New-Object System.Drawing.Point(150,172); $btnPullCdr.Size=New-Object System.Drawing.Size(120,32); $btnPullCdr.Text="Pull CDR"; Style-Button $btnPullCdr $clrBlue
$btnOpenCdr=New-Object System.Windows.Forms.Button; $btnOpenCdr.Location=New-Object System.Drawing.Point(280,172); $btnOpenCdr.Size=New-Object System.Drawing.Size(110,32); $btnOpenCdr.Text="Open Report"; Style-Button $btnOpenCdr $clrGray
$btnSaveLog=New-Object System.Windows.Forms.Button; $btnSaveLog.Location=New-Object System.Drawing.Point(400,172); $btnSaveLog.Size=New-Object System.Drawing.Size(110,32); $btnSaveLog.Text="Save Log"; Style-Button $btnSaveLog $clrGray
$lblEvery=New-Object System.Windows.Forms.Label; $lblEvery.Location=New-Object System.Drawing.Point(20,218); $lblEvery.Size=New-Object System.Drawing.Size(120,20); $lblEvery.Text="Auto delay (s)"
$numEvery=New-Object System.Windows.Forms.NumericUpDown;
$numEvery.Location=New-Object System.Drawing.Point(150,215);
$numEvery.Size=New-Object System.Drawing.Size(80,22); $numEvery.Minimum=0;
$numEvery.Maximum=3600; $numEvery.Value=0; $numEvery.Increment=5
$btnAutoStart=New-Object System.Windows.Forms.Button;
$btnAutoStart.Location=New-Object System.Drawing.Point(240,213);
$btnAutoStart.Size=New-Object System.Drawing.Size(120,28); $btnAutoStart.Text="Start Auto (live)"; Style-Button $btnAutoStart $clrGreen
$btnAutoStop=New-Object System.Windows.Forms.Button;
$btnAutoStop.Location=New-Object System.Drawing.Point(368,213);
$btnAutoStop.Size=New-Object System.Drawing.Size(120,28); $btnAutoStop.Text="Stop";
Style-Button $btnAutoStop $clrAmber; $btnAutoStop.Enabled=$false
$lblAutoState=New-Object System.Windows.Forms.Label;
$lblAutoState.Location=New-Object System.Drawing.Point(500,218);
$lblAutoState.Size=New-Object System.Drawing.Size(500,20);
$lblAutoState.Text="Engine: idle"; $lblAutoState.ForeColor=$clrGray
$lblCdrNote=New-Object System.Windows.Forms.Label; $lblCdrNote.Location=New-Object System.Drawing.Point(20,248); $lblCdrNote.Size=New-Object System.Drawing.Size(1200,20); $lblCdrNote.ForeColor=[System.Drawing.Color]::DimGray;
$lblCdrNote.Text="Auto delay 0 = back-to-back.  Live baseline starts TODAY.  Records re-fetched on version bump for up to 60 min (Microsoft enriches in phases)."
$txtCdr=New-Object System.Windows.Forms.RichTextBox; $txtCdr.Location=New-Object System.Drawing.Point(20,278); $txtCdr.Size=New-Object System.Drawing.Size(1240,250);
$txtCdr.ReadOnly=$true; $txtCdr.Font=New-Object System.Drawing.Font("Consolas",9)
$tabCdr.Controls.AddRange(@($lblCdrHead,$lblCdrUser,$txtCdrUser,$btnPullCdr,$btnOpenCdr,$btnSaveLog,$lblFrom,$dtFrom,$lblTo,$dtTo,$chkDR,$chkPstn,$chkFullCallRecords,$lblEvery,$numEvery,$btnAutoStart,$btnAutoStop,$lblAutoState,$lblCdrNote,$txtCdr))

# ===== Catalogs tab =====
$lblCatHead=New-Object System.Windows.Forms.Label; $lblCatHead.Location=New-Object System.Drawing.Point(20,16); $lblCatHead.Size=New-Object System.Drawing.Size(1240,20); $lblCatHead.Font=New-Object System.Drawing.Font("Segoe UI",9,[System.Drawing.FontStyle]::Bold); $lblCatHead.Text="Per-tenant catalog management.  Files named _<KEY>.csv load automatically with the selected Environment."
$lblCatFiles=New-Object System.Windows.Forms.Label; $lblCatFiles.Location=New-Object System.Drawing.Point(20,40); $lblCatFiles.Size=New-Object System.Drawing.Size(1240,20); $lblCatFiles.ForeColor=$clrGray; $lblCatFiles.Text=""
$grpLoc=New-Object System.Windows.Forms.GroupBox; $grpLoc.Location=New-Object System.Drawing.Point(20,66); $grpLoc.Size=New-Object System.Drawing.Size(1240,64);
$grpLoc.Text="Emergency Locations"
$btnDlLoc=New-Object System.Windows.Forms.Button; $btnDlLoc.Location=New-Object System.Drawing.Point(16,24); $btnDlLoc.Size=New-Object System.Drawing.Size(210,28);
$btnDlLoc.Text="Download from Tenant"; Style-Button $btnDlLoc $clrBlue
$btnSaveLoc=New-Object System.Windows.Forms.Button; $btnSaveLoc.Location=New-Object System.Drawing.Point(234,24); $btnSaveLoc.Size=New-Object System.Drawing.Size(150,28); $btnSaveLoc.Text="Save to CSV"; Style-Button $btnSaveLoc $clrGreen
$btnReloadLoc=New-Object System.Windows.Forms.Button;
$btnReloadLoc.Location=New-Object System.Drawing.Point(392,24);
$btnReloadLoc.Size=New-Object System.Drawing.Size(150,28);
$btnReloadLoc.Text="Reload from CSV"; Style-Button $btnReloadLoc $clrGray
$lblLocSrc=New-Object System.Windows.Forms.Label; $lblLocSrc.Location=New-Object System.Drawing.Point(556,30); $lblLocSrc.Size=New-Object System.Drawing.Size(670,20); $lblLocSrc.ForeColor=$clrGray; $lblLocSrc.Text="RBAC = full civic addresses.  REST-only = locations already in use (from number assignments)."
$grpLoc.Controls.AddRange(@($btnDlLoc,$btnSaveLoc,$btnReloadLoc,$lblLocSrc))
$grpPol=New-Object System.Windows.Forms.GroupBox; $grpPol.Location=New-Object System.Drawing.Point(20,138); $grpPol.Size=New-Object System.Drawing.Size(1240,64);
$grpPol.Text="Voice Policies"
$btnDlPol=New-Object System.Windows.Forms.Button; $btnDlPol.Location=New-Object System.Drawing.Point(16,24); $btnDlPol.Size=New-Object System.Drawing.Size(210,28);
$btnDlPol.Text="Download (RBAC)"; Style-Button $btnDlPol $clrPurple
$btnRefreshPol=New-Object System.Windows.Forms.Button;
$btnRefreshPol.Location=New-Object System.Drawing.Point(234,24);
$btnRefreshPol.Size=New-Object System.Drawing.Size(210,28);
$btnRefreshPol.Text="Refresh IDs (REST)"; Style-Button $btnRefreshPol $clrBlue
$btnSavePol=New-Object System.Windows.Forms.Button; $btnSavePol.Location=New-Object System.Drawing.Point(452,24); $btnSavePol.Size=New-Object System.Drawing.Size(150,28); $btnSavePol.Text="Save to CSV"; Style-Button $btnSavePol $clrGreen
$btnReloadPol=New-Object System.Windows.Forms.Button;
$btnReloadPol.Location=New-Object System.Drawing.Point(610,24);
$btnReloadPol.Size=New-Object System.Drawing.Size(150,28);
$btnReloadPol.Text="Reload from CSV"; Style-Button $btnReloadPol $clrGray
$lblPolSrc=New-Object System.Windows.Forms.Label; $lblPolSrc.Location=New-Object System.Drawing.Point(774,30); $lblPolSrc.Size=New-Object System.Drawing.Size(452,20); $lblPolSrc.ForeColor=$clrGray; $lblPolSrc.Text="REST cannot enumerate policies; Refresh IDs resolves known names.  Download needs RBAC."
$grpPol.Controls.AddRange(@($btnDlPol,$btnRefreshPol,$btnSavePol,$btnReloadPol,$lblPolSrc))

# ---- NEW: DR Inventory group (RBAC cmdlets, dormant until roles) ----
$grpDr=New-Object System.Windows.Forms.GroupBox; $grpDr.Location=New-Object System.Drawing.Point(20,210); $grpDr.Size=New-Object System.Drawing.Size(1240,96);
$grpDr.Text="Direct Routing Number Inventory  (MicrosoftTeams cmdlets - needs RBAC; no Graph v1.0 equivalent)"
$lblDrNums=New-Object System.Windows.Forms.Label; $lblDrNums.Location=New-Object System.Drawing.Point(16,26); $lblDrNums.Size=New-Object System.Drawing.Size(150,20);
$lblDrNums.Text="Number(s) / range"
$txtDrNums=New-Object System.Windows.Forms.TextBox; $txtDrNums.Location=New-Object System.Drawing.Point(170,24); $txtDrNums.Size=New-Object System.Drawing.Size(360,22); $txtDrNums.Text="+16094745936"
$lblDrRange=New-Object System.Windows.Forms.Label; $lblDrRange.Location=New-Object System.Drawing.Point(540,26); $lblDrRange.Size=New-Object System.Drawing.Size(680,20); $lblDrRange.ForeColor=$clrGray;
$lblDrRange.Text="Single, comma-list (+1..,+1..), or a range as START..END (e.g. +16094745900..+16094745910)."
$btnDrAdd=New-Object System.Windows.Forms.Button; $btnDrAdd.Location=New-Object System.Drawing.Point(16,58); $btnDrAdd.Size=New-Object System.Drawing.Size(160,28);
$btnDrAdd.Text="Add to Inventory"; Style-Button $btnDrAdd $clrPurple
$btnDrStatus=New-Object System.Windows.Forms.Button;
$btnDrStatus.Location=New-Object System.Drawing.Point(184,58);
$btnDrStatus.Size=New-Object System.Drawing.Size(150,28); $btnDrStatus.Text="Check Last Order"; Style-Button $btnDrStatus $clrBlue
$btnDrRelease=New-Object System.Windows.Forms.Button;
$btnDrRelease.Location=New-Object System.Drawing.Point(342,58);
$btnDrRelease.Size=New-Object System.Drawing.Size(150,28);
$btnDrRelease.Text="Release Number"; Style-Button $btnDrRelease $clrAmber
$lblDrOrder=New-Object System.Windows.Forms.Label; $lblDrOrder.Location=New-Object System.Drawing.Point(504,64); $lblDrOrder.Size=New-Object System.Drawing.Size(720,20); $lblDrOrder.ForeColor=$clrPurple;
$lblDrOrder.Font=New-Object System.Drawing.Font("Segoe UI",8,[System.Drawing.FontStyle]::Bold); $lblDrOrder.Text="Last OrderId:  (none)"
$grpDr.Controls.AddRange(@($lblDrNums,$txtDrNums,$lblDrRange,$btnDrAdd,$btnDrStatus,$btnDrRelease,$lblDrOrder))
$txtCat=New-Object System.Windows.Forms.RichTextBox; $txtCat.Location=New-Object System.Drawing.Point(20,314); $txtCat.Size=New-Object System.Drawing.Size(1240,224); $txtCat.Font=New-Object System.Drawing.Font("Consolas",9)
$txtCat.ReadOnly=$true; $tabCat.Controls.AddRange(@($lblCatHead,$lblCatFiles,$grpLoc,$grpPol,$grpDr,$txtCat))

# ===== Helpers =====
function Add-Status {
param([string]$Text,[System.Drawing.Color]$Color=[System.Drawing.Color]::Black);
$txtStatus.SelectionStart=$txtStatus.TextLength; $txtStatus.SelectionLength=0;
$txtStatus.SelectionColor=$Color; $txtStatus.AppendText($Text+"`r`n");
$txtStatus.SelectionColor=$txtStatus.ForeColor; $txtStatus.ScrollToCaret() }
function Add-Cdr {
param([string]$Text,[System.Drawing.Color]$Color=[System.Drawing.Color]::Black);
$txtCdr.SelectionStart=$txtCdr.TextLength; $txtCdr.SelectionLength=0;
$txtCdr.SelectionColor=$Color; $txtCdr.AppendText($Text+"`r`n");
$txtCdr.SelectionColor=$txtCdr.ForeColor; $txtCdr.ScrollToCaret() }
function Add-Cat {
param([string]$Text,[System.Drawing.Color]$Color=[System.Drawing.Color]::Black);
$txtCat.SelectionStart=$txtCat.TextLength; $txtCat.SelectionLength=0;
$txtCat.SelectionColor=$Color; $txtCat.AppendText($Text+"`r`n");
$txtCat.SelectionColor=$txtCat.ForeColor; $txtCat.ScrollToCaret() }
function CdrColor { param([string]$n); switch ($n) { 'green' {$clrGreen} 'gray' {$clrGray} 'red' {[System.Drawing.Color]::Firebrick} 'amber' {$clrAmber} 'navy' {[System.Drawing.Color]::Navy} 'purple' {$clrPurple} default {[System.Drawing.Color]::Black} } }
function Add-Result { param([int]$Num,[string]$Name,[string]$Result); switch ($Result) { 'PASS' {$c=$clrGreen} 'FAIL' {$c=[System.Drawing.Color]::Firebrick} 'N/A' {$c=[System.Drawing.Color]::SlateGray} default {$c=[System.Drawing.Color]::DimGray} }; Add-Status ("{0,-5} Test {1,2}  {2}" -f $Result,$Num,$Name) $c }
function Add-ReportRow {
param([int]$TestNumber,[string]$Operation,[string]$Phase,[string]$MethodUsed,[string]$Command,[string]$HttpStatus,[string]$Result,[string]$Notes='')
$script:report.Add([pscustomobject]@{ Timestamp=(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); Environment=$script:CurrentEnv; TestNumber=$TestNumber; Operation=$Operation; Phase=$Phase; MethodUsed=$MethodUsed; TargetUser=$txtUser.Text.Trim(); TargetUserId=$script:LastUserId; VoiceType="$($cmbVoice.SelectedItem)"; Number=$txtNumber.Text.Trim(); HttpStatus=$HttpStatus; Result=$Result; ApiCommand=$Command; Notes=$Notes }) | Out-Null }
function Export-Report { param([string]$Kind); if ($script:report.Count -eq 0) { return $null }; $key=$script:Environments[$script:CurrentEnv].Key; $path=Get-OutputPath -Area Changes -File ("TeamsVoice_ChangeReport_{0}_{1}_{2}.csv" -f $Kind,$key,(Get-Date -Format 'yyyyMMdd_HHmmss')); $script:report | Sort-Object { [int]$_.TestNumber } | Export-Csv $path -NoTypeInformation -Encoding UTF8; return $path }

function ToE164 { param([string]$Number); $n=($Number -replace '[^\d+]',''); if ($n -notmatch '^\+') { $n='+'+$n }; return $n }
function Get-CountryFromNumber { param([string]$Number); if ([string]::IsNullOrWhiteSpace($Number)) { return '' }; $n=ToE164 $Number; $best=''; $bl=0; foreach ($k in $script:DialToIso.Keys) { if ($n.StartsWith($k) -and $k.Length -gt $bl) { $best=$script:DialToIso[$k]; $bl=$k.Length } }; return $best }
function Get-LocationCountry {
    param($Row); if ($null -eq $Row) { return '' }
    $v=''; foreach ($p in 'IsoCountryCode','isoCountryCode','CountryCode','Country','country') { if (($Row.PSObject.Properties.Name -contains $p) -and -not [string]::IsNullOrWhiteSpace($Row.$p)) { $v="$($Row.$p)"; break } }
    if (-not [string]::IsNullOrWhiteSpace($v)) { $v=$v.Trim().ToUpper(); switch -Regex ($v) { '^(US|USA|UNITED STATES.*)$' { return 'US' } '^(GB|UK|GREAT BRITAIN|UNITED KINGDOM.*|ENG.*|SCT.*|WLS.*|NIR.*)$' { return 'GB' } default { if ($v.Length -ge 2) { return $v.Substring(0,2) } else { return $v } } } }
    $addr="$($Row.Address)"; if ([string]::IsNullOrWhiteSpace($addr)) { return '' }
    $parts=@($addr -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }); if ($parts.Count -lt 2) { return '' }
    $region=($parts[$parts.Count-2]).ToUpper(); if ($script:UsStates -contains $region) { return 'US' }
    switch -Regex ($region) { '^(ENG|SCT|WLS|NIR|GB|UK)$' { return 'GB' } default { return '' } }
}

function Populate-Locations {
    param([string]$IsoFilter=''); $cmbLocation.Items.Clear();
    $subset=@($script:allLocations); $note=''
    if (-not [string]::IsNullOrWhiteSpace($IsoFilter)) {
        $subset=@($script:allLocations | Where-Object { (Get-LocationCountry $_) -eq $IsoFilter }); if ($subset.Count -eq 0) { $subset=@($script:allLocations); $note="no $IsoFilter locations - showing all" } }
    $script:locations=$subset
    foreach ($loc in $subset) { $c=Get-LocationCountry $loc; if ($c) { [void]$cmbLocation.Items.Add("$($loc.LocationName)  [$c]") } else { [void]$cmbLocation.Items.Add("$($loc.LocationName)") } }
    if ($cmbLocation.Items.Count -gt 0) { $cmbLocation.SelectedIndex=0 } else { $txtLocation.Text=''; $lblAddress.Text='' }
    return $note
}
$cmbLocation.Add_SelectedIndexChanged({ $i=$cmbLocation.SelectedIndex; if ($i -ge 0 -and $i -lt $script:locations.Count) { $m=$script:locations[$i]; $txtLocation.Text=$m.LocationId; $lblAddress.Text=$m.Address } else { $txtLocation.Text=''; $lblAddress.Text='' } })
function Resolve-LocationById { param([string]$LocationId); if ([string]::IsNullOrWhiteSpace($LocationId)) { return $null }; $script:allLocations | Where-Object { $_.LocationId -eq $LocationId } | Select-Object -First 1 }
function Load-PolicyType { param($Combo,$Catalog,$Type); $Combo.Items.Clear(); $items=$Catalog | Where-Object { $_.PolicyType -eq $Type -and $_.Enabled -eq "True" } | Select-Object -ExpandProperty PolicyName; foreach ($item in $items) { [void]$Combo.Items.Add($item) }; if ($Combo.Items.Count -gt 0) { $Combo.SelectedIndex=0 } }
function Get-EnvCatalogPath { param([string]$Base);
    $key=$script:Environments[$script:CurrentEnv].Key; $cat=Get-AppFolder Catalogs; $envPath=Join-Path $cat ("{0}_{1}.csv" -f $Base,$key); if (Test-Path $envPath) { return $envPath }; return (Join-Path $cat ("{0}.csv" -f $Base)) }
function Get-EnvCatalogWritePath { param([string]$Base);
    $key=$script:Environments[$script:CurrentEnv].Key; Join-Path (Get-AppFolder Catalogs) ("{0}_{1}.csv" -f $Base,$key) }
function Load-LocationCatalog {
    $script:allLocations=@(); $lf=Get-EnvCatalogPath "TeamsVoice_LocationCatalog_Engineer"
    if (Test-Path $lf) { $script:allLocations=@(Import-Csv $lf | Where-Object { $_.Enabled -eq "True" -or [string]::IsNullOrWhiteSpace($_.Enabled) }); Add-Status ("Locations: $([IO.Path]::GetFileName($lf))  ($($script:allLocations.Count) rows)") $clrGray }
    else { Add-Status "Location catalog not found for this environment." $clrAmber }
    if ("$($cmbVoice.SelectedItem)" -eq 'callingPlan') { Update-ForVoiceType $true }
    else { [void](Populate-Locations '') }
}
function Load-PolicyCatalog {
    $pf=Get-EnvCatalogPath "TeamsVoice_PolicyCatalog_Engineer"
    if (Test-Path $pf) {
        $script:catalog=Import-Csv $pf
        Load-PolicyType $cmbDialPlan $script:catalog "TenantDialPlan"; Load-PolicyType $cmbCallerId $script:catalog "CallingLineIdentity"; Load-PolicyType $cmbCallingPolicy $script:catalog "TeamsCallingPolicy"; Load-PolicyType $cmbCallPark $script:catalog "TeamsCallParkPolicy"; Load-PolicyType $cmbVoiceRouting $script:catalog "OnlineVoiceRoutingPolicy"; Load-PolicyType $cmbEmergencyCalling $script:catalog "TeamsEmergencyCallingPolicy"; Load-PolicyType $cmbEmergencyRouting $script:catalog "TeamsEmergencyCallRoutingPolicy"; Load-PolicyType $cmbMobility $script:catalog "TeamsMobilityPolicy"; Load-PolicyType $cmbVoicemail $script:catalog "OnlineVoicemailPolicy"
        Add-Status ("Policies : $([IO.Path]::GetFileName($pf))  ($(@($script:catalog).Count) rows)") $clrGray
    } else { $script:catalog=@(); foreach ($t in $script:PolicyTypes) { $c=Get-ComboByType $t; if ($c) { $c.Items.Clear() } }; Add-Status "Policy catalog not found for this environment." $clrAmber }
}

# ===== REST (UI-thread) =====
function Get-SpnToken {
    param([string]$Secret,[string]$Scope='https://graph.microsoft.com/.default');
    $body=@{ grant_type='client_credentials'; scope=$Scope; client_id=$script:ClientId; client_secret=$Secret }; (Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$($script:TenantId)/oauth2/v2.0/token" -Body $body -ErrorAction Stop).access_token }

function Invoke-RbacSpnConnect {
<#
.SYNOPSIS
    App-only RBAC connect: two fresh tokens (Graph + Teams resource), then
    Connect-MicrosoftTeams -AccessTokens.
.DESCRIPTION
    This is the exact logic the "Connect RBAC" button runs for SPN mode,
    pulled out so the keep-alive timer can call the same tested path instead
    of a second copy that could drift from it. Client-credentials tokens carry
    no refresh token - Connect-MicrosoftTeams has no refresh API either (see
    Confirm-TeamsConnection's own note on this) - so "keeping alive" an SPN
    session means redoing this whole sequence before the ~1h token expires,
    not refreshing anything in place.
.PARAMETER Silent
    Skips cursor/button-state UI changes - used by the keep-alive timer, which
    runs on a Tick, not a click.
.OUTPUTS
    $true on success, $false on failure. Updates $lblRbacState either way.
#>
    param([Parameter(Mandatory)][string]$Secret,[switch]$Silent)
    if (-not $Silent) { $form.Cursor=[System.Windows.Forms.Cursors]::WaitCursor; $btnConnectRbac.Enabled=$false }
    try {
        $mr=Ensure-ConfiguredTeamsModule; if ($mr -and -not $mr.Success) { throw $mr.Message }
        if (-not (Test-CmdletPresent -Name 'Connect-MicrosoftTeams')) {
            throw "Connect-MicrosoftTeams is not available. Install the MicrosoftTeams module, or pick its folder in the Configuration window."
        }
        $graphTok=Get-SpnToken -Secret $Secret -Scope 'https://graph.microsoft.com/.default'
        $teamsTok=Get-SpnToken -Secret $Secret -Scope '48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default'
        Connect-MicrosoftTeams -AccessTokens @("$graphTok","$teamsTok") -ErrorAction Stop | Out-Null
        $script:TeamsConnectedAt=Get-Date; $script:TeamsTenantId=$script:TenantId; $script:TeamsAccount="app:$($script:ClientId)"
        $script:AuthContext.TenantId=$script:TenantId; $script:AuthContext.ClientId=$script:ClientId
        $script:AuthContext.AccessTokens=@("$graphTok","$teamsTok"); $script:AuthContext.TeamsAuthMode="AccessToken"
        $script:RbacConnected=$true
        $lblRbacState.Text="RBAC (Teams PS): connected ($($script:CurrentEnv))$(if($Silent){' - auto-renewed'})"; $lblRbacState.ForeColor=$clrGreen
        if ($Silent -and (Get-Command Add-Status -ErrorAction SilentlyContinue)) {
            Add-Status ("RBAC session auto-renewed at {0:HH:mm:ss}." -f (Get-Date)) $clrGray
        }
        return $true
    }
    catch {
        $script:RbacConnected=$false
        $lblRbacState.Text="RBAC: FAILED - $($_.Exception.Message)"; $lblRbacState.ForeColor=[System.Drawing.Color]::Firebrick
        if ($Silent -and (Get-Command Add-Status -ErrorAction SilentlyContinue)) {
            Add-Status "RBAC auto-renew failed - reconnect manually: $($_.Exception.Message)" ([System.Drawing.Color]::Firebrick)
        }
        return $false
    }
    finally {
        $graphTok=$null; $teamsTok=$null
        if (-not $Silent) { $btnConnectRbac.Enabled=$true; $form.Cursor=[System.Windows.Forms.Cursors]::Default }
    }
}
# --- TOKEN AUTO-REFRESH -------------------------------------------------------
# Client credentials issues no refresh token and needs none: we hold the secret,
# so "refresh" is simply re-requesting. That requires KEEPING the secret, which
# is why the Connect handler no longer discards it after the first mint.
#
# Held as a SecureString and decrypted only for the few milliseconds a token
# request takes. Lazy, not on a timer - this app can idle for hours between
# actions, and a timer would both waste requests and block the WinForms UI
# thread on a network call.
$script:TokenSecure=$null
$script:TokenExpiry=[datetime]::MinValue

function Set-AppSecret {
    param([string]$Secret)
    if ([string]::IsNullOrWhiteSpace($Secret)) { $script:TokenSecure=$null; return }
    $script:TokenSecure=ConvertTo-SecureString $Secret -AsPlainText -Force
}
function Clear-AppSecret {
    # Only drops the ability to RENEW. The token already held stays valid until
    # it expires, so TokenExpiry is deliberately left alone - resetting it to
    # MinValue is what produced "un-representable DateTime" on the next check.
    $script:TokenSecure=$null
}

function Get-PlainSecret {
    if (-not $script:TokenSecure) { return $null }
    $b=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:TokenSecure)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}

function Get-LiveToken {
    # Renew 5 minutes early: covers clock drift and a call that starts valid and
    # lands expired.
    param([switch]$Force)
    if (-not $Force -and $script:Token -and (Get-Date).AddMinutes(5) -lt $script:TokenExpiry) {
        return $script:Token
    }
    if (-not $script:TokenSecure) {
        # Retention is off (or the secret expired out). Say so rather than
        # letting the caller fail with an opaque 401.
        if ($script:Token -and (Get-Date) -ge $script:TokenExpiry -and (Get-Command Add-Status -ErrorAction SilentlyContinue)) {
            Add-Status "API token has expired and auto-renew is off - re-enter the SPN secret and Connect API." ([System.Drawing.Color]::Firebrick)
        }
        return $script:Token
    }
    $script:LastSecretUse=Get-Date
    $s=Get-PlainSecret
    try {
        $body=@{ grant_type='client_credentials'; scope='https://graph.microsoft.com/.default'; client_id=$script:ClientId; client_secret=$s }
        $r=Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$($script:TenantId)/oauth2/v2.0/token" -Body $body -ErrorAction Stop
        $script:Token=$r.access_token
        $script:TokenExpiry=(Get-Date).AddSeconds([int]$r.expires_in)
        if (Get-Command Add-Status -ErrorAction SilentlyContinue) {
            Add-Status ("API token renewed automatically; valid until {0:HH:mm:ss}." -f $script:TokenExpiry) $clrGray
        }
    }
    catch { if (Get-Command Add-Status -ErrorAction SilentlyContinue) { Add-Status "Token renewal FAILED - $($_.Exception.Message)" ([System.Drawing.Color]::Firebrick) } }
    finally { $s=$null }
    $script:Token
}

# Every Graph call routes through Get-LiveToken, so expiry is handled in one
# place rather than at each call site.
function Invoke-GraphGet {
    # -Headers merges in on top of Authorization - used for ConsistencyLevel:
    # eventual, required by the $count filter on the licensing-groups query.
    param([string]$Uri,[hashtable]$Headers)
    $h=@{ Authorization="Bearer $(Get-LiveToken)" }
    if ($Headers) { foreach ($k in $Headers.Keys) { $h[$k]=$Headers[$k] } }
    Invoke-RestMethod -Method GET -Uri $Uri -Headers $h -ErrorAction Stop
}
function Invoke-GraphGetAll { param([string]$Uri);
    $all=[Collections.Generic.List[object]]::new(); $next=$Uri; while (-not [string]::IsNullOrWhiteSpace($next)) { $r=Invoke-GraphGet $next; foreach ($row in @($r.value)) { $all.Add($row)|Out-Null }; $next=$r.'@odata.nextLink' }; return $all }
function Invoke-GraphPost {
<#
.SYNOPSIS
    POST to Graph. Captures the Location header for 202-Accepted async actions.
.DESCRIPTION
    assignNumber and similar teamsAdministration actions return 202 with a
    Location header pointing at the operation to poll - that is the documented
    completion signal, not a fixed wait. Callers that need it read .Location;
    callers that don't (most of the file) are unaffected.
#>
    param([string]$Uri,$Body)
    $p=@{ Method='POST'; Uri=$Uri; Headers=@{ Authorization="Bearer $(Get-LiveToken)" }; UseBasicParsing=$true; ErrorAction='Stop' }
    if ($null -ne $Body) { $p.Body=$Body | ConvertTo-Json -Depth 20; $p.ContentType='application/json' }
    try {
        $r=Invoke-WebRequest @p
        $d=$null; if ($r.Content) { $d=$r.Content | ConvertFrom-Json }
        $loc=$null; try { $loc="$($r.Headers['Location'])"; if ([string]::IsNullOrWhiteSpace($loc)) { $loc=$null } } catch {}
        [pscustomobject]@{ OK=$true; Status=[int]$r.StatusCode; Data=$d; Error=$null; Location=$loc }
    } catch {
        $st=''; try { $st=[int]$_.Exception.Response.StatusCode } catch {}
        [pscustomobject]@{ OK=$false; Status=$st; Data=$null; Error=$_.Exception.Message; Location=$null }
    }
}
function Wait-GraphOperation {
<#
.SYNOPSIS
    Poll a teamsAdministration operation URL (from a 202's Location header)
    until it reports a terminal state, or the attempt budget runs out.
.DESCRIPTION
    Falls back to the caller's own readback (e.g. re-GET the number) when no
    Location header was returned - some tenants/module paths still answer
    202 without one, and the old polling behaviour must keep working.
#>
    param([string]$OperationUri,[int]$MaxAttempts=8,[int]$DelaySeconds=5)
    if ([string]::IsNullOrWhiteSpace($OperationUri)) { return $null }
    for ($i=0; $i -lt $MaxAttempts; $i++) {
        Start-Sleep -Seconds $DelaySeconds
        try {
            $op = Invoke-GraphGet $OperationUri
            $status = "$($op.status)"
            if ($status -in @('succeeded','failed','completed')) { return $op }
        } catch {}
    }
    return $null
}
function Use-TeamsFirst {
    return ([bool]$script:AppSettings.PreferTeamsModule -and [bool]$script:RbacConnected -and (Test-CmdletPresent 'Get-CsPhoneNumberAssignment'))
}
function ConvertTo-GraphNumberRow {
    # Shape the Teams number row like the Graph numberAssignments row, so callers read the same property names.
    param($Row)
    if (-not $Row) { return $null }
    [pscustomobject]@{
        telephoneNumber    = "$($Row.TelephoneNumber)"
        numberType         = "$($Row.NumberType)"
        numberSource       = "$($Row.NumberSource)"
        assignmentTargetId = "$($Row.AssignedPstnTargetId)"
        assignmentCategory = "$($Row.AssignmentCategory)"
        assignmentStatus   = "$($Row.PstnAssignmentStatus)"
        capabilities       = @($Row.Capability)
        city               = "$($Row.City)"
        locationId         = "$($Row.LocationId)"
    }
}
function Get-NumberRowByTarget {
    param([string]$TargetId)
    if (Use-TeamsFirst) {
        try { $row = ConvertTo-GraphNumberRow (Get-CsPhoneNumberAssignment -AssignedPstnTargetId $TargetId -ErrorAction Stop | Select-Object -First 1); if ($row) { return $row } } catch {}
    }
    $f=[uri]::EscapeDataString("assignmentTargetId eq '$TargetId'"); $r=Invoke-GraphGet "$($script:Graph)/admin/teams/telephoneNumberManagement/numberAssignments?`$filter=$f"; @($r.value) | Select-Object -First 1
}
function Get-UserIdentityRow {
    # Returns id / userPrincipalName / displayName / accountEnabled, Teams first when it is preferred.
    param([string]$Upn)
    if (Use-TeamsFirst) {
        try {
            $u = Get-CsOnlineUser -Identity $Upn -ErrorAction Stop
            $id = if ($u.ObjectId) { "$($u.ObjectId)" } else { "$($u.Identity)" }
            if ($id) { return [pscustomobject]@{ id=$id; userPrincipalName="$($u.UserPrincipalName)"; displayName="$($u.DisplayName)"; accountEnabled=[bool]$u.AccountEnabled } }
        } catch {}
    }
    $eu=[uri]::EscapeDataString($Upn); return (Invoke-GraphGet "$($script:Graph)/users/$eu`?`$select=id,userPrincipalName,displayName,accountEnabled")
}
function Get-NumberAssignment { param([string]$Number); $nn=ToE164 $Number
    if (Use-TeamsFirst) {
        try { $row = ConvertTo-GraphNumberRow (Get-CsPhoneNumberAssignment -TelephoneNumber $nn -ErrorAction Stop | Select-Object -First 1); if ($row) { return $row } } catch {}
    }
    $f=[uri]::EscapeDataString("telephoneNumber eq '$nn'"); $r=Invoke-GraphGet "$($script:Graph)/admin/teams/telephoneNumberManagement/numberAssignments?`$filter=$f"; @($r.value) | Select-Object -First 1 }

function Get-TargetKind {
    param([string]$Upn)
    try { $eu=[uri]::EscapeDataString($Upn); $lic=Invoke-GraphGet "$($script:Graph)/users/$eu/licenseDetails"; $plans=@($lic.value.servicePlans); if ($plans | Where-Object { "$($_.servicePlanName)" -like 'MCOEV_VIRTUALUSER*' }) { return 'ResourceAccount' }; return 'User' } catch { return 'Unknown' }
}
function Resolve-TargetKind {
    param([string]$Upn)
    $sel="$($cmbTargetType.SelectedItem)"
    if ($sel -eq 'User') { return 'User' }
    if ($sel -eq 'Resource Account') { return 'ResourceAccount' }
    return (Get-TargetKind $Upn)
}
function Get-NumberInfo {
    param([string]$Number)
    $row=$null; try { $row=Get-NumberAssignment $Number } catch {}
    if (-not $row) { return $null }
    [pscustomobject]@{
        Number       = "$($row.telephoneNumber)"
        NumberType   = "$($row.numberType)"
        NumberSource = "$($row.numberSource)"
        Capabilities = @($row.capabilities)
        Status       = "$($row.assignmentStatus)"
        AssignedTo   = "$($row.assignmentTargetId)"
        Country      = "$($row.isoCountryCode)"
        City         = "$($row.city)"
        LocationId   = "$($row.locationId)"
        CivicId      = "$($row.civicAddressId)"
        Activation   = "$($row.activationState)"
    }
}
function Test-NumberUsage {
    param($Info,[string]$TargetKind,[string]$NumberType)
    if ($NumberType -eq 'directRouting') { return @{ OK=$true; Msg='Direct Routing - usage set by assignment. Guard skipped.' } }
    if ($null -eq $Info) { return @{ OK=$true; Msg='Number not in inventory - cannot check capability (proceeding).' } }
    $caps=@($Info.Capabilities); $capStr=($caps -join ', ')
    $isUserCap = (($caps -match 'userAssignment') | Measure-Object).Count -gt 0
    $isVoiceApp = ((($caps -match 'voiceApplicationAssignment') | Measure-Object).Count -gt 0) -or ($caps -match 'conferenceAssignment')
    if ($TargetKind -eq 'ResourceAccount') {
        if ($isVoiceApp) { return @{ OK=$true; Msg="Capability OK: number supports voice-app/conference ($capStr)." } }
        return @{ OK=$false; Msg="Number usage is '$capStr' (user). A resource account needs a Conference/Voice-app number. Change the number's usage type in Teams admin, then retry." }
    } else {
        if ($isUserCap) { return @{ OK=$true; Msg="Capability OK: number supports user assignment ($capStr)." } }
        return @{ OK=$false; Msg="Number usage is '$capStr' (voice-app/conference). A user needs a user-usage number. Change the number's usage type, then retry." }
    }
}
# resolve an emergency location display (catalog name/address) from a locationId
function Resolve-EmergencyLocation {
    param([string]$LocationId)
    if ([string]::IsNullOrWhiteSpace($LocationId)) { return $null }
    $lm=Resolve-LocationById $LocationId
    if ($lm) { return [pscustomobject]@{ Name=$lm.LocationName; Address=$lm.Address; Id=$LocationId; InCatalog=$true } }
    return [pscustomobject]@{ Name='(not in catalog)'; Address=''; Id=$LocationId; InCatalog=$false }
}
function Resolve-CatalogPolicy { param([string]$Type,[string]$Name); if ($Name -eq 'Global') { return [pscustomobject]@{ Name='Global'; Id='' } }; $row=$script:catalog | Where-Object { $_.PolicyType -eq $Type -and $_.PolicyName -eq $Name -and $_.Enabled -eq 'True' } | Select-Object -First 1; $id=''; if ($row -and $row.PolicyId) { $id="$($row.PolicyId)" }; [pscustomobject]@{ Name=$Name; Id=$id } }

# Voice licensing evaluation.
# Per Microsoft Learn (dial-pad-configuration): a Teams Phone license is ANY service
# plan whose name starts with MCOEV ("MCOEV, MCOEV1, and so on. All are acceptable").
# E5 is NOT required - it merely bundles Teams Phone Standard. The same capability
# comes from the standalone add-on on E1/E3/Business/F/EDU/GOV plans, Business Voice, etc.
# MCOEV_VIRTUALUSER is the Resource Account variant and is tracked separately.
# PSTN connectivity (MCOPSTN*) is only license-gated for Microsoft Calling Plan;
# Direct Routing, Operator Connect, Teams Phone Mobile and Shared Calling need no license.
function Get-VoiceLicenseInfo {
    param($LicenseDetails)
    $plans=@(); if ($LicenseDetails) { $plans=@($LicenseDetails.value.servicePlans) }
    $isOn = { param($p) ("$($p.provisioningStatus)" -notin @('Disabled','PendingActivation')) }

    $allMcoev = @($plans | Where-Object { "$($_.servicePlanName)" -like 'MCOEV*' })
    $vuAll    = @($allMcoev | Where-Object { "$($_.servicePlanName)" -like 'MCOEV_VIRTUALUSER*' })
    $phoneAll = @($allMcoev | Where-Object { "$($_.servicePlanName)" -notlike 'MCOEV_VIRTUALUSER*' })
    $cpAll    = @($plans | Where-Object { "$($_.servicePlanName)" -like 'MCOPSTN*' })

    $phoneOn = @($phoneAll | Where-Object { & $isOn $_ })
    $vuOn    = @($vuAll    | Where-Object { & $isOn $_ })
    $cpOn    = @($cpAll    | Where-Object { & $isOn $_ })

    [pscustomobject]@{
        PhonePlans      = $phoneOn
        PhoneNames      = @($phoneOn | ForEach-Object { "$($_.servicePlanName)" })
        HasPhone        = ($phoneOn.Count -gt 0)
        PhoneDisabled   = @($phoneAll | Where-Object { -not (& $isOn $_) } | ForEach-Object { "$($_.servicePlanName) [$($_.provisioningStatus)]" })
        VirtualUser     = $vuOn
        VirtualNames    = @($vuOn | ForEach-Object { "$($_.servicePlanName)" })
        HasVirtualUser  = ($vuOn.Count -gt 0)
        CallingPlans    = $cpOn
        CallingNames    = @($cpOn | ForEach-Object { "$($_.servicePlanName)" })
        HasCallingPlan  = ($cpOn.Count -gt 0)
        SkuNames        = @(if ($LicenseDetails) { @($LicenseDetails.value) | ForEach-Object { "$($_.skuPartNumber)" } })
    }
}

function Get-PolicySelections { return @([pscustomobject]@{ N=14; Type='TenantDialPlan'; Name="$($cmbDialPlan.SelectedItem)" },[pscustomobject]@{ N=15; Type='CallingLineIdentity'; Name="$($cmbCallerId.SelectedItem)" },[pscustomobject]@{ N=17; Type='TeamsCallingPolicy'; Name="$($cmbCallingPolicy.SelectedItem)" },[pscustomobject]@{ N=18; Type='TeamsCallParkPolicy'; Name="$($cmbCallPark.SelectedItem)" },[pscustomobject]@{ N=19; Type='OnlineVoiceRoutingPolicy'; Name="$($cmbVoiceRouting.SelectedItem)" },[pscustomobject]@{ N=20; Type='TeamsEmergencyCallingPolicy'; Name="$($cmbEmergencyCalling.SelectedItem)" },[pscustomobject]@{ N=21; Type='TeamsEmergencyCallRoutingPolicy'; Name="$($cmbEmergencyRouting.SelectedItem)" },[pscustomobject]@{ N=22; Type='TeamsMobilityPolicy'; Name="$($cmbMobility.SelectedItem)" },[pscustomobject]@{ N=23; Type='OnlineVoicemailPolicy'; Name="$($cmbVoicemail.SelectedItem)" },[pscustomobject]@{ N=25; Type='TeamsSharedCallingRoutingPolicy'; Name="$($cmbSharedCalling.SelectedItem)" },[pscustomobject]@{ N=26; Type='TeamsVoiceApplicationsPolicy'; Name="$($cmbVoiceApps.SelectedItem)" },[pscustomobject]@{ N=27; Type='TeamsIPPhonePolicy'; Name="$($cmbIpPhone.SelectedItem)" },[pscustomobject]@{ N=28; Type='TeamsCallHoldPolicy'; Name="$($cmbCallHold.SelectedItem)" }) }
function Get-ComboByType { param([string]$Type); switch ($Type) { 'TenantDialPlan' { $cmbDialPlan } 'CallingLineIdentity' { $cmbCallerId } 'TeamsCallingPolicy' { $cmbCallingPolicy } 'TeamsCallParkPolicy' { $cmbCallPark } 'OnlineVoiceRoutingPolicy' { $cmbVoiceRouting } 'TeamsEmergencyCallingPolicy' { $cmbEmergencyCalling } 'TeamsEmergencyCallRoutingPolicy' { $cmbEmergencyRouting } 'TeamsMobilityPolicy' { $cmbMobility } 'OnlineVoicemailPolicy' { $cmbVoicemail } 'TeamsSharedCallingRoutingPolicy' { $cmbSharedCalling } 'TeamsVoiceApplicationsPolicy' { $cmbVoiceApps } 'TeamsIPPhonePolicy' { $cmbIpPhone } 'TeamsCallHoldPolicy' { $cmbCallHold } default { $null } } }
function Format-ApiCommand { param([string]$Method,[string]$Uri,$Body=$null); if ($null -eq $Body) { return ("{0} {1}" -f $Method,$Uri) }; ("{0} {1} | {2}" -f $Method,$Uri,($Body | ConvertTo-Json -Depth 20 -Compress)) }
function Set-UserPolicyRest { param([string]$Type,[string]$Name,[string]$PolicyId);
    if ($Name -eq 'Global') { $body=@{ value=@(@{ '@odata.type'='#microsoft.graph.teamsAdministration.teamsPolicyUserAssignment'; userId=$script:LastUserId; policyType=$Type }) }; return Invoke-GraphPost "$($script:Graph)/admin/teams/policy/userAssignments/unassign" $body } else {
    $body=@{ value=@(@{ '@odata.type'='#microsoft.graph.teamsAdministration.teamsPolicyUserAssignment'; userId=$script:LastUserId; policyType=$Type; policyId=$PolicyId }) }; return Invoke-GraphPost "$($script:Graph)/admin/teams/policy/userAssignments/assign" $body }
}
function Test-PermissionError { param([string]$Message); if ([string]::IsNullOrWhiteSpace($Message)) { return $false }; ($Message -match 'Access is denied|AccessDenied|Authorization_RequestDenied|Forbidden|does not have permission|not authorized|insufficient privileg|role assignment|RoleAssignment|401|403') }
function New-StepResult {
    param([bool]$OK,[bool]$PermIssue,[string]$Status,[string]$Detail,[string]$Command='',[string]$Method=''); [pscustomobject]@{ OK=$OK; PermIssue=$PermIssue; Status=$Status; Detail=$Detail; Command=$Command; Method=$Method } }
function Normalize-Name { param($Value); if ($null -eq $Value) { return 'Global' }; $s="$Value"; if ([string]::IsNullOrWhiteSpace($s)) { return 'Global' }; ($s -replace '^Tag:','') }
function Set-Combo { param($Combo,[string]$Name); if ($null -eq $Combo) { return }; if ([string]::IsNullOrWhiteSpace($Name)) { $Name='Global' }; $idx=$Combo.Items.IndexOf($Name); if ($idx -lt 0) { [void]$Combo.Items.Add($Name); $idx=$Combo.Items.IndexOf($Name) }; $Combo.SelectedIndex=$idx }
function Invoke-PolicyWrite {
    param([string]$Type,[string]$Name,[string]$PolicyId,[bool]$UseRbac)
    $primary=if ($UseRbac) { 'RBAC' } else { 'API' }; $order=if ($chkFallback.Checked) { if ($primary -eq 'RBAC') { @('RBAC','API') } else { @('API','RBAC') } } else { @($primary) }; $last=$null
    foreach ($m in $order) {
        if ($m -eq 'API') { if ([string]::IsNullOrWhiteSpace($script:Token)) { $res=New-StepResult $false $true 'NOAUTH' 'No API token' '' } else {
            $r=Set-UserPolicyRest -Type $Type -Name $Name -PolicyId $PolicyId; $op=if ($Name -eq 'Global') { 'unassign' } else { 'assign' }; $res=New-StepResult ($r.OK -and $r.Status -eq 204) ($r.Status -in @(401,403)) "$($r.Status)" ($(if($r.OK){'ok'}else{$r.Error})) ("POST /policy/userAssignments/$op | $Type=$Name") } }
        else { if (-not $script:RbacConnected) { $res=New-StepResult $false $true 'NOAUTH' 'RBAC not connected' '' } else { $c=$script:rbacGrant[$Type]; if (-not $c) { $res=New-StepResult $false $false 'NOCMD' "No RBAC cmdlet for $Type" '' } else {
            $pn=if ($Name -eq 'Global') { $null } else { $Name }; $cmd="$c -Identity $($script:CurrentUpn) -PolicyName " + $(if ($pn) { $pn } else { '$null' }); try { & $c -Identity $script:CurrentUpn -PolicyName $pn -ErrorAction Stop; $res=New-StepResult $true $false 'OK' 'granted' $cmd } catch {
            $mm=$_.Exception.Message; $res=New-StepResult $false (Test-PermissionError $mm) 'ERR' $mm $cmd } } } }
        $res.Method=$m; $last=$res; if ($res.OK) { break }; if (-not $res.PermIssue) { break }; Add-Status "  [$m] role/permission issue -> trying other method..." $clrAmber
    }
    return $last
}
function Get-NumberCountry { param([string]$Number); $iso=Get-CountryFromNumber $Number; if (-not [string]::IsNullOrWhiteSpace($iso)) { return $iso }; if ([string]::IsNullOrWhiteSpace($script:Token) -or [string]::IsNullOrWhiteSpace($Number)) { return '' }; try { $row=Get-NumberAssignment $Number; if ($row -and $row.isoCountryCode) { return "$($row.isoCountryCode)".Trim().ToUpper() } } catch {}; return '' }
function Update-ForVoiceType {
    param([bool]$RefreshLocs); $vt="$($cmbVoice.SelectedItem)";
    $iso=Get-CountryFromNumber ($txtNumber.Text.Trim()); $lblNumCountry.Text=$(if ($iso) { "[$iso]" } else { "" })
    if ($vt -eq 'callingPlan') { $chkLocationOn.Checked=$true; $chkLocationOn.Enabled=$false; if ($RefreshLocs) { $note=Populate-Locations $iso; if (-not [string]::IsNullOrWhiteSpace($iso)) { $msg="Calling Plan: showing $iso locations"; if (-not [string]::IsNullOrWhiteSpace($note)) { $msg="$msg ($note)" }; Add-Status $msg $clrBlue } else { Add-Status "Enter a number (with country prefix, e.g. +1...) to filter locations." $clrAmber } } }
    else { $chkLocationOn.Enabled=$true; if ($RefreshLocs) { [void](Populate-Locations '') } }
}
$cmbVoice.Add_SelectedIndexChanged({ Update-ForVoiceType $true })
$txtNumber.Add_Leave({ if ("$($cmbVoice.SelectedItem)" -eq 'callingPlan') { Update-ForVoiceType $true } else { $iso=Get-CountryFromNumber ($txtNumber.Text.Trim()); $lblNumCountry.Text=$(if ($iso) { "[$iso]" } else { "" }) } })
$cmbTargetType.Add_SelectedIndexChanged({ $lblTargetDetected.Text=$(if ("$($cmbTargetType.SelectedItem)" -eq 'Auto-detect') { "" } else { "(manual)" }) })
function Get-UserAssignedNumber {
    param([string]$UserId,[string]$Upn)
    try { $row=Get-NumberRowByTarget -TargetId $UserId; if ($row -and $row.telephoneNumber) { return [pscustomobject]@{ Number="$($row.telephoneNumber)"; Type="$($row.numberType)"; Source='numberAssignments' } } } catch {}
    try { $uf=[uri]::EscapeDataString("userPrincipalName eq '$Upn'"); $uc=Invoke-GraphGet "$($script:Graph)/admin/teams/userConfigurations?`$filter=$uf"; $cfg=@($uc.value) | Select-Object -First 1; $line="$($cfg.telephoneNumber)"; if ([string]::IsNullOrWhiteSpace($line)) { $line="$($cfg.lineUri)" }; if (-not [string]::IsNullOrWhiteSpace($line)) { $n=($line -replace '^tel:',''); $n=($n -split ';')[0]; return [pscustomobject]@{ Number=$n; Type='directRouting'; Source='userConfigurations' } } } catch {}
    return $null
}
function Invoke-NumberRemoval {
    param([string]$Upn,[string]$Number,[string]$NumberType); $nn=ToE164 $Number; if ([string]::IsNullOrWhiteSpace($nn)) { return New-StepResult $false $false 'NOINPUT' 'No assigned number found to remove (enter the number manually).' '' 'API' };
    $unUri="$($script:Graph)/admin/teams/telephoneNumberManagement/numberAssignments/unassignNumber"; $unBody=@{ telephoneNumber=$nn; numberType=$NumberType };
    $un=Invoke-GraphPost $unUri $unBody; return New-StepResult ($un.OK) ($un.Status -in @(401,403)) "$($un.Status)" ($(if($un.OK){'removed via REST'}else{$un.Error})) (Format-ApiCommand 'POST' $unUri $unBody) 'API' }

# ===== Catalog download/save =====
function Update-CatFileLabel { $lf=Get-EnvCatalogPath "TeamsVoice_LocationCatalog_Engineer"; $pf=Get-EnvCatalogPath "TeamsVoice_PolicyCatalog_Engineer"; $lblCatFiles.Text=("Env $($script:CurrentEnv)  |  Locations: {0} ({1})  |  Policies: {2} ({3})" -f [IO.Path]::GetFileName($lf),$(if (Test-Path $lf){'found'}else{'missing'}),[IO.Path]::GetFileName($pf),$(if (Test-Path $pf){'found'}else{'missing'})) }
function Save-LocationCatalogToCsv { if (-not $script:allLocations -or @($script:allLocations).Count -eq 0) { Add-Cat "Nothing to save - location catalog is empty." $clrAmber; return }; $p=Get-EnvCatalogWritePath "TeamsVoice_LocationCatalog_Engineer"; $script:allLocations | Select-Object LocationName,LocationId,Address,IsoCountryCode,Enabled | Export-Csv $p -NoTypeInformation -Encoding UTF8; Add-Cat "Saved $(@($script:allLocations).Count) locations -> $([IO.Path]::GetFileName($p))" $clrGreen; Update-CatFileLabel }
function Save-PolicyCatalogToCsv { if (-not $script:catalog -or @($script:catalog).Count -eq 0) { Add-Cat "Nothing to save - policy catalog is empty." $clrAmber; return }; $p=Get-EnvCatalogWritePath "TeamsVoice_PolicyCatalog_Engineer"; $script:catalog | Select-Object PolicyType,PolicyName,PolicyId,Enabled,IsDefault | Export-Csv $p -NoTypeInformation -Encoding UTF8; Add-Cat "Saved $(@($script:catalog).Count) policy rows ->
$([IO.Path]::GetFileName($p))" $clrGreen; Update-CatFileLabel }
function Resolve-PolicyIdRest { param([string]$Type,[string]$Name); if ([string]::IsNullOrWhiteSpace($Name) -or $Name -eq 'Global') { return '' }; $n=$Name -replace ' ','%20'; try { $r=Invoke-GraphGet "$($script:Graph)/admin/teams/policy/getPolicyId(type='$Type',name='$n')"; $row=@($r.value) | Select-Object -First 1; if ($row -and $row.policyId) { return "$($row.policyId)" } } catch {}; return '' }
function Download-LocationsFromTenant {
    $rows=[Collections.Generic.List[object]]::new(); $src=''
    if ($script:RbacConnected) { try { $locs=Get-CsOnlineLisLocation -ErrorAction Stop; foreach ($l in $locs) {
        $addr=@("$($l.HouseNumber)","$($l.StreetName)","$($l.City)","$($l.StateOrProvince)","$($l.PostalCode)") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) };
        $name="$($l.Description)"; if ([string]::IsNullOrWhiteSpace($name)) { $name="$($l.City) - $($l.LocationId)" }; $rows.Add([pscustomobject]@{ LocationName=$name; LocationId="$($l.LocationId)"; Address=($addr -join ', '); IsoCountryCode="$($l.CountryOrRegion)"; Enabled='True' }) | Out-Null }; $src='RBAC Get-CsOnlineLisLocation (full)' } catch { Add-Cat "  RBAC location pull failed: $($_.Exception.Message)" $clrAmber } }
    if ($rows.Count -eq 0) {
        if ([string]::IsNullOrWhiteSpace($script:Token)) { Add-Cat "No API token and no RBAC - connect first." ([System.Drawing.Color]::Firebrick); return }
        $all=@(); try { $all=Invoke-GraphGetAll "$($script:Graph)/admin/teams/telephoneNumberManagement/numberAssignments?`$top=500" } catch { Add-Cat "  REST numberAssignments failed: $($_.Exception.Message)" ([System.Drawing.Color]::Firebrick); return }
        $seen=@{}
        foreach ($r in $all) { $lid="$($r.locationId)"; if ([string]::IsNullOrWhiteSpace($lid) -or $seen.ContainsKey($lid)) { continue };
            $seen[$lid]=$true; $existing=$script:allLocations | Where-Object { $_.LocationId -eq $lid } | Select-Object -First 1; $name=if ($existing) { $existing.LocationName } else { "$($r.city) - $lid" }; $addr=if ($existing -and $existing.Address) { $existing.Address } else { "$($r.city)" }; $iso=if ($r.isoCountryCode) { "$($r.isoCountryCode)" } elseif ($existing) { "$($existing.IsoCountryCode)" } else { '' }; $rows.Add([pscustomobject]@{ LocationName=$name; LocationId=$lid; Address=$addr; IsoCountryCode=$iso; Enabled='True' }) | Out-Null }
        $src='REST numberAssignments (partial - in-use only; street address may be blank)'
    }
    if ($rows.Count -eq 0) { Add-Cat "No locations found." $clrAmber; return }
    $script:allLocations=@($rows); Add-Cat "Downloaded $($rows.Count) locations via $src." $clrGreen
    if ("$($cmbVoice.SelectedItem)" -eq 'callingPlan') { Update-ForVoiceType $true }
    else { [void](Populate-Locations '') }
    Add-Cat "Loaded into dropdown.  Click 'Save to CSV' to persist for $($script:CurrentEnv)." $clrBlue
}

function Download-PoliciesRbac {
    if (-not $script:RbacConnected) { Add-Cat "Download needs RBAC (Teams PS). REST/app-only cannot enumerate policies - use 'Refresh IDs (REST)' for known names." ([System.Drawing.Color]::Firebrick); return }
    $out=[Collections.Generic.List[object]]::new(); $haveToken=-not [string]::IsNullOrWhiteSpace($script:Token)
    foreach ($type in $script:PolicyTypes) { $getCmd=$script:rbacGet[$type]; if (-not $getCmd) { continue }; try { $items=& $getCmd -ErrorAction Stop; $added=0;
        foreach ($it in @($items)) { $ident="$($it.Identity)"; if ([string]::IsNullOrWhiteSpace($ident)) { continue }; $name=($ident -replace '^Tag:',''); if ([string]::IsNullOrWhiteSpace($name)) { $name='Global' }; $polId='';
            if ($haveToken -and $name -ne 'Global') { $polId=Resolve-PolicyIdRest $type $name };
            $isDef=if ($name -eq 'Global') { 'True' } else { 'False' };
            $out.Add([pscustomobject]@{ PolicyType=$type; PolicyName=$name; PolicyId=$polId; Enabled='True'; IsDefault=$isDef }) | Out-Null; $added++ }; Add-Cat ("  {0,-32} {1} policies" -f $type,$added) $clrGray } catch { Add-Cat "  $type failed: $($_.Exception.Message)" $clrAmber } }
    if ($out.Count -eq 0) { Add-Cat "No policies enumerated." $clrAmber; return }
    $script:catalog=@($out); Add-Cat "Downloaded $($out.Count) policy rows via RBAC$(if($haveToken){' (+REST IDs)'}else{''})." $clrGreen
    Load-PolicyType $cmbDialPlan $script:catalog "TenantDialPlan"; Load-PolicyType $cmbCallerId $script:catalog "CallingLineIdentity"; Load-PolicyType $cmbCallingPolicy $script:catalog "TeamsCallingPolicy"; Load-PolicyType $cmbCallPark $script:catalog "TeamsCallParkPolicy"; Load-PolicyType $cmbVoiceRouting $script:catalog "OnlineVoiceRoutingPolicy"; Load-PolicyType $cmbEmergencyCalling $script:catalog "TeamsEmergencyCallingPolicy"; Load-PolicyType $cmbEmergencyRouting $script:catalog "TeamsEmergencyCallRoutingPolicy"; Load-PolicyType $cmbMobility $script:catalog "TeamsMobilityPolicy"; Load-PolicyType $cmbVoicemail $script:catalog "OnlineVoicemailPolicy"
    Add-Cat "Loaded into dropdowns.  Click 'Save to CSV' to persist for $($script:CurrentEnv)." $clrBlue
}
function Refresh-PolicyIdsRest {
    if ([string]::IsNullOrWhiteSpace($script:Token)) { Add-Cat "No API token.  Connect API first." ([System.Drawing.Color]::Firebrick); return }
    if (-not $script:catalog -or @($script:catalog).Count -eq 0) { Add-Cat "Policy catalog is empty - load or download one first." $clrAmber; return }
    $upd=0; $miss=0
    foreach ($row in $script:catalog) { $type="$($row.PolicyType)"; $name="$($row.PolicyName)"; if ([string]::IsNullOrWhiteSpace($type) -or [string]::IsNullOrWhiteSpace($name) -or $name -eq 'Global') { continue };
        $polId=Resolve-PolicyIdRest $type $name; if ($polId) { if ("$($row.PolicyId)" -ne $polId) { $row.PolicyId=$polId; $upd++ } } else { $miss++; Add-Cat "  no ID: $type / $name" $clrAmber } }
    Add-Cat "Refreshed IDs via REST getPolicyId.  Updated: $upd  |  Unresolved: $miss" $clrGreen; Add-Cat "Click 'Save to CSV' to persist." $clrBlue
}
$btnDlLoc.Add_Click({ Add-Cat ("Download Locations ($($script:CurrentEnv))") ([System.Drawing.Color]::Navy);
    $form.Cursor=[System.Windows.Forms.Cursors]::WaitCursor; $btnDlLoc.Enabled=$false;
    try { Download-LocationsFromTenant } catch { Add-Cat "Error: $($_.Exception.Message)" ([System.Drawing.Color]::Firebrick) } finally { $btnDlLoc.Enabled=$true; $form.Cursor=[System.Windows.Forms.Cursors]::Default } })
$btnSaveLoc.Add_Click({ Save-LocationCatalogToCsv })
$btnReloadLoc.Add_Click({ Add-Cat "Reloading locations from CSV..." $clrGray; Load-LocationCatalog; Update-CatFileLabel })
$btnDlPol.Add_Click({ Add-Cat ("Download Policies ($($script:CurrentEnv))") ([System.Drawing.Color]::Navy);
    $form.Cursor=[System.Windows.Forms.Cursors]::WaitCursor; $btnDlPol.Enabled=$false;
    try { Download-PoliciesRbac } catch { Add-Cat "Error: $($_.Exception.Message)" ([System.Drawing.Color]::Firebrick) } finally { $btnDlPol.Enabled=$true; $form.Cursor=[System.Windows.Forms.Cursors]::Default } })
$btnRefreshPol.Add_Click({ Add-Cat ("Refresh Policy IDs via REST ($($script:CurrentEnv))") ([System.Drawing.Color]::Navy);
    $form.Cursor=[System.Windows.Forms.Cursors]::WaitCursor; $btnRefreshPol.Enabled=$false; try { Refresh-PolicyIdsRest } finally { $btnRefreshPol.Enabled=$true; $form.Cursor=[System.Windows.Forms.Cursors]::Default } })
$btnSavePol.Add_Click({ Save-PolicyCatalogToCsv })
$btnReloadPol.Add_Click({ Add-Cat "Reloading policies from CSV..." $clrGray; Load-PolicyCatalog; Update-CatFileLabel })

# ===== DR INVENTORY (RBAC cmdlets; dormant until roles) =====
$script:LastDrOrderId=$null
# Expand "+1..A..+1..B" range or comma list into an array of E.164 strings.
function Expand-DrNumbers {
    param([string]$Text)
    $t=$Text.Trim()
    if ($t -match '^\s*(\+?\d+)\s*\.\.\s*(\+?\d+)\s*$') {
        $a=ToE164 $Matches[1]; $b=ToE164 $Matches[2]
        $an=[int64]($a -replace '\D',''); $bn=[int64]($b -replace '\D','')
        if ($bn -lt $an) { return @() }
        if (($bn-$an) -gt 999) { return @('__TOOBIG__') }
        $list=@(); for ($i=$an; $i -le $bn; $i++) { $list += ('+'+$i.ToString()) }
        return $list
    }
    return @($t -split ',' | ForEach-Object { ToE164 ($_.Trim()) } | Where-Object { $_ })
}
$btnDrAdd.Add_Click({
    Add-Cat ("DR Add to Inventory ($($script:CurrentEnv))") ([System.Drawing.Color]::Navy)
    if (-not $script:RbacConnected) { Add-Cat "Needs RBAC (Teams PS) - New-CsOnlineDirectRoutingTelephoneNumberUploadOrder has no Graph v1.0 equivalent.  Connect RBAC (dormant until SPN roles granted)." ([System.Drawing.Color]::Firebrick); return }
    $nums=Expand-DrNumbers $txtDrNums.Text
    if ($nums -contains '__TOOBIG__') { Add-Cat "Range too large (>1000).  Split it into smaller ranges." ([System.Drawing.Color]::Firebrick); return }
    if (-not $nums -or $nums.Count -eq 0) { Add-Cat "Enter a number, comma list, or START..END range." ([System.Drawing.Color]::Firebrick); return }
    Add-Cat ("Uploading $($nums.Count) DR number(s): " + ($nums -join ', ')) $clrGray
    $form.Cursor=[System.Windows.Forms.Cursors]::WaitCursor; $btnDrAdd.Enabled=$false
    try {
        $order = New-CsOnlineDirectRoutingTelephoneNumberUploadOrder -TelephoneNumber ($nums -join ',') -ErrorAction Stop
        $oid="$order"; $script:LastDrOrderId=$oid; $lblDrOrder.Text="Last OrderId: $oid"
        Add-Cat "Upload order created.  OrderId: $oid" $clrGreen
        Add-Cat "Click 'Check Last Order' for status (async)." $clrBlue
    } catch { $msg=$_.Exception.Message; if (Test-PermissionError $msg) { Add-Cat "RBAC role missing for DR upload: $msg" ([System.Drawing.Color]::Firebrick) } else { Add-Cat "DR upload failed: $msg" ([System.Drawing.Color]::Firebrick) } }
    finally { $btnDrAdd.Enabled=$true; $form.Cursor=[System.Windows.Forms.Cursors]::Default }
})
$btnDrStatus.Add_Click({
    Add-Cat ("DR Order Status ($($script:CurrentEnv))") ([System.Drawing.Color]::Navy)
    if (-not $script:RbacConnected) { Add-Cat "Needs RBAC (Teams PS).  Dormant until SPN roles granted." ([System.Drawing.Color]::Firebrick); return }
    if ([string]::IsNullOrWhiteSpace($script:LastDrOrderId)) { Add-Cat "No OrderId yet.  Add numbers first." $clrAmber; return }
    $form.Cursor=[System.Windows.Forms.Cursors]::WaitCursor; $btnDrStatus.Enabled=$false
    try {
        $st = Get-CsOnlineTelephoneNumberOrder -OrderType DirectRoutingNumberCreation -OrderId $script:LastDrOrderId -ErrorAction Stop
        Add-Cat "Status : $($st.Status)" $clrGreen
        if ($st.SuccessPhoneNumbers) { Add-Cat "Success: $($st.SuccessPhoneNumbers -join ', ')" $clrGreen }
        if ($st.WarningPhoneNumbers) { Add-Cat "Warning: $($st.WarningPhoneNumbers -join ', ')" $clrAmber }
        if ($st.ErrorMessage) { Add-Cat "Errors : $($st.ErrorMessage)" ([System.Drawing.Color]::Firebrick) }
    } catch { Add-Cat "Order status failed: $($_.Exception.Message)" ([System.Drawing.Color]::Firebrick) }
    finally { $btnDrStatus.Enabled=$true; $form.Cursor=[System.Windows.Forms.Cursors]::Default }
})
$btnDrRelease.Add_Click({
    Add-Cat ("DR Release ($($script:CurrentEnv))") ([System.Drawing.Color]::Navy)
    if (-not $script:RbacConnected) { Add-Cat "Needs RBAC (Teams PS).  Dormant until SPN roles granted." ([System.Drawing.Color]::Firebrick); return }
    $nums=Expand-DrNumbers $txtDrNums.Text
    if (-not $nums -or $nums.Count -eq 0 -or $nums -contains '__TOOBIG__') { Add-Cat "Enter one or more numbers to release." ([System.Drawing.Color]::Firebrick); return }
    $confirm=[System.Windows.Forms.MessageBox]::Show(("Release from inventory:`n" + ($nums -join "`n")),"Confirm DR Release",[System.Windows.Forms.MessageBoxButtons]::YesNo,[System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { Add-Cat "Cancelled." ([System.Drawing.Color]::DimGray); return }
    $form.Cursor=[System.Windows.Forms.Cursors]::WaitCursor; $btnDrRelease.Enabled=$false
    try {
        $order = New-CsOnlineTelephoneNumberReleaseOrder -TelephoneNumber ($nums -join ',') -ErrorAction Stop
        $oid="$order"; $script:LastDrOrderId=$oid; $lblDrOrder.Text="Last OrderId (Release): $oid"
        Add-Cat "Release order created.  OrderId: $oid" $clrGreen
    } catch { Add-Cat "Release failed: $($_.Exception.Message)" ([System.Drawing.Color]::Firebrick) }
    finally { $btnDrRelease.Enabled=$true; $form.Cursor=[System.Windows.Forms.Cursors]::Default }
})

# ===== ENV SWITCH =====
function Switch-Environment {
    param([string]$Key); if ([string]::IsNullOrWhiteSpace($Key) -or -not $script:Environments.Contains($Key)) { return }
    $env=$script:Environments[$Key]; $script:CurrentEnv=$Key; $script:TenantId=$env.TenantId; $script:ClientId=$env.ClientId
    $script:Token=$null; $script:RbacConnected=$false; $script:LastUserId=$null; $script:LastAssignOk=$false
    Clear-AppSecret
    # Toolkit shares this app's session. Switching tenants must invalidate its
    # cached Graph token and forget which tenant the Teams session was bound to,
    # or a policy migration will happily write into the tenant you just left.
    Clear-GraphTokenCache
    $script:TeamsConnectedAt=$null; $script:TeamsTenantId=$null; $script:TeamsAccount=$null
    $script:AuthContext.TenantId=$env.TenantId; $script:AuthContext.ClientId=$env.ClientId
    $lblTokenState.Text="API Token: not acquired  (primary - required)"; $lblTokenState.ForeColor=[System.Drawing.Color]::Firebrick
    $lblRbacState.Text="RBAC (Teams PS): not connected  (optional)"; $lblRbacState.ForeColor=$clrGray
    $lblEnvInfo.Text=("{0}  |  Tenant {1}  |  Client {2}" -f $env.App,$env.TenantId,$env.ClientId)
    $txtStatus.Clear(); Add-Status ("Environment: $Key") ([System.Drawing.Color]::Navy); Add-Status ("  App    : $($env.App)"); Add-Status ("  Tenant : $($env.TenantId)"); Add-Status ("  Client : $($env.ClientId)"); Add-Status ("-"*42)
    Add-Status "Token cleared.  Enter the SPN secret for THIS environment and Connect API." $clrAmber
    Load-LocationCatalog; Load-PolicyCatalog; if (Get-Command Update-CatFileLabel -ErrorAction SilentlyContinue) { Update-CatFileLabel }; Add-Status ("-"*42)
    # Per-tenant pre-fills from TeamsVoice_Tenants.csv - only when the operator
    # has not already typed something, so switching tenants mid-edit never
    # clobbers unsaved input.
    if ([string]::IsNullOrWhiteSpace($txtUser.Text)) { $txtUser.Text = Get-EnvDefault 'DefaultUpn' }
    if ([string]::IsNullOrWhiteSpace($txtNumber.Text)) { $txtNumber.Text = Get-EnvDefault 'DefaultNumber' }
    if ([string]::IsNullOrWhiteSpace($txtCdrUser.Text)) { $txtCdrUser.Text = Get-EnvDefault 'DefaultCdrFilter' }
}
function Refresh-EnvCombo {
    $prev=$cmbEnv.SelectedItem; $cmbEnv.Items.Clear()
    foreach ($k in $script:Environments.Keys) { [void]$cmbEnv.Items.Add($k) }
    if ($prev -and $script:Environments.Contains("$prev")) { $cmbEnv.SelectedItem=$prev }
    elseif ($cmbEnv.Items.Count -gt 0) { $cmbEnv.SelectedIndex=0 }
}
function Clear-EnvironmentUI {
    $script:CurrentEnv=$null; $script:TenantId=$null; $script:ClientId=$null
    $script:Token=$null; $script:RbacConnected=$false; $script:LastUserId=$null; $script:LastAssignOk=$false
    Clear-AppSecret
    $lblEnvInfo.Text="No environment configured - add one in the Configuration window."
    $lblTokenState.Text="API Token: n/a  (no environment configured)"; $lblTokenState.ForeColor=$clrGray
    $lblRbacState.Text="RBAC (Teams PS): n/a  (no environment configured)"; $lblRbacState.ForeColor=$clrGray
    $txtStatus.Clear(); Add-Status "No environment configured.  Add a Tenant Id / Client Id / App name in the Configuration window." $clrAmber
    $script:allLocations=@(); $script:catalog=@(); [void](Populate-Locations '')
    foreach ($t in $script:PolicyTypes) { $c=Get-ComboByType $t; if ($c) { $c.Items.Clear() } }
    if (Get-Command Update-CatFileLabel -ErrorAction SilentlyContinue) { $lblCatFiles.Text="" }
}
$btnManageEnv.Add_Click({
    $dlg = New-ConfigurationTabPage -BackColor $clrLight `
        -ColorBlue $clrBlue -ColorPurple $clrPurple -ColorGreen $clrGreen `
        -ColorGray $clrGray -ColorAmber $clrAmber -ColorRed $clrRed
    [void]$dlg.ShowDialog($form)
    $dlg.Dispose()
    Refresh-EnvCombo
})
$form.Add_Shown({
    Pl-RefreshLocations; Pl-RefreshPolicyChoices
    $r=$script:StartupModuleResult
    if ($r) { Add-Status ("Teams module (startup): " + ($r.Message -replace "`r?`n",' ')) $(if ($r.Success) { $clrGray } else { $clrAmber }); Cfg-Log $r.Message (-not $r.Success); Cfg-RefreshLoaded }
})

# ===== CONNECT =====
$btnConnect.Add_Click({ if (-not $script:CurrentEnv) { $lblTokenState.Text="No environment configured - use the Configuration window first."; $lblTokenState.ForeColor=[System.Drawing.Color]::Firebrick; return }; $secret=$txtSecret.Text; if ([string]::IsNullOrWhiteSpace($secret)) { $lblTokenState.Text="Enter the SPN secret first."; $lblTokenState.ForeColor=[System.Drawing.Color]::Firebrick; return };
    $form.Cursor=[System.Windows.Forms.Cursors]::WaitCursor; $btnConnect.Enabled=$false;
    try { $script:Token=Get-SpnToken -Secret $secret; $script:TokenExpiry=(Get-Date).AddSeconds(3600); $txtSecret.Clear()
          if ($chkKeepSecret.Checked) { Set-AppSecret $secret; $script:LastSecretUse=Get-Date
              $lblTokenState.Text="API Token: acquired ($($script:CurrentEnv))  auto-renew ON"; $lblTokenState.ForeColor=$clrGreen }
          else { Clear-AppSecret
              $lblTokenState.Text="API Token: acquired ($($script:CurrentEnv))  auto-renew OFF - expires in ~1h"; $lblTokenState.ForeColor=$clrGreen }
          } catch { $script:Token=$null; $lblTokenState.Text="API Token: FAILED - $($_.Exception.Message)"; $lblTokenState.ForeColor=[System.Drawing.Color]::Firebrick } finally { $secret=$null; $btnConnect.Enabled=$true; $form.Cursor=[System.Windows.Forms.Cursors]::Default } })
$btnConnectRbac.Add_Click({ if (-not $script:CurrentEnv) { $lblRbacState.Text="No environment configured - use the Configuration window first."; $lblRbacState.ForeColor=[System.Drawing.Color]::Firebrick; return };
    $mode=[string]$cboRbacMode.SelectedItem
    if ($mode -ne 'SPN (app-only)') {
        # --- delegated sign-in -------------------------------------------------
        # Deliberately NOT passing -AccountId. Supplying it makes MSAL try a
        # silent / integrated flow first; networks that block that path fail here
        # without falling back, and the error does not name the cause.
        $form.Cursor=[System.Windows.Forms.Cursors]::WaitCursor; $btnConnectRbac.Enabled=$false
        try {
            # The tool does not manage the MicrosoftTeams module. Get-Command
            # resolves exactly as PowerShell would at the prompt; Import-Module
            # here would mutate caller state, and Get-Module -ListAvailable can
            # report a stale install that is not what answers the call.
            $mr=Ensure-ConfiguredTeamsModule; if ($mr -and -not $mr.Success) { throw $mr.Message }
            if (-not (Test-CmdletPresent -Name 'Connect-MicrosoftTeams')) {
                throw "Connect-MicrosoftTeams is not available. Install the MicrosoftTeams module, or pick its folder in the Configuration window."
            }
            $p=@{ TenantId=$script:TenantId; ErrorAction='Stop' }
            if ($mode -like '*device*') {
                $p['UseDeviceAuthentication']=$true
                Add-Status "Device code sign-in: a code will be written to the PowerShell console for you to enter at microsoft.com/devicelogin." $clrAmber
            } else {
                Add-Status "Interactive sign-in: a browser tab will open. If your default browser is SSO-pinned to another identity, open a guest/incognito window BEFORE clicking through." $clrAmber
            }
            $sess=Connect-MicrosoftTeams @p
            $who=$null; try { $who=$sess.Account.Id } catch {}
            $script:RbacConnected=$true
            $script:TeamsConnectedAt=Get-Date; $script:TeamsTenantId=$script:TenantId; $script:TeamsAccount=$who
            $script:AuthContext.TenantId=$script:TenantId; $script:AuthContext.ClientId=$script:ClientId
            $script:AuthContext.TeamsAuthMode=$(if ($mode -like '*device*') { 'DeviceCode' } else { 'Interactive' })
            $script:AuthContext.AccessTokens=$null
            $lblRbacState.Text="RBAC (Teams PS): connected as $(if($who){$who}else{'signed-in user'})"; $lblRbacState.ForeColor=$clrGreen
        }
        catch {
            $script:RbacConnected=$false
            $d=$null; try { $d=Resolve-TeamsAuthError -ErrorRecord $_ -Mode $mode } catch {}
            $lblRbacState.Text="RBAC: FAILED - $($_.Exception.Message)"; $lblRbacState.ForeColor=[System.Drawing.Color]::Firebrick
            if ($d) { Add-Status "RBAC sign-in failed$(if($d.Code){" [$($d.Code)]"}) - $($d.Guidance)" ([System.Drawing.Color]::Firebrick) }
        }
        finally { $btnConnectRbac.Enabled=$true; $form.Cursor=[System.Windows.Forms.Cursors]::Default }
        return
    }
    $secret=$txtSecret.Text; if ([string]::IsNullOrWhiteSpace($secret)) { $secret=Get-PlainSecret }; if ([string]::IsNullOrWhiteSpace($secret)) { $lblRbacState.Text="Enter the SPN secret above first (RBAC reuses it)."; $lblRbacState.ForeColor=[System.Drawing.Color]::Firebrick; return };
    [void](Invoke-RbacSpnConnect -Secret $secret); $secret=$null })
# Probe every policy read and classify: Empty is the treacherous one - the call
# succeeded and returned nothing, which reads as "tenant has none" but usually
# means the identity has no directory role.
$btnProbe=New-Object System.Windows.Forms.Button
$btnProbe.Location=New-Object System.Drawing.Point(228,76); $btnProbe.Size=New-Object System.Drawing.Size(96,26)
$btnProbe.Text="Probe Roles"; Style-Button $btnProbe $clrGray
$btnProbe.Add_Click({
    if (-not $script:RbacConnected) { $lblRbacState.Text="RBAC: connect first."; $lblRbacState.ForeColor=$clrAmber; return }
    $form.Cursor=[System.Windows.Forms.Cursors]::WaitCursor
    try {
        $res=@(Test-ToolkitPermission -NoConnect)
        Add-Status ("-"*42); Add-Status "RBAC probe as $($script:TeamsAccount)" ([System.Drawing.Color]::Navy)
        foreach ($r in $res) {
            $c=switch ($r.Outcome) { 'Ok' {$clrGreen} 'Empty' {$clrAmber} 'Denied' {[System.Drawing.Color]::Firebrick} 'Failed' {[System.Drawing.Color]::Firebrick} default {$clrGray} }
            Add-Status ("  {0,-30} {1,-9} {2}" -f $r.Key,$r.Outcome,$(if($null -ne $r.Count){"$($r.Count) object(s)"}else{''})) $c
        }
        $empty=@($res | Where-Object Outcome -eq 'Empty').Count
        if ($empty -ge 8) { Add-Status "Nearly everything returned EMPTY - that is the signature of a missing Teams Administrator directory role, not an empty tenant." ([System.Drawing.Color]::Firebrick) }
        Add-Status ("-"*42)
    }
    catch { Add-Status "Probe failed - $($_.Exception.Message)" ([System.Drawing.Color]::Firebrick) }
    finally { $form.Cursor=[System.Windows.Forms.Cursors]::Default }
})
$spnBar.Controls.Add($btnProbe)

$btnTestRbac.Add_Click({ if (-not $script:RbacConnected) { $lblRbacState.Text="RBAC: connect first before testing."; $lblRbacState.ForeColor=$clrAmber; return };
    $form.Cursor=[System.Windows.Forms.Cursors]::WaitCursor; $btnTestRbac.Enabled=$false; try { $t=Get-CsTenant -ErrorAction Stop; $tid="$($t.TenantId)"; if ([string]::IsNullOrWhiteSpace($tid)) { $tid="$($t.Identity)" }; $lblRbacState.Text="RBAC OK: role works (tenant $tid)"; $lblRbacState.ForeColor=$clrGreen } catch { $msg=$_.Exception.Message; if (Test-PermissionError $msg) { $lblRbacState.Text="RBAC: connected but ROLE MISSING (Get-CsTenant denied)"; $lblRbacState.ForeColor=[System.Drawing.Color]::Firebrick }
    else { $lblRbacState.Text="RBAC test error: $msg"; $lblRbacState.ForeColor=[System.Drawing.Color]::Firebrick } } finally { $btnTestRbac.Enabled=$true; $form.Cursor=[System.Windows.Forms.Cursors]::Default } })

# ===== INSPECT NUMBER =====
$btnInspect.Add_Click({
    $txtStatus.Clear(); Add-Status "Inspect Number  ($($script:CurrentEnv))" ([System.Drawing.Color]::Navy)
    if ([string]::IsNullOrWhiteSpace($script:Token)) { Add-Status "No API token.  Connect API first." ([System.Drawing.Color]::Firebrick); return }
    $nn=ToE164 ($txtNumber.Text.Trim())
    if ([string]::IsNullOrWhiteSpace($nn)) { Add-Status "Enter a phone number first." ([System.Drawing.Color]::Firebrick); return }
    Add-Status "Number: $nn"; Add-Status ("-"*42)
    $form.Cursor=[System.Windows.Forms.Cursors]::WaitCursor; $btnInspect.Enabled=$false
    try {
        $info=Get-NumberInfo $nn
        if (-not $info) { Add-Status "Not found in tenant inventory.  (Direct Routing numbers not yet uploaded won't appear.)" $clrAmber; return }
        Add-Status "NumberType    : $($info.NumberType)" $clrGreen
        Add-Status "NumberSource  : $($info.NumberSource)"
        Add-Status "Capabilities  : $((@($info.Capabilities)) -join ', ')" $clrPurple
        Add-Status "Status        : $($info.Status)"
        Add-Status "Assigned To   : $($info.AssignedTo)"
        Add-Status "Country       : $($info.Country)"
        Add-Status "Native city   : $($info.City)     (rate-center city of the number; not the emergency address)" $clrGray
        # emergency location (locationId) resolved from catalog
        $loc=Resolve-EmergencyLocation $info.LocationId
        if ($loc) { if ($loc.InCatalog) { Add-Status "Emergency Loc : $($loc.Name)" $clrGreen; Add-Status "  Address     : $($loc.Address)"; Add-Status "  Loc ID      : $($loc.Id)" } else { Add-Status "Emergency Loc : $($loc.Name)" $clrAmber; Add-Status "  Loc ID      : $($loc.Id)" } }
        else { Add-Status "Emergency Loc : (none set)" }
        if ("$($info.CivicId)") { Add-Status "Civic Addr Id : $($info.CivicId)" }
        Add-Status "Activation    : $($info.Activation)"
        Add-Status ("-"*42)
        $caps=@($info.Capabilities); $capStr=($caps -join ', ')
        if ($caps -match 'voiceApplicationAssignment' -or $caps -match 'conferenceAssignment') { Add-Status "Usage: VOICE APP / CONFERENCE -> assign to a Resource Account." $clrGreen }
        elseif ($caps -match 'userAssignment') { Add-Status "Usage: USER -> assign to a user." $clrGreen }
        else { Add-Status "Usage: $capStr" $clrAmber }
    } catch { Add-Status "Inspect error: $($_.Exception.Message)" ([System.Drawing.Color]::Firebrick) } finally { $btnInspect.Enabled=$true; $form.Cursor=[System.Windows.Forms.Cursors]::Default }
})

# ===== READ =====
$btnRead.Add_Click({
    $upn=$txtUser.Text.Trim(); $txtStatus.Clear(); Add-Status "Read Settings ($($script:CurrentEnv)) for:" ([System.Drawing.Color]::Navy); Add-Status $upn; Add-Status ("-"*42)
    if ([string]::IsNullOrWhiteSpace($upn)) { Add-Status "Enter a UPN first." ([System.Drawing.Color]::Firebrick); return }
    if ([string]::IsNullOrWhiteSpace($script:Token)) { Add-Status "No API token.  Connect API first." ([System.Drawing.Color]::Firebrick); return }
    $form.Cursor=[System.Windows.Forms.Cursors]::WaitCursor; $btnRead.Enabled=$false
    try {
        $u = Get-UserIdentityRow $upn; $eu=[uri]::EscapeDataString($upn)
        Add-Status "[ IDENTITY ]" $clrBlue; Add-Status "Display Name  : $($u.displayName)"; Add-Status "Object Id     : $($u.id)"; Add-Status "Account Enab. : $($u.accountEnabled)"
        $kind=Get-TargetKind $upn; $lblTargetDetected.Text="detected: $kind"; Add-Status "Target Kind   : $kind" $clrPurple; Add-Status ("-"*42)
        $lic=Invoke-GraphGet "$($script:Graph)/users/$eu/licenseDetails"; $vl=Get-VoiceLicenseInfo $lic
        Add-Status "[ LICENSING ]" $clrBlue
        Add-Status "SKUs          : $(if ($vl.SkuNames.Count) { ($vl.SkuNames -join ', ') } else { '(none)' })" $clrGray
        Add-Status "Teams Phone   : $(if ($vl.HasPhone) { ($vl.PhoneNames -join ', ') } else { 'NONE' })" $(if ($vl.HasPhone) { $clrGreen } else { [System.Drawing.Color]::Firebrick })
        if ($vl.PhoneDisabled.Count) { Add-Status "  not active  : $($vl.PhoneDisabled -join ', ')" $clrAmber }
        Add-Status "Virtual User  : $(if ($vl.HasVirtualUser) { ($vl.VirtualNames -join ', ') } else { 'Not present' })"
        Add-Status "Calling Plan  : $(if ($vl.HasCallingPlan) { ($vl.CallingNames -join ', ') } else { 'None (not required for DR / Operator Connect / Shared Calling)' })"
        if ($kind -eq 'ResourceAccount') {
            if ($vl.HasVirtualUser -or $vl.HasPhone) { Add-Status "RA LICENSING: OK - voice-capable." $clrGreen }
            else { Add-Status "RA LICENSING: NO voice-capable license (needs Teams Phone Resource Account or any MCOEV plan)." ([System.Drawing.Color]::Firebrick) }
        }
        elseif ($vl.HasPhone) { Add-Status "LICENSING: OK - voice-capable via $($vl.PhoneNames -join ', ')." $clrGreen }
        else { Add-Status "LICENSING: NO voice-capable license. User needs a Teams Phone (MCOEV*) plan - standalone add-on or bundled (E5, Business Voice, etc.)." ([System.Drawing.Color]::Firebrick) }
        Add-Status ("-"*42)
        # ---- NUMBER SUMMARY CARD ----
        Add-Status "[ NUMBER ]" $clrBlue
        $na=$null; try { $na=Get-NumberRowByTarget -TargetId "$($u.id)" } catch {}
        if ($na -and $na.telephoneNumber) {
            Add-Status "Assigned #    : $($na.telephoneNumber)" $clrGreen
            Add-Status "Type / Source : $($na.numberType) / $($na.numberSource)"
            Add-Status "Usage (caps)  : $((@($na.capabilities)) -join ', ')" $clrPurple
            Add-Status "Status        : $($na.assignmentStatus)"
            Add-Status "Native city   : $($na.city)" $clrGray
            $loc=Resolve-EmergencyLocation "$($na.locationId)"
            if ($loc) { if ($loc.InCatalog) { Add-Status "Emergency Loc: $($loc.Name)" $clrGreen; Add-Status "  Address     : $($loc.Address)"; Add-Status "  Loc ID      : $($loc.Id)" } else { Add-Status "Emergency Loc: $($loc.Name)" $clrAmber } }
            else { Add-Status "Emergency Loc: (none set)" }
            Add-Status "Activation    : $($na.activationState)"
        } else { Add-Status "Assigned #    : (none)" $clrAmber }
        # The Phone Lines grid and the number box are both filled from the same reader.
        $primary=$null
        try {
            Pl-ReadLines
            $primary=@($script:Pl.Lines | Where-Object { $_.Category -match '^Primary' }) | Select-Object -First 1
            if ($primary) { $txtNumber.Text="$($primary.Number)"; Add-Status "Primary #   : $($primary.Number) (loaded into the number box)" $clrGreen }
        } catch { Add-Status "Phone lines unavailable: $($_.Exception.Message)" $clrGray }
        # Sync the Voice Type combo to the number's type. Matching is case-insensitive because the API returns DirectRouting while the combo uses directRouting.
        $typeFromInv="$($info.NumberType)"; $typeFromLine="$($primary.Type)"; $numType=$(if ($typeFromLine) { $typeFromLine } else { $typeFromInv })
        $vtMatch=@($cmbVoice.Items | Where-Object { "$_" -ieq $numType }) | Select-Object -First 1
        if ($vtMatch) { $cmbVoice.SelectedItem=$vtMatch; Add-Status "Voice Type   : $vtMatch (set from number)" $clrGreen }
        elseif ($numType) { Add-Status "Voice Type   : '$numType' has no matching option; left unchanged." $clrAmber }
        Add-Status ("-"*42)
        # Get-CsOnlineUser reports the actual policy names, so it is the primary source when RBAC is connected.
        # Graph userConfigurations is the fallback for the types it covers.
        $rbacPolicies=$false
        if ($script:RbacConnected -and (Test-CmdletPresent -Name 'Get-CsOnlineUser')) {
            try {
                $csUser=Get-CsOnlineUser -Identity $upn -ErrorAction Stop
                $n=0
                foreach ($type in $script:ucMap.Keys) {
                    if ($script:DisabledPolicyTypes -contains $type) { continue }
                    $prop=$csUser.PSObject.Properties[$type]
                    if ($prop) { Set-Combo (Get-ComboByType $type) (Normalize-Name $prop.Value); $n++ }
                }
                $rbacPolicies=$true
                Add-Status "  dropdowns set from RBAC Get-CsOnlineUser ($n types)." $clrGreen
            } catch { Add-Status "Get-CsOnlineUser failed: $($_.Exception.Message)" $clrAmber }
        }
        try {
            $ucFilter=[uri]::EscapeDataString("userPrincipalName eq '$upn'"); $uc=Invoke-GraphGet "$($script:Graph)/admin/teams/userConfigurations?`$filter=$ucFilter"; $cfg=@($uc.value) | Select-Object -First 1
            if ($cfg) { Add-Status "[ POLICIES / EV ]" $clrBlue; if ([bool]$cfg.isEnterpriseVoiceEnabled) { Add-Status "EnterpriseVoice: ENABLED" $clrGreen } else { Add-Status "EnterpriseVoice: DISABLED" ([System.Drawing.Color]::Firebrick) }; foreach ($pa in
            @($cfg.effectivePolicyAssignments)) { $type="$($pa.policyType)"; if ($script:ucMap.ContainsKey($type) -and -not $rbacPolicies) { $combo=Get-ComboByType $type; $name=Normalize-Name $pa.displayName; if ([string]::IsNullOrWhiteSpace($pa.displayName)) { $name='Global' }; Set-Combo $combo $name } }; if (-not $rbacPolicies) { Add-Status "  dropdowns updated from Graph userConfigurations." $clrGreen } }
        } catch { $msg=$_.Exception.Message; if (Test-PermissionError $msg) { Add-Status "userConfigurations denied (needs TeamsUserConfiguration.Read.All)." $clrAmber } else { Add-Status "userConfigurations error: $msg" ([System.Drawing.Color]::Firebrick) } }
        if (-not $rbacPolicies) { Add-Status "  Connect RBAC to read every policy dropdown from the user's account." $clrGray }
        Add-Status ("-"*42); Add-Status "Read complete." ([System.Drawing.Color]::Navy)
    } catch { Add-Status "Read failed: $($_.Exception.Message)" ([System.Drawing.Color]::Firebrick) } finally { $btnRead.Enabled=$true; $form.Cursor=[System.Windows.Forms.Cursors]::Default }
})

# ===== VALIDATE =====
$btnValidate.Add_Click({
    $upn=$txtUser.Text.Trim(); $number=ToE164 ($txtNumber.Text.Trim()); $numberType="$($cmbVoice.SelectedItem)"
    $txtStatus.Clear(); Add-Status "Validation ($($script:CurrentEnv))" ([System.Drawing.Color]::Navy); Add-Status ("Target: $upn"); Add-Status ("Voice Type: $numberType"); Add-Status ("-"*42)
    if ([string]::IsNullOrWhiteSpace($script:Token)) { Add-Status "No API token.  Connect API first." ([System.Drawing.Color]::Firebrick); return }
    if ([string]::IsNullOrWhiteSpace($upn)) { Add-Status "Enter a UPN first." ([System.Drawing.Color]::Firebrick); return }
    if ([string]::IsNullOrWhiteSpace($number)) { Add-Status "Enter a phone number first." ([System.Drawing.Color]::Firebrick); return }
    $form.Cursor=[System.Windows.Forms.Cursors]::WaitCursor; $btnValidate.Enabled=$false
    try {
        $eu=[uri]::EscapeDataString($upn)
        try { $u=Invoke-GraphGet "$($script:Graph)/users/$eu`?`$select=id,userPrincipalName,displayName"; Add-Result 1 "Target exists" 'PASS' } catch { Add-Result 1 "Target exists" 'FAIL'; Add-Status "$($_.Exception.Message)" ([System.Drawing.Color]::Firebrick); return }
        $kind=Resolve-TargetKind $upn; $lblTargetDetected.Text=$(if ("$($cmbTargetType.SelectedItem)" -eq 'Auto-detect') { "detected: $kind" } else { "(manual)" }); Add-Result 2 "Target kind = $kind" 'PASS'
        $lic=$null; try { $lic=Invoke-GraphGet "$($script:Graph)/users/$eu/licenseDetails" } catch {}; $vl=Get-VoiceLicenseInfo $lic
        if ($kind -eq 'ResourceAccount') {
            if ($vl.HasVirtualUser) { Add-Result 3 "Voice license ($($vl.VirtualNames -join ', '))" 'PASS' }
            elseif ($vl.HasPhone) { Add-Result 3 "Voice license ($($vl.PhoneNames -join ', '))" 'PASS'; Add-Status "  Resource account is using a standard Teams Phone plan rather than the Virtual User plan." $clrAmber }
            else { Add-Result 3 "Voice license" 'FAIL'; Add-Status "  NO voice-capable license - needs Teams Phone Resource Account (MCOEV_VIRTUALUSER) or any MCOEV plan." ([System.Drawing.Color]::Firebrick) }
        }
        else {
            if ($vl.HasPhone) { Add-Result 3 "Teams Phone license ($($vl.PhoneNames -join ', '))" 'PASS' }
            else {
                Add-Result 3 "Teams Phone license" 'FAIL'
                if ($vl.PhoneDisabled.Count) { Add-Status "  Found but NOT active: $($vl.PhoneDisabled -join ', ')" ([System.Drawing.Color]::Firebrick) }
                else { Add-Status "  NO voice-capable license. Assign a Teams Phone (MCOEV*) plan - standalone add-on or bundled (E5, Business Voice, etc.)." ([System.Drawing.Color]::Firebrick) }
                Add-Status "  SKUs held: $(if ($vl.SkuNames.Count) { ($vl.SkuNames -join ', ') } else { '(none)' })" $clrGray
            }
        }
        if ($numberType -eq 'callingPlan') {
            if ($vl.HasCallingPlan) { Add-Result 7 "Calling Plan license ($($vl.CallingNames -join ', '))" 'PASS' }
            elseif ($kind -eq 'ResourceAccount') { Add-Result 7 "Calling Plan license" 'N/A'; Add-Status "  (Resource accounts can hold a Calling Plan number without a Calling Plan license.)" $clrGray }
            else { Add-Result 7 "Calling Plan license" 'FAIL'; Add-Status "  Calling Plan number selected but no MCOPSTN* plan assigned." ([System.Drawing.Color]::Firebrick) }
        }
        else { Add-Result 7 "Calling Plan license" 'N/A'; Add-Status "  ($numberType needs no Calling Plan license.)" $clrGray }
        $info=$null; if ($numberType -ne 'directRouting') { try { $info=Get-NumberInfo $number } catch {} }
        if ($numberType -eq 'directRouting') { Add-Result 9 "Number inventory (DR)" 'N/A' }
        elseif ($info) { Add-Result 9 "Number in inventory ($($info.NumberType))" 'PASS'; Add-Status "  Capabilities: $((@($info.Capabilities)) -join ', ')   Status: $($info.Status)" $clrGray }
        else { Add-Result 9 "Number in inventory" 'FAIL'; Add-Status "  Not found - acquire it or check the number." ([System.Drawing.Color]::Firebrick) }
        $usage=Test-NumberUsage $info $kind $numberType
        if ($usage.OK) { Add-Result 10 "Number usage vs target kind" 'PASS'; Add-Status "  $($usage.Msg)" $clrGreen } else { Add-Result 10 "Number usage vs target kind" 'FAIL'; Add-Status "  $($usage.Msg)" ([System.Drawing.Color]::Firebrick) }
        if ($numberType -eq 'callingPlan') {
            $locRow=Resolve-LocationById ($txtLocation.Text.Trim()); $numIso=Get-NumberCountry $number; $locIso=Get-LocationCountry $locRow
            if ([string]::IsNullOrWhiteSpace($txtLocation.Text.Trim())) { Add-Status "  NOTE: Calling Plan needs a Location - none selected." $clrAmber }
            elseif ($numIso -and $locIso -and $numIso -ne $locIso) { Add-Status "  WARN: number country ($numIso) != location country ($locIso)." $clrAmber }
            else { Add-Status "  Location country matches number ($numIso)." $clrGreen }
        }
        Add-Status ("-"*42); Add-Status "Validation complete." ([System.Drawing.Color]::Navy)
    } catch { Add-Status "Validation error: $($_.Exception.Message)" ([System.Drawing.Color]::Firebrick) } finally { $btnValidate.Enabled=$true; $form.Cursor=[System.Windows.Forms.Cursors]::Default }
})

# ===== PROVISION =====
$btnProvision.Add_Click({
    $upn=$txtUser.Text.Trim(); $number=ToE164 ($txtNumber.Text.Trim()); $numberType="$($cmbVoice.SelectedItem)"; $location=$txtLocation.Text.Trim(); $script:CurrentUpn=$upn
    $doNumber=$chkNumberOn.Checked; $doLocation=$chkLocationOn.Checked
    $txtStatus.Clear(); Add-Status "Provisioning ($($script:CurrentEnv))" ([System.Drawing.Color]::Navy); Add-Status ("Target: $upn"); Add-Status ("Voice: $numberType   Number: $number"); Add-Status ("Location: $($cmbLocation.SelectedItem)"); Add-Status ("-"*42)
    if ([string]::IsNullOrWhiteSpace($script:Token)) { Add-Status "No API token.  Connect API first." ([System.Drawing.Color]::Firebrick); return }
    if ([string]::IsNullOrWhiteSpace($upn)) { Add-Status "UPN required." ([System.Drawing.Color]::Firebrick); return }
    if ($doNumber -and [string]::IsNullOrWhiteSpace($number)) { Add-Status "Number toggle is On but no phone number entered." ([System.Drawing.Color]::Firebrick); return }
    try { $u=Get-UserIdentityRow $upn; $script:LastUserId="$($u.id)" } catch { Add-Status "Target lookup failed - aborting." ([System.Drawing.Color]::Firebrick); return }
    $kind=Resolve-TargetKind $upn; $lblTargetDetected.Text=$(if ("$($cmbTargetType.SelectedItem)" -eq 'Auto-detect') { "detected: $kind" } else { "(manual)" })
    Add-Status "Target kind: $kind   (id=$($script:LastUserId))" $clrPurple
    if ($doNumber) {
        if ($numberType -eq 'callingPlan') {
            if ([string]::IsNullOrWhiteSpace($location)) { Add-Status "Calling Plan requires an emergency Location.  Select one and retry." ([System.Drawing.Color]::Firebrick); return }
            $numIso=Get-NumberCountry $number; $locRow=Resolve-LocationById $location; $locIso=Get-LocationCountry $locRow
            if ([string]::IsNullOrWhiteSpace($numIso)) { Add-Status "STOP: cannot determine number country.  Enter E.164 (+1...) and retry." ([System.Drawing.Color]::Firebrick); return }
            if ([string]::IsNullOrWhiteSpace($locIso)) { Add-Status "STOP: cannot determine location country." ([System.Drawing.Color]::Firebrick); return }
            if ($numIso -ne $locIso) { Add-Status "STOP: number country ($numIso) != location country ($locIso).  Pick a $numIso location." ([System.Drawing.Color]::Firebrick); return }
            Add-Status "Country check OK: number and location are both $numIso." $clrGreen
        }
        $info=$null; if ($numberType -ne 'directRouting') { try { $info=Get-NumberInfo $number } catch {} }
        $usage=Test-NumberUsage $info $kind $numberType
        if (-not $usage.OK) { Add-Status "STOP: $($usage.Msg)" ([System.Drawing.Color]::Firebrick); return }
        Add-Status $usage.Msg $clrGreen
        if ($info -and "$($info.AssignedTo)" -and "$($info.AssignedTo)" -ne "$($script:LastUserId)") { Add-Status "STOP: number already assigned to $($info.AssignedTo)  (status $($info.Status))." ([System.Drawing.Color]::Firebrick); return }
    }
    $onPolicies=@(); foreach ($sel in (Get-PolicySelections)) { if ($script:provChk[$sel.Type].Checked) { $onPolicies += $sel.Type } }
    $planLines=@(); $planLines += ("Environment : $($script:CurrentEnv)"); $planLines += ("Target : $upn [$kind]"); $planLines += ("Number : " + $(if ($doNumber) { "$number ($numberType)" } else { "SKIP" })); $planLines += ("Location update : " + $(if ($numberType -eq 'callingPlan' -and $doNumber -and $doLocation) { "$($cmbLocation.SelectedItem)" } else { "SKIP" })); $planLines += ("Policies ON : " + $(if ($onPolicies.Count) { ($onPolicies -join ', ') } else { "none" }))
    $confirm=[System.Windows.Forms.MessageBox]::Show(("REAL changes for:`n$upn`n`n" + ($planLines -join "`n") + "`n`nProceed?"),"Confirm Provision - $($script:CurrentEnv)",[System.Windows.Forms.MessageBoxButtons]::YesNo,[System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { Add-Status "Cancelled by user." ([System.Drawing.Color]::DimGray); return }
    $form.Cursor=[System.Windows.Forms.Cursors]::WaitCursor; $script:report.Clear(); $btnProvision.Enabled=$false
    try {
        $assignN=if ($numberType -eq 'directRouting') { 11 } else { 13 }
        if (-not $doNumber) { Add-Result $assignN "Assign Number ($numberType) - SKIPPED (toggle off)" 'SKIP'; Add-ReportRow -TestNumber $assignN -Operation "Assign Number ($numberType)" -Phase 'Write' -MethodUsed '-' -Command '(skipped)' -HttpStatus 'N/A' -Result 'SKIP' -Notes 'Disabled by user'; $script:LastAssignOk=$false }
        else {
            $assignUri="$($script:Graph)/admin/teams/telephoneNumberManagement/numberAssignments/assignNumber"; $body=@{ telephoneNumber=$number; assignmentTargetId=$script:LastUserId; numberType=$numberType; assignmentCategory='primary' }; if ($numberType -eq 'callingPlan' -and $location) { $body.locationId=$location }
            $ar=Invoke-GraphPost $assignUri $body; $after=$null; $confirmed=$false
            if ($ar.OK) {
                # Total confirmation budget stays ~40s either way, matching the
                # original behaviour - the Location-header path does not add a
                # second full wait on top of the readback fallback, it splits
                # the same budget between them.
                if ($ar.Location) {
                    $op = Wait-GraphOperation -OperationUri $ar.Location -MaxAttempts 4 -DelaySeconds 5
                    if ($op -and "$($op.status)" -eq 'succeeded') { $confirmed=$true }
                }
                if (-not $confirmed) {
                    for ($i=0; $i -lt 4; $i++) { Start-Sleep 5; try { $after=Get-NumberAssignment $number } catch {}; if ("$($after.assignmentTargetId)" -eq $script:LastUserId) { $confirmed=$true; break } }
                }
            }
            $assignOk=($ar.OK -and ($ar.Status -in @(200,202,204)) -and $confirmed); $script:LastAssignOk=$assignOk
            if ($ar.OK -and -not $confirmed) { Add-Status "  POST accepted ($($ar.Status)) but readback not confirmed within ~40s." $clrAmber; if ($after) { Add-Status "  current status: $($after.assignmentStatus)   target: $($after.assignmentTargetId)" $clrGray } }
            Add-Result $assignN "Assign Number ($numberType)  [API $($ar.Status)]" $(if ($assignOk) {'PASS'} else {'FAIL'}); if (-not $ar.OK) { Add-Status "  $($ar.Error)" ([System.Drawing.Color]::Firebrick) }
            Add-ReportRow -TestNumber $assignN -Operation "Assign Number ($numberType) [$kind]" -Phase 'Write' -MethodUsed 'API' -Command (Format-ApiCommand 'POST' $assignUri $body) -HttpStatus "$($ar.Status)" -Result $(if ($assignOk) {'PASS'} else {'FAIL'}) -Notes $ar.Error
        }
        if ($numberType -ne 'callingPlan') { Add-Result 12 "Update Number Location" 'N/A'; Add-ReportRow -TestNumber 12 -Operation 'Update Number Location' -Phase 'Write' -MethodUsed '-' -Command '(N/A)' -HttpStatus 'N/A' -Result 'N/A' -Notes 'N/A' }
        elseif (-not ($doNumber -and $doLocation)) { Add-Result 12 "Update Number Location - SKIPPED (toggle off)" 'SKIP'; Add-ReportRow -TestNumber 12 -Operation 'Update Number Location' -Phase 'Write' -MethodUsed '-' -Command '(skipped)' -HttpStatus 'N/A' -Result 'SKIP' -Notes 'Disabled by user' }
        else {
            $updUri="$($script:Graph)/admin/teams/telephoneNumberManagement/numberAssignments/updateNumber"; $updBody=@{ telephoneNumber=$number; locationId=$location }
            $xr=Invoke-GraphPost $updUri $updBody; Start-Sleep 5; $xa=$null; try { $xa=Get-NumberAssignment $number } catch {}; $xok=($xr.OK -and "$($xa.locationId)" -eq $location); Add-Result 12 "Update Number Location  [API $($xr.Status)]" $(if ($xok) {'PASS'} else {'FAIL'}); Add-ReportRow -TestNumber 12 -Operation 'Update Number Location' -Phase 'Write' -MethodUsed 'API' -Command (Format-ApiCommand 'POST' $updUri $updBody) -HttpStatus "$($xr.Status)" -Result $(if ($xok) {'PASS'} else {'FAIL'}) -Notes $xr.Error
        }
        $anyFail=$false
        foreach ($sel in (Get-PolicySelections)) {
            if ($script:DisabledPolicyTypes -contains $sel.Type) { Add-Result $sel.N "$($sel.Type) - SKIPPED (type disabled in this build)" 'SKIP'; Add-ReportRow -TestNumber $sel.N -Operation "$($sel.Type)" -Phase 'Write' -MethodUsed '-' -Command '-' -HttpStatus 'N/A' -Result 'SKIP' -Notes 'Type disabled - no API permission and no RBAC role'; continue }
            if (-not $script:provChk[$sel.Type].Checked) { Add-Result $sel.N "$($sel.Type) - SKIPPED (toggle off)" 'SKIP'; Add-ReportRow -TestNumber $sel.N -Operation "$($sel.Type)" -Phase 'Write' -MethodUsed '-' -Command '-' -HttpStatus 'N/A' -Result 'SKIP' -Notes 'Disabled by user'; continue }
            $useRbac=[bool]$script:rbacChk[$sel.Type].Checked; $resolved=Resolve-CatalogPolicy $sel.Type $sel.Name; $res=Invoke-PolicyWrite -Type $sel.Type -Name $sel.Name -PolicyId $resolved.Id -UseRbac $useRbac; if (-not $res.OK) { $anyFail=$true }
            Add-Result $sel.N "$($sel.Type) -> $($sel.Name)  [$($res.Method) $($res.Status)]" $(if ($res.OK) {'PASS'} else {'FAIL'}); if (-not $res.OK) { Add-Status "  $($res.Detail)" ([System.Drawing.Color]::Firebrick) }
            Add-ReportRow -TestNumber $sel.N -Operation "$($sel.Type) -> $($sel.Name)" -Phase 'Write' -MethodUsed $res.Method -Command $res.Command -HttpStatus $res.Status -Result $(if ($res.OK) {'PASS'} else {'FAIL'}) -Notes $res.Detail
        }
        Add-Result 24 "Verify Policy Assignments" $(if ($anyFail) {'FAIL'} else {'PASS'}); Add-ReportRow -TestNumber 24 -Operation 'Verify Policy Assignments' -Phase 'Validation' -MethodUsed '-' -Command '(local check)' -HttpStatus 'N/A' -Result $(if ($anyFail) {'FAIL'} else {'PASS'}) -Notes ''
        Add-Status ("-"*42); $rpt=Export-Report -Kind 'Provision'; if ($rpt) { Add-Status "Report: $rpt" ([System.Drawing.Color]::Navy) }; Add-Status "Provisioning complete." ([System.Drawing.Color]::Navy)
    } catch { Add-Status "Provisioning error: $($_.Exception.Message)" ([System.Drawing.Color]::Firebrick) } finally { $btnProvision.Enabled=$true; $form.Cursor=[System.Windows.Forms.Cursors]::Default }
})

# ===== ROLLBACK =====
$btnRollback.Add_Click({
    $upn=$txtUser.Text.Trim(); $number=ToE164 ($txtNumber.Text.Trim()); $numberType="$($cmbVoice.SelectedItem)"; $script:CurrentUpn=$upn
    $txtStatus.Clear(); Add-Status "Rollback ($($script:CurrentEnv))" ([System.Drawing.Color]::Navy); Add-Status ("Target: $upn"); Add-Status ("-"*42)
    if ([string]::IsNullOrWhiteSpace($script:LastUserId)) { Add-Status "No provisioned target in this session.  Run Provision first." ([System.Drawing.Color]::Firebrick); return }
    if ([string]::IsNullOrWhiteSpace($script:Token)) { Add-Status "No API token.  Connect API first." ([System.Drawing.Color]::Firebrick); return }
    $confirm=[System.Windows.Forms.MessageBox]::Show("Restore catalog defaults (for On policies) and unassign the test number for:`n$upn`n`nProceed?","Confirm Rollback - $($script:CurrentEnv)",[System.Windows.Forms.MessageBoxButtons]::YesNo,[System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { Add-Status "Cancelled by user." ([System.Drawing.Color]::DimGray); return }
    $form.Cursor=[System.Windows.Forms.Cursors]::WaitCursor; $btnRollback.Enabled=$false; $script:report.Clear()
    try {
        foreach ($sel in (Get-PolicySelections)) {
            if (-not $script:provChk[$sel.Type].Checked) { Add-Result $sel.N "$($sel.Type) - SKIPPED (toggle off)" 'SKIP'; Add-ReportRow -TestNumber $sel.N -Operation "$($sel.Type) restore default" -Phase 'Rollback' -MethodUsed '-' -Command '-' -HttpStatus 'N/A' -Result 'SKIP' -Notes 'Disabled by user'; continue }
            $def=$script:catalog | Where-Object { $_.PolicyType -eq $sel.Type -and $_.IsDefault -eq 'True' -and $_.Enabled -eq 'True' } | Select-Object -First 1
            if (-not $def) { Add-Result $sel.N "$($sel.Type) - no default in catalog" 'FAIL'; Add-ReportRow -TestNumber $sel.N -Operation "$($sel.Type) restore default" -Phase 'Rollback' -MethodUsed '-' -Command '(no default)' -HttpStatus 'N/A' -Result 'FAIL' -Notes 'No IsDefault row'; continue }
            $useRbac=[bool]$script:rbacChk[$sel.Type].Checked; $resolved=Resolve-CatalogPolicy $sel.Type $def.PolicyName; $res=Invoke-PolicyWrite -Type $sel.Type -Name $def.PolicyName -PolicyId $resolved.Id -UseRbac $useRbac
            Add-Result $sel.N "$($sel.Type) -> $($def.PolicyName)  [$($res.Method) $($res.Status)]" $(if ($res.OK) {'PASS'} else {'FAIL'})
            Add-ReportRow -TestNumber $sel.N -Operation "$($sel.Type) -> $($def.PolicyName)" -Phase 'Rollback' -MethodUsed $res.Method -Command $res.Command -HttpStatus $res.Status -Result $(if ($res.OK) {'PASS'} else {'FAIL'}) -Notes $res.Detail
        }
        if ($script:LastAssignOk) {
            $unUri="$($script:Graph)/admin/teams/telephoneNumberManagement/numberAssignments/unassignNumber"; $unBody=@{ telephoneNumber=$number; numberType=$numberType }
            $un=Invoke-GraphPost $unUri $unBody; Add-Result 11 "Unassign test number  [API $($un.Status)]" $(if ($un.OK) {'PASS'} else {'FAIL'}); Add-ReportRow -TestNumber 11 -Operation 'Unassign test number' -Phase 'Rollback' -MethodUsed 'API' -Command (Format-ApiCommand 'POST' $unUri $unBody) -HttpStatus "$($un.Status)" -Result $(if ($un.OK) {'PASS'} else {'FAIL'}) -Notes $un.Error
        } else { Add-Status "No session number assignment to undo." ([System.Drawing.Color]::DimGray) }
        Add-Status ("-"*42); $rpt=Export-Report -Kind 'Rollback'; if ($rpt) { Add-Status "Report: $rpt" ([System.Drawing.Color]::Navy) }; Add-Status "Rollback complete." ([System.Drawing.Color]::Navy)
    } catch { Add-Status "Rollback error: $($_.Exception.Message)" ([System.Drawing.Color]::Firebrick) } finally { $btnRollback.Enabled=$true; $form.Cursor=[System.Windows.Forms.Cursors]::Default }
})

# ===== REMOVE NUMBER =====
$btnRemoveNum.Add_Click({
    $upn=$txtUser.Text.Trim(); $script:CurrentUpn=$upn; $number=ToE164 ($txtNumber.Text.Trim()); $numberType="$($cmbVoice.SelectedItem)"
    $txtStatus.Clear(); Add-Status "Remove Number ($($script:CurrentEnv))" ([System.Drawing.Color]::Navy); Add-Status ("Target: $upn"); Add-Status ("-"*42)
    if ([string]::IsNullOrWhiteSpace($script:Token)) { Add-Status "No API token.  Connect API first." ([System.Drawing.Color]::Firebrick); return }
    if ([string]::IsNullOrWhiteSpace($upn)) { Add-Status "Enter a UPN first." ([System.Drawing.Color]::Firebrick); return }
    $form.Cursor=[System.Windows.Forms.Cursors]::WaitCursor; $btnRemoveNum.Enabled=$false; $script:report.Clear()
    try {
        try { $u=Get-UserIdentityRow $upn; $script:LastUserId="$($u.id)" } catch { Add-Status "Target lookup failed - aborting." ([System.Drawing.Color]::Firebrick); return }
        if ([string]::IsNullOrWhiteSpace($number)) { Add-Status "No number entered - looking up current assignment..." $clrGray; $cur=Get-UserAssignedNumber -UserId $script:LastUserId -Upn $upn; if ($cur) { $number=ToE164 $cur.Number; $numberType=$cur.Type; Add-Status "Found: $number ($numberType) via $($cur.Source)" $clrGreen } else { Add-Status "No assigned number found via REST." $clrAmber } }
        if ([string]::IsNullOrWhiteSpace($number)) { Add-Status "No number resolved - enter the number and retry." ([System.Drawing.Color]::Firebrick); return }
        $confirm=[System.Windows.Forms.MessageBox]::Show("Remove number from:`n$upn`n`nNumber: $number`nType: $numberType`n`nProceed?","Confirm Remove Number",[System.Windows.Forms.MessageBoxButtons]::YesNo,[System.Windows.Forms.MessageBoxIcon]::Warning)
        if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { Add-Status "Cancelled by user." ([System.Drawing.Color]::DimGray); return }
        $res=Invoke-NumberRemoval -Upn $upn -Number $number -NumberType $numberType
        Add-Result 11 "Remove number  [$($res.Method) $($res.Status)]" $(if ($res.OK) {'PASS'} else {'FAIL'}); if (-not $res.OK) { Add-Status "  $($res.Detail)" ([System.Drawing.Color]::Firebrick) }
        if ($res.OK) { $script:LastAssignOk=$false; Add-Status "  REST unassign done." $clrGray }
        Add-ReportRow -TestNumber 11 -Operation 'Remove number' -Phase 'Deprovision' -MethodUsed $res.Method -Command $res.Command -HttpStatus $res.Status -Result $(if ($res.OK) {'PASS'} else {'FAIL'}) -Notes $res.Detail
        Add-Status ("-"*42); $rpt=Export-Report -Kind 'RemoveNumber'; if ($rpt) { Add-Status "Report: $rpt" ([System.Drawing.Color]::Navy) }; Add-Status "Remove complete." ([System.Drawing.Color]::Navy)
    } catch { Add-Status "Remove error: $($_.Exception.Message)" ([System.Drawing.Color]::Firebrick) } finally { $btnRemoveNum.Enabled=$true; $form.Cursor=[System.Windows.Forms.Cursors]::Default }
})

# ===== DEPROVISION =====
$btnDeprovision.Add_Click({
    $upn=$txtUser.Text.Trim(); $script:CurrentUpn=$upn; $number=ToE164 ($txtNumber.Text.Trim()); $numberType="$($cmbVoice.SelectedItem)"
    $txtStatus.Clear(); Add-Status "Deprovision ($($script:CurrentEnv))" ([System.Drawing.Color]::Navy); Add-Status ("Target: $upn"); Add-Status ("-"*42)
    if ([string]::IsNullOrWhiteSpace($script:Token)) { Add-Status "No API token.  Connect API first." ([System.Drawing.Color]::Firebrick); return }
    if ([string]::IsNullOrWhiteSpace($upn)) { Add-Status "Enter a UPN first." ([System.Drawing.Color]::Firebrick); return }
    $onPolicies=@(); foreach ($sel in (Get-PolicySelections)) { if ($script:provChk[$sel.Type].Checked) { $onPolicies += $sel.Type } }
    $confirm=[System.Windows.Forms.MessageBox]::Show(("FULL DEPROVISION ($($script:CurrentEnv)) for:`n$upn`n`nRemove assigned number (REST)`nReset ON policies to Global (REST):`n" + $(if ($onPolicies.Count) { ($onPolicies -join ', ') } else { '(none selected)' }) + "`n`nProceed?"),"Confirm Deprovision",[System.Windows.Forms.MessageBoxButtons]::YesNo,[System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { Add-Status "Cancelled by user." ([System.Drawing.Color]::DimGray); return }
    $form.Cursor=[System.Windows.Forms.Cursors]::WaitCursor; $btnDeprovision.Enabled=$false; $script:report.Clear()
    try {
        try { $u=Get-UserIdentityRow $upn; $script:LastUserId="$($u.id)" } catch { Add-Status "Target lookup failed - aborting." ([System.Drawing.Color]::Firebrick); return }
        if ([string]::IsNullOrWhiteSpace($number)) { $cur=Get-UserAssignedNumber -UserId $script:LastUserId -Upn $upn; if ($cur) { $number=ToE164 $cur.Number; $numberType=$cur.Type; Add-Status "Current number: $number ($numberType) via $($cur.Source)" $clrGray } }
        $res=Invoke-NumberRemoval -Upn $upn -Number $number -NumberType $numberType
        Add-Result 11 "Remove number  [$($res.Method) $($res.Status)]" $(if ($res.OK) {'PASS'} else {'FAIL'}); if (-not $res.OK) { Add-Status "  $($res.Detail)" ([System.Drawing.Color]::Firebrick) }; if ($res.OK) { $script:LastAssignOk=$false }
        Add-ReportRow -TestNumber 11 -Operation 'Remove number' -Phase 'Deprovision' -MethodUsed $res.Method -Command $res.Command -HttpStatus $res.Status -Result $(if ($res.OK) {'PASS'} else {'FAIL'}) -Notes $res.Detail
        foreach ($sel in (Get-PolicySelections)) {
            if (-not $script:provChk[$sel.Type].Checked) { Add-Result $sel.N "$($sel.Type) - SKIPPED (toggle off)" 'SKIP'; Add-ReportRow -TestNumber $sel.N -Operation "$($sel.Type) -> Global" -Phase 'Deprovision' -MethodUsed '-' -Command '-' -HttpStatus 'N/A' -Result 'SKIP' -Notes 'Disabled by user'; continue }
            $res2=Invoke-PolicyWrite -Type $sel.Type -Name 'Global' -PolicyId '' -UseRbac $false
            Add-Result $sel.N "$($sel.Type) -> Global  [$($res2.Method) $($res2.Status)]" $(if ($res2.OK) {'PASS'} else {'FAIL'}); if (-not $res2.OK) { Add-Status "  $($res2.Detail)" ([System.Drawing.Color]::Firebrick) }
            Add-ReportRow -TestNumber $sel.N -Operation "$($sel.Type) -> Global" -Phase 'Deprovision' -MethodUsed $res2.Method -Command $res2.Command -HttpStatus $res2.Status -Result $(if ($res2.OK) {'PASS'} else {'FAIL'}) -Notes $res2.Detail
        }
        Add-Status ("-"*42); $rpt=Export-Report -Kind 'Deprovision'; if ($rpt) { Add-Status "Report: $rpt" ([System.Drawing.Color]::Navy) }; Add-Status "Deprovision complete." ([System.Drawing.Color]::Navy)
    } catch { Add-Status "Deprovision error: $($_.Exception.Message)" ([System.Drawing.Color]::Firebrick) } finally { $btnDeprovision.Enabled=$true; $form.Cursor=[System.Windows.Forms.Cursors]::Default }
})

# =========================================================
# ===== CDR (UI side): row build + CSV.  Pull happens in runspace. =====
# =========================================================
function ConvertTo-FlatRecord {
    param($Object,[string]$Prefix="",[System.Collections.Specialized.OrderedDictionary]$Out=$null)
    if ($null -eq $Out) { $Out=[ordered]@{} }
    if ($null -eq $Object) { return $Out }
    foreach ($p in $Object.PSObject.Properties) {
        $name=if ([string]::IsNullOrWhiteSpace($Prefix)) { $p.Name } else { "$Prefix.$($p.Name)" }
        $val=$p.Value
        if ($null -eq $val) { $Out[$name]=""; continue }
        if ($val -is [string] -or $val -is [int] -or $val -is [long] -or $val -is [double] -or $val -is [decimal] -or $val -is [bool] -or $val -is [datetime]) { $Out[$name]=$val }
        elseif ($val -is [System.Array]) { try { $Out[$name]=($val | ConvertTo-Json -Depth 60 -Compress) } catch { $Out[$name]="$val" } }
        elseif ($val -is [System.Collections.IEnumerable]) { try { $Out[$name]=($val | ConvertTo-Json -Depth 60 -Compress) } catch { $Out[$name]="$val" } }
        else { ConvertTo-FlatRecord -Object $val -Prefix $name -Out $Out | Out-Null }
    }
    return $Out
}
function New-CdrOutputRow {
    param([string]$RecordType,[string]$SourceEndpoint,[string]$ApiCommand,$Object,[hashtable]$Extra=$null)
    $base=[ordered]@{ PullTimestamp=(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); Environment=$script:CurrentEnv; RecordType=$RecordType; SourceEndpoint=$SourceEndpoint; ApiCommand=$ApiCommand }
    if ($Extra) { foreach ($k in $Extra.Keys) { $base[$k]=$Extra[$k] } }
    $flat=ConvertTo-FlatRecord -Object $Object
    foreach ($k in $flat.Keys) { if (-not $base.Contains($k)) { $base[$k]=$flat[$k] } }
    return [pscustomobject]$base
}
function Export-DynamicCsv {
    param([object[]]$Rows,[string]$Path)
    if (-not $Rows -or $Rows.Count -eq 0) { return $null }
    $cols=New-Object System.Collections.Generic.List[string]
    foreach ($r in $Rows) { foreach ($p in $r.PSObject.Properties.Name) { if (-not $cols.Contains($p)) { $cols.Add($p) | Out-Null } } }
    $normalized=foreach ($r in $Rows) { $o=[ordered]@{}; foreach ($c in $cols) { $prop=$r.PSObject.Properties[$c]; if ($prop) { $o[$c]=$prop.Value } else { $o[$c]="" } }; [pscustomobject]$o }
    $normalized | Export-Csv $Path -NoTypeInformation -Encoding UTF8
    return $Path
}
function Export-CdrCsv {
    if ($script:cdrRows.Count -eq 0) { return $null }
    if (-not $script:cdrSessionCsv) {
        $key=$script:Environments[$script:CurrentEnv].Key
        $script:cdrSessionCsv=Get-OutputPath -Area CdrReports -File ("TeamsVoice_CDRReport_{0}_{1}.csv" -f $key,(Get-Date -Format 'yyyyMMdd_HHmmss'))
    }
    Export-DynamicCsv -Rows @($script:cdrRows) -Path $script:cdrSessionCsv | Out-Null
    $script:LastCdrReport=$script:cdrSessionCsv
    return $script:cdrSessionCsv
}

# ===== Worker script block =====
$script:cdrWorker = {
    param($state,$cfg)
    $ErrorActionPreference='Stop'
    function EQ($o) { $state.Queue.Enqueue($o) }
    function LOG([string]$t,[string]$c='gray') { EQ @{ kind='log'; text=$t; color=$c } }
    function RenewCfgToken {
        if (-not $cfg.Secret) { return }
        $bstr=[IntPtr]::Zero; $plain=$null
        try {
            $bstr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($cfg.Secret)
            $plain=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            $b=@{ grant_type='client_credentials'; scope='https://graph.microsoft.com/.default'; client_id=$cfg.ClientId; client_secret=$plain }
            $r=Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$($cfg.TenantId)/oauth2/v2.0/token" -Body $b -ErrorAction Stop
            $cfg.Token=$r.access_token
            $cfg.TokenExpiry=(Get-Date).AddSeconds([int]$r.expires_in)
        } catch { }
        finally {
            $plain=$null
            if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        }
    }
    function GraphGetEx([string]$uri) {
        # Renew 5 minutes early, then retry once on a 401 - AAD can revoke before
        # the stated expiry after a credential or CA policy change.
        # Same rearrangement as Get-LiveToken: keep the arithmetic on Get-Date so
        # a MinValue expiry (retention off) can never produce an invalid date.
        if ($cfg.TokenExpiry -is [datetime] -and (Get-Date).AddMinutes(5) -ge $cfg.TokenExpiry) { RenewCfgToken }
        $h=@{ Authorization="Bearer $($cfg.Token)"; Prefer='include-unknown-enum-members' }
        try { Invoke-RestMethod -Method GET -Uri $uri -Headers $h -ErrorAction Stop }
        catch {
            $st=0; try { $st=[int]$_.Exception.Response.StatusCode } catch {}
            if ($st -ne 401) { throw }
            RenewCfgToken
            $h=@{ Authorization="Bearer $($cfg.Token)"; Prefer='include-unknown-enum-members' }
            Invoke-RestMethod -Method GET -Uri $uri -Headers $h -ErrorAction Stop
        }
    }
    function GraphGetAllEx([string]$uri) {
        $all=[Collections.Generic.List[object]]::new(); $next=$uri; while (-not [string]::IsNullOrWhiteSpace($next)) { $r=GraphGetEx $next; foreach($row in @($r.value)) { $all.Add($row)|Out-Null }; $next=$r.'@odata.nextLink' }; return $all }
    function SaveRaw([string]$folder,[string]$name,$obj) {
        if([string]::IsNullOrWhiteSpace($folder)){return $null}; $safe=$name -replace '[^a-zA-Z0-9_.-]','_'; $p=Join-Path $folder ($safe+'.json'); try{ $obj|ConvertTo-Json -Depth 100|Out-File -FilePath $p -Encoding UTF8; return $p }catch{ return $null } }
    function DeepGet([string]$id){
        $b="$($cfg.Graph)/communications/callRecords/$id"; $rec=GraphGetEx ($b+'?$expand=sessions($expand=segments)'); try{ $pv2=GraphGetEx ($b+'?$expand=participants_v2'); $rec|Add-Member -NotePropertyName participants_v2 -NotePropertyValue $pv2.participants_v2 -Force }catch{}; return $rec }
    function LatSec($endUtcStr){ if([string]::IsNullOrWhiteSpace($endUtcStr)){ return '' }; try{ $e=([datetime]$endUtcStr).ToUniversalTime(); return [math]::Round(((Get-Date).ToUniversalTime()-$e).TotalSeconds,1) }catch{ return '' } }

    function MatchUser($row,[string]$flt){
        if([string]::IsNullOrWhiteSpace($flt)){ return $true }
        $f=$flt.Trim()
        if($f -like '*@*'){
        foreach($fld in @($row.userPrincipalName,$row.organizer.user.userPrincipalName,$row.organizer_v2.identity.user.userPrincipalName)){ if($fld -and "$fld" -ieq $f){ return $true } }
        try{ $j=$row|ConvertTo-Json -Depth 80 -Compress; if($j -match [regex]::Escape($f)){ return $true } }catch{}
        return $false
    } else {
        $d=($f -replace '[^0-9]','')
        foreach($fld in @($row.callerNumber,$row.calleeNumber,$row.number,$row.callee,$row.caller,$row.from,$row.to)){ if($fld){ $fd=("$fld" -replace '[^0-9]',''); if($fd -and $d -and ($fd -like "*$d*")){ return $true } } }
        try{ $j=$row|ConvertTo-Json -Depth 80 -Compress; $jd=($j -replace '[^0-9]',''); if($jd -like "*$d*"){ return $true } }catch{}
        return $false
    }
}
function EmitRec([string]$rt,[string]$src,[string]$api,$obj,$extra){ EQ @{ kind='rec'; rt=$rt; src=$src; api=$api; obj=$obj; extra=$extra } }
function EmitDeep($deep,[string]$raw,[string]$api,$common){
    $callId="$($deep.id)"
    $base=@{ CallRecordId=$callId; RawJsonFile=$raw; CallRecordVersion=$deep.version; LastModifiedUtc=$deep.lastModifiedDateTime }
    if($common){ foreach($k in $common.Keys){ $base[$k]=$common[$k] } }
    EmitRec 'CallRecord' 'callRecords' $api $deep $base
    foreach($p in @($deep.participants_v2)){ EmitRec 'CallRecordParticipant' 'callRecords.participants_v2' $api $p $base }
    foreach($s in @($deep.sessions)){
        $sid="$($s.id)"; $bS=@{}+$base; $bS.SessionId=$sid
        EmitRec 'CallRecordSession' 'callRecords.sessions' $api $s $bS
        foreach($seg in @($s.segments)){
            $segid="$($seg.id)"; $bG=@{}+$bS; $bG.SegmentId=$segid
            EmitRec 'CallRecordSegment' 'callRecords.sessions.segments' $api $seg $bG
            foreach($m in @($seg.media)){
                $mlbl="$($m.label)"; $bM=@{}+$bG; $bM.MediaLabel=$mlbl
                EmitRec 'CallRecordMedia' 'callRecords.sessions.segments.media' $api $m $bM
                foreach($st in @($m.streams)){ EmitRec 'CallRecordStream' 'callRecords.sessions.segments.media.streams' $api $st $bM }
            }
        }
    }
}
$state.Running=$true
EQ @{ kind='reset' }
$stamp=Get-Date -Format 'yyyyMMdd_HHmmss'; $folder=Join-Path $cfg.RawRoot ("{0}_{1}" -f $cfg.EnvKey,$stamp)
try { if(-not (Test-Path $cfg.RawRoot)){ New-Item -Path $cfg.RawRoot -ItemType Directory -Force|Out-Null }; if(-not (Test-Path $folder)){ New-Item -Path $folder -ItemType Directory -Force|Out-Null } } catch {}
$seen=New-Object System.Collections.Generic.HashSet[string]
$crVer=@{}; $crFirst=@{}; $crLast=@{}
$flt=$cfg.Filter

do {
    if($state.Stop){ break }
    $state.CycleCount++
    $cyc=$state.CycleCount
    $suppress = ($cfg.Baseline -and $cyc -eq 1)
    if($suppress){ LOG ("[baseline $(Get-Date -Format 'HH:mm:ss')] marking existing records (silent)...") 'navy' }
    elseif($cyc % 60 -eq 0){ LOG ("[heartbeat $(Get-Date -Format 'HH:mm:ss')] cycle #$cyc  watching (log-rows $($seen.Count), callRecs $($crVer.Count))") 'gray' }
    $fromDate=$cfg.FromDate
    $toDate= if($cfg.Loop){ (Get-Date) } else { $cfg.ToDate }
    $fromIso=('{0:yyyy-MM-ddTHH:mm:ss}Z' -f $fromDate.ToUniversalTime())
    $toIso=('{0:yyyy-MM-ddTHH:mm:ss}Z' -f $toDate.ToUniversalTime())

    $kinds=@(); if($cfg.DoDR){ $kinds+='DirectRouting' }; if($cfg.DoPstn){ $kinds+='Pstn' }
    foreach($k in $kinds){
        if($state.Stop){ break }
        $fn=if($k -eq 'DirectRouting'){ 'getDirectRoutingCalls' } else { 'getPstnCalls' }
        $rows=@()
        try{ $rows=GraphGetAllEx "$($cfg.Graph)/communications/callRecords/$fn(fromDateTime=$fromIso,toDateTime=$toIso)" }
        catch{ LOG ("  $k pull failed: $($_.Exception.Message)") 'red'; continue }

        foreach($r in $rows){
            if($state.Stop){ break }
            if(-not (MatchUser $r $flt)){ continue }
            $id="$($r.id)"; if([string]::IsNullOrWhiteSpace($id)){ $id="$($r.callId)-$($r.startDateTime)-$k" }
            if($seen.Add("$k-$id")){
                if($suppress){ continue }
                $raw=SaveRaw $folder "$k-$id" $r
                $api=if($k -eq 'DirectRouting'){ "GET getDirectRoutingCalls(from=$fromIso,to=$toIso)" } else { "GET getPstnCalls(from=$fromIso,to=$toIso)" }
                $extra=@{ RawJsonFile=$raw; SeenAt=(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') }
                $latTxt=''
                if($cfg.Loop){ $lat=LatSec $r.endDateTime; $extra.FirstSeenUtc=((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')); $extra.LatencyEndSec=$lat; $latTxt="  latency=${lat}s" }
                EmitRec $k $k $api $r $extra
                LOG ("  NEW  [$k] $($r.startDateTime)  $($r.callerNumber) -> $($r.calleeNumber)  $($r.duration)s$latTxt  ($($r.userPrincipalName))") 'green'
            }
        }
    }

    if($cfg.DoFull -and -not $state.Stop){
        $nowU=(Get-Date).ToUniversalTime(); $fromU=$fromDate.ToUniversalTime(); $toU=$toDate.ToUniversalTime()
        $ceil=$nowU.AddMinutes(-2); $flr=$nowU.AddDays(-30).AddMinutes(2)
        if($toU -gt $ceil){ $toU=$ceil }; if($fromU -lt $flr){ $fromU=$flr }
        if($fromU -gt $toU){ $fromU=$toU.AddHours(-1) }
        $ff=$fromU.ToString('yyyy-MM-ddTHH:mm:ssZ')
        $tt=$toU.ToString('yyyy-MM-ddTHH:mm:ssZ')
        $filt="startDateTime ge $ff and startDateTime le $tt"
        $listUri="$($cfg.Graph)/communications/callRecords?`$filter=" + ($filt -replace ' ','%20')
        $basic=@(); try{ $basic=GraphGetAllEx $listUri } catch{ LOG ("  Full callRecords listing failed: $($_.Exception.Message)") 'red'; $basic=@() }
        foreach($cr in @($basic)){
            if($state.Stop){ break }
            $cid="$($cr.id)"; if([string]::IsNullOrWhiteSpace($cid)){ continue }
            $ver=0; try{ $ver=[int64]$cr.version }catch{}
            $isNew = -not $crVer.ContainsKey($cid)
            if($suppress){ $crVer[$cid]=$ver; $crFirst[$cid]=$nowU.AddMinutes(-999); $crLast[$cid]=$nowU; continue }
            if(-not $isNew){
                if($ver -le $crVer[$cid]){ continue }
                if(($nowU-$crFirst[$cid]).TotalMinutes -gt $cfg.RecheckMin){ continue }
            }
            try{
                $deep=DeepGet $cid; $crLast[$cid]=(Get-Date).ToUniversalTime()
                if(-not (MatchUser $deep $flt)){ $crVer[$cid]=$ver; if($isNew){ $crFirst[$cid]=(Get-Date).ToUniversalTime() }; continue }
                $crVer[$cid]=$ver
                if($isNew){ $crFirst[$cid]=(Get-Date).ToUniversalTime() }
                $tag= if($isNew){'NEW'}else{'UPDATED'}
                $api="GET callRecords/$cid?`$expand=sessions(`$expand=segments)"
                $raw=SaveRaw $folder "callRecord-$cid-v$ver" $deep
                $common=@{ UpdateTag=$tag }
                $latTxt=''
                if($cfg.Loop){ $latEnd=LatSec $deep.endDateTime; $latMod=LatSec $deep.lastModifiedDateTime; $common.FirstSeenUtc=$crFirst[$cid].ToString('yyyy-MM-ddTHH:mm:ssZ'); $common.LatencyEndSec=$latEnd; $common.LatencyModifiedSec=$latMod; $latTxt="  latEnd=${latEnd}s latMod=${latMod}s" }
                EmitDeep $deep $raw $api $common
                $col= if($isNew){'green'}else{'purple'}
                LOG ("  $tag [FullCallRecord v$ver]  $($deep.startDateTime)  type=$($deep.type)  modalities=$($deep.modalities -join ',')$latTxt") $col
                LOG ("       saved -> $raw") 'gray'
                foreach($p in @($deep.participants_v2)){
                    $who=$p.identity.user.displayName;
                    if([string]::IsNullOrWhiteSpace($who)){$who=$p.identity.phone.id};
                    if([string]::IsNullOrWhiteSpace($who)){$who=$p.identity.acsUser.id}; LOG ("       participant: $who") 'gray' }
                $si=0
                foreach($s in @($deep.sessions)){ $si++; LOG ("       session $si  $($s.caller.name) -> $($s.callee.name)   segments=$(@($s.segments).Count)") 'gray'
                    foreach($seg in @($s.segments)){ foreach($m in @($seg.media)){
                        $strm=@($m.streams)|Select-Object -First 1; LOG ("         media[$($m.label)] streams=$(@($m.streams).Count)  jitter=$($strm.averageAudioNetworkJitter)  roundTrip=$($strm.averageRoundTripTime)  packetLoss=$($strm.averagePacketLossRate)") 'gray' } } }
            } catch { LOG ("  callRecord detail failed for $cid : $($_.Exception.Message)") 'red' }
        }
    }

    if($suppress){ LOG ("  baseline complete - log-rows $($seen.Count), callRecs $($crVer.Count) marked.  Watching for NEW telemetry...") 'amber' }
    EQ @{ kind='cycle'; n=$cyc; baseline=$suppress }
    if(-not $cfg.Loop){ break }
    $delay=[double]$cfg.DelaySec; if($delay -lt 0){ $delay=0 }
    $slept=0.0
    while($slept -lt $delay -and -not $state.Stop){ Start-Sleep -Milliseconds 250; $slept+=0.25 }
    if($delay -lt 0.5 -and -not $state.Stop){ Start-Sleep -Milliseconds 300 }
} while(-not $state.Stop)

EQ @{ kind='stopped' }
$state.Running=$false
}

# ===== Drain timer =====
$script:drainTimer=New-Object System.Windows.Forms.Timer
$script:drainTimer.Interval=150
$script:drainTimer.Add_Tick({
    $q=$script:cdrState.Queue
    $n=0
    while ($q.Count -gt 0 -and $n -lt 400) {
        $item=$q.Dequeue(); $n++
        switch ($item.kind) {
            'log'   { Add-Cdr $item.text (CdrColor $item.color) }
            'reset' { $txtCdr.Clear(); $script:cdrRows.Clear() }
            'rec'   { $script:cdrRows.Add((New-CdrOutputRow -RecordType $item.rt -SourceEndpoint $item.src -ApiCommand $item.api -Object $item.obj -Extra $item.extra)) | Out-Null }
            'cycle' {
                if ($item.baseline) {
                    $lblAutoState.Text="Engine: LIVE  (baselined, watching for new)"; $lblAutoState.ForeColor=$clrGreen
                    $script:cdrPrevCount=$script:cdrRows.Count
                } else {
                    if ($script:cdrRows.Count -ne $script:cdrPrevCount) {
                        $path=Export-CdrCsv
                        if ($path) { Add-Cdr ("  saved $($script:cdrRows.Count) total rows -> $([IO.Path]::GetFileName($path))") $clrGreen }
                        $script:cdrPrevCount=$script:cdrRows.Count
                    }
                    $lblAutoState.Text="Engine: LIVE  (cycle #$($item.n), total $($script:cdrRows.Count))"; $lblAutoState.ForeColor=$clrGreen
                }
            }
            'stopped' {
                $path=Export-CdrCsv; if ($path) { Add-Cdr ("Stopped.  Final CSV: $path") ([System.Drawing.Color]::Navy) }
                Add-Cdr ("Raw JSON: $script:cdrRawRoot") $clrGray
                Set-CdrRunningUI $false
                $lblAutoState.Text="Engine: idle"; $lblAutoState.ForeColor=$clrGray
                Cleanup-CdrRunspace
            }
        }
    }
})
$script:drainTimer.Start()

function Set-CdrRunningUI { param([bool]$Running)
    $btnPullCdr.Enabled = -not $Running
    $btnAutoStart.Enabled = -not $Running
    $btnAutoStop.Enabled = $Running
    $numEvery.Enabled = -not $Running
    $txtCdrUser.Enabled = -not $Running
    $chkDR.Enabled = -not $Running; $chkPstn.Enabled = -not $Running; $chkFullCallRecords.Enabled = -not $Running
    $dtFrom.Enabled = -not $Running; $dtTo.Enabled = -not $Running; $btnConnect.Enabled = -not $Running
    $cmbEnv.Enabled = -not $Running
}
function Cleanup-CdrRunspace {
    try { if ($script:cdrPs) { if ($script:cdrAsync) { $script:cdrPs.EndInvoke($script:cdrAsync) | Out-Null }; $script:cdrPs.Dispose() } } catch {}
    try { if ($script:cdrRs) { $script:cdrRs.Close(); $script:cdrRs.Dispose() } } catch {}
    $script:cdrPs=$null; $script:cdrRs=$null; $script:cdrAsync=$null
}
function Start-CdrWorker { param([bool]$Loop,[bool]$Baseline)
    if ($script:cdrState.Running) { Add-Cdr "Engine already running." $clrAmber; return }
    if ([string]::IsNullOrWhiteSpace($script:Token)) { Add-Cdr "No API token.  Connect API first." ([System.Drawing.Color]::Firebrick); return }
    if (-not ($chkDR.Checked -or $chkPstn.Checked -or $chkFullCallRecords.Checked)) { Add-Cdr "Select at least one record type." ([System.Drawing.Color]::Firebrick); return }
    $fromDate = if ($Loop) { (Get-Date).Date } else { $dtFrom.Value.Date }
    # A DateTimePicker returns midnight, so .Date alone means "up to 00:00 that
    # morning" and silently excludes everything that happened on the To date -
    # including today's calls. Take the end of the chosen day instead.
    $toDate   = if ($Loop) { (Get-Date) } else { $dtTo.Value.Date.AddDays(1).AddTicks(-1) }
    if (-not $Loop -and $dtFrom.Value.Date -gt $dtTo.Value.Date) { Add-Cdr "From date must be on or before To date." ([System.Drawing.Color]::Firebrick); return }
    $txtCdr.Clear()
    if ($Loop) {
        Add-Cdr ("CDR LIVE engine ($($script:CurrentEnv))  -  baseline today, then only NEW/UPDATED telemetry") ([System.Drawing.Color]::Navy)
        Add-Cdr ("Filter: $(if ($txtCdrUser.Text.Trim()) { $txtCdrUser.Text.Trim() } else { '(all users)' })   Delay=$([int]$numEvery.Value)s") $clrGray
        Add-Cdr "Latency columns are recorded in AUTO mode only.  callRecords re-fetched on version bump for up to 60 min." $clrAmber
    } else {
        Add-Cdr ("CDR HISTORICAL pull ($($script:CurrentEnv))  -  $($fromDate.ToString('yyyy-MM-dd')) to $($toDate.ToString('yyyy-MM-dd'))  (no latency columns)") ([System.Drawing.Color]::Navy)
        Add-Cdr ("Filter: $(if ($txtCdrUser.Text.Trim()) { $txtCdrUser.Text.Trim() } else { '(all users)' })") $clrGray
    }
    $cfg=@{
        # Token is a SNAPSHOT. A long Auto run outlives it - the worker starts
        # 401ing roughly an hour in, which looks like intermittent network drops
        # rather than an auth expiry. Pass the credential so the worker can mint
        # its own, and the expiry so it knows when to.
        Token=$script:Token; Graph=$script:Graph
        # SecureString, not plaintext. The worker decrypts per renewal and zeroes
        # the buffer, so there is no long-lived cleartext copy for the life of
        # the run. Null when retention is off - the worker then runs on the
        # token it was handed and stops when that expires, which is the correct
        # behaviour for an operator who declined to store the credential.
        Secret=$script:TokenSecure; TenantId=$script:TenantId; ClientId=$script:ClientId
        TokenExpiry=$script:TokenExpiry
        EnvKey=$script:Environments[$script:CurrentEnv].Key; EnvLabel=$script:CurrentEnv
        Filter=$txtCdrUser.Text.Trim(); FromDate=$fromDate; ToDate=$toDate
        DoDR=[bool]$chkDR.Checked; DoPstn=[bool]$chkPstn.Checked; DoFull=[bool]$chkFullCallRecords.Checked
        Loop=$Loop; Baseline=$Baseline; DelaySec=[double]$numEvery.Value; RawRoot=$script:cdrRawRoot; RecheckMin=60
    }
    $script:cdrState.Stop=$false; $script:cdrState.CycleCount=0
    $script:cdrSessionCsv=$null; $script:cdrPrevCount=0
    while ($script:cdrState.Queue.Count -gt 0) { [void]$script:cdrState.Queue.Dequeue() }
    $script:cdrRs=[runspacefactory]::CreateRunspace(); $script:cdrRs.ApartmentState='MTA'; $script:cdrRs.Open()
    $script:cdrRs.SessionStateProxy.SetVariable('state',$script:cdrState)
    $script:cdrRs.SessionStateProxy.SetVariable('cfg',$cfg)
    $script:cdrPs=[powershell]::Create(); $script:cdrPs.Runspace=$script:cdrRs
    [void]$script:cdrPs.AddScript($script:cdrWorker.ToString()).AddArgument($script:cdrState).AddArgument($cfg)
    $script:cdrAsync=$script:cdrPs.BeginInvoke()
    Set-CdrRunningUI $true
    $lblAutoState.Text=if ($Loop) { "Engine: LIVE starting..." } else { "Engine: pulling..." }; $lblAutoState.ForeColor=$clrGreen
}
$btnPullCdr.Add_Click({ Start-CdrWorker -Loop:$false -Baseline:$false })
$btnAutoStart.Add_Click({ Start-CdrWorker -Loop:$true -Baseline:$true })
$btnAutoStop.Add_Click({ if ($script:cdrState.Running) { $script:cdrState.Stop=$true; Add-Cdr "Stop requested - finishing current record..." $clrAmber } })
$btnOpenCdr.Add_Click({ if ($script:LastCdrReport -and (Test-Path $script:LastCdrReport)) { Invoke-Item $script:LastCdrReport } else { Add-Cdr "No CDR report generated yet." ([System.Drawing.Color]::DimGray); return } })
$btnSaveLog.Add_Click({ if ($script:cdrLog.Count -eq 0) { Add-Cdr "No pull log yet." ([System.Drawing.Color]::DimGray); return };
    $key=$script:Environments[$script:CurrentEnv].Key; $logPath=Get-OutputPath -Area CdrLogs -File ("TeamsVoice_CDRPullLog_{0}_{1}.csv" -f $key,(Get-Date -Format 'yyyyMMdd_HHmmss'));
    try { $script:cdrLog | Export-Csv $logPath -NoTypeInformation -Encoding UTF8; Add-Cdr ("Pull log saved: $logPath") $clrGreen } catch { Add-Cdr "Save log failed: $($_.Exception.Message)" ([System.Drawing.Color]::Firebrick) } })

$form.Add_FormClosing({ try { $script:cdrState.Stop=$true } catch {}; try { if ($script:drainTimer) { $script:drainTimer.Stop() } } catch {}; Cleanup-CdrRunspace })

# ===== Wire env selector + initial load =====
$cmbEnv.Add_SelectedIndexChanged({ if (-not $cmbEnv.SelectedItem) { return }; if ($script:cdrState.Running) { Add-Status "Stop the CDR engine before switching environment." $clrAmber; $cmbEnv.SelectedItem=$script:CurrentEnv; return }; Switch-Environment $cmbEnv.SelectedItem })
if ($script:CurrentEnv) { Switch-Environment $script:CurrentEnv } else { Clear-EnvironmentUI }

$form.Controls.Add($tabs); $form.Controls.Add($spnBar); $form.Controls.Add($banner)
[void]$form.ShowDialog()
