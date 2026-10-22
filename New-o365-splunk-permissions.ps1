<#
.SYNOPSIS
    Creates an Entra ID app <NAME>-SPLUNK-O365 (app registration + enterprise app) for the
    Splunk Add-on for Microsoft Office 365 (v6.0.0+) and Entra ID (Azure AD) audit logs,
    grants admin consent for the application permissions and creates a client secret.

.DESCRIPTION
    1. creates the app registration + enterprise app <NAME>-SPLUNK-O365 (reused if it exists)
    2. adds the API permissions to the app registration (visible under "API permissions")
    3. grants admin consent (app role assignments on the service principal)
    4. creates a client secret valid for -SecretYears (default 100)
    5. optionally removes Application.ReadWrite.All again (see -RemoveAppReadWrite)

    Required permissions (Application type):
      Microsoft Graph
        ServiceHealth.Read.All, ServiceMessage.Read.All, AuditLog.Read.All, Reports.Read.All,
        ExchangeMessageTrace.Read.All, User.Read.All, Group.Read.All, Directory.Read.All
        + for Entra ID / security inputs: Application.Read.All, IdentityRiskyUser.Read.All,
          SecurityEvents.Read.All
      Office 365 Management APIs
        ActivityFeed.Read

    Splunk Add-on for Microsoft 365 Defender - required:
      Microsoft Graph (default)
        SecurityIncident.Read.All, SecurityAlert.Read.All, ThreatHunting.Read.All
      or with -DefenderLegacyApi (Microsoft 365 Defender APIs)
        Microsoft Threat Protection: Incident.Read.All, AdvancedHunting.Read.All
        WindowsDefenderATP:          Alert.Read.All
      always (Microsoft Graph)
        AttackSimulation.Read.All, ThreatIntelligence.Read.All

    Optional permissions (skip with -SkipOptional):
      Microsoft Graph
        Application.ReadWrite.All            - lets Splunk set up the Message Trace prerequisites itself
        InformationProtectionPolicy.Read.All - published sensitivity labels and label policies
        GroupMember.ReadWrite.All            - "Add Member to Group" alert action
        SecurityIncident.ReadWrite.All       - Defender "update incident" alert action
                                               (Microsoft Threat Protection Incident.ReadWrite.All with -DefenderLegacyApi)
      Office 365 Management APIs
        ActivityFeed.ReadDlp                 - DLP events (needs an additional Entra ID subscription)

    The Defender Event Hub input (ms:defender:eventhub) needs no API permission - give the app the
    "Azure Event Hubs Data Receiver" role on the Event Hub instead.

    Only for USGovGCC / USGovGCCHigh tenants (-GovTenant):
      Office 365 Exchange Online ReportingWebService.Read.All (Message Trace through RWS)
      ExchangeMessageTrace.Read.All and Application.ReadWrite.All are then not added.

    Application.ReadWrite.All is only needed until Splunk has finished the Message Trace setup.
    After the Message Trace input has run once successfully, remove it again:
        .\New-o365-splunk-permissions.ps1 -Tenant "domain.si" -Name "CUSTOMER" -RemoveAppReadWrite
    The first run also offers to wait and remove it at the end.

    Delegated ActivityFeed.* permissions and IdentityRiskyUser.ReadWrite.All are NOT added -
    the add-on uses application permissions only and read access is enough.

    The secret is shown only once at the end. Every run (except -RemoveAppReadWrite) adds a NEW secret.

.EXAMPLE
    .\New-o365-splunk-permissions.ps1 -Tenant "secureon.si" -Name "SECUREON"

    Result:
        Enterprise app : SECUREON-SPLUNK-O365
        Permissions    : required + optional, admin consent granted
        Client secret  : valid for 100 years, shown once at the end

.EXAMPLE
    .\New-o365-splunk-permissions.ps1 -Tenant "secureon.si" -Name "SECUREON" -RemoveAppReadWrite

    Removes Application.ReadWrite.All (consent + API permission entry) once Splunk no longer needs it.

.NOTES
    Author  : Luka Krizman, SECUROEN
    Modules : Microsoft.Graph.Applications
    Roles   : Global Administrator or Privileged Role Administrator (admin consent for Graph app roles)
    See     : https://splunk.github.io/splunk-add-on-for-microsoft-office-365/ConfigureAppinAzureAD/
#>

[CmdletBinding()]
param(
    # Tenant primary domain or tenant ID
    [string]$Tenant      = "domain.si",
    # Base name - the app is named <NAME>-SPLUNK-O365
    [string]$Name        = "CUSTOMER",
    # Full app name - leave empty to derive it from -Name
    [string]$AppName     = "",
    # Client secret lifetime in years
    [ValidateRange(1, 100)]
    [int]   $SecretYears = 100,
    # Do not add the optional permissions
    [switch]$SkipOptional,
    # USGovGCC / USGovGCCHigh tenant - Message Trace through Exchange RWS instead of Graph
    [switch]$GovTenant,
    # Defender incidents/alerts/hunting through the legacy Microsoft 365 Defender APIs instead of Graph
    [switch]$DefenderLegacyApi,
    # Only remove Application.ReadWrite.All from an existing app (no new secret)
    [switch]$RemoveAppReadWrite
)

$ErrorActionPreference = "Stop"
$PSDefaultParameterValues['*-Mg*:ErrorAction'] = 'Stop'

if (-not $AppName) { $AppName = "$($Name.ToUpper())-SPLUNK-O365" }

# Resource app IDs (same in every tenant)
$GraphAppId    = "00000003-0000-0000-c000-000000000000"   # Microsoft Graph
$O365MgmtAppId = "c5393580-f805-4401-95e8-94b7a6ef2fc2"   # Office 365 Management APIs
$ExchangeAppId = "00000002-0000-0ff1-ce00-000000000000"   # Office 365 Exchange Online
$MtpAppId      = "8ee8fdad-f234-4243-8f3b-15c294843740"   # Microsoft Threat Protection (Defender XDR API)
$MdeAppId      = "fc780465-2017-40d4-a0c5-307022471b92"   # WindowsDefenderATP

$required = @{
    $GraphAppId    = @(
        "ServiceHealth.Read.All", "ServiceMessage.Read.All", "AuditLog.Read.All", "Reports.Read.All",
        "User.Read.All", "Group.Read.All", "Directory.Read.All",
        "Application.Read.All", "IdentityRiskyUser.Read.All", "SecurityEvents.Read.All"
    )
    $O365MgmtAppId = @("ActivityFeed.Read")
}
$optional = @{
    $GraphAppId    = @("InformationProtectionPolicy.Read.All", "GroupMember.ReadWrite.All")
    $O365MgmtAppId = @("ActivityFeed.ReadDlp")
}
# Splunk Add-on for Microsoft 365 Defender
if ($DefenderLegacyApi) {
    $required[$MtpAppId]   = @("Incident.Read.All", "AdvancedHunting.Read.All")
    $required[$MdeAppId]   = @("Alert.Read.All")
    $optional[$MtpAppId]   = @("Incident.ReadWrite.All")
}
else {
    $required[$GraphAppId] += "SecurityIncident.Read.All", "SecurityAlert.Read.All", "ThreatHunting.Read.All"
    $optional[$GraphAppId] += "SecurityIncident.ReadWrite.All"
}
$required[$GraphAppId] += "AttackSimulation.Read.All", "ThreatIntelligence.Read.All"

if ($GovTenant) {
    $required[$ExchangeAppId] = @("ReportingWebService.Read.All")
}
else {
    $required[$GraphAppId] += "ExchangeMessageTrace.Read.All"
    $optional[$GraphAppId] += "Application.ReadWrite.All"
}

# Merge required + optional into one list per resource
$sets = if ($SkipOptional) { @($required) } else { @($required, $optional) }
$wanted = @{}
foreach ($set in $sets) {
    foreach ($resourceAppId in $set.Keys) { $wanted[$resourceAppId] = @($wanted[$resourceAppId]) + $set[$resourceAppId] | Where-Object { $_ } }
}

# Retries a script block while Entra replicates newly created objects
function Invoke-WithRetry {
    param([scriptblock]$Action, [string]$Activity, [int]$MaxAttempts = 20, [int]$DelaySeconds = 15)
    for ($i = 1; ; $i++) {
        try { return & $Action }
        catch {
            if ($i -ge $MaxAttempts) { throw "$Activity failed after $MaxAttempts attempts: $($_.Exception.Message)" }
            Write-Host "  Waiting for replication - $Activity (attempt $i/$MaxAttempts)..." -ForegroundColor DarkYellow
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

# Returns the tenant's service principal of a Microsoft resource API, creating it if missing
function Get-ResourceServicePrincipal {
    param([string]$AppId)
    $resSp = Get-MgServicePrincipal -Filter "appId eq '$AppId'" | Select-Object -First 1
    if (-not $resSp) {
        Write-Host "  Resource service principal $AppId missing in tenant - creating it..." -ForegroundColor DarkYellow
        $resSp = New-MgServicePrincipal -AppId $AppId
    }
    $resSp
}

# Removes Application.ReadWrite.All consent + API permission entry from the app
function Remove-AppReadWrite {
    param($App, $Sp, $GraphSp)
    $role = $GraphSp.AppRoles | Where-Object { $_.Value -eq "Application.ReadWrite.All" -and $_.AllowedMemberTypes -contains "Application" }

    $assignment = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $Sp.Id -All |
        Where-Object { $_.ResourceId -eq $GraphSp.Id -and $_.AppRoleId -eq $role.Id }
    if ($assignment) {
        Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $Sp.Id -AppRoleAssignmentId $assignment.Id
        Write-Host "Admin consent for Application.ReadWrite.All removed." -ForegroundColor Green
    }
    else {
        Write-Host "Application.ReadWrite.All is not consented." -ForegroundColor Yellow
    }

    $App = Get-MgApplication -ApplicationId $App.Id
    $rra = @(foreach ($r in $App.RequiredResourceAccess) {
        @{
            resourceAppId  = $r.ResourceAppId
            resourceAccess = @($r.ResourceAccess | Where-Object { $_.Id -ne $role.Id } | ForEach-Object { @{ id = $_.Id; type = $_.Type } })
        }
    }) | Where-Object { $_.resourceAccess.Count -gt 0 }
    Update-MgApplication -ApplicationId $App.Id -RequiredResourceAccess @($rra)
    Write-Host "Application.ReadWrite.All removed from API permissions." -ForegroundColor Green
}

# --- 1. Connect to Graph ------------------------------------------------------
Write-Host "Connecting to Microsoft Graph ($Tenant)..." -ForegroundColor Cyan
Connect-MgGraph -TenantId $Tenant -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All" -NoWelcome
$tenantId = (Get-MgContext).TenantId
Write-Host "Tenant ID      : $tenantId" -ForegroundColor DarkGray
Write-Host "Enterprise app : $AppName"

$graphSp = Get-ResourceServicePrincipal -AppId $GraphAppId

# --- 2. App registration + enterprise app (service principal) -----------------
$app = Get-MgApplication -Filter "displayName eq '$AppName'" | Select-Object -First 1

if ($RemoveAppReadWrite) {
    if (-not $app) { throw "App registration '$AppName' not found." }
    $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" | Select-Object -First 1
    if (-not $sp) { throw "Enterprise app for '$AppName' not found." }
    Remove-AppReadWrite -App $app -Sp $sp -GraphSp $graphSp
    Disconnect-MgGraph | Out-Null
    return
}

if ($app) {
    Write-Host "`nReusing existing app registration '$AppName' ($($app.AppId))" -ForegroundColor Yellow
}
else {
    Write-Host "`nCreating app registration '$AppName'..." -ForegroundColor Cyan
    $app = New-MgApplication -DisplayName $AppName -SignInAudience "AzureADMyOrg" `
        -Notes "Splunk Add-on for Microsoft Office 365 - O365 management activity, message trace and Entra ID audit logs."
}

$sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" | Select-Object -First 1
if (-not $sp) {
    Write-Host "Creating enterprise application (service principal)..." -ForegroundColor Cyan
    $sp = Invoke-WithRetry -Activity "service principal" -Action { New-MgServicePrincipal -AppId $app.AppId -ErrorAction Stop }
}
Write-Host "App (client) ID : $($app.AppId)"
Write-Host "SP object ID    : $($sp.Id)"

# --- 3. Resolve permissions to app role IDs -----------------------------------
$resolved = @()   # one entry per permission: ResourceSp, Role
foreach ($resourceAppId in $wanted.Keys) {
    $resSp = if ($resourceAppId -eq $GraphAppId) { $graphSp } else { Get-ResourceServicePrincipal -AppId $resourceAppId }
    foreach ($perm in ($wanted[$resourceAppId] | Select-Object -Unique)) {
        $role = $resSp.AppRoles | Where-Object { $_.Value -eq $perm -and $_.AllowedMemberTypes -contains "Application" }
        if (-not $role) {
            Write-Host "  '$perm' not found on $($resSp.DisplayName) - skipped." -ForegroundColor Red
            continue
        }
        $resolved += [PSCustomObject]@{ ResourceSp = $resSp; Role = $role }
    }
}

# --- 4. API permissions on the app registration -------------------------------
# Merge with what the app already has so reruns never drop existing permissions
Write-Host "`nSetting API permissions on the app registration..." -ForegroundColor Cyan
$app = Get-MgApplication -ApplicationId $app.Id
$access = @{}
foreach ($r in $app.RequiredResourceAccess) {
    $access[$r.ResourceAppId] = @($r.ResourceAccess | ForEach-Object { @{ id = $_.Id; type = $_.Type } })
}
foreach ($item in $resolved) {
    $resAppId = $item.ResourceSp.AppId
    if (-not $access.ContainsKey($resAppId)) { $access[$resAppId] = @() }
    if ($access[$resAppId].id -notcontains $item.Role.Id) {
        $access[$resAppId] += @{ id = $item.Role.Id; type = "Role" }
    }
}
$rra = foreach ($key in $access.Keys) { @{ resourceAppId = $key; resourceAccess = $access[$key] } }
Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess @($rra)

# --- 5. Admin consent (app role assignments) ----------------------------------
Write-Host "Granting admin consent..." -ForegroundColor Cyan
$assigned = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All
foreach ($item in $resolved) {
    $label = "$($item.ResourceSp.DisplayName) / $($item.Role.Value)"
    if ($assigned | Where-Object { $_.ResourceId -eq $item.ResourceSp.Id -and $_.AppRoleId -eq $item.Role.Id }) {
        Write-Host "  $label - already granted" -ForegroundColor Yellow
        continue
    }
    Invoke-WithRetry -Activity "consent $label" -Action {
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id `
            -ResourceId $item.ResourceSp.Id -AppRoleId $item.Role.Id -ErrorAction Stop | Out-Null
    }
    Write-Host "  $label - granted" -ForegroundColor Green
}

# --- 6. Client secret (created last so failures don't leave stray secrets) ----
Write-Host "`nCreating client secret valid for $SecretYears years..." -ForegroundColor Cyan
$secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
    displayName = "Splunk-$SecretYears-years-$(Get-Date -Format 'yyyyMMdd')"
    endDateTime = (Get-Date).AddYears($SecretYears).ToUniversalTime()
}

# --- 7. Output ----------------------------------------------------------------
Write-Host "=========== SAVE THESE VALUES (secret is shown only once) ===========" -ForegroundColor Yellow
[PSCustomObject]@{
    TenantId     = $tenantId
    ClientId     = $app.AppId
    ClientSecret = $secret.SecretText
    SecretExpiry = $secret.EndDateTime
    AppName      = $AppName
    Permissions  = ($resolved | ForEach-Object { $_.Role.Value }) -join ", "
} | Format-List

# --- 8. Optionally remove Application.ReadWrite.All right away ----------------
if ($resolved.Role.Value -contains "Application.ReadWrite.All") {
    Write-Host "Application.ReadWrite.All is only needed until Splunk finishes the Message Trace setup." -ForegroundColor Yellow
    $answer = Read-Host "Configure the Message Trace input in Splunk now, then type 'remove' to drop it (Enter = keep it for now)"
    if ($answer.Trim() -eq "remove") {
        Remove-AppReadWrite -App $app -Sp $sp -GraphSp $graphSp
    }
    else {
        Write-Host "Kept. Remove later with: .\New-o365-splunk-permissions.ps1 -Tenant `"$Tenant`" -AppName `"$AppName`" -RemoveAppReadWrite" -ForegroundColor Yellow
    }
}

Disconnect-MgGraph | Out-Null
