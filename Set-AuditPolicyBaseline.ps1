<#
.SYNOPSIS
    Applies the SECUREON Advanced Audit Policy baseline (TA-audit-check) to the local machine.

.DESCRIPTION
    For hosts that do not receive the policy by GPO (workgroup / non-domain machines).
    - Enables Success and/or Failure for every subcategory the baseline requires
      (lookups/audit_policy_baseline.csv). Settings are only ADDED: nothing that is already
      enabled is switched off, subcategories with "No Auditing" in the baseline are untouched.
    - DC-only subcategories (DS Access: Directory Service Access / Changes, DPAPI Activity)
      are applied only on domain controllers, unless -IncludeDcPolicies.
    - Sets "Audit: Force audit policy subcategory settings ... to override audit policy
      category settings" = Enabled (SCENoApplyLegacyAuditPolicy = 1) and the other Audit:
      options from audit_security_options_baseline.csv (CrashOnAuditFail,
      FullPrivilegeAuditing, AuditBaseObjects = Disabled), unless -SkipSecurityOptions.
    - Writes a backup (auditpol /backup) before changing anything; restore with
      auditpol /restore /file:<backup>.
    Subcategories are addressed by GUID, so it works on any Windows language.
    Supports -WhatIf. Must run elevated (Administrator or SYSTEM).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Set-AuditPolicyBaseline.ps1 -WhatIf
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Set-AuditPolicyBaseline.ps1
.EXAMPLE
    .\Set-AuditPolicyBaseline.ps1 -BaselineCsv .\audit_policy_baseline.csv -IncludeDcPolicies
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # Optional: use this baseline file (same format as lookups/audit_policy_baseline.csv)
    [string]$BaselineCsv,
    # Apply DC-only subcategories also on non-DC hosts
    [switch]$IncludeDcPolicies,
    # Do not change the Audit: security options (Force subcategory settings etc.)
    [switch]$SkipSecurityOptions,
    # Folder for the auditpol backup
    [string]$BackupPath = $env:TEMP
)

$ErrorActionPreference = 'Stop'
$auditpol = Join-Path $env:SystemRoot 'System32\auditpol.exe'

# Required subcategories from lookups/audit_policy_baseline.csv (guid,subcategory,req_success,req_failure,dc_only)
$embedded = @'
guid,subcategory,req_success,req_failure,dc_only
{0CCE923F-69AE-11D9-BED3-505054503030},Audit Credential Validation,1,1,0
{0CCE9242-69AE-11D9-BED3-505054503030},Audit Kerberos Authentication Service,1,1,0
{0CCE9240-69AE-11D9-BED3-505054503030},Audit Kerberos Service Ticket Operations,1,1,0
{0CCE9241-69AE-11D9-BED3-505054503030},Audit Other Account Logon Events,1,1,0
{0CCE9239-69AE-11D9-BED3-505054503030},Audit Application Group Management,1,1,0
{0CCE9236-69AE-11D9-BED3-505054503030},Audit Computer Account Management,1,1,0
{0CCE9238-69AE-11D9-BED3-505054503030},Audit Distribution Group Management,1,1,0
{0CCE923A-69AE-11D9-BED3-505054503030},Audit Other Account Management Events,1,1,0
{0CCE9237-69AE-11D9-BED3-505054503030},Audit Security Group Management,1,1,0
{0CCE9235-69AE-11D9-BED3-505054503030},Audit User Account Management,1,1,0
{0CCE922D-69AE-11D9-BED3-505054503030},Audit DPAPI Activity,1,1,1
{0CCE922B-69AE-11D9-BED3-505054503030},Audit Process Creation,1,1,0
{0CCE922C-69AE-11D9-BED3-505054503030},Audit Process Termination,1,1,0
{0CCE922E-69AE-11D9-BED3-505054503030},Audit RPC Events,1,1,0
{0CCE923B-69AE-11D9-BED3-505054503030},Audit Directory Service Access,1,1,1
{0CCE923C-69AE-11D9-BED3-505054503030},Audit Directory Service Changes,1,1,1
{0CCE9217-69AE-11D9-BED3-505054503030},Audit Account Lockout,1,1,0
{0CCE9216-69AE-11D9-BED3-505054503030},Audit Logoff,1,1,0
{0CCE9215-69AE-11D9-BED3-505054503030},Audit Logon,1,1,0
{0CCE9243-69AE-11D9-BED3-505054503030},Audit Network Policy Server,1,1,0
{0CCE921C-69AE-11D9-BED3-505054503030},Audit Other Logon/Logoff Events,1,1,0
{0CCE921B-69AE-11D9-BED3-505054503030},Audit Special Logon,1,1,0
{0CCE9222-69AE-11D9-BED3-505054503030},Audit Application Generated,1,1,0
{0CCE9221-69AE-11D9-BED3-505054503030},Audit Certification Services,1,1,0
{0CCE9224-69AE-11D9-BED3-505054503030},Audit File Share,1,1,0
{0CCE921D-69AE-11D9-BED3-505054503030},Audit File System,1,1,0
{0CCE921F-69AE-11D9-BED3-505054503030},Audit Kernel Object,1,1,0
{0CCE9227-69AE-11D9-BED3-505054503030},Audit Other Object Access Events,1,1,0
{0CCE921E-69AE-11D9-BED3-505054503030},Audit Registry,1,1,0
{0CCE9245-69AE-11D9-BED3-505054503030},Audit Removable Storage,1,1,0
{0CCE922F-69AE-11D9-BED3-505054503030},Audit Audit Policy Change,1,1,0
{0CCE9230-69AE-11D9-BED3-505054503030},Audit Authentication Policy Change,1,1,0
{0CCE9231-69AE-11D9-BED3-505054503030},Audit Authorization Policy Change,1,1,0
{0CCE9234-69AE-11D9-BED3-505054503030},Audit Other Policy Change Events,1,1,0
{0CCE9228-69AE-11D9-BED3-505054503030},Audit Sensitive Privilege Use,1,1,0
{0CCE9210-69AE-11D9-BED3-505054503030},Audit Security State Change,1,1,0
{0CCE9211-69AE-11D9-BED3-505054503030},Audit Security System Extension,1,1,0
{0CCE9212-69AE-11D9-BED3-505054503030},Audit System Integrity,1,1,0
'@

# --- checks -------------------------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script elevated (Run as Administrator) or as SYSTEM.'
}

$baseline = if ($BaselineCsv) { Import-Csv -Path $BaselineCsv } else { $embedded | ConvertFrom-Csv }
$baseline = @($baseline | Where-Object { $_.req_success -eq '1' -or $_.req_failure -eq '1' })
if ($baseline.Count -eq 0) { throw 'Baseline contains no required subcategories.' }

$domainRole = [int](Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
$isDc = $domainRole -ge 4
$roleText = @('Standalone workstation', 'Member workstation', 'Standalone server', 'Member server', 'Backup DC', 'Primary DC')[$domainRole]
Write-Host "Host: $env:COMPUTERNAME ($roleText)"
if ($domainRole -in 1, 3, 4, 5) {
    Write-Warning 'This host is domain joined - a domain GPO with Advanced Audit Policy will override local settings at the next refresh.'
}

# --- backup -------------------------------------------------------------------------
if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Backup current audit policy')) {
    $backup = Join-Path $BackupPath ('auditpol_backup_{0}_{1:yyyyMMdd_HHmmss}.csv' -f $env:COMPUTERNAME, (Get-Date))
    & $auditpol /backup /file:"$backup" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "auditpol /backup failed (exit $LASTEXITCODE)" }
    Write-Host "Backup: $backup  (restore: auditpol /restore /file:`"$backup`")"
}

# --- subcategories ------------------------------------------------------------------
$results = foreach ($b in $baseline) {
    $guid = $b.guid.Trim().ToUpper()
    if ($b.dc_only -eq '1' -and -not $isDc -and -not $IncludeDcPolicies) {
        [pscustomobject]@{ Subcategory = $b.subcategory; Applied = ''; Result = 'Skipped (DC only)' }
        continue
    }
    $apArgs = @('/set', "/subcategory:$guid")
    $what = @()
    if ($b.req_success -eq '1') { $apArgs += '/success:enable'; $what += 'Success' }
    if ($b.req_failure -eq '1') { $apArgs += '/failure:enable'; $what += 'Failure' }

    $result = 'WhatIf'
    if ($PSCmdlet.ShouldProcess("$($b.subcategory) $guid", "Enable $($what -join ', ')")) {
        $out = & $auditpol @apArgs 2>&1
        $result = if ($LASTEXITCODE -eq 0) { 'OK' } else { "ERROR $LASTEXITCODE $out" }
    }
    [pscustomobject]@{ Subcategory = $b.subcategory; Applied = ($what -join ', '); Result = $result }
}
$results | Format-Table -AutoSize | Out-String -Width 200 | Write-Host

# --- Audit: security options --------------------------------------------------------
if (-not $SkipSecurityOptions) {
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    if ($PSCmdlet.ShouldProcess('SCENoApplyLegacyAuditPolicy', 'Set to 1 (Force audit policy subcategory settings = Enabled)')) {
        New-ItemProperty -Path $lsa -Name 'SCENoApplyLegacyAuditPolicy' -PropertyType DWord -Value 1 -Force | Out-Null
        Write-Host 'Audit: Force audit policy subcategory settings = Enabled'
    }
    foreach ($opt in 'CrashOnAuditFail', 'FullPrivilegeAuditing', 'AuditBaseObjects') {
        if ($PSCmdlet.ShouldProcess($opt, 'Set to Disabled')) {
            $out = & $auditpol /set /option:$opt /value:disable 2>&1
            if ($LASTEXITCODE -eq 0) { Write-Host "Audit option $opt = Disabled" }
            else { Write-Warning "auditpol /set /option:$opt failed (exit $LASTEXITCODE): $out" }
        }
    }
}

$failed = @($results | Where-Object { $_.Result -like 'ERROR*' })
if ($failed.Count) {
    Write-Warning "$($failed.Count) subcategory setting(s) failed - see table above."
    exit 1
}
Write-Host 'Done. Verify with: auditpol /get /category:*  (the Splunk dashboard updates after the next scheduled run).'
