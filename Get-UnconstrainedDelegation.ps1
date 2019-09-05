<#
.Synopsis
    Search the domains for accounts with Unconstrained Kerberos Delegation.  This is an attempt at test-driven security, where I write code to prove a fault, work to to eliminate the fault, then schedule a version of the code
  to continuously look for a reoccurance of the fault.
.DESCRIPTION
  This script REQUIRES
  (1) Powershell 5.0 or above
  (2) Set-ExecutionPolicy to "RemoteSigned" (Type "Set-ExecutionPolicy RemoteSigned" at an elevated PowerShell prompt)
  (3) Remote Server Admin Tools Active Directory module for Windows PowerShell
  (4) Modify variables in the "define variables" region to match your environment
  (5) Schedule this to be ran on a frequent basis.  The tool will only send an email if it finds exceptions.

    Kerberos Delegation is a security sensitive configuration. Especially
    full (unconstrained) delegation has significant impact: any service
    that is configured with full delegation can take any account that
    authenticates to it, and impersonate that account for any other network 
    service that it likes. So, if a Domain Admin were to use that service,
    the service in turn could read the hash of KRBRTG and immediately 
    effectuate a golden ticket. Etc :)
        
    Main takeaway: chase all services with unconstrained delegation. If 
    these are _not_ DC accounts, reconfigure them with constrained delegation, 
    OR claim them als DCs from a security perspective. Meaning, that the AD 
    team manages the service and the servers it runs on. 

.NOTES
    Version:        Based heavily upon a script written by Willem Kasdorp, Microsoft. 
    Author:         J. Mike Mills
    Creation Date:  4/1/2019
#>
#region define variables
$DomainControllers = "dc01.domain.tld","dc01.differentdomain.tld" #specify a DC per domain that you wish to scan.  Useful for forests with multiple domains.
$Groups = "Server Operators","Schema Admins","Print Operators","Enterprise Admins","Domain Admins","Cert Publishers","Backup Operators","Account Operators" #define which groups are "administrative" add your custom groups if necessary.
$OutputPath="\\servername\report-path\" #Can be a local file or a network share
$OutputFile = $OutputPath + 'AD-Privileged-Accounts-Weak-Config' + $Date + '.csv'

#email parameter setup
$Recipients = "user@domain.com" #specify your email recipients.  I send to my ticketing software to create a ticket for me.
$SmtpServer = "mail.domain.com" #specify your mail server.
$Sender = "no-reply@domain.com" #specify your "from" address
$Body = "Filename: Get-UnconstrainedDelgation.ps1, executed from: $env:COMPUTERNAME, executed by: $env:USERNAME<br/><br/>Description: Search the domains for accounts with Unconstrained Kerberos Delegation.<br/><br/>The tool evaluates accounts and alerts if a non-DC account is configured with Unconstrained Delegation.<br/><br/><br/>"
#endregion define variables

$SERVER_TRUST_ACCOUNT = 0x2000
$TRUSTED_FOR_DELEGATION = 0x80000
$TRUSTED_TO_AUTH_FOR_DELEGATION= 0x1000000
$PARTIAL_SECRETS_ACCOUNT = 0x4000000  
$bitmask = $TRUSTED_FOR_DELEGATION -bor $TRUSTED_TO_AUTH_FOR_DELEGATION -bor $PARTIAL_SECRETS_ACCOUNT

# LDAP filter to find all accounts having some form of delegation.
# 1.2.840.113556.1.4.804 is an OR query. 
$filter = @"
(&
  (servicePrincipalname=*)
  (|
    (msDS-AllowedToActOnBehalfOfOtherIdentity=*)
    (msDS-AllowedToDelegateTo=*)
    (UserAccountControl:1.2.840.113556.1.4.804:=$bitmask)
  )
  (|
    (objectcategory=computer)
    (objectcategory=person)
    (objectcategory=msDS-GroupManagedServiceAccount)
    (objectcategory=msDS-ManagedServiceAccount)
  )
)
"@ -replace "[\s\n]", ''

$propertylist = @(
    "servicePrincipalname", 
    "useraccountcontrol", 
    "samaccountname", 
    "msDS-AllowedToDelegateTo", 
    "msDS-AllowedToActOnBehalfOfOtherIdentity"
)

$Object_List = @()

$DomainControllers | ForEach-Object {
    [string]$DN = (Get-ADDomain -server $_).DistinguishedName
    Get-ADObject -server $_ -LDAPFilter $filter -SearchBase $DN -SearchScope Subtree -Properties $propertylist -PipelineVariable account | ForEach-Object {
        $isDC = ($account.useraccountcontrol -band $SERVER_TRUST_ACCOUNT) -ne 0
        $fullDelegation = ($account.useraccountcontrol -band $TRUSTED_FOR_DELEGATION) -ne 0
        $constrainedDelegation = ($account.'msDS-AllowedToDelegateTo').count -gt 0
        $isRODC = ($account.useraccountcontrol -band $PARTIAL_SECRETS_ACCOUNT) -ne 0
        $resourceDelegation = $account.'msDS-AllowedToActOnBehalfOfOtherIdentity' -ne $null
    
        $comment = ""
        if ((-not $isDC) -and $fullDelegation) { 
            $comment += "Full delegation to non-DC is not recommended!; " 
        }
        if ($isRODC) { 
            $comment += "WARNING: investigation needed if this is not a real RODC; " 
        }
        if ($resourceDelegation) { 
            # to count it using PS, we need the object type to select the correct function... broken, but there we are. 
            $comment += "INFO: Account allows delegation FROM other server(s); " 
        }
        if ($constrainedDelegation) { 
            $comment += "INFO: constrained delegation service count: $(($account.'msDS-AllowedToDelegateTo').count); " 
        }
        IF ($isDC -eq $false -and $fullDelegation -eq $true) {
            $Object = New-Object PSObject
            Add-Member -InputObject $Object -MemberType NoteProperty -Name BaseDN -Value $DN
            Add-Member -InputObject $Object -MemberType NoteProperty -Name samaccountname -Value $account.samaccountname
            Add-Member -InputObject $Object -MemberType NoteProperty -Name objectClass -Value $account.objectclass
            #Add-Member -InputObject $Object -MemberType NoteProperty -Name uac -Value ('{0:x}' -f $account.useraccountcontrol)
            #Add-Member -InputObject $Object -MemberType NoteProperty -Name isDC -Value $isDC
            Add-Member -InputObject $Object -MemberType NoteProperty -Name isRODC -Value $isRODC
            #Add-Member -InputObject $Object -MemberType NoteProperty -Name fullDelegation -Value $fullDelegation
            #Add-Member -InputObject $Object -MemberType NoteProperty -Name constrainedDelegation -Value $constrainedDelegation
            Add-Member -InputObject $Object -MemberType NoteProperty -Name resourceDelegation -Value $resourceDelegation
            Add-Member -InputObject $Object -MemberType NoteProperty -Name comment -Value $comment
            $Object_List += $Object
        }
    }
}
If ($Object_List -ne $null) {
    $Body = $Body +  ($Object_List|ConvertTo-Html)
    #Alert via email
    Send-MailMessage -SmtpServer $SmtpServer -From $Sender -To $Recipients -Subject "AD accounts with unconstrained delgation" -Body $Body -BodyAsHtml
    }