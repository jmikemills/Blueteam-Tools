<#
.SYNOPSIS
  Look through all specified domains, searching for accounts that are members of groups that provide elevated rights and check that the account is configured per 
  security best practices.  This is an attempt at test-driven security, where I write code to prove a fault, work to to eliminate the fault, then schedule a version of the code
  to continuously look for a reoccurance of the fault.

.DESCRIPTION
  This script REQUIRES
  (1) Powershell 5.0 or above
  (2) Set-ExecutionPolicy to "RemoteSigned" (Type "Set-ExecutionPolicy RemoteSigned" at an elevated PowerShell prompt)
  (3) Remote Server Admin Tools Active Directory module for Windows PowerShell
  (4) Modify variables in the "define variables" region to match your environment
  (5) Schedule this to be ran on a frequent basis.  The tool will only send an email if it finds exceptions.

.INPUTS
  AD information

.OUTPUTS
  CSV file, email

.NOTES
  Version:        1.0
  Author:         JMM
  Creation Date:  20190215
  Purpose/Change: Initial script

.TODO
  Parameterize
  Incorporate additional items to monitor
#>

#Get today's date in ISO 8601, because only cavemen would use any other format.  See https://xkcd.com/1179/ for more details.
$Date=Get-Date -UFormat %Y%m%d

#region define variables
$DomainControllers = "dc01.domain.tld","dc01.differentdomain.tld" #specify a DC per domain that you wish to scan.  Useful for forests with multiple domains.
$Groups = "Server Operators","Schema Admins","Print Operators","Enterprise Admins","Domain Admins","Cert Publishers","Backup Operators","Account Operators" #define which groups are "administrative" add your custom groups if necessary.
$OutputPath="\\servername\report-path\" #Can be a local file or a network share
$OutputFile = $OutputPath + 'AD-Privileged-Accounts-Weak-Config' + $Date + '.csv'

#email parameter setup
$Recipients = "user@domain.com" #specify your email recipients.  I send to my ticketing software to create a ticket for me.
$SmtpServer = "mail.domain.com" #specify your mail server.
$Sender = "no-reply@domain.com" #specify your "from" address
$Body = "Filename: Get-AdminsWithWeakParams.ps1, executed from: $env:COMPUTERNAME, executed by: $env:USERNAME<br/><br/>Description: This tool enumerates user membership of the Server Operators, Schema Admins, Print Operators, Enterprise Admins, Domain Admins, Cert Publishers, Backup Operators and Account Operators groups across all domains.<br/><br/>The tool evaluates each of these user accounts and alerts if a parameter that is considered insecure is configured.  An alert indicates that at least one parameter for the account(s) detailed below is configured in an insecure manner.<br/><br/>A description of each parameter follows:<br/><b>Group:</b> The elevated group for which the user account has been assigned.<br/><b>DistinguishedName:</b> The location of the account<br/><b>Enabled:</b> The tool only reports on enabled accounts<br/><b>AccountNotDelegated:</b> This should be TRUE to prevent unconstrained Kerberos Delegation attacks<br/><b>AllowReversiblePasswordEncryption:</b> This should be FALSE to prevent the use of reversible password encryption<br/><b>DoesNotRequirePreAuth:</b> This should be FALSE to prevent password-guessing attacks in Kerberos<br/><b>PasswordNotRequired:</b> This should be FALSE to prevent empty passwords<br/><b>UseDESKeyOnly:</b> This should be FALSE to prevent the use of DES56 for Kerberos encryption<br/><br/><br/>"
#endregion define variables

$UserlistAllDomains = @()
foreach ($DC in $DomainControllers) {
    foreach ($Group in $Groups) {
        $Users = Get-ADUser -Server $DC -Filter "memberOf -RecursiveMatch '$((Get-ADGroup -server $DC $Group).DistinguishedName)'" -Properties AccountNotDelegated,AllowReversiblePasswordEncryption,DoesNotRequirePreAuth,PasswordNotRequired,UseDESKeyOnly | Select-Object DistinguishedName,Enabled,AccountNotDelegated,AllowReversiblePasswordEncryption,DoesNotRequirePreAuth,PasswordNotRequired,UseDESKeyOnly
        $Users | ForEach-Object {
            $Userlist = New-Object PSObject
            Add-Member -InputObject $Userlist -MemberType NoteProperty -Name Domain -Value $DC
            Add-Member -InputObject $Userlist -MemberType NoteProperty -Name Group -Value $Group
            Add-Member -InputObject $Userlist -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName
            Add-Member -InputObject $Userlist -MemberType NoteProperty -Name Enabled -Value $_.Enabled
            Add-Member -InputObject $Userlist -MemberType NoteProperty -Name AccountNotDelegated -Value $_.AccountNotDelegated
            Add-Member -InputObject $Userlist -MemberType NoteProperty -Name AllowReversiblePasswordEncryption -Value $_.AllowReversiblePasswordEncryption
            Add-Member -InputObject $Userlist -MemberType NoteProperty -Name DoesNotRequirePreAuth -Value $_.DoesNotRequirePreAuth
            Add-Member -InputObject $Userlist -MemberType NoteProperty -Name PasswordNotRequired -Value $_.PasswordNotRequired
            Add-Member -InputObject $Userlist -MemberType NoteProperty -Name UseDESKeyOnly -Value $_.UseDESKeyOnly
            $UserlistAllDomains += $Userlist
            }
        }
    }
$UserlistAllDomainsFiltered = $UserlistAllDomains | Where-Object {($_.AccountNotDelegated -eq $false -or $_.AllowReversiblePasswordEncryption -eq $true -or $_.DoesNotRequirePreAuth -eq $true -or $_.PasswordNotRequired -eq $true -or $_.UseDESKeyOnly -eq $true)}
If ($UserlistAllDomainsFiltered -ne $null) {
    $UserlistAllDomainsFiltered | Export-CSV $Outputfile -NoTypeInformation
    $Body = $Body +  ($UserlistAllDomainsFiltered|ConvertTo-Html)
    #Alert via email
    Send-MailMessage -SmtpServer $SmtpServer -From $Sender -To $Recipients -Subject "Admin AD accounts with insecure parameters" -Body $Body -BodyAsHtml
    }