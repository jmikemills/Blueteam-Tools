# Blueteam-Tools
Simple tools to help the good guys

Get-AdminsWithWeakParams.ps1:  Look through all specified domains, searching for accounts that are members of groups that provide elevated rights and check that the account is configured per security best practices.  This is an attempt at test-driven security, where I write code to prove a fault, work to to eliminate the fault, then schedule a version of the code to continuously look for a reoccurance of the fault.


Get-Active-Emails.ps1: Given a list of email addresses, check AD and produce a list of those that are still actvive.  Used for HaveIBeenPwned notifications to identify potentially impacted employees.


Get-UnconstrainedDelegation.ps1: Look through all specified domains for accounts with Unconstrained Kerberos Delegation.  This is an attempt at test-driven security, where I write code to prove a fault, work to to eliminate the fault, then schedule a version of the code
to continuously look for a reoccurance of the fault.
