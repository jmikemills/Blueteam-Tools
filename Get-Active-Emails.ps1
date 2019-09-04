#Given a list of email addresses, check AD and produce a list of those that are still actvive.  Used for HaveIBeenPwned notifications to identify potentially impacted employees.
$ADSMTP = (get-aduser -filter "Enabled -eq 'TRUE'" -properties proxyAddresses | Select proxyAddresses).proxyAddresses | foreach {IF ($_ -notlike "x400:*"){$_}}
$ADSMTP = ($ADSMTP.tolower()).replace("smtp:","")
$ActiveAddresslist = @()

$InputSMTP = Get-Content C:\tools\temp\SMTP-All.txt #list of email addresses, one per line.
Foreach ($Address in $InputSMTP) {
    Foreach ($Record in $ADSMTP){
        IF ($Address -match $Record) {
            $ActiveAddress = New-Object PSObject
            Add-Member -InputObject $ActiveAddress -MemberType NoteProperty -Name Address -Value $Address
            $ActiveAddresslist += $ActiveAddress
            }
        }
    }
$ActiveAddresslist.address #>C:\tools\temp\active-smtp-addresses.txt