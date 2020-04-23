<#
.SYNOPSIS
  
Receieves alerts from a simulated SIEM and responds to perform
an action on the vm based on severity by using powercli
  
.DESCRIPTION

Polls an email account every 5 munites using IMAP for emails with a specific subject line
Each email gathered is parsed for a string that looks like "Level:$severity`nComputer:$computerName"
Each alert is then used to perform an action on a vcenter vm using powercli. This script also can send alerts for 
testing purposes. Simulated alerts are created when the script is called with the -alert flag and sends the alert with SMTP

.EXAMPLE

pwsh ./Simulate-Alert.ps1
pwsh ./Simulate-Alert.ps1 -alert
alert flag simulates the SIEM alert

.Notes
               
Author: Jacob Henning
tested on both windows 10 and ubuntu 19.04
#>

#.NET libraries needed to open an SSL connection
using namespace System.IO;
using namespace System.Text;
using namespace System.Net.Sockets;
using namespace System.Net.Security;
using namespace System.Security.Cryptography.X509Certificates;

param(
        [switch]$alert
)

<#
.DESCRIPTION

Main Entrypoint of the script
#>
function main
{
        #send simulated email alert if switch is called and stop script execution
        if ($alert)
        {
                $computer = Read-Host "enter the computer vm name"
                $level = Read-Host "Enter the alert level ex. low,normal,high"
                $sender = Read-Host "Enter email sender"
                $recip = Read-Host "Enter email recipient"
                send-Alert $sender $recip $computer $level
                Exit
        }

        #get email credentials
        $usr = Read-Host "Enter email username"
        $pswd = Read-Host "Enter $usr password" -AsSecureString
        $cred = New-Object System.Net.NetworkCredential $usr,$pswd

        #get vcenter credentials
        $vcen = Read-Host "Enter Vcenter server"
        $vusr = Read-Host "Enter Vcenter user"
        $vpswd = Read-Host "Enter Vcenter password" -AsSecureString
        
        
        echo "Listening for Security Alerts"
        #poll email every five minutes infinite loop
        while($true)
        {

                $alerts = get-SecurityAlert $usr ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pswd))) "imap.gmail.com" 993
                #echo $alerts

                foreach ($alert in $alerts){
                        echo "alert:$alert"
                        #perform action

                        $split =$alert.IndexOf("Computer:")

                        #alert level
                        $l = $alert.Substring(6,$split-9)

                        #computer name
                        $c = $alert.Substring($split+9)

                        vcenter-Response $vcen $vusr ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($vpswd))) $l $c

                }

                echo "Last updated on $(Get-Date)"
                #wait 5 minutes
                start-sleep -seconds 500
        }

        echo "Stopped Listening for security alerts"
}

<#
.DESCRIPTION

Sends the simulated SIEM alert using SMTP

.PARAMETER Sender

Email account that will be used to send the email

.PARAMETER recip

Email account that the email will be sent to

.PARAMETER computerName 

Computer hostname that will be used in the alert

.PARAMETER severity

Severity level that will be used in the alert i.e low,normal,high

.PARAMTER smtpServer

smtp server to be used; defualt smtp.gmail.com

.PARAMETER smtpPort

tcp port of the smtp sever; default 587 
#>
function send-Alert
{
param (
        [parameter (Mandatory=$true)]
        [String]$sender,
        [parameter (Mandatory=$true)]
        [String]$recip,
        [parameter (Mandatory=$true)]
        [String]$computerName,
        [String]$severity="normal",
        [String]$smtpServer="smtp.gmail.com",
        [String]$smtpPort="587"
)
        $pswd = Read-Host "Enter Password for $sender" -AsSecureString
        $cred = New-Object System.Net.NetworkCredential $sender,$pswd
        $emailMessage = New-Object System.Net.Mail.MailMessage($sender,$recip)
        $emailMessage.Subject = "SIEM-Security-Alert"
        $emailMessage.Body = "Level:$severity`nComputer:$computerName"

        $client = New-Object System.Net.Mail.SmtpClient( $smtpServer, $smtpPort)
        $client.EnableSsl = $True
        $client.Credentials = $cred
        $client.Send($emailMessage)
}

<#
.DESCRIPTION

Reads from a buffered network stream

.PARAMETER stream

stream object to read from 

.PARAMETER bufsize 
size of the buffer; default 4KB

.PARAMETER enc

what format the stream is formatted in; default ASCII
#>
function StreamRead
{
        param([Stream]$stream, [int]$bufsize = 4*1KB, [Encoding]$enc = [Encoding]::ASCII)
        $buffer = [byte[]]::new($bufsize)
        $bytecount = $stream.Read($buffer, 0, $bufsize)
        $response = $enc.GetString($buffer, 0, $bytecount)
        Write-Debug "< $($response.trim())"
        $response
}

<#
.DESCRIPTION

Writes to a network stream

.PARAMETER stream

stream object to write to

.PARAMETER command 
what is being written to the stream

.PARAMETER enc

what format the stream is formatted in; default ASCII
#>
function StreamWrite
{
        param([Stream]$stream, [string]$command, [Encoding]$enc = [Encoding]::ASCII)
        $data = $enc.GetBytes($command)
        Write-Debug "> $($command.trim())"
        $stream.Write($data, 0, $data.Length)
}

<#
.DESCRIPTION

Gets the body of the email alerts

.PARAMETER usr

username of the email account recieving alerts

.PARAMETER pswd

password of the email account receiving alerts

.PARAMETER server

hostname or address of the IMAP server

.PARAMETER

TCP port of the IMAP server
#>
function get-SecurityAlert
{
        param([String]$usr,[String]$pswd,[String]$server,$port)

        #carriage return + newline i.e enter
        $CRLF = "`r`n"

        #instantiate tcp socket
        $client = [TcpClient]::new($server, $port)
        $client.ReceiveTimeout = 2000 #milliseconds

        #setup ssl stream to use gmail
        $acceptAnyCertificate = [RemoteCertificateValidationCallback] { $true }
        $sslStream = [SslStream]::new($client.GetStream(), $false, $acceptAnyCertificate)
        $sslStream.AuthenticateAsClient($server)

        # read server hello
        $response = StreamRead $sslStream
        #echo $response

        # log in
        StreamWrite $sslStream ("a2 LOGIN $usr $pswd" + $CRLF)
        $response = StreamRead $sslStream
        #echo $response

        #select defualt GMAIL inbox may need to be changed if you don't use gmail
        StreamWrite $sslStream ("a2 SELECT Inbox" + $CRLF)
        $response = StreamRead $sslStream
        #echo $response

        #Get the email UIDS of unread emails with SIEM-Security-Alert as the subject
        StreamWrite $sslStream ("a2 UID SEARCH SUBJECT `"SIEM-Security-Alert`" UNSEEN" + $CRLF)
        $response = StreamRead $sslStream
        #echo $response

        #get the uids from the response
        $response = $response -replace "`n"," "
        $uids = $response.split(" ")
        #echo $uids
        
        $uidsN = @()

        #make sure the uid in the array is a valid number
        foreach ($uid in $uids)
        {
                $uid = $uid.Trim()
                #regex checks if number
                if ($uid -match '^[0-9]+$')
                {
                        $uidsN = $uidsN += $uid
                }
        }
        
        
        #get each email message
        $alerts = @()
        $counter=1
        foreach ($uid in $uidsN)
        {
                #echo $uid
                $qualifier = "f$counter"
                #gets each email but doesn't mark it as read
                #StreamWrite $sslStream ("a2 UID FETCH $uid BODY.PEEK[TEXT]" + $CRLF)
                
                #gets each email but marks it as read
                $msg = "$qualifier UID FETCH $uid BODY[TEXT]"
                #echo $msg
                StreamWrite $sslStream ($msg + $CRLF)
                
                $response = StreamRead $sslStream
                $filteredResponse = ""
                #echo $response

                #ensure that there is a valid alert format before continuing
                while ($filteredResponse.Length -lt 1)
                {
                    $response = $response + (StreamRead $sslStream)
                    $cmd = $response.Split()
                    $filteredResponse = $cmd | Where-Object -FilterScript { $_ -like "Level:*Computer:*" }
                }

                #echo $response

                
                #echo $filteredResponse
                $alerts = $alerts += $filteredResponse
                $counter++
        }

        # log out
        StreamWrite $sslStream ("a2 LOGOUT" + $CRLF)
        $response = StreamRead $sslStream
        #echo $response

        #disconnect from the server
        $sslStream.Close()
        $client.Close()

        return $alerts
}

<#
.DESCRIPTION      

Connects to the vcenter server and perform a triage action on a vm based on the severity

.PARAMETER server

vcenter server

.PARAMETER usr

vcenter username

.PARAMETER pswd

vcenter users password

.PARAMETER level

severity from the alert 

.PARAMETER computer

computer from the alert 
#>
function vcenter-Response
{
        param([String]$server,[String]$usr,[String]$pswd,[String]$level,[String]$computer)

        #accept untrusted cert from vcenter server
        #Set-PowerCLIConfiguration -InvalidCertificationAction Ignore -Confirm:$false

        Connect-VIServer -Server $server -User $usr -Password $pswd -Force

        $vm = Get-VM $computer

        if ($level -eq "low")
        {
                #forcibly shutdown vm if it triggered a low level alert
                $vm | Stop-VM -Confirm:$false
        }
        elseif ($level -eq "normal")
        {
                #forcibly shutdown vm if it triggered a normal level alert but also take a snapshot for forensic purposes
                $vm | Stop-VM -Confirm:$false
                $vm | New-Snapshot -Name "Alert Triggered" -Confirm:$false
        }
        elseif ($level -eq "high")
        {
                #shutdown vm, take snapshot, disable network adapter
                $vm | Get-NetworkAdapter | Set-NetworkAdapter -Connected:$false -Confirm:$false
                $vm | Stop-VM -Confirm:$false
                $vm | New-Snapshot -Name "Alert Triggered" -Confirm:$false
        }
        else{
                echo "error: invalid alert level"
        }

        Disconnect-VIServer -Server $server -Force -Confirm:$false
}


main
