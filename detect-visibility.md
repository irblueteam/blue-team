# Detect\(Visibility\)

## NETWORK MONITORING

### TCPDUMP

#### View ASCII \(-A\) or HEX \(-X\) traffic:

```text
# tcpdump -A
#tcpdump -X
```

#### View traffic with timestamps and don't convert addresses and be verbose:

```text
# tcpdump -tttt -n -vv
```

#### Find top talkers after 1000 packets \(Potential DDoS\):

```text
# tcpdump -nn -c 1000 jawk '{print $3}' I cut -d. 
-fl-4 I sort -n I uniq -c I sort -nr
```

#### Capture traffic on any interface from a target host and specific port and output to a file:

```text
# tcpdump -w <FILENAME>,pcap -i any dst <TARGET IP
ADDRESS> and port 80
```

#### View traffic only between two hosts:

```text
# tcpdump host 10.0.0.1 && host 10.0.0.2
```

#### View all traffic except from a net or a host:

```text
# tcpdump not net 10.10 && not host 192.168.1,2
```

#### View host and either of two other hosts:

```text
#tcpdump host 10,10,10.10 && \(10,10.10.20 or
10,10,10,30\)
```

#### Save pcap file on rotating size:

```text
# tcpdump -n -s65535 -C 1000 -w '%host_%Y-%m­%d_%H:%M:%S.pcap'
```

#### Save pcap file to a remote host:

```text
# tcpdump -w - I ssh <REMOTE HOST ADDRESS> -p 50005
"cat - > /tmp/remotecapture.pcap"
```

#### Grab traffic that contains the word pass:

```text
# tcpdump -n -A -s0 I grep pass
```

#### Grab many clear text protocol passwords:

```text
# tcpdump -n -A -s0 port http or port ftp or port
smtp or port imap or port pop3 I egrep -i
'pass=lpwd=llog=llogin=luser=lusername=lpw=lpassw=IP
asswd=lpassword=lpass: I user: lusername: I password: I log
in: I pass I user ' --color=auto --line-buffered -B20
```

#### Get throughput:

```text
# tcpdump -w - lpv -bert >/dev/null
```

#### Filter out ipv6 traffic:

```text
# tcpdump not ip6
```

#### Filer out ipv4 traffic:

```text
# tcpdump ip6
```

#### Script to capture multiple interface tcpdumps to files rotating every hour:

```text
#!/bin/bash
tcpdump -pni any -s65535 -G 3600 -w any%Y-%m­
%d_%H:%M:%S.pcap
```

#### Script to move multiple tcpdump files to alternate location:

```text
#!/bin/bash
while true; do
sleep 1;
rsync -azvr -progress <USER NAME>@<IP
ADDRESS>:<TRAFFIC DIRECTORY>/, <DESTINATION
DIRECTORY/.
done
```

#### Look for suspicious and self-signed SSL certificates:

```text
# tcpdump -s 1500 -A '(tcp[((tcp[12:1] & 0xf0) >>
2)+5:1] = 0x01) and (tcp[((tcp[12:1] & 0xf0) >>
2) : 1] : 0x16)'
```

#### Get SSL Certificate:

```text
# openssl s_client -connect <URL>:443
# openssl s_client -connect <SITE>:443 </dev/null
2>/dev/null I sed -ne '/-BEGIN CERTIFICATE-/,/-END
CERTIFICATE-Ip' > <CERT>.pem
```

#### Examine and verify the certificate and check for Self-Signed:

```text
# openssl x509 -text -in <CERT>.pem

#openssl x509 -in <CERT>,pem -noout -issuer -
subject -startdate -enddate -fingerprint

# openssl verify <CERT>.pem
```

#### Extract Certificate Server Name:

```text
# tshark -nr <PCAP FILE NAME> -Y
"ssl. handshake. ciphersuites" -Vx I grep "Server
Name:" I sort I uniq -c I sort -r
```

#### Extract Certificate info for analysis:

```text
# ssldump -Nr <FILE NAME>.pcap I awk 'BEGIN {c=0;}
{ if ($0 � / A [ ]+Certificate$/) {c=l; print
"========================================";} if
($0 !�/ A +/) {c=0;} if (c==l) print $0; }'
```

#### Which application using port :

```text
netstat -aon | findstr '[port_number]'
tasklist | findstr '[PID]'
tasklist | findstr '[application_name]'
netstat -aon | findstr '[PID]'
```

### TSHARK

#### Get list of network interfaces:

```text
> tshark -D
```

#### Listen on multiple network interfaces:

```text
> tshark -i ethl -i eth2 -i eth3
```

#### Save to pcap and disable name resolution:

```text
> tshark -nn -w <FILE NAME>,pcap
```

#### Get absolute date and time stamp:

```text
> tshark -t a
```

#### Get arp or icmp traffic:

```text
> tshark arp or icmp
```

#### Capture traffic between to \[hosts\] and/or \[nets\]:

```text
> tshark "host <HOST l> && host <HOST 2>"
> tshark -n "net <NET 1> && net <NET 2>"
```

#### Filter just host and IPs \(or not your IP\):

```text
> tshark -r <FILE NAME>,pcap -q -z hosts,ipv4
> tshark not host <YOUR IP ADDRESS>
```

#### Not ARP and not UDP:

```text
> tshark not arp and not (udp.port -- 53)
```

#### Replay a pcap file:

```text
> tshark -r <FILE NAME>.pcap
```

#### Replay a pcap and just grab hosts and IPs:

```text
> tshark -r <FILE NAME>.pcap -q -z hosts
```

#### Setup a capture session\(duration=60sec\):

```text
> tshark -n -a files:10 -a filesize:100 -a
duration:60 -w <FILE NAME>,pcap
```

Grab src/dst IPs only:

```text
> tshark -n -e ip.src -e ip.dst -T fields -E
separator=, -Rip
```

#### Grab IP of src DNS and DNS query:

```text
> tshark -n -e ip.src -e dns,qry.name -E
separator=';' -T fields port 53
```

#### Grab HTTP URL host and request:

```text
> tshark -R http.request -T fields -E separator=';'
-e http.host -e http.request.uri
```

#### Grab just HTTP host requests:

```text
> tshark -n -R http.request -T fields -e http.host
```

#### Grab top talkers by IP dst:

```text
> tshark -n -c 150 I awk '{print $4}' I sort -n I
uniq -c I sort -nr
```

#### Grab top stats of protocols:

```text
> tshark -q -z io,phs -r <FILE NAME>.pcap
> tshark -r <PCAP FILE>,cap -R http.request -T
fields -e http.host -e http.request.uri lsed -e
'sf?,*$//' I sed -e 's#"(,*)t(,*)$#http://l2#' I
sort I uniq -c I sort -rn I head
> tshark -n -c 100 -e ip.src -R "dns.flags.response
eq 1" -T fields po rt 53
> tshark -n -e http.request.uri -R http.request -T
fields I grep exe
> tshark -n -c 1000 -e http.host -R http.request -T
fields port 80 I sort I uniq -c I sort -r
```

### SNORT

#### Run test on snort config file:

```text
# snort -T -c /<PATH TO SNORT>/snort/snort.conf
```

#### Use snort\(v=verbose,d=dump packet payload\):

```text
# snort -dv -r <LOG FILE NAME>, log
```

#### Replay a log file and match icmp traffic:

```text
# snort -dvr packet.log icmp
```

#### Logs in ASCII:

```text
# snort -K ascii -l <LOG DIRECTORY>
```

#### Logs in binary:

```text
snort -l <LOG DIRECTORY>
```

#### Sent events to console:

```text
# snort -q -A console -i eth0 -c
/etc/snort/snort.conf
# snort -c snort.conf -l /tmp/so/console -A console
```

#### Create a single snort rule and save:

```text
# echo alert any any <SNORT RULE> > one.rule
```

#### Test single rule:

```text
# snort -T -c one.rule
```

#### Run single rule and output to console and logs dir:

```text
# mkdir ,/logs
# snort -vd -c one.rule -r <PCAP FILE NAME>,pcap -A
console -l logs
```

## NETWORK CAPTURE \(PCAP\) TOOLS

### EDITCAP

#### Use to edit a pcap file \(split into 1000 packets\):

```text
> editcap -F pcap -c 1000 orignal.pcap
out_split,pcap
```

#### Use to edit a pcap file \(split into 1 hour each packets\):

```text
> editcap -F pcap -t+3600 orignal.pcap
out_split.pcap
```

### MERGECAP

#### Use to merge multiple pcap files:

```text
> mergecap -w merged_cap.pcap capl.pcap cap2.pcap
cap3.pcap
```

## HONEY TECHNIQUES

### WINDOWS

#### Honey Ports Windows:

Ref. [http://securityweekly.com/wp­](http://securityweekly.com/wp­) content/uploads/2013/06/howtogetabetterpentest.pdf

**Step 1:** Create new TCP Firewall Block rule on anything connecting on port 3333:

```text
C:\> echo @echo off for /L %%i in (1,1,1) do @for /f
"tokens=3" %%j in ('netstat -nao A l find "'":3333 A "')
do@for /f "tokens=l delims=:" %%k in ("%%j") do
netsh advfirewall firewall add rulename="HONEY TOKEN
RULE" dir=in remoteip=%%k localport=any protocol=TCP
action=block >> <BATCH FILE NAME>.bat
```

**Step 2:** Run Batch Script

```text
C:\> <BATCH FILE NAME>,bat
```

#### Windows Honey Ports PowerShell Script:

Ref. [https://github.com/Pwdrkeg/honeyport/blob/master/hon](https://github.com/Pwdrkeg/honeyport/blob/master/hon) eyport.psl

**Step 1:** Download PowerShell Script

```text
C: \> "%ProgramFiles%\Internet Exp lo rer\iexplo re. exe"
https://github.com/Pwdrkeg/honeyport/blob/master/hon
eyport.psl
```

**Step 2:** Run PowerShell Script

```text
C:\> honeyport.psl
```

#### Honey Hashes for Windows \(Also for Detecting Mimikatz Use\) :

Ref. [https://isc.sans.edu/forums/diary/Detecting+Mimikatz](https://isc.sans.edu/forums/diary/Detecting+Mimikatz) +Use+On+Your+Network/19311/

**Step 1:** Create Fake Honey Hash. Note enter a fake password and keep command prompts open to keep password in memory

```text
C:\> runas
/user:yourdomain.com\fakeadministratoraccount
/netonly cmd.exe
```

**Step 2:** Query for Remote Access Attempts

```text
C:\> wevtutil qe System /q:"*[System
[(EventID=20274)]]" /f:text /rd:true /c:1
/r:remotecomputername
```

**Step 3:** Query for Failed Login Attempts

```text
C:\> wevtutil qe Security /q:"*[System[(EventID=4624
or EventID=4625)]]" /f:text /rd:true /c:5
/r:remotecomputername
```

**Step 4:** \(Optional\) Run queries in infinite loop with 30s pause

```text
C:\> for /L %i in (1,0,2) do (Insert Step 2) &
(Insert Step 3) & timeout 30
```

### LINUX

#### Honey Ports Linux:

Ref. [http://securityweekly.com/wp­](http://securityweekly.com/wp­) content/uploads/2013/06/howtogetabetterpentest.pdf

**Step 1:** Run a while loop to create TCP Firewall rules to block any hosts connecting on port 2222

```text
# while [ 1 ] ; echo "started" ; do IP='nc -v -l -p
2222 2>&1 l> /dev/null I grep from I cut -d[ -f 3 I
cut -d] -f 1'; iptables -A INPUT -p tcp -s ${IP} -j
DROP ; done
```

#### Linux Honey Ports Python Script:

Ref. [https://github.com/gchetrick/honeyports/blob/master/](https://github.com/gchetrick/honeyports/blob/master/) honeyports-0.5.py

**Step 1:** Download Python Script

```text
# wget
https://github.com/gchetrick/honeyports/blob/master/
honeyports-0.5.py
```

**Step 2:** Run Python Script

```text
# python honeyports-0.5.py -p <CHOOSE AN OPEN PORT>
-h <HOST IP ADDRESS>
```

#### Detect rogue scanning with Labrea Tarpit:

```text
# apt-get install labrea
# labrea -z -s -o -b -v -i eth0 2>&1 | tee -a log.txt
```

### NETCAT

#### Use netcat to listen for scanning threats:

```text
> nc -v -k -l 80
> nc -v -k -l 443
> nc -v -k -l 3389
```

### PASSIVE DNS MONITORING

#### Use dnstop to monitor DNS requests at any sniffer location:

```text
# apt-get update
# apt-get install dnstop
# dnstop -l 3 <INTERFACE NAME>
```

**Step 1:** Hit 2 key to show query names

#### Use dnstop to monitor DNS requests from a pcap file:

```text
# dnstop -l 3 <PCAP FILE NAME> I <OUTPUT FILE
NAME>,txt
```

## LOG AUDITING

### WINDOWS

#### Increase Log size to support increased auditing:

```text
C:\> reg add
HKLM\Software\Policies\Microsoft\Windows\Eventlog\Ap
plication /v MaxSize /t REG_DWORD /d 0x19000
C:\> reg add
HKLM\Software\Policies\Microsoft\Windows\Eventlog\Se
curity /v MaxSize /t REG_DWORD /d 0x64000
C:\> reg add
HKLM\Software\Policies\Microsoft\Windows\EventLog\Sy
stem /v MaxSize /t REG_DWORD /d 0x19000
```

#### Check settings of Security log:

```text
C:\> wevtutil gl Security
```

#### Check settings of audit policies:

```text
C:\> auditpol /get /category:*
```

#### Set Log Auditing on for Success and/or Failure on All Categories:

```text
C:\> auditpol /set /category:* /success:enable
/failure:enable
```

#### Set Log Auditing on for Success and/or Failure on Subcategories:

```text
C: \> auditpol /set /subcategory: "Detailed File
Share" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"File System"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Security System
Extension" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"System Integrity"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Security State
Change" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Other System
Events" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"System Integrity"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Logon"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Logoff"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Account Lockout"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Other Logon/Logoff
Events" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Network Policy
Server" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Registry"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"SAM"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Certification
Services" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Application
Generated" /success:enable /failure:enable
C: \> auditpol / set /subcategory: "Handle
Manipulation" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"file Share"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"filtering Platform
Packet Drop" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Filtering Platform
Connection" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Other Object Access
Events" /success:enable /failure:enable
C: \> auditpol /set /subcategory: "Detailed File
Share" /success:enable /failure:enable
C: \> auditpol /set /subcategory: "Sensitive Privilege
Use" /success:enable /failure:enable
C: \> auditpol /set /subcategory: "Non Sensitive
Privilege Use" /success:enable /failure:enable
C: \> auditpol /set /subcategory: "Other Privilege Use
Events" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Process
Termination" /success:enable /failure:enable
C:\> auditpol /set /subcategory: "DPAPI Activity"
/success:enable /failure:enable
C: \> audit pol /set /subcategory: "RPC Events"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Process Creation"
/success:enable /failure:enable
C:\> auditpol /set /subcategory:"Audit Policy
Change" /success:enable /failure:enable
C:\> auditpol /set /subcategory: "Authentication
Policy Change" /success:enable /failure:enable
C:\> auditpol /set /subcategory: "Authorization
Policy Change" /success:enable /failure:enable
C: \> audit pol /set /subcategory: "MPSSVC Rule-Level
Policy Change" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Filtering Platform
Policy Change" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Other Policy Change
Events" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"User Account
Management" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Computer Account
Management" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Security Group
Management" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Distribution Group
Management" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Application Group
Management" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Other Account
Management Events" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Directory Service
Changes" /success:enable /failure:enable
C: \> auditpol / set /subcategory: "Directory Service
Replication" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Detailed Directory
Service Replication" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Directory Service
Access" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Kerberos Service
Ticket Operations" /success:enable /failure:enable
C:\> auditpol /set /subcategory:"Other Account Logan
Events" /success:enable /failure:enable
C: \> audit pol /set /subcategory: "Kerberos
Authentication Service" /success:enable
/failure:enable
C:\> auditpol /set /subcategory:"Credential
Validation" /success:enable /failure:enable
```

#### Check for list of available logs, size, retention limit:

```text
PS C:\> Get-Eventlog -list
```

#### Partial list of Key Security Log Auditing events to monitor:

```text
PS C:\> Get-Eventlog -newest 5 -logname application
I Format-List
```

#### Show log from remote system:

```text
PS C:\> Show-Eventlog -computername <SERVER NAME>
```

#### Get a specific list of events based on Event ID:

```text
PS C:\> Get-Eventlog Security I ? { $_.Eventid -eq
4800}
PS C:\> Get-WinEvent -FilterHashtable
@{LogName="Secu rity"; ID=4774}
```

#### Account Logon - Audit Credential Validation Last 14 Days:

```text
PS C:\> Get-Eventlog Security
4768,4771,4772,4769,4770,4649,4778,4779,4800,4801,48
02,4803,5378,5632,5633 -after ((get-date).addDays(-
14))
```

#### Account - Logon/Logoff:

```text
PS C:\> Get-Eventlog Security
4625,4634,4647,4624,4625,4648,4675,6272,6273,6274,62
75,6276,6277,6278,6279,6280,4649,4778,4779,4800,4801
,4802,4803,5378,5632,5633,4964 -after ((get­
date).addDays(-1))
```

#### Account Management - Audit Application Group Management:

```text
PS C:\> Get-Eventlog Security
4783,4784,4785,4786,4787,4788,4789,4790,4741,4742,47
43,4744,4745,4746,4747,4748,4749,4750,4751,4752,4753
,4759,4760,4761,4762,4782,4793,4727,4728,4729,4730,4
731,4732,4733,4734,4735,4737,4754,4755,4756,4757,475
8,4764,4720,4722,4723,4724,4725,4726,4738,4740,4765,
4766,4767,4780,4781,4794,5376,5377 -after ((get­
date).addDays(-1))
```

#### Detailed Tracking - Audit DPAPI Activity, Process Termination, RPC Events:

```text
PS C:\> Get-EventLog Security
4692,4693,4694,4695,4689,5712 -after ((get­
date).addDays(-1))
```

#### Domain Service Access - Audit Directory Service Access:

```text
PS C:\> Get-EventLog Security
4662,5136,5137,5138,5139,5141 -after ((get­
date).addDays(-1))
```

#### Object Access - Audit File Share, File System, SAM, Registry, Certifications:

```text
PS C:\> Get-EventLog Security
4671,4691,4698,4699,4700,4701,4702,5148,5149,5888,58
89,5890,4657,5039,4659,4660,4661,4663,4656,4658,4690
,4874,4875,4880,4881,4882,4884,4885,4888,4890,4891,4
892,4895,4896,4898,5145,5140,5142,5143,5144,5168,514
0,5142,5143,5144,5168,5140,5142,5143,5144,5168,4664,
4985,5152,5153,5031,5140,5150,5151,5154,5155,5156,51
57,5158,5159 -after ((get-date).addDays(-1))
```

#### Policy Change - Audit Policy Change, Microsoft Protection Service, Windows Filtering Platform:

```text
PS C:\> Get-EventLog Security
4715,4719,4817,4902,4904,4905,4906,4907,4908,4912,47
13,4716,4717,4718,4739,4864,4865,4866,4867,4704,4705
,4706,4707,4714,4944,4945,4946,4947,4948,4949,4950,4
951,4952,4953,4954,4956,4957,4958,5046,5047,5048,544
9,5450,4670 -after ((get-date).addDays(-1))
```

#### Privilege Use - Audit Non-Sensitive/Sensitive Privilege Use:

```text
PS C:\> Get-EventLog Security 4672,4673,4674 -after
((get-date),addDays(-1))
```

#### System - Audit Security State Change, Security System Extension, System Integrity, System Events:

```text
PS C:\> Get-Eventlog Security
5024,5025,5027,5028,5029,5030,5032,5033,5034,5035,50
37,5058,5059,6400,6401,6402,6403,6404,6405,6406,6407
,4608,4609 ,4616, 4621, 4610, 4611, 4614,
4622,4697,4612,4615,4618,4816,5038,5056,5057,5060,50
61,5062,6281 -after ((get-date).addDays(-1))
```

#### Add Microsoft IIS cmdlet:

```text
PS C:\> add-pssnapin WebAdministration
PS C:\> Import-Module WebAdministration
```

#### Get IIS Website info:

```text
PS C:\> Get-IISSite
```

#### Get IIS Log Path Location:

```text
PS C:\> (Get-WebConfigurationProperty
'/system.applicationHost/sites/siteDefaults' -Name
'logfile.directory').Value
```

#### Set variable for IIS Log Path \(default path\):

```text
PS C:\> $LogDirPath =
"C:\inetpub\logs\LogFiles\W3SVCl"
```

#### Get IIS HTTP log file list from Last 7 days:

```text
PS C:\> Get-Child!tem -Path
C:\inetpub\logs\LogFiles\w3svcl -recurse I Where­
Object {$_. lastwritetime -lt (get-date).addDays(-7)}
```

#### View IIS Logs \(Using $LogDirPath variable set above\):

```text
PS C:\> Get-Content $LogDirPath\*, log I%{$_ -replace
'#Fields: ', "} I?{$_ -notmatch ""#'} I
ConvertFrom-Csv -Delimiter ' '
```

#### View IIS Logs:

```text
PS C:\> Get-Content <!IS LOG FILE NAME>, log I%{$_ -
replace '#Fields: ', ''} 17{$_ -notmatch 'A#'} I
ConvertFrom-Csv -Delimiter ' '
```

#### Find in IIS logs IP address 192.168._·_ pattern:

```text
PS C:\> Select-String -Path $LogDirPath\*, log -
Pattern '192,168,*,*'
```

#### Find in IIS logs common SQL injection patterns:

```text
PS C:\> Select-String -Path $LogDirPath\*, log
'(@@version) I (sqlmap) I (Connect\(\)) I (cast\() I (char\(
) I ( bcha r\ () I ( sys
databases) I ( \ (select) I (convert\ () I ( Connect\ () I ( count
\() I (sys objects)'
```

### LINUX

#### Authentication logs in Ubuntu:

```text
# tail /var/log/auth. log
# grep -i "fail" /var/log/auth. log
```

#### User login logs in Ubuntu:

```text
# tail /var/
```

#### Look at samba activity:

```text
# grep -i samba /var/log/syslog
```

#### Look at cron activity:

```text
# grep -i cron /var/log/syslog
```

#### Look at sudo activity:

```text
# grep -i sudo /var/log/auth. log
```

#### Look in Apache Logs for 404 errors:

```text
# grep 404 <LOG FILE NAME> I grep -v -E
"favicon. ico I robots. txt"
```

#### Look at Apache Logs for files requested:

```text
# head access_log I awk '{print $7}'
```

#### Monitor for new created files every 5min:

```text
# watch -n 300 -d ls -lR /<WEB DIRECTORY>
```

#### Look where traffic is coming from:

```text
# cat <LOG FILE NAME> I fgrep -v <YOUR DOMAIN> I cut
-d\" -f4 I grep -v ""-
```

#### Monitor for TCP connections every 5 seconds:

```text
# netstat -ac 5 I grep tcp
```

#### Install audit framework and review syscalls/events:

```text
# apt-get install auditd
# auditctl -a exit,always -5 execve
# ausearch -m execve
```

#### Get audit report summary:

```text
# aureport
```

